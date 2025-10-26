package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"

	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"user-management-grpc/api/proto"
	"user-management-grpc/internal/auth"
	"user-management-grpc/internal/config"
	"user-management-grpc/internal/database"
	"user-management-grpc/internal/notification"
	"user-management-grpc/internal/scheduler"
	"user-management-grpc/internal/tracing" // ⬅️ THÊM: Import PProf xịn của bạn
	"user-management-grpc/internal/user"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type contextKey string

const (
	userIDKey   contextKey = "userID"
	userRoleKey contextKey = "userRole"
)

func main() {
	log.Println("🚀 Starting User Management gRPC Service...")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("❌ Lỗi khi load config: %v", err)
	}

	if cfg.AppEnv == "dev" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// ✅ Chạy pprof (Req 9) - ⬅️ SỬA: Dùng profiler xịn của bạn
	var profiler *tracing.Profiler
	if cfg.AppEnv == "dev" && cfg.Server.PProfPort != "" {
		profiler = tracing.NewProfiler(cfg.Server.PProfPort)
		profiler.Start()                                                          // Chạy server pprof (bất đồng bộ)
		log.Printf("📊 PProf server đang chạy tại port: %s", cfg.Server.PProfPort) // Thêm log rõ ràng
	}

	// ✅ Kết nối MySQL (Req 3)
	mysqlDB, err := database.NewMySQL(cfg.Database.MySQLDSN)
	if err != nil {
		log.Fatalf("❌ Lỗi kết nối với MySQL: %v", err)
	}
	defer mysqlDB.Close()
	log.Println("✅ Đã kết nối MySQL")

	// Tạo bảng (chỉ nên dùng cho dev)
	if cfg.AppEnv == "dev" {
		if err := database.CreateUserTable(mysqlDB); err != nil {
			// Sửa lỗi log để rõ ràng hơn
			log.Printf("⚠️ Lỗi tạo bảng MySQL (có thể đã tồn tại): %v", err)
		}
	}

	// ✅ Kết nối ScyllaDB (Req 3) - ⬅️ SỬA: Dùng logic thật
	var scyllaRepo *database.ScyllaRepo // Khai báo repo thật
	// Gọi hàm NewScylla thật từ database/scylla.go
	scyllaSession, err := database.NewScylla(
		[]string{cfg.Database.ScyllaAddr},
		cfg.Database.ScyllaKeyspace,
	)
	if err != nil {
		log.Printf("⚠️ Không thể kết nối ScyllaDB (sẽ tiếp tục chạy): %v", err)
		// scyllaRepo sẽ là nil,các service cần xử lý được điều này
	} else {
		scyllaRepo = scyllaSession // Gán repo thật nếu kết nối thành công
		defer scyllaRepo.Close()   // Đảm bảo đóng kết nối khi thoát
		log.Println("✅ Đã kết nối ScyllaDB")
	}

	// ✅ Kết nối Redis (Req 3)
	redisDBClient, err := database.NewRedis(
		cfg.Database.RedisAddr,
		cfg.Database.RedisPass,
		cfg.Database.RedisDB,
	)
	if err != nil {
		log.Fatalf("❌ Lỗi kết nối với Redis: %v", err)
	}
	defer database.CloseRedis(redisDBClient)
	log.Println("✅ Đã kết nối Redis")

	// === Khởi tạo Services ===
	redisAdapter := database.NewRedisAdapter(redisDBClient)
	userRepo := user.NewMySQLRepository(mysqlDB)

	// Service cần kiểm tra nil trước khi dùng repo
	notificationService := notification.NewService(scyllaRepo)
	defer notificationService.Stop()

	// Wrapper
	notificationClient := NewNotificationClientWrapper(notificationService)

	// User Service
	userService := user.NewService(userRepo, notificationClient)

	// Auth Service
	authService := auth.NewService(
		userRepo,
		redisAdapter,
		cfg.JWT.Secret,
		cfg.JWT.Expiry,
	)

	// === Khởi tạo gRPC Server (Req 1) ===
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(authInterceptor(authService)),
	)
	proto.RegisterUserServiceServer(grpcServer, userService)
	proto.RegisterAuthServiceServer(grpcServer, authService)
	proto.RegisterNotificationServiceServer(grpcServer, notificationService)

	go func() {
		lis, err := net.Listen("tcp", ":"+cfg.Server.GRPCPort)
		if err != nil {
			log.Fatalf("❌ Không thể lắng nghe gRPC: %v", err)
		}
		log.Println("✅ gRPC Server lắng nghe tại :" + cfg.Server.GRPCPort)
		if err := grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			log.Fatalf("❌ gRPC lỗi: %v", err)
		}
	}()

	// === Khởi tạo HTTP Server (Req 1) ===
	var httpSrv *http.Server // Cần tham chiếu để Shutdown
	go func() {
		r := gin.Default()
		httpHandler := NewHTTPHandler(userService, authService)
		setupHTTPRoutes(r, httpHandler, authService)

		log.Println("✅ HTTP Server chạy tại :" + cfg.Server.HTTPPort)
		httpSrv = &http.Server{
			Addr:    ":" + cfg.Server.HTTPPort,
			Handler: r,
		}
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ HTTP lỗi: %v", err)
		}
	}()

	// === Khởi tạo Scheduler (Req 4) ===
	schedulerCtx, schedulerCancel := context.WithCancel(context.Background())
	defer schedulerCancel()

	// Đảm bảo interface scheduler.ScyllaRepository và database.ScyllaRepo khớp

	scheduler.StartScheduler(schedulerCtx, userRepo, authService, scyllaRepo)
	log.Println("✅ Scheduler đã khởi chạy")
	// === Graceful shutdown ===
	// Chờ tín hiệu shutdown và gọi hàm xử lý
	waitForShutdown(grpcServer, httpSrv, profiler, schedulerCancel, notificationService)
}

// 🎯 NOTIFICATION CLIENT WRAPPER

type NotificationClientWrapper struct{ service *notification.Service }

func NewNotificationClientWrapper(service *notification.Service) *NotificationClientWrapper {
	return &NotificationClientWrapper{service: service}
}
func (w *NotificationClientWrapper) SendWelcomeEmail(ctx context.Context, req *proto.NotificationRequest, opts ...grpc.CallOption) (*proto.NotificationResponse, error) {
	return w.service.SendWelcomeEmail(ctx, req)
}
func (w *NotificationClientWrapper) SendNotification(ctx context.Context, req *proto.NotificationRequest, opts ...grpc.CallOption) (*proto.NotificationResponse, error) {
	return w.service.SendNotification(ctx, req)
}

// 🛡️ gRPC AUTHENTICATION INTERCEPTOR

func authInterceptor(authService *auth.Service) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		publicMethods := map[string]bool{
			"/user.AuthService/Login":                    true,
			"/user.UserService/CreateUser":               true,
			"/user.AuthService/ValidateToken":            true,
			"/user.NotificationService/SendWelcomeEmail": true,
		}
		if publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}
		// Private methods: Extract token
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "metadata không tồn tại")
		}
		tokens := md.Get("authorization")
		if len(tokens) == 0 {
			return nil, status.Error(codes.Unauthenticated, "authorization header là bắt buộc")
		}
		tokenString := strings.TrimPrefix(tokens[0], "Bearer ")

		// Validate token
		authResp, err := authService.ValidateToken(ctx, &proto.AuthRequest{Token: tokenString})
		if err != nil || !authResp.Valid {
			return nil, status.Error(codes.Unauthenticated, "token không hợp lệ")
		}
		// Get user role
		userRole, err := authService.GetUserRole(ctx, authResp.UserId)
		if err != nil {
			log.Printf("Lỗi khi lấy role cho user %s: %v", authResp.UserId, err)
			return nil, status.Error(codes.Internal, "không thể lấy user role")
		}

		// Authorization check for admin methods
		adminMethods := map[string]bool{
			"/user.UserService/DeleteUser":               true,
			"/user.UserService/ListUsers":                true,
			"/user.NotificationService/SendNotification": true,
			// Thêm các endpoint admin khác nếu có
			"/user.UserService/GetAdminMetrics": true,
			"/user.UserService/BulkCreateUsers": true,
		}
		if adminMethods[info.FullMethod] {
			if userRole != "admin" {
				return nil, status.Error(codes.PermissionDenied, "yêu cầu quyền admin")
			}
			log.Printf("👑 Admin access granted for user: %s", authResp.UserId)
		}
		ctx = context.WithValue(ctx, userIDKey, authResp.UserId)
		ctx = context.WithValue(ctx, userRoleKey, userRole)
		log.Printf("✅ Auth (gRPC) passed for user: %s, method: %s", authResp.UserId, info.FullMethod)
		return handler(ctx, req)
	}
}

// 🛑 GRACEFUL SHUTDOWN HANDLER

func waitForShutdown(grpcServer *grpc.Server, httpSrv *http.Server, profiler *tracing.Profiler, schedulerCancel context.CancelFunc, notificationService *notification.Service) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("🛑 Nhận tín hiệu shutdown: %v", sig)
	log.Println("🛑 Đang tắt hệ thống...")
	// Thứ tự shutdown: PProf -> Scheduler -> Notification -> HTTP -> gRPC
	if profiler != nil {
		log.Println("⏹️ 0. Đang dừng PProf server...")
		profiler.Stop()
	}
	log.Println("⏹️ 1. Đang dừng scheduler...")
	schedulerCancel()
	if notificationService != nil {
		log.Println("⏹️ 2. Đang dừng notification service...")
		notificationService.Stop()
	}
	if httpSrv != nil {
		log.Println("⏹️ 3. Đang dừng HTTP server...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(ctx); err != nil {
			log.Printf("❌ Lỗi shutdown HTTP server: %v", err)
		}
	}
	log.Println("⏹️ 4. Đang dừng gRPC server (GracefulStop)...")
	grpcServer.GracefulStop()
	log.Println("⏳ Đang đợi các goroutine hoàn thành...")
	time.Sleep(1 * time.Second)
	log.Println("✅ Hệ thống đã tắt an toàn")
}

// 🌐 HTTP HANDLERS (Gin) (Giữ nguyên)

type HTTPHandler struct {
	userService *user.Service
	authService *auth.Service
}

func NewHTTPHandler(u *user.Service, a *auth.Service) *HTTPHandler {
	return &HTTPHandler{userService: u, authService: a}
}
func setupHTTPRoutes(r *gin.Engine, h *HTTPHandler, authService *auth.Service) {
	r.GET("/health", h.healthCheck)
	r.GET("/api/system/info", h.systemInfo)
	apiV1 := r.Group("/api/v1")
	{
		// Public routes
		apiV1.POST("/auth/login", h.login)
		apiV1.POST("/users", h.createUser)
		// Private routes (cần auth)
		private := apiV1.Group("")
		private.Use(httpAuthMiddleware(authService))
		{
			users := private.Group("/users")
			{
				// User routes
				users.GET("/me", h.getMe) // Lấy thông tin user đang đăng nhập
				users.GET("/:id", h.getUser)
				users.PUT("/:id", h.updateUser)
				users.GET("", adminOnlyMiddleware(), h.listUsers)
				users.DELETE("/:id", adminOnlyMiddleware(), h.deleteUser) // Cần kiểm tra quyền admin
			}
			// Auth routes (cần auth)
			authGroup := private.Group("/auth") // Đổi tên biến để tránh trùng
			{
				authGroup.POST("/logout", h.logout)
				authGroup.POST("/refresh", h.refreshToken) // ⬅️ THÊM ROUTE REFRESH
			}
			// Admin routes (cần auth + role admin)
			admin := private.Group("/admin")
			admin.Use(adminOnlyMiddleware())
			{
				admin.GET("/metrics", h.getAdminMetrics)
				admin.POST("/users/bulk", h.bulkCreateUsers) // ⬅️ THÊM ROUTE BULK CREATE
			}
		}
	}
}
func (h *HTTPHandler) healthCheck(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "healthy"}) }
func (h *HTTPHandler) systemInfo(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"goroutines": runtime.NumGoroutine()})
}
func (h *HTTPHandler) login(c *gin.Context) {
	var req proto.LoginRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Gọi trực tiếp auth service
	resp, err := h.authService.Login(c.Request.Context(), &req)
	if err != nil {
		st, _ := status.FromError(err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": st.Message()})
		return
	}
	c.JSON(http.StatusOK, resp)
}
func (h *HTTPHandler) createUser(c *gin.Context) {
	var req proto.CreateUserRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}
	// Gọi trực tiếp user service
	resp, err := h.userService.CreateUser(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, resp)
}
func (h *HTTPHandler) getMe(c *gin.Context) {
	authUserID, _ := c.Get(string(userIDKey)) // Lấy userID từ context
	resp, err := h.userService.GetUser(c.Request.Context(), &proto.GetUserRequest{Id: authUserID.(string)})
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	c.JSON(http.StatusOK, resp)
}
func (h *HTTPHandler) getUser(c *gin.Context) {
	userID := c.Param("id")
	authUserID, _ := c.Get(string(userIDKey))
	authUserRole, _ := c.Get(string(userRoleKey))
	// Cho phép admin xem mọi user, hoặc user tự xem mình
	if authUserRole != "admin" && authUserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
		return
	}
	resp, err := h.userService.GetUser(c.Request.Context(), &proto.GetUserRequest{Id: userID})
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	c.JSON(http.StatusOK, resp)
}
func (h *HTTPHandler) updateUser(c *gin.Context) {
	userID := c.Param("id")
	authUserID, _ := c.Get(string(userIDKey))
	// Chỉ cho phép user tự cập nhật
	if authUserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied: you can only update your own profile"})
		return
	}
	var req proto.UpdateUserRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}
	req.Id = userID // Đảm bảo ID từ URL được dùng
	resp, err := h.userService.UpdateUser(c.Request.Context(), &req)
	if err != nil {
		st, _ := status.FromError(err)
		if st.Code() == codes.NotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": st.Message()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": st.Message()})
		}
		return
	}
	c.JSON(http.StatusOK, resp)
}
func (h *HTTPHandler) listUsers(c *gin.Context) { // ⬅️ SỬA: Logic phân trang nằm trong hàm
	// Logic phân trang
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("pageSize", "20")
	var pageInt, pageSizeInt int32
	_, _ = fmt.Sscan(page, &pageInt)
	_, _ = fmt.Sscan(pageSize, &pageSizeInt)
	if pageInt <= 0 {
		pageInt = 1
	}
	if pageSizeInt <= 0 {
		pageSizeInt = 20
	}

	resp, err := h.userService.ListUsers(c.Request.Context(), &proto.ListUsersRequest{Page: pageInt, PageSize: pageSizeInt})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}
func (h *HTTPHandler) deleteUser(c *gin.Context) {
	userID := c.Param("id")
	_, err := h.userService.DeleteUser(c.Request.Context(), &proto.DeleteUserRequest{Id: userID})
	if err != nil {
		st, _ := status.FromError(err)
		if st.Code() == codes.NotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": st.Message()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": st.Message()})
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// Handler logout HTTP
func (h *HTTPHandler) logout(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader || tokenString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Valid Bearer token required in Authorization header"})
		return
	}
	_, err := h.authService.Logout(c.Request.Context(), &proto.LogoutRequest{Token: tokenString})
	if err != nil {
		st, _ := status.FromError(err)
		if st.Code() == codes.Unauthenticated {
			log.Printf("ℹ️ HTTP Logout: Token was already invalid or expired")
			c.JSON(http.StatusOK, gin.H{"message": "Logged out (token was invalid/expired)"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Logout failed: " + st.Message()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// Handler admin metrics
func (h *HTTPHandler) getAdminMetrics(c *gin.Context) {
	// Trong thực tế, bạn sẽ gọi một hàm trong service để lấy dữ liệu này
	metrics := gin.H{"totalUsers": 1000, "activeUsers": 800, "timestamp": time.Now()}
	c.JSON(http.StatusOK, metrics)
}
func (h *HTTPHandler) refreshToken(c *gin.Context) {
	var req proto.RefreshTokenRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}
	// Gọi trực tiếp auth service
	resp, err := h.authService.RefreshToken(c.Request.Context(), &req)
	if err != nil {
		st, _ := status.FromError(err)
		// Trả về lỗi Unauthenticated nếu refresh token không hợp lệ
		if st.Code() == codes.Unauthenticated {
			c.JSON(http.StatusUnauthorized, gin.H{"error": st.Message()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh token: " + st.Message()})
		}
		return
	}
	c.JSON(http.StatusOK, resp) // Trả về LoginResponse (token mới)
}

// ⬅️ THÊM: Handler bulkCreateUsers (Admin only)
func (h *HTTPHandler) bulkCreateUsers(c *gin.Context) {
	var req proto.BulkCreateRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}
	if len(req.Users) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Request must contain at least one user"})
		return
	}
	// Gọi trực tiếp user service
	resp, err := h.userService.BulkCreateUsers(c.Request.Context(), &req)
	if err != nil {
		// Xử lý lỗi từ service (ví dụ lỗi validation chung, lỗi DB không mong muốn...)
		// Có thể trả về InternalServerError hoặc BadRequest tùy lỗi
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.InvalidArgument {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Bulk create failed: " + st.Message()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Bulk create failed: " + err.Error()})
		}
		return
	}

	// Kiểm tra xem có lỗi từng phần không
	if resp.FailureCount > 0 {
		// Trả về 207 Multi-Status để báo hiệu thành công một phần
		c.JSON(http.StatusMultiStatus, resp)
	} else {
		// Trả về 201 Created nếu tất cả thành công
		c.JSON(http.StatusCreated, resp)
	}
}

// 🛡️ HTTP AUTHENTICATION MIDDLEWARE

// Middleware này xác thực token và thêm userID, userRole vào context
func httpAuthMiddleware(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format, must be 'Bearer <token>'"})
			return
		}
		authResp, err := authService.ValidateToken(c.Request.Context(), &proto.AuthRequest{Token: tokenString})
		if err != nil || !authResp.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}
		userRole, err := authService.GetUserRole(c.Request.Context(), authResp.UserId)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user role"})
			return
		}
		c.Set(string(userIDKey), authResp.UserId)
		c.Set(string(userRoleKey), userRole)
		log.Printf("✅ Auth (HTTP) passed for user: %s", authResp.UserId)
		c.Next()
	}
}

// 👑 HTTP ADMIN ONLY MIDDLEWARE

// Middleware này kiểm tra role "admin" trong context
func adminOnlyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		roleValue, exists := c.Get(string(userRoleKey))
		if !exists {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Permission denied: Role not found in context"})
			return
		}
		role, ok := roleValue.(string)
		if !ok || role != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Permission denied: Admin only"})
			return
		}
		c.Next()
	}
}
