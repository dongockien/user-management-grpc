package http

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"user-management-grpc/api/proto"
	"user-management-grpc/internal/utils"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// =========================================
// 🌐 HTTP GATEWAY - REST API LAYER
// =========================================

// Gateway - Struct chứa các gRPC clients để giao tiếp với backend services
type Gateway struct {
	userClient         proto.UserServiceClient
	authClient         proto.AuthServiceClient
	notificationClient proto.NotificationServiceClient
}

// NewGateway - Khởi tạo Gateway với kết nối gRPC đến các service
func NewGateway(grpcAddr string) (*Gateway, error) {
	conn, err := grpc.Dial(
		grpcAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),           // 🔹 KHÔNG MÃ HÓA: Dùng cho development
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1024*1024*10)), // 🔹 GIỚI HẠN: 10MB message size
	)
	if err != nil {
		return nil, err
	}

	return &Gateway{
		userClient:         proto.NewUserServiceClient(conn),
		authClient:         proto.NewAuthServiceClient(conn),
		notificationClient: proto.NewNotificationServiceClient(conn),
	}, nil
}

// SetupRoutes - Thiết lập tất cả routes cho HTTP Gateway
func (g *Gateway) SetupRoutes(r *gin.Engine) {
	// 🔹 HEALTH CHECK: Route kiểm tra tình trạng service
	r.GET("/health", g.healthCheck)

	// 🔹 AUTH ROUTES: Đăng nhập, xác thực token (không cần JWT)
	auth := r.Group("/api/auth")
	{
		auth.POST("/login", g.login)
		auth.POST("/validate", g.validateToken)
		auth.POST("/refresh", g.refreshToken)
		auth.POST("/logout", g.logout)
	}

	// 🔹 USER ROUTES: Yêu cầu JWT xác thực
	users := r.Group("/api/users")
	users.Use(g.JWTMiddleware())
	{
		users.POST("/", g.createUser)
		users.GET("/:id", g.getUser)
		users.PUT("/:id", g.updateUser)
		users.DELETE("/:id", g.deleteUser)
		users.GET("/", g.listUsers)
		users.GET("/:id/referrals", g.getUserReferrals)
	}

	// 🔹 ADMIN ROUTES: Yêu cầu JWT + quyền admin
	admin := r.Group("/api/admin")
	admin.Use(g.JWTMiddleware(), g.AdminMiddleware())
	{
		admin.GET("/metrics", g.getAdminMetrics)
		admin.GET("/metrics/detailed", g.getDetailedMetrics)
		admin.POST("/notify", g.sendNotification)
		admin.GET("/users/export", g.exportUsers)
		admin.POST("/users/bulk", g.bulkCreateUsers)
		admin.GET("/notifications/stats", g.getNotificationStats)
		admin.GET("/system/info", g.getSystemInfo)
		admin.GET("/audit/logs", g.getAuditLogs)
	}

	// 🔹 PUBLIC ROUTES: Một số route public không cần auth
	public := r.Group("/api/public")
	{
		public.GET("/status", g.healthCheck)
		public.GET("/stats", g.getPublicStats)
	}
}

// =========================================
// 🩺 HEALTH & UTILITY HANDLERS
// =========================================

// healthCheck - Kiểm tra sức khỏe hệ thống
func (g *Gateway) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"service":   "User Management API Gateway",
		"timestamp": utils.CurrentTimestamp(),
		"version":   "1.0.0",
	})
}

// =========================================
// 🔐 AUTHENTICATION HANDLERS
// =========================================

// login - Xử lý đăng nhập user
func (g *Gateway) login(c *gin.Context) {
	defer utils.RecoveryWithContext("LoginHandler")

	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	// 🔹 VALIDATION: Kiểm tra input
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	// 🔹 TIMEOUT: Set timeout cho gRPC call
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// 🔹 GRPC CALL: Gọi AuthService.Login
	resp, err := g.authClient.Login(ctx, &proto.LoginRequest{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		log.Printf("❌ Login failed for %s: %v", req.Email, err)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	log.Printf("✅ User %s logged in successfully", req.Email)
	c.JSON(http.StatusOK, resp)
}

// validateToken - Xác thực JWT token
func (g *Gateway) validateToken(c *gin.Context) {
	defer utils.RecoveryWithContext("ValidateTokenHandler")

	var req struct {
		Token string `json:"token" binding:"required"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token is required"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	resp, err := g.authClient.ValidateToken(ctx, &proto.AuthRequest{
		Token: req.Token,
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token validation failed"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// refreshToken - Làm mới token
func (g *Gateway) refreshToken(c *gin.Context) {
	defer utils.RecoveryWithContext("RefreshTokenHandler")

	var req struct {
		Token string `json:"token" binding:"required"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token is required"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	// 🔹 GỌI GRPC: RefreshToken method (cần thêm vào AuthService)
	resp, err := g.authClient.ValidateToken(ctx, &proto.AuthRequest{
		Token: req.Token,
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token refresh failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":   resp.Valid,
		"user_id": resp.UserId,
		"message": "Token refreshed successfully",
	})
}

// logout - Đăng xuất
func (g *Gateway) logout(c *gin.Context) {
	defer utils.RecoveryWithContext("LogoutHandler")

	var req struct {
		Token string `json:"token" binding:"required"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token is required"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()

	// 🔹 GỌI GRPC: Logout method (cần thêm vào AuthService)
	resp, err := g.authClient.ValidateToken(ctx, &proto.AuthRequest{
		Token: req.Token,
	})
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Logout failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
		"user_id": resp.UserId,
	})
}

// =========================================
// 👥 USER MANAGEMENT HANDLERS
// =========================================

// createUser - Tạo user mới
func (g *Gateway) createUser(c *gin.Context) {
	defer utils.RecoveryWithContext("CreateUserHandler")

	var req struct {
		Email      string `json:"email" binding:"required,email"`
		Password   string `json:"password" binding:"required,min=6"`
		FullName   string `json:"full_name" binding:"required"`
		ReferrerID string `json:"referrer_id"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid user data",
			"details": err.Error(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	resp, err := g.userClient.CreateUser(ctx, &proto.CreateUserRequest{
		Email:      req.Email,
		Password:   req.Password,
		FullName:   req.FullName,
		ReferrerId: req.ReferrerID,
	})
	if err != nil {
		log.Printf("❌ Create user failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	log.Printf("✅ User created: %s", req.Email)
	c.JSON(http.StatusCreated, resp)
}

// getUser - Lấy thông tin user theo ID
func (g *Gateway) getUser(c *gin.Context) {
	defer utils.RecoveryWithContext("GetUserHandler")

	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	resp, err := g.userClient.GetUser(ctx, &proto.GetUserRequest{
		Id: userID,
	})
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// updateUser - Cập nhật thông tin user
func (g *Gateway) updateUser(c *gin.Context) {
	defer utils.RecoveryWithContext("UpdateUserHandler")

	userID := c.Param("id")
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		FullName string `json:"full_name" binding:"required"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid update data"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	resp, err := g.userClient.UpdateUser(ctx, &proto.UpdateUserRequest{
		Id:       userID,
		Email:    req.Email,
		FullName: req.FullName,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Printf("✅ User updated: %s", userID)
	c.JSON(http.StatusOK, resp)
}

// deleteUser - Xóa user
func (g *Gateway) deleteUser(c *gin.Context) {
	defer utils.RecoveryWithContext("DeleteUserHandler")

	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	_, err := g.userClient.DeleteUser(ctx, &proto.DeleteUserRequest{
		Id: userID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Printf("✅ User deleted: %s", userID)
	c.JSON(http.StatusOK, gin.H{
		"message": "User deleted successfully",
		"user_id": userID,
	})
}

// listUsers - Lấy danh sách user với phân trang
func (g *Gateway) listUsers(c *gin.Context) {
	defer utils.RecoveryWithContext("ListUsersHandler")

	// 🔹 PAGINATION: Lấy query parameters
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "20")

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	resp, err := g.userClient.ListUsers(ctx, &proto.ListUsersRequest{
		Page:     parseInt32(page, 1),
		PageSize: parseInt32(pageSize, 20),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// getUserReferrals - Lấy danh sách người được giới thiệu bởi user
func (g *Gateway) getUserReferrals(c *gin.Context) {
	defer utils.RecoveryWithContext("GetUserReferralsHandler")

	userID := c.Param("id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// 🔹 SỬA: Dùng GetReferralsRequest thay vì GetUserReferralsRequest
	resp, err := g.userClient.GetUserReferrals(ctx, &proto.GetReferralsRequest{
		UserId: userID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// =========================================
// 📊 ADMIN & MONITORING HANDLERS - MỚI HOÀN TOÀN
// =========================================

// getAdminMetrics - Lấy metrics chi tiết cho admin dashboard
func (g *Gateway) getAdminMetrics(c *gin.Context) {
	defer utils.RecoveryWithContext("GetAdminMetrics")

	timeRange := c.DefaultQuery("range", "week")
	refresh := c.DefaultQuery("refresh", "false")

	log.Printf("📊 Admin metrics requested - Range: %s, Refresh: %s", timeRange, refresh)

	// 🔹 MOCK DATA: Trong thực tế sẽ gọi UserService.GetAdminMetrics
	metrics := map[string]interface{}{
		"total_users":         150,
		"active_users":        120,
		"new_users_today":     5,
		"new_users_this_week": 25,
		"referral_count":      23,
		"referral_rate":       15.5,
		"growth_rate":         8.2,
		"time_range":          timeRange,
		"cache_refreshed":     refresh == "true",
		"timestamp":           time.Now(),
		"data_source":         "mock", // "database" trong thực tế
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"metrics": metrics,
	})
}

// getDetailedMetrics - Lấy metrics chi tiết với phân tích
func (g *Gateway) getDetailedMetrics(c *gin.Context) {
	defer utils.RecoveryWithContext("GetDetailedMetrics")

	// 🔹 MOCK DATA: Phân tích chi tiết
	detailedMetrics := map[string]interface{}{
		"user_analytics": map[string]interface{}{
			"total_users":    150,
			"active_users":   120,
			"inactive_users": 30,
			"premium_users":  45,
			"free_users":     105,
		},
		"growth_analytics": map[string]interface{}{
			"daily_growth":   5,
			"weekly_growth":  25,
			"monthly_growth": 95,
			"growth_rate":    8.2,
		},
		"referral_analytics": map[string]interface{}{
			"total_referrals":     23,
			"referral_conversion": 15.5,
			"top_referrers": []map[string]interface{}{
				{"user_id": "user123", "referrals": 5, "name": "John Doe"},
				{"user_id": "user456", "referrals": 4, "name": "Jane Smith"},
				{"user_id": "user789", "referrals": 3, "name": "Bob Johnson"},
			},
		},
		"system_analytics": map[string]interface{}{
			"response_time_ms":  125,
			"uptime_percentage": 99.8,
			"error_rate":        0.2,
			"active_sessions":   45,
			"pending_emails":    3,
		},
		"timestamp": time.Now(),
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"metrics":      detailedMetrics,
		"generated_at": time.Now().Format(time.RFC3339),
	})
}

// sendNotification - Gửi thông báo đến user
func (g *Gateway) sendNotification(c *gin.Context) {
	defer utils.RecoveryWithContext("SendNotificationHandler")

	var req struct {
		UserID  string `json:"user_id" binding:"required"`
		Email   string `json:"email" binding:"required,email"`
		Type    string `json:"type" binding:"required"`
		Message string `json:"message" binding:"required"`
		Subject string `json:"subject,omitempty"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid notification data"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	// 🔹 SỬA: Dùng NotificationRequest thay vì SendNotificationRequest
	resp, err := g.notificationClient.SendNotification(ctx, &proto.NotificationRequest{
		UserId:  req.UserID,
		Email:   req.Email,
		Type:    req.Type,
		Message: req.Message,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Printf("✅ Admin sent notification to user: %s, Type: %s", req.UserID, req.Type)
	c.JSON(http.StatusOK, resp)
}

// exportUsers - Export users data (streaming)
func (g *Gateway) exportUsers(c *gin.Context) {
	defer utils.RecoveryWithContext("ExportUsers")

	format := c.DefaultQuery("format", "csv")

	log.Printf("📤 Admin exporting users - Format: %s", format)

	// Set headers cho file download
	if format == "csv" {
		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", "attachment; filename=users-export-"+time.Now().Format("20060102")+".csv")

		// CSV header
		c.Writer.Write([]byte("ID,Email,FullName,ReferrerID,CreatedAt,Status\n"))

		// 🔹 MOCK DATA: Trong thực tế sẽ stream từ database
		c.Writer.Write([]byte("1,user1@example.com,User One,,2024-01-01,active\n"))
		c.Writer.Write([]byte("2,user2@example.com,User Two,1,2024-01-02,active\n"))
		c.Writer.Write([]byte("3,user3@example.com,User Three,,2024-01-03,inactive\n"))
	} else if format == "json" {
		c.Header("Content-Type", "application/json")
		c.Header("Content-Disposition", "attachment; filename=users-export-"+time.Now().Format("20060102")+".json")

		// JSON data
		exportData := []map[string]interface{}{
			{
				"id":          "1",
				"email":       "user1@example.com",
				"full_name":   "User One",
				"referrer_id": nil,
				"created_at":  "2024-01-01",
				"status":      "active",
			},
			{
				"id":          "2",
				"email":       "user2@example.com",
				"full_name":   "User Two",
				"referrer_id": "1",
				"created_at":  "2024-01-02",
				"status":      "active",
			},
		}

		jsonData, _ := json.MarshalIndent(exportData, "", "  ")
		c.Writer.Write(jsonData)
	}
}

// bulkCreateUsers - Tạo nhiều users cùng lúc
func (g *Gateway) bulkCreateUsers(c *gin.Context) {
	defer utils.RecoveryWithContext("BulkCreateUsers")

	var req struct {
		Users []struct {
			Email    string `json:"email" binding:"required,email"`
			Password string `json:"password" binding:"required,min=6"`
			FullName string `json:"full_name" binding:"required"`
		} `json:"users" binding:"required,min=1,max=100"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid bulk data"})
		return
	}

	// 🔹 MOCK IMPLEMENTATION: Trong thực tế sẽ gọi UserService.BulkCreateUsers
	results := make([]map[string]interface{}, len(req.Users))

	for i, user := range req.Users {
		results[i] = map[string]interface{}{
			"email":     user.Email,
			"status":    "created",
			"user_id":   fmt.Sprintf("temp_%d", i+1),
			"timestamp": time.Now(),
		}
	}

	log.Printf("✅ Admin bulk created %d users", len(req.Users))

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Successfully processed %d users", len(req.Users)),
		"results": results,
		"summary": map[string]interface{}{
			"total":    len(req.Users),
			"success":  len(req.Users),
			"failed":   0,
			"duration": "2.1s",
		},
	})
}

// getNotificationStats - Thống kê notification
func (g *Gateway) getNotificationStats(c *gin.Context) {
	defer utils.RecoveryWithContext("GetNotificationStats")

	// 🔹 MOCK DATA: Thống kê notification
	stats := map[string]interface{}{
		"total_sent":             1500,
		"welcome_emails":         200,
		"password_resets":        50,
		"security_alerts":        25,
		"promotional":            1225,
		"success_rate":           98.5,
		"pending_queue":          3,
		"failed_deliveries":      22,
		"avg_delivery_time_ms":   150,
		"top_notification_types": []string{"promotional", "welcome", "password_reset"},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"stats":   stats,
		"period":  "last_30_days",
	})
}

// getSystemInfo - Lấy thông tin hệ thống
func (g *Gateway) getSystemInfo(c *gin.Context) {
	defer utils.RecoveryWithContext("GetSystemInfo")

	// 🔹 SYSTEM INFO: Thông tin runtime
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	systemInfo := map[string]interface{}{
		"go_version": runtime.Version(),
		"goroutines": runtime.NumGoroutine(),
		"cpu_cores":  runtime.NumCPU(),
		"memory_usage": map[string]interface{}{
			"alloc_mb":       m.Alloc / 1024 / 1024,
			"sys_mb":         m.Sys / 1024 / 1024,
			"total_alloc_mb": m.TotalAlloc / 1024 / 1024,
			"num_gc":         m.NumGC,
		},
		"service_versions": map[string]string{
			"user_service":         "1.0.0",
			"auth_service":         "1.0.0",
			"notification_service": "1.0.0",
			"gateway":              "1.0.0",
		},
		"start_time": time.Now().Add(-30 * time.Minute).Format(time.RFC3339), // Giả lập
		"uptime":     "30 minutes",
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"system":  systemInfo,
	})
}

// getAuditLogs - Lấy audit logs
func (g *Gateway) getAuditLogs(c *gin.Context) {
	defer utils.RecoveryWithContext("GetAuditLogs")

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))

	// 🔹 MOCK DATA: Audit logs
	logs := []map[string]interface{}{
		{
			"id":         "1",
			"user_id":    "admin123",
			"action":     "user_created",
			"resource":   "users",
			"timestamp":  time.Now().Add(-5 * time.Minute).Format(time.RFC3339),
			"ip_address": "192.168.1.100",
			"user_agent": "Mozilla/5.0...",
		},
		{
			"id":         "2",
			"user_id":    "admin123",
			"action":     "user_deleted",
			"resource":   "users",
			"timestamp":  time.Now().Add(-10 * time.Minute).Format(time.RFC3339),
			"ip_address": "192.168.1.100",
			"user_agent": "Mozilla/5.0...",
		},
		{
			"id":         "3",
			"user_id":    "user456",
			"action":     "login",
			"resource":   "auth",
			"timestamp":  time.Now().Add(-15 * time.Minute).Format(time.RFC3339),
			"ip_address": "192.168.1.101",
			"user_agent": "PostmanRuntime/7.0...",
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"logs":    logs,
		"pagination": map[string]interface{}{
			"page":        page,
			"page_size":   pageSize,
			"total":       len(logs),
			"total_pages": 1,
		},
	})
}

// getPublicStats - Thống kê public
func (g *Gateway) getPublicStats(c *gin.Context) {
	defer utils.RecoveryWithContext("GetPublicStats")

	c.JSON(http.StatusOK, gin.H{
		"total_users":     150,
		"online_users":    45,
		"total_referrals": 23,
		"service_status":  "online",
		"last_updated":    time.Now().Format(time.RFC3339),
	})
}

// =========================================
// 🛡️ MIDDLEWARE FUNCTIONS
// =========================================

// JWTMiddleware - Middleware kiểm tra JWT token
func (g *Gateway) JWTMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header is required",
			})
			c.Abort()
			return
		}

		// 🔹 LOẠI BỎ "Bearer " prefix nếu có
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
		defer cancel()

		resp, err := g.authClient.ValidateToken(ctx, &proto.AuthRequest{
			Token: token,
		})
		if err != nil || !resp.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		// 🔹 SET USER CONTEXT: Lưu user ID vào context cho các handler sau
		c.Set("userID", resp.UserId)
		c.Next()
	}
}

// AdminMiddleware - Middleware kiểm tra quyền admin
func (g *Gateway) AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User not authenticated",
			})
			c.Abort()
			return
		}

		// 🔹 TODO: Trong thực tế, sẽ kiểm tra role từ database
		// Ở đây giả lập: user có ID chứa "admin" là admin
		userIDStr := userID.(string)
		if len(userIDStr) >= 5 && userIDStr[:5] == "admin" {
			log.Printf("👑 Admin access granted for user: %s", userIDStr)
			c.Next()
			return
		}

		log.Printf("🚫 Admin access denied for user: %s", userIDStr)
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Insufficient permissions. Admin access required.",
		})
		c.Abort()
	}
}

// =========================================
// 🛠️ HELPER FUNCTIONS
// =========================================

// parseInt32 - Chuyển string sang int32 với giá trị mặc định
func parseInt32(s string, defaultValue int32) int32 {
	var result int32
	_, err := fmt.Sscanf(s, "%d", &result)
	if err != nil {
		return defaultValue
	}
	return result
}
