package user

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"user-management-grpc/api/proto"
	"user-management-grpc/internal/utils"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// GatewayHandler quản lý client gRPC dùng trong tầng HTTP (Gin)
type GatewayHandler struct {
	UserClient proto.UserServiceClient
	AuthClient proto.AuthServiceClient
	Timeout    time.Duration
	JWTSecret  string // Thêm: để verify JWT nội bộ
}

// NewGatewayHandler khởi tạo GatewayHandler
func NewGatewayHandler(conn *grpc.ClientConn, timeout time.Duration, jwtSecret string) *GatewayHandler {
	return &GatewayHandler{
		UserClient: proto.NewUserServiceClient(conn),
		AuthClient: proto.NewAuthServiceClient(conn),
		Timeout:    timeout,
		JWTSecret:  jwtSecret,
	}
}

// RegisterRoutes - đăng ký endpoint cho router group
func (h *GatewayHandler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.POST("/auth/login", h.Login)
	rg.POST("/users", h.CreateUser)

	protected := rg.Group("/")
	protected.Use(h.AuthMiddleware())
	{
		protected.GET("/users/:id", h.GetUser)
		protected.PUT("/users/:id", h.UpdateUser)
		protected.DELETE("/users/:id", h.DeleteUser)
		protected.GET("/users", h.ListUsers)
		protected.POST("/auth/refresh", h.RefreshToken)
		protected.POST("/auth/logout", h.Logout)
	}
}

// ====== Helpers ======

func (h *GatewayHandler) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, h.Timeout)
}

// map gRPC error → HTTP code
func grpcErrToHTTPStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	if s, ok := status.FromError(err); ok {
		switch s.Code() {
		case codes.NotFound:
			return http.StatusNotFound
		case codes.InvalidArgument:
			return http.StatusBadRequest
		case codes.Unauthenticated:
			return http.StatusUnauthorized
		case codes.PermissionDenied:
			return http.StatusForbidden
		case codes.AlreadyExists:
			return http.StatusConflict
		case codes.ResourceExhausted:
			return http.StatusTooManyRequests
		case codes.DeadlineExceeded:
			return http.StatusGatewayTimeout
		default:
			return http.StatusInternalServerError
		}
	}
	return http.StatusInternalServerError
}

// contextWithToken - nhúng token vào metadata gửi gRPC
func contextWithToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

// ====== HANDLERS ======

// Đăng nhập
func (h *GatewayHandler) Login(c *gin.Context) {
	defer utils.RecoveryWithContext("Login")

	var body struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := h.withTimeout(c.Request.Context())
	defer cancel()

	resp, err := h.AuthClient.Login(ctx, &proto.LoginRequest{
		Email:    body.Email,
		Password: body.Password,
	})
	if err != nil {
		c.JSON(grpcErrToHTTPStatus(err), gin.H{"error": status.Convert(err).Message()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": resp.Token,
		"user":  resp.User,
	})
}

// Tạo user mới
func (h *GatewayHandler) CreateUser(c *gin.Context) {
	defer utils.RecoveryWithContext("CreateUser")

	var body struct {
		Email      string `json:"email" binding:"required,email"`
		Password   string `json:"password" binding:"required,min=6"`
		FullName   string `json:"full_name"`
		ReferrerID string `json:"referrer_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := h.withTimeout(c.Request.Context())
	defer cancel()

	req := &proto.CreateUserRequest{
		Email:      body.Email,
		Password:   body.Password,
		FullName:   body.FullName,
		ReferrerId: body.ReferrerID,
	}

	user, err := h.UserClient.CreateUser(ctx, req)
	if err != nil {
		c.JSON(grpcErrToHTTPStatus(err), gin.H{"error": status.Convert(err).Message()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":        user.Id,
		"email":     user.Email,
		"full_name": user.FullName,
		"created":   user.CreatedAt,
	})
}

// Lấy thông tin user theo ID
func (h *GatewayHandler) GetUser(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id required"})
		return
	}

	ctx, cancel := h.withTimeout(c.Request.Context())
	defer cancel()

	resp, err := h.UserClient.GetUser(ctx, &proto.GetUserRequest{Id: id})
	if err != nil {
		c.JSON(grpcErrToHTTPStatus(err), gin.H{"error": status.Convert(err).Message()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// Cập nhật user
func (h *GatewayHandler) UpdateUser(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Email    string `json:"email"`
		FullName string `json:"full_name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := h.withTimeout(c.Request.Context())
	defer cancel()

	resp, err := h.UserClient.UpdateUser(ctx, &proto.UpdateUserRequest{
		Id:       id,
		Email:    body.Email,
		FullName: body.FullName,
	})
	if err != nil {
		c.JSON(grpcErrToHTTPStatus(err), gin.H{"error": status.Convert(err).Message()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// Xóa user
func (h *GatewayHandler) DeleteUser(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id required"})
		return
	}
	ctx, cancel := h.withTimeout(c.Request.Context())
	defer cancel()

	_, err := h.UserClient.DeleteUser(ctx, &proto.DeleteUserRequest{Id: id})
	if err != nil {
		c.JSON(grpcErrToHTTPStatus(err), gin.H{"error": status.Convert(err).Message()})
		return
	}
	c.Status(http.StatusNoContent)
}

// Liệt kê user
func (h *GatewayHandler) ListUsers(c *gin.Context) {
	page, pageSize := int32(1), int32(20)
	if p := c.Query("page"); p != "" {
		fmt.Sscan(p, &page)
	}
	if ps := c.Query("page_size"); ps != "" {
		fmt.Sscan(ps, &pageSize)
	}

	ctx, cancel := h.withTimeout(c.Request.Context())
	defer cancel()

	resp, err := h.UserClient.ListUsers(ctx, &proto.ListUsersRequest{Page: page, PageSize: pageSize})
	if err != nil {
		c.JSON(grpcErrToHTTPStatus(err), gin.H{"error": status.Convert(err).Message()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// Làm mới token
func (h *GatewayHandler) RefreshToken(c *gin.Context) {
	var body struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := h.withTimeout(c.Request.Context())
	defer cancel()

	resp, err := h.AuthClient.RefreshToken(ctx, &proto.RefreshTokenRequest{
		RefreshToken: body.Token,
	})
	if err != nil {
		c.JSON(grpcErrToHTTPStatus(err), gin.H{"error": status.Convert(err).Message()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// Đăng xuất
func (h *GatewayHandler) Logout(c *gin.Context) {
	var body struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := h.withTimeout(c.Request.Context())
	defer cancel()

	_, err := h.AuthClient.Logout(ctx, &proto.LogoutRequest{
		Token: body.Token,
	})
	if err != nil {
		c.JSON(grpcErrToHTTPStatus(err), gin.H{"error": status.Convert(err).Message()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

// ===== Middleware xác thực JWT =====
func (h *GatewayHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization header required"})
			return
		}
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header"})
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Thử verify JWT local trước (tiết kiệm 1 RPC)
		if claims, err := utils.VerifyJWT(token, h.JWTSecret); err == nil {
			c.Set("userID", claims.UserID)
		} else {
			// fallback: xác thực qua AuthService
			ctx, cancel := h.withTimeout(c.Request.Context())
			defer cancel()

			resp, err := h.AuthClient.ValidateToken(ctx, &proto.AuthRequest{Token: token})
			if err != nil || !resp.GetValid() {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
				return
			}
			c.Set("userID", resp.GetUserId())
		}

		// Truyền token cho gRPC
		c.Request = c.Request.WithContext(contextWithToken(c.Request.Context(), token))
		c.Next()
	}
}
