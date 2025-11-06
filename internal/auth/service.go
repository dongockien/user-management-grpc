// File: internal/auth/service.go
package auth

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"user-management-grpc/api/proto"
	"user-management-grpc/internal/user"
	"user-management-grpc/internal/utils"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// 🧱 1. Interface Redis — thêm context cho tất cả method
type RedisClient interface {
	Set(ctx context.Context, key, value string, expiration time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Delete(ctx context.Context, key string) error
	Close() error
	Ping(ctx context.Context) error

	// Các hàm ZSET cho blacklist
	ZAdd(ctx context.Context, key string, socre float64, member string) error
	ZRemRangeByScore(ctx context.Context, key, min, max string) (int64, error)
	ZScore(ctx context.Context, key, member string) (float64, error)
}

// 🧩 2. MockRedisClient — mô phỏng Redis (dùng cho dev)
type MockRedisClient struct {
	data map[string]string
	zset map[string]map[string]float64 // Giả lập ZSET
	mu   sync.RWMutex
}

// NewMockRedisClient - Đổi tên để rõ ràng hơn
func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{
		data: make(map[string]string),
		zset: make(map[string]map[string]float64),
	}
}

func (r *MockRedisClient) Set(ctx context.Context, key, value string, expiration time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[key] = value
	log.Printf("🔐 Mock Redis: SET %s = %s (expire: %v)", key, value, expiration)
	return nil
}

func (r *MockRedisClient) Get(ctx context.Context, key string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	value, exists := r.data[key]
	if !exists {
		return "", status.Error(codes.NotFound, "key không tồn tại")
	}
	return value, nil
}

func (r *MockRedisClient) Delete(ctx context.Context, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.data, key)
	log.Printf("🔐 Mock Redis: DELETE %s", key)
	return nil
}

func (r *MockRedisClient) Close() error {
	return nil
}

func (r *MockRedisClient) Ping(ctx context.Context) error {
	log.Println("❤️ Mock Redis: PING -> PONG")
	return nil
}
func (r *MockRedisClient) ZAdd(ctx context.Context, key string, score float64, member string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.zset[key] == nil {
		r.zset[key] = make(map[string]float64)
	}
	r.zset[key][member] = score
	log.Printf("Mock Redis: ZADD %s %f %s", key, score, member)
	return nil
}

func (r *MockRedisClient) ZRemRangeByScore(ctx context.Context, key, min, max string) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	minF, _ := strconv.ParseFloat(min, 64)
	maxF, _ := strconv.ParseFloat(max, 64)
	var count int64 = 0
	if r.zset[key] != nil {
		for member, score := range r.zset[key] {
			if score >= minF && score <= maxF {
				delete(r.zset[key], member)
				count++
			}
		}
	}
	log.Printf("Mock Redis: ZREMRANGEBYSCORE %s %s %s (Removed: %d)", key, min, max, count)
	return count, nil
}

func (r *MockRedisClient) ZScore(ctx context.Context, key, member string) (float64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.zset[key] != nil {
		if score, ok := r.zset[key][member]; ok {
			return score, nil
		}
	}
	return 0, fmt.Errorf("redis: nil")
}

// ⚙️ 3. Service struct — giữ secret trong biến jwtSecret
type Service struct {
	proto.UnimplementedAuthServiceServer
	userRepo     user.Repository
	redisClient  RedisClient
	jwtSecret    string
	tokenExpiry  time.Duration
	activeSessions *utils.SafeMap
	mu           sync.RWMutex
}

func NewService(userRepo user.Repository, redisClient RedisClient, jwtSecret string, tokenExpiry time.Duration) *Service {
	return &Service{
		userRepo:       userRepo,
		redisClient:    redisClient,
		jwtSecret:      jwtSecret,
		tokenExpiry:    tokenExpiry, // Lấy từ cfg.JWT.Expiry
		activeSessions: utils.NewSafeMap(),
	}
}

// 🔑 4. Login — verify password, generate JWT, cache Redis
func (s *Service) Login(ctx context.Context, req *proto.LoginRequest) (*proto.LoginResponse, error) {
	defer utils.RecoveryWithContext("Login")

	if req.Email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email và password là bắt buộc")
	}
	// ⚙️ Giới hạn timeout cho DB query
	ctxDB, cancelDB := context.WithTimeout(ctx, 3*time.Second)
	defer cancelDB()

	userObj, err := s.userRepo.GetByEmail(ctxDB, req.Email)
	if err != nil {
		log.Printf("❌ Login failed for email: %s, error: %v", req.Email, err)
		return nil, status.Error(codes.NotFound, "email hoặc password không đúng")
	}

	// ✅ Dùng utils.VerifyPassword để kiểm tra mật khẩu
	if err := utils.VerifyPassword(userObj.Password, req.Password); err != nil {
		log.Printf("❌ Invalid password for user: %s", req.Email)
		return nil, status.Error(codes.Unauthenticated, "email hoặc password không đúng")
	}

	go func() {
		defer utils.RecoveryWithContext("UpdateLastLogin")
		ctxUpdate, cancelUpdate := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelUpdate()
		if err := s.userRepo.UpdateLastLogin(ctxUpdate, userObj.ID); err != nil {
			log.Printf("Failed to update last_login_at for user %s: %v", userObj.ID, err)
		}
	}()

	// 🔐 Tạo JWT token
	jti := uuid.New().String()
	token, err := utils.GenerateJWT(userObj.ID, s.jwtSecret, s.tokenExpiry, jti)
	if err != nil {
		return nil, status.Error(codes.Internal, "lỗi tạo token")
	}

	log.Printf("User %s đăng nhập thành công. JTI: %s", userObj.ID, jti)
	return &proto.LoginResponse{
		Token: token,
		User: &proto.User{
			Id:       userObj.ID,
			Email:    userObj.Email,
			FullName: userObj.FullName,
			// ⭐️ SỬA: Trả về Role khi Login
			Role:     userObj.Role, 
		},
	}, nil
}

// 🧩 5. ValidateToken — kiểm tra blacklist
func (s *Service) ValidateToken(ctx context.Context, req *proto.AuthRequest) (*proto.AuthResponse, error) {
	defer utils.RecoveryWithContext("ValidateToken")

	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token là bắt buộc")
	}

	claims, err := utils.VerifyJWT(req.Token, s.jwtSecret)
	if err != nil {
		log.Printf("❌ Token validation failed (verify): %v", err)
		return &proto.AuthResponse{Valid: false}, nil
	}

	// ⚙️ Thêm timeout khi kiểm tra blacklist
	ctxR, cancelR := context.WithTimeout(ctx, 2*time.Second)
	defer cancelR()

	_, err = s.redisClient.ZScore(ctxR, "revoked_tokens", claims.ID)
	if err == nil {
		log.Printf("❌ Token validation failed: Token is blacklisted (JTI: %s)", claims.ID)
		return &proto.AuthResponse{Valid: false}, nil
	}

	// Nếu err != nil (ví dụ: "redis: nil"), nghĩa là KHÔNG TÌM THẤY key -> token HỢP LỆ
	return &proto.AuthResponse{Valid: true, UserId: claims.UserID}, nil
}

func (s *Service) RefreshToken(ctx context.Context, req *proto.RefreshTokenRequest) (*proto.LoginResponse, error) {
	defer utils.RecoveryWithContext("RefreshToken")

	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token là bắt buộc")
	}

	claims, err := utils.VerifyJWT(req.RefreshToken, s.jwtSecret)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "refresh token không hợp lệ")
	}

	// ⭐️ SỬA: Khi Refresh, chúng ta cũng cần lấy Role mới nhất
	userObj, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lỗi lấy thông tin user khi refresh: %v", err)
	}

	// Token mới cũng cần JTI mới
	newJTI := uuid.New().String()
	newToken, err := utils.GenerateJWT(claims.UserID, s.jwtSecret, s.tokenExpiry, newJTI)
	if err != nil {
		return nil, status.Error(codes.Internal, "lỗi tạo token mới")
	}

	log.Printf("✅ Token refreshed for user: %s (New JTI: %s)", claims.UserID, newJTI)
	return &proto.LoginResponse{
		Token: newToken,
		User: &proto.User{
			Id:       userObj.ID,
			// ⭐️ SỬA: Trả về thông tin user đầy đủ (bao gồm cả Role)
			Email:    userObj.Email,
			FullName: userObj.FullName,
			Role:     userObj.Role,
		},
	}, nil
}

// Logout - logic blacklist
func (s *Service) Logout(ctx context.Context, req *proto.LogoutRequest) (*emptypb.Empty, error) {
	defer utils.RecoveryWithContext("Logout")

	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token là bắt buộc để logout")
	}

	// Xác thực token này LẦN CUỐI
	claims, err := utils.VerifyJWT(req.Token, s.jwtSecret)
	if err != nil {
		// Kể cả khi token hết hạn, vẫn coi như logout thành công
		if err == jwt.ErrTokenExpired {
			log.Printf("ℹ️ Logout với token đã hết hạn")
			return &emptypb.Empty{}, nil
		}
		return nil, status.Error(codes.Unauthenticated, "token không hợp lệ")
	}
	// Lấy thời gian hết hạn
	expTime, err := claims.GetExpirationTime()
	if err != nil {
		return nil, status.Error(codes.Internal, "lỗi lấy thời gian hết hạn token")
	}
	expTimestamp := expTime.Unix()
	jti := claims.ID
	if jti == "" {
		return nil, status.Error(codes.Internal, "token không chứa JTI")
	}
	// Thêm JTI vào ZSET "revoked_tokens" với score là timestamp hết hạn
	ctxR, cancelR := context.WithTimeout(ctx, 2*time.Second)
	defer cancelR()
	key := "revoked_tokens"
	score := float64(expTimestamp)

	if err := s.redisClient.ZAdd(ctxR, key, score, jti); err != nil {
		log.Printf("⚠️ Lỗi khi thêm token vào blacklist: %v", err)
		// Không trả lỗi nghiêm trọng, chỉ log
	}

	log.Printf("✅ User %s đã đăng xuất (JTI: %s blacklisted)", claims.UserID, jti)
	return &emptypb.Empty{}, nil
}


// Thêm method GetUserRole
func (s *Service) GetUserRole(ctx context.Context, userID string) (string, error) {
	// Dùng repo đã có để lấy user
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return "", status.Errorf(codes.NotFound, "không tìm thấy user %s: %v", userID, err)
	}

	// 🔹 XÓA BỎ LOGIC HARD-CODE
	// if user.Email == "admin@example.com" { 
	//     return "admin", nil
	// }
	// return "user", nil
	
	// === LOGIC ĐÚNG ===
	// Trả về Role thật sự (ví dụ: "admin" hoặc "user")
	// mà userRepo đã đọc được từ Redis (hoặc MySQL)
	if user.Role == "" {
		// An toàn: Nếu Role bị rỗng, coi như là 'user'
		return "user", nil
	}
	
	return user.Role, nil
}

// Ping - Kiểm tra sức khỏe kết nối Redis (cho Scheduler)
func (s *Service) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if s.redisClient == nil {
		return fmt.Errorf("redisClient is nil")
	}
	return s.redisClient.Ping(ctx)
}

// Hàm CleanupExpiredTokens (cho Scheduler)
func (s *Service) CleanupExpiredTokens(ctx context.Context) (int64, error) {
	now := time.Now().Unix()
	key := "revoked_tokens"

	// Xóa tất cả JTI trong ZSET có score (timestamp hết hạn)
	// nhỏ hơn hoặc bằng thời điểm hiện tại.
	count, err := s.redisClient.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(now, 10))
	if err != nil {
		log.Printf("❌ Failed to cleanup expired tokens from Redis: %v", err)
		return 0, err
	}
	return count, nil
}