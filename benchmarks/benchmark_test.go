package benchmarks

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid" // Đã có
	"user-management-grpc/api/proto"
	"user-management-grpc/internal/auth"
	"user-management-grpc/internal/user"
	"user-management-grpc/internal/utils"
)

type BenchmarkUserRepo struct{}

func (b *BenchmarkUserRepo) Create(ctx context.Context, u *user.User) error { return nil }
func (b *BenchmarkUserRepo) GetByID(ctx context.Context, id string) (*user.User, error) {
	newHash := "$2a$10$pcaJLyGbxSY4VL2u8Rx6CeV9VPheiZJFKHUb0VFU3hc/91F0zBeSu" // Hash mới cho "password"
	return &user.User{ID: id, Email: "test@example.com", Password: newHash}, nil
} // ⬅️ SỬA: Thêm dấu }

func (b *BenchmarkUserRepo) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	newHash := "$2a$10$pcaJLyGbxSY4VL2u8Rx6CeV9VPheiZJFKHUb0VFU3hc/91F0zBeSu" // Hash mới cho "password"
	// ⬅️ SỬA: Thêm newHash}, nil
	return &user.User{ID: "123", Email: email, Password: newHash}, nil
}

// ⬅️ SỬA: Thiếu hàm Update() - Bổ sung lại
func (b *BenchmarkUserRepo) Update(ctx context.Context, u *user.User) error { return nil }

func (b *BenchmarkUserRepo) Delete(ctx context.Context, id string) error                         { return nil }
func (b *BenchmarkUserRepo) List(ctx context.Context, page, pageSize int32) ([]*user.User, int32, error) {
	return []*user.User{}, 100, nil
}
func (b *BenchmarkUserRepo) GetReferrals(ctx context.Context, userID string) ([]*user.User, error) {
	return []*user.User{}, nil
}
func (b *BenchmarkUserRepo) DeleteInactive(ctx context.Context, threshold time.Time) (int64, error) {
	return 0, nil
}
func (r *BenchmarkUserRepo) GetActiveUsersCount(ctx context.Context, since time.Time) (int64, error) {
	return 100, nil
}
func (b *BenchmarkUserRepo) Ping(ctx context.Context) error {
	return nil
}
func (b *BenchmarkUserRepo) UpdateLastLogin(ctx context.Context, userID string) error {
	return nil
}

func BenchmarkLogin(b *testing.B) {
	userRepo := &BenchmarkUserRepo{}
	redisClient := auth.NewMockRedisClient()
	authService := auth.NewService(userRepo, redisClient, "benchmark-secret-key", time.Hour)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := authService.Login(context.Background(), &proto.LoginRequest{
				Email:    "test@example.com",
				Password: "password", // Mật khẩu thật để verify bcrypt
			})
			if err != nil {
				b.Errorf("Login failed: %v", err)
			}
		}
	})
}

func BenchmarkTokenValidation(b *testing.B) {
	userRepo := &BenchmarkUserRepo{}
	redisClient := auth.NewMockRedisClient()
	authService := auth.NewService(userRepo, redisClient, "benchmark-secret-key", time.Hour)

	token, _ := utils.GenerateJWT("user123", "benchmark-secret-key", time.Hour, uuid.New().String())

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := authService.ValidateToken(context.Background(), &proto.AuthRequest{Token: token})
			if err != nil {
				b.Errorf("ValidateToken failed: %v", err)
			}
		}
	})
}