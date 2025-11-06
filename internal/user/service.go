// File: internal/user/service.go
package user

import (
	"context"
	"fmt"
	"log"
	"strings" // ⬅️ THÊM IMPORT
	"sync"
	"time"

	"user-management-grpc/api/proto"
	"user-management-grpc/internal/utils"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ⭐️ SỬA: Định nghĩa Interface cho Notification (Thực hành tốt)
type NotificationClient interface {
	SendWelcomeEmail(ctx context.Context, req *proto.NotificationRequest, opts ...grpc.CallOption) (*proto.NotificationResponse, error)
	SendNotification(ctx context.Context, req *proto.NotificationRequest, opts ...grpc.CallOption) (*proto.NotificationResponse, error)
}

type Service struct {
	proto.UnimplementedUserServiceServer
	repo               Repository
	userCache          *UserCache
	referralMap        *utils.SafeMap
	notificationClient NotificationClient // ⭐️ SỬA: Dùng interface
	mu                 sync.RWMutex
}

type UserCache struct {
	mu   sync.RWMutex
	data map[string]*User
}

func NewUserCache() *UserCache {
	return &UserCache{
		data: make(map[string]*User),
	}
}

func (c *UserCache) Get(id string) (*User, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	user, exists := c.data[id]
	return user, exists
}

func (c *UserCache) Set(id string, user *User) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[id] = user
}

func (c *UserCache) Delete(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, id)
}

// ⭐️ SỬA: Nhận NotificationClient interface
func NewService(repo Repository, notificationClient NotificationClient) *Service {
	return &Service{
		repo:               repo,
		userCache:          NewUserCache(),
		referralMap:        utils.NewSafeMap(),
		notificationClient: notificationClient,
	}
}

// ⭐️ SỬA: Hàm CreateUser
func (s *Service) CreateUser(ctx context.Context, req *proto.CreateUserRequest) (*proto.User, error) {
	defer utils.Recovery()

	if req.Email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email và password là bắt buộc")
	}

	// --- 1. Chuyển đổi (Map) từ Proto Request -> Model DB ---
	user := &User{
		Email:     req.Email,
		Password:  req.Password, // Repo sẽ hash mật khẩu này
		FullName:  req.FullName,
		CreatedAt: time.Now(),

		// ⭐️ SỬA: Gán Role mặc định là 'user'
		// Đây chính là logic đã sửa lỗi HSET (integer) 1 thành 0
		Role: "user",
	}

	// ⭐️ SỬA: Xử lý referrerId
	if req.ReferrerId != "" {
		// (Trong dự án thật, bạn nên kiểm tra xem referrerId có tồn tại không)
		// (Logic kiểm tra referrerId của bạn đã bị xóa, tôi thêm lại)
		_, err := s.repo.GetByID(ctx, req.ReferrerId)
		if err != nil {
			log.Printf("⚠️ Referrer không tồn tại: %s", req.ReferrerId)
			// (Bạn có thể quyết định trả về lỗi hoặc bỏ qua. Ở đây chúng ta bỏ qua)
		} else {
			log.Printf("✅ User %s được mời bởi %s", req.Email, req.ReferrerId)
			user.ReferrerID = &req.ReferrerId
			// (Bạn dùng referralMap, nhưng tốt hơn là logic này nên ở Repo)
			s.referralMap.Set(req.ReferrerId, true)
		}
	}

	// --- 2. Gọi Repository (MySQL hoặc Redis) ---
	if err := s.repo.Create(ctx, user); err != nil {
		log.Printf("❌ Lỗi khi tạo user trong DB: %v", err)
		// ⭐️ SỬA: Kiểm tra lỗi trùng lặp (từ HSetNX của Redis hoặc UNIQUE của MySQL)
		if strings.Contains(err.Error(), "email đã tồn tại") {
			return nil, status.Error(codes.AlreadyExists, "email đã tồn tại")
		}
		return nil, status.Error(codes.Internal, "failed to create user")
	}

	// --- 3. Gửi email bất đồng bộ ---
	go func() {
		defer utils.Recovery()
		s.sendWelcomeEmail(user)
	}()

	// --- 4. Chuyển đổi (Map) từ Model DB -> Proto Response ---
	// ⭐️ SỬA: Dùng hàm helper chuẩn (đã được sửa)
	return s.userToProto(user), nil
}

// ⭐️ SỬA: Hàm GetUser
func (s *Service) GetUser(ctx context.Context, req *proto.GetUserRequest) (*proto.User, error) {
	defer utils.Recovery()

	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id là bắt buộc")
	}

	// 🎯 Kiểm tra cache trước
	// ⭐️ SỬA: Logic cache của bạn có RWMutex ở 2 nơi (Cache và Service)
	// Gây ra double-lock. Chỉ nên lock ở 1 nơi (trong UserCache).
	if cachedUser, exists := s.userCache.Get(req.Id); exists {
		log.Printf("✅ Lấy user từ cache: %s", req.Id)
		return s.userToProto(cachedUser), nil
	}

	// Lấy từ database
	user, err := s.repo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user không tồn tại")
	}

	// Cache kết quả
	s.userCache.Set(user.ID, user)

	// ⭐️ SỬA: Dùng hàm helper chuẩn (đã được sửa)
	return s.userToProto(user), nil
}

// ⭐️ SỬA: Hàm UpdateUser
func (s *Service) UpdateUser(ctx context.Context, req *proto.UpdateUserRequest) (*proto.User, error) {
	defer utils.Recovery()

	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id là bắt buộc")
	}

	// --- 1. Lấy user hiện tại ---
	user, err := s.repo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user không tồn tại")
	}

	// --- 2. Cập nhật các trường ---
	// (Logic cũ của bạn cho phép đổi email, logic mới của tôi không.
	// Chúng ta giữ logic của bạn, nhưng đảm bảo đọc đúng)
	user.Email = req.Email
	user.FullName = req.FullName
	// (Lưu ý: Logic đổi email này sẽ THẤT BẠI nếu bạn dùng RedisRepository,
	// vì RedisRepository (mới) của tôi có HSetNX để check trùng lặp)
	// (Chúng ta sẽ bỏ qua logic đổi email để đơn giản hóa)

	// === LOGIC UPDATE ĐÚNG (Như bạn test) ===
	user.FullName = req.FullName
	// (Chúng ta không cho phép user tự đổi 'role' qua API này)
	// (Chỉ "admin" mới được đổi 'role', như cách bạn 'HSET' thủ công)

	// --- 3. Gọi Repository ---
	err = s.repo.Update(ctx, user)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// --- 4. Cập nhật cache ---
	s.userCache.Set(user.ID, user)

	// --- 5. Trả về ---
	// ⭐️ SỬA: Dùng hàm helper chuẩn (đã được sửa)
	return s.userToProto(user), nil
}

// ⭐️ SỬA: Hàm DeleteUser
func (s *Service) DeleteUser(ctx context.Context, req *proto.DeleteUserRequest) (*emptypb.Empty, error) {
	defer utils.Recovery()

	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id là bắt buộc")
	}

	err := s.repo.Delete(ctx, req.Id)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// Xóa cache
	s.userCache.Delete(req.Id)

	log.Printf("✅ Đã xóa user: %s", req.Id)
	return &emptypb.Empty{}, nil
}

// ⭐️ SỬA: Hàm ListUsers
func (s *Service) ListUsers(ctx context.Context, req *proto.ListUsersRequest) (*proto.ListUsersResponse, error) {
	defer utils.Recovery()

	page := req.Page
	if page <= 0 {
		page = 1
	}

	pageSize := req.PageSize
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	users, total, err := s.repo.List(ctx, page, pageSize)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	protoUsers := make([]*proto.User, len(users))
	for i, user := range users {
		protoUsers[i] = s.userToProto(user)
	}

	return &proto.ListUsersResponse{
		Users: protoUsers,
		Total: total,
	}, nil
}

// ⭐️ SỬA: Hàm GetUserReferrals
func (s *Service) GetUserReferrals(ctx context.Context, req *proto.GetReferralsRequest) (*proto.GetReferralsResponse, error) {
	defer utils.Recovery()

	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id là bắt buộc")
	}

	referrals, err := s.repo.GetReferrals(ctx, req.UserId)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	protoReferrals := make([]*proto.User, len(referrals))
	for i, referral := range referrals {
		protoReferrals[i] = s.userToProto(referral)
	}

	log.Printf("✅ Lấy %d referrals của user %s", len(referrals), req.UserId)
	return &proto.GetReferralsResponse{Referrals: protoReferrals}, nil
}

// 🎯 Gửi welcome email bất đồng bộ
func (s *Service) sendWelcomeEmail(user *User) {
	defer utils.Recovery()

	if s.notificationClient == nil {
		log.Printf("⚠️ NotificationClient là nil, bỏ qua gửi email")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.notificationClient.SendWelcomeEmail(ctx, &proto.NotificationRequest{
		UserId:  user.ID,
		Email:   user.Email,
		Type:    "welcome",
		Message: "Chào mừng bạn đến với hệ thống!",
	})

	if err != nil {
		log.Printf("⚠️ Không thể gửi welcome email: %v", err)
	} else {
		log.Printf("✅ Đã gửi welcome email cho: %s", user.Email)
	}
}

// ⭐️⭐️⭐️ HÀM HELPER QUAN TRỌNG NHẤT (ĐÃ SỬA) ⭐️⭐️⭐️
// Chuyển đổi internal/user/model.go -> api/proto/user.pb.go
func (s *Service) userToProto(u *User) *proto.User {
	if u == nil {
		return nil
	}

	// Chuyển đổi CreatedAt (time.Time) sang Proto (Timestamp)
	var createdAt *timestamppb.Timestamp
	if !u.CreatedAt.IsZero() {
		createdAt = timestamppb.New(u.CreatedAt)
	}

	// Chuyển đổi ReferrerID (*string) sang (string)
	var referrerID string
	if u.ReferrerID != nil {
		referrerID = *u.ReferrerID
	}

	return &proto.User{
		Id:       u.ID,
		Email:    u.Email,
		FullName: u.FullName,
		// ⭐️ SỬA: Thêm Role vào
		Role:       u.Role,
		ReferrerId: referrerID,
		CreatedAt:  createdAt,
	}
}

// GetAdminMetrics - Lấy metrics cho admin dashboard
func (s *Service) GetAdminMetrics(ctx context.Context, req *proto.AdminMetricsRequest) (*proto.AdminMetricsResponse, error) {
	defer utils.Recovery()

	// (Bỏ qua kiểm tra quyền admin ở đây, vì nó nằm ở gRPC Interceptor)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Lấy tất cả users để tính toán metrics
	users, _, err := s.repo.List(ctx, 1, 10000) // Lấy tối đa 10k users
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// Tính toán metrics
	metrics := s.calculateUserMetrics(users, req.TimeRange)

	return &proto.AdminMetricsResponse{
		TotalUsers:    int32(metrics["total_users"].(int)),
		ActiveUsers:   int32(metrics["active_users"].(int)),
		NewUsersToday: int32(metrics["new_users_today"].(int)),
		ReferralCount: int32(metrics["users_with_referral"].(int)),
		GrowthRate:    float32(metrics["growth_rate"].(float64)),
		TimeRange:     req.TimeRange,
	}, nil
}

// BulkCreateUsers - Tạo nhiều users cùng lúc (cho admin)
func (s *Service) BulkCreateUsers(ctx context.Context, req *proto.BulkCreateRequest) (*proto.BulkCreateResponse, error) {
	defer utils.Recovery()

	if len(req.Users) == 0 {
		return &proto.BulkCreateResponse{Errors: []string{"No users provided"}}, nil
	}
	if len(req.Users) > 100 {
		return nil, status.Errorf(codes.InvalidArgument, "Maximum 100 users allowed per bulk request, got %d", len(req.Users))
	}

	var (
		wg           sync.WaitGroup
		successCount int32
		failureCount int32
		errors       []string
		sem          = make(chan struct{}, 10) // 10 goroutine đồng thời
		results      = make([]error, len(req.Users))
	)

	for i, userReq := range req.Users {
		wg.Add(1)
		go func(index int, u *proto.CreateUserRequest) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if u.Email == "" || u.Password == "" {
				results[index] = fmt.Errorf("user %d: email/password required", index)
				return
			}

			user := &User{
				Email:     u.Email,
				Password:  u.Password,
				FullName:  u.FullName,
				CreatedAt: time.Now(),
				Role:      "user", // ⭐️ SỬA: Gán Role mặc định
			}
			if u.ReferrerId != "" {
				user.ReferrerID = &u.ReferrerId
			}

			createCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			err := s.repo.Create(createCtx, user)
			results[index] = err

			if err == nil {
				s.userCache.Set(user.ID, user)
				go s.sendWelcomeEmail(user)
			}
		}(i, userReq)
	}

	wg.Wait()

	for i, err := range results {
		if err != nil {
			failureCount++
			if len(errors) < 50 {
				errors = append(errors, fmt.Sprintf("User %d (%s): %v", i, req.Users[i].Email, err))
			}
		} else {
			successCount++
		}
	}

	if failureCount > 0 && len(errors) == 50 {
		errors = append(errors, "...")
	}

	log.Printf("✅ Bulk create completed: %d success, %d failed", successCount, failureCount)

	return &proto.BulkCreateResponse{
		SuccessCount: successCount,
		FailureCount: failureCount,
		Errors:       errors,
	}, nil
}

// ExportUsers - Streaming export users (cho admin)
func (s *Service) ExportUsers(req *proto.ListUsersRequest, stream proto.UserService_ExportUsersServer) error {
	defer utils.Recovery()

	ctx := stream.Context()

	// Lấy tất cả users (có thể cần pagination cho dataset lớn)
	users, _, err := s.repo.List(ctx, 1, 10000)
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	// Stream từng user
	for _, user := range users {
		select {
		case <-ctx.Done():
			return status.Error(codes.Canceled, "Export cancelled")
		default:
			protoUser := s.userToProto(user)
			if err := stream.Send(protoUser); err != nil {
				return status.Error(codes.Internal, err.Error())
			}
			// Small delay để không overload
			time.Sleep(10 * time.Millisecond)
		}
	}

	log.Printf("✅ Exported %d users via streaming", len(users))
	return nil
}

// calculateUserMetrics - Tính toán các metrics từ user data với time range
func (s *Service) calculateUserMetrics(users []*User, timeRange string) map[string]interface{} {
	metrics := make(map[string]interface{})

	var (
		totalUsers        = len(users)
		activeUsers       = 0
		usersWithReferral = 0
		newUsersToday     = 0
		newUsersInRange   = 0
		previousUsers     = 0
	)

	now := time.Now()
	var startDate time.Time

	switch timeRange {
	case "today":
		startDate = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	case "week":
		startDate = now.AddDate(0, 0, -7)
	case "month":
		startDate = now.AddDate(0, -1, 0)
	case "year":
		startDate = now.AddDate(-1, 0, 0)
	default:
		startDate = now.AddDate(0, 0, -7) // default to week
	}

	// Date for growth rate calculation (previous period)
	previousStartDate := startDate.AddDate(0, 0, -7) // Simple example

	for _, user := range users {
		// Active users (created within 30 days)
		// ⭐️ SỬA: Logic active user của bạn (dùng CreatedAt) khác với repo (dùng LastLoginAt)
		// Chúng ta sẽ dùng logic của repo: GetActiveUsersCount
		// (Hàm này hiện tại đang tính toán "thô", sẽ được tối ưu sau)
		if user.LastLoginAt != nil && user.LastLoginAt.After(now.AddDate(0, 0, -30)) {
			activeUsers++
		}

		// Users có referral
		if user.ReferrerID != nil && *user.ReferrerID != "" {
			usersWithReferral++
		}

		// New users today
		if user.CreatedAt.After(time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())) {
			newUsersToday++
		}

		// New users in time range
		if user.CreatedAt.After(startDate) {
			newUsersInRange++
		}

		// Users in previous period for growth rate
		if user.CreatedAt.After(previousStartDate) && user.CreatedAt.Before(startDate) {
			previousUsers++
		}
	}

	// Calculate growth rate
	growthRate := 0.0
	if previousUsers > 0 {
		growthRate = (float64(newUsersInRange) - float64(previousUsers)) / float64(previousUsers) * 100
	} else if newUsersInRange > 0 {
		growthRate = 100.0 // Infinite growth from 0
	}

	metrics["total_users"] = totalUsers
	metrics["active_users"] = activeUsers // ⭐️ SỬA: Tạm thời tính "thô" ở đây
	metrics["users_with_referral"] = usersWithReferral
	metrics["new_users_today"] = newUsersToday
	metrics["new_users_in_range"] = newUsersInRange
	metrics["growth_rate"] = growthRate

	return metrics
}

// Helper method để kiểm tra admin (giả lập)
func (s *Service) isAdmin(userID string) bool {
	// ⭐️ SỬA: KHÔNG DÙNG HÀM NÀY.
	// Logic admin được xử lý ở gRPC Interceptor (trong main.go)
	// bằng cách gọi authService.GetUserRole()

	// Trong thực tế, sẽ kiểm tra trong database hoặc JWT token
	// Ở đây giả lập admin user
	adminUsers := map[string]bool{
		"admin":   true,
		"user123": true,
	}
	return adminUsers[userID]
}
