package user

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"user-management-grpc/api/proto"
	"user-management-grpc/internal/utils"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Service struct {
	proto.UnimplementedUserServiceServer
	repo               Repository
	userCache          *UserCache
	referralMap        *utils.SafeMap
	notificationClient proto.NotificationServiceClient
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

func NewService(repo Repository, notificationClient proto.NotificationServiceClient) *Service {
	return &Service{
		repo:               repo,
		userCache:          NewUserCache(),
		referralMap:        utils.NewSafeMap(),
		notificationClient: notificationClient,
	}
}

func (s *Service) CreateUser(ctx context.Context, req *proto.CreateUserRequest) (*proto.User, error) {
	defer utils.Recovery()

	if req.Email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email và password là bắt buộc")
	}

	// Kiểm tra referrer
	if req.ReferrerId != "" {
		_, err := s.repo.GetByID(ctx, req.ReferrerId)
		if err != nil {
			log.Printf("⚠️ Referrer không tồn tại: %s", req.ReferrerId)
		} else {
			s.referralMap.Set(req.ReferrerId, true)
			log.Printf("✅ User %s được mời bởi %s", req.Email, req.ReferrerId)
		}
	}

	user := &User{
		Email:     req.Email,
		Password:  req.Password,
		FullName:  req.FullName,
		CreatedAt: time.Now(),
	}
	if req.ReferrerId != "" {
		user.ReferrerID = &req.ReferrerId
	}

	// 🧱 Tạo user đồng bộ
	if err := s.repo.Create(ctx, user); err != nil {
		log.Printf("❌ Lỗi khi tạo user trong DB: %v", err)
		return nil, status.Error(codes.Internal, "failed to create user")
	}

	// 🚀 Gửi email bất đồng bộ, không ảnh hưởng response
	go func() {
		defer utils.Recovery()
		s.sendWelcomeEmail(user)
	}()

	return &proto.User{
		Id:        user.ID,
		Email:     user.Email,
		FullName:  user.FullName,
		CreatedAt: timestamppb.New(user.CreatedAt),
	}, nil
}

func (s *Service) GetUser(ctx context.Context, req *proto.GetUserRequest) (*proto.User, error) {
	defer utils.Recovery()

	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id là bắt buộc")
	}

	// 🎯 Kiểm tra cache trước
	s.mu.RLock()
	if cachedUser, exists := s.userCache.Get(req.Id); exists {
		s.mu.RUnlock()
		log.Printf("✅ Lấy user từ cache: %s", req.Id)
		return s.userToProto(cachedUser), nil
	}
	s.mu.RUnlock()

	// Lấy từ database
	user, err := s.repo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user không tồn tại")
	}

	// Cache kết quả
	s.mu.Lock()
	s.userCache.Set(user.ID, user)
	s.mu.Unlock()

	return s.userToProto(user), nil
}

func (s *Service) UpdateUser(ctx context.Context, req *proto.UpdateUserRequest) (*proto.User, error) {
	defer utils.Recovery()

	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id là bắt buộc")
	}

	user, err := s.repo.GetByID(ctx, req.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user không tồn tại")
	}

	user.Email = req.Email
	user.FullName = req.FullName

	err = s.repo.Update(ctx, user)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// Cập nhật cache
	s.mu.Lock()
	s.userCache.Set(user.ID, user)
	s.mu.Unlock()

	return s.userToProto(user), nil
}

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
	s.mu.Lock()
	s.userCache.Delete(req.Id)
	s.mu.Unlock()

	log.Printf("✅ Đã xóa user: %s", req.Id)
	return &emptypb.Empty{}, nil
}

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

func (s *Service) userToProto(u *User) *proto.User {
	protoUser := &proto.User{
		Id:        u.ID,
		Email:     u.Email,
		FullName:  u.FullName,
		CreatedAt: timestamppb.New(u.CreatedAt),
	}

	if u.ReferrerID != nil {
		protoUser.ReferrerId = *u.ReferrerID
	}

	return protoUser
}

// GetAdminMetrics - Lấy metrics cho admin dashboard
func (s *Service) GetAdminMetrics(ctx context.Context, req *proto.AdminMetricsRequest) (*proto.AdminMetricsResponse, error) {
	defer utils.Recovery()

	// 🔹 KIỂM TRA QUYỀN ADMIN (trong thực tế sẽ kiểm tra role từ context)
	// userID := ctx.Value("userID").(string)
	// if !s.isAdmin(userID) {
	//     return nil, status.Error(codes.PermissionDenied, "Admin access required")
	// }

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
		sem          = make(chan struct{}, 10)
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
		if user.CreatedAt.After(now.AddDate(0, 0, -30)) {
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
	metrics["active_users"] = activeUsers
	metrics["users_with_referral"] = usersWithReferral
	metrics["new_users_today"] = newUsersToday
	metrics["new_users_in_range"] = newUsersInRange
	metrics["growth_rate"] = growthRate

	return metrics
}

// Helper method để kiểm tra admin (giả lập)
func (s *Service) isAdmin(userID string) bool {
	// Trong thực tế, sẽ kiểm tra trong database hoặc JWT token
	// Ở đây giả lập admin user
	adminUsers := map[string]bool{
		"admin":   true,
		"user123": true,
	}
	return adminUsers[userID]
}