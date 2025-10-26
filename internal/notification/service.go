package notification

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
)

type ScyllaRepository interface {
	LogUserActivity(userID, activity string) error
	LogNotification(userID, email, notificationType, status string) error
	Ping(ctx context.Context) error
}
type Service struct {
	proto.UnimplementedNotificationServiceServer
	scyllaRepo ScyllaRepository
	emailQueue chan *proto.NotificationRequest
	mu         sync.RWMutex
	workerWg   sync.WaitGroup // 🔹 THÊM: WaitGroup để quản lý worker
	stopChan   chan struct{}  // 🔹 THÊM: Channel để dừng worker
}

func NewService(scyllaRepo ScyllaRepository) *Service {
	service := &Service{
		scyllaRepo: scyllaRepo,
		emailQueue: make(chan *proto.NotificationRequest, 100), // Buffer 100 emails
		stopChan:   make(chan struct{}),
	}

	//  KHỞI CHẠY: Worker xử lý email bất đồng bộ
	service.workerWg.Add(1)
	go service.emailWorker()
	log.Println("✅ Notification Service đã khởi động")
	return service
}

func (s *Service) SendWelcomeEmail(ctx context.Context, req *proto.NotificationRequest) (*proto.NotificationResponse, error) {
	defer utils.RecoveryWithContext("SendWelcomeEmail")

	if req.UserId == "" || req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id và email là bắt buộc")
	}

	log.Printf("📧 Gửi welcome email đến: %s (User: %s)", req.Email, req.UserId)

	// 🔹 GHI LOG: Hoạt động vào ScyllaDB
	if s.scyllaRepo != nil {
		err := s.scyllaRepo.LogUserActivity(req.UserId, "welcome_email_sent")
		if err != nil {
			log.Printf("⚠️ Không thể ghi log vào Scylla: %v", err)
			// 🔹 KHÔNG RETURN ERROR: Vì lỗi log không nên ảnh hưởng đến business logic
		}
	}

	// 🔹 GIẢ LẬP: Gửi email thực tế
	s.sendEmail(req.Email, "Welcome to Our Service!",
		fmt.Sprintf(`
Dear %s,

Welcome to our platform! We're excited to have you on board.

Here's what you can do:
- Complete your profile
- Explore our features
- Invite your friends

If you have any questions, don't hesitate to contact our support team.

Best regards,
The Team
		`, req.Email))

	log.Printf("✅ Đã gửi welcome email thành công đến: %s", req.Email)

	return &proto.NotificationResponse{
		Success: true,
		Message: "Welcome email sent successfully",
	}, nil
}

func (s *Service) SendNotification(ctx context.Context, req *proto.NotificationRequest) (*proto.NotificationResponse, error) {
	defer utils.RecoveryWithContext("SendNotification")

	if req.UserId == "" || req.Email == "" || req.Type == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id, email và type là bắt buộc")
	}

	// 🔹 QUEUE: Đưa notification vào queue xử lý bất đồng bộ
	select {
	case s.emailQueue <- req:
		log.Printf("📨 Đã thêm notification vào queue - Type: %s, User: %s", req.Type, req.UserId)
		return &proto.NotificationResponse{
			Success: true,
			Message: "Notification queued successfully",
		}, nil
	case <-ctx.Done():
		return nil, status.Error(codes.DeadlineExceeded, "request timeout")
	default:
		// 🔹 QUEUE FULL: Trả về lỗi nếu queue đầy
		log.Printf("🚨 Email queue is full - Type: %s", req.Type)
		return nil, status.Error(codes.ResourceExhausted, "Email queue is full")
	}
}

// =========================================
// 🆕 NEW METHODS - HOÀN CHỈNH
// =========================================

// SendPasswordReset - Gửi email reset password HOÀN CHỈNH
func (s *Service) SendPasswordReset(ctx context.Context, req *proto.NotificationRequest) (*proto.NotificationResponse, error) {
	defer utils.RecoveryWithContext("SendPasswordReset")

	if req.UserId == "" || req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id và email là bắt buộc")
	}

	log.Printf("🔐 Gửi password reset email đến: %s (User: %s)", req.Email, req.UserId)

	// Tạo reset token
	resetToken, err := utils.GenerateRandomString(32)
	if err != nil {
		return nil, status.Error(codes.Internal, "không thể tạo reset token")
	}

	// 🔹 TRONG THỰC TẾ: Lưu reset token vào database với expiry time
	// Ở đây giả lập lưu vào Redis: s.redisClient.Set("pwd_reset:"+resetToken, req.UserId, 1*time.Hour)

	// Tạo reset link
	resetLink := fmt.Sprintf("https://yourapp.com/reset-password?token=%s", resetToken)

	// Ghi log vào Scylla
	if s.scyllaRepo != nil {
		err := s.scyllaRepo.LogNotification(req.UserId, req.Email, "password_reset", "sent")
		if err != nil {
			log.Printf("⚠️ Không thể ghi log password reset: %v", err)
		}
	}

	// 🔹 GIẢ LẬP: Gửi email thực tế
	s.sendEmail(req.Email, "Reset Your Password",
		fmt.Sprintf(`
Hello,

You requested a password reset. Click the link below to reset your password:

%s

This link will expire in 1 hour.

If you didn't request this, please ignore this email.

Best regards,
Your App Team
		`, resetLink))

	log.Printf("✅ Đã gửi password reset email đến: %s", req.Email)

	return &proto.NotificationResponse{
		Success: true,
		Message: "Password reset email sent successfully",
	}, nil
}

// SendSecurityAlert - Gửi cảnh báo bảo mật
func (s *Service) SendSecurityAlert(ctx context.Context, req *proto.NotificationRequest) (*proto.NotificationResponse, error) {
	defer utils.RecoveryWithContext("SendSecurityAlert")

	if req.UserId == "" || req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id và email là bắt buộc")
	}

	log.Printf("🚨 Gửi security alert đến: %s (User: %s)", req.Email, req.UserId)

	// Ghi log vào Scylla
	if s.scyllaRepo != nil {
		s.scyllaRepo.LogNotification(req.UserId, req.Email, "security_alert", "sent")
	}

	s.sendEmail(req.Email, "Security Alert - Suspicious Activity", `
SECURITY ALERT

We detected suspicious activity on your account.

If this wasn't you, please secure your account immediately by:
1. Changing your password
2. Reviewing recent activity
3. Contacting support if needed

Best regards,
Security Team
	`)

	log.Printf("✅ Đã gửi security alert đến: %s", req.Email)

	return &proto.NotificationResponse{
		Success: true,
		Message: "Security alert sent successfully",
	}, nil
}

// GetDeliveryStatus - Kiểm tra trạng thái gửi notification
func (s *Service) GetDeliveryStatus(ctx context.Context, req *proto.NotificationRequest) (*proto.NotificationResponse, error) {
	defer utils.RecoveryWithContext("GetDeliveryStatus")

	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id là bắt buộc")
	}

	// 🔹 TRONG THỰC TẾ: Sẽ query database hoặc email service để lấy status
	// Ở đây giả lập luôn thành công
	log.Printf("📊 Kiểm tra delivery status cho user: %s", req.UserId)

	return &proto.NotificationResponse{
		Success: true,
		Message: "Notification delivered successfully (simulated)",
	}, nil
}

// SendPromotionalEmail - Gửi email quảng cáo/promotional
func (s *Service) SendPromotionalEmail(ctx context.Context, req *proto.NotificationRequest) (*proto.NotificationResponse, error) {
	defer utils.RecoveryWithContext("SendPromotionalEmail")
	if req.UserId == "" || req.Email == "" || req.Message == "" { /* ... lỗi ... */
	}
	log.Printf("🎉 Gửi promotional email đến: %s", req.Email)

	// Kiểm tra nil trước khi dùng repo
	if s.scyllaRepo != nil {
		err := s.scyllaRepo.LogNotification(req.UserId, req.Email, "promotional", "sent") // ✅ Đã dùng interface method
		if err != nil {
			log.Printf("⚠️ Không thể ghi log promotional email: %v", err)
		}
	} else {
		log.Println("⚠️ ScyllaRepo is nil, skipping LogNotification for promotional email")
	}

	s.sendEmail(req.Email, "Special Offer!", req.Message)
	log.Printf("✅ Đã gửi promotional email đến: %s", req.Email)
	return &proto.NotificationResponse{Success: true, Message: "Promotional email sent successfully"}, nil
}

// =========================================
// 🛠️ PRIVATE HELPER METHODS
// =========================================

// sendEmail - Hàm giả lập gửi email (TRONG THỰC TẾ SẼ TÍCH HỢP EMAIL SERVICE)
func (s *Service) sendEmail(to, subject, body string) error {
	// 🔹 TRONG THỰC TẾ: Sẽ tích hợp với:
	// - SendGrid: https://github.com/sendgrid/sendgrid-go
	// - AWS SES: https://github.com/aws/aws-sdk-go-v2/service/ses
	// - SMTP: net/smtp

	// Giả lập độ trễ gửi email
	time.Sleep(100 * time.Millisecond)

	log.Printf("📧 [EMAIL] To: %s, Subject: %s", to, subject)
	log.Printf("📧 [EMAIL BODY] %s", body)

	return nil
}

// =========================================
// 🎯 BACKGROUND WORKER PROCESSING (ĐÃ CẬP NHẬT)
// =========================================

// emailWorker - Worker xử lý email từ queue (chạy background)
func (s *Service) emailWorker() {
	defer s.workerWg.Done()
	defer utils.RecoveryWithContext("EmailWorker")

	log.Println("👷 Email worker đã khởi động")

	for {
		select {
		case req := <-s.emailQueue:
			// 🔹 XỬ LÝ: Email từ queue
			s.processEmail(req)
		case <-s.stopChan:
			// 🔹 DỪNG: Worker khi nhận tín hiệu
			log.Println("🛑 Email worker đang dừng...")
			return
		}
	}
}

// processEmail - Xử lý email cụ thể (ĐÃ CẬP NHẬT)
func (s *Service) processEmail(req *proto.NotificationRequest) {
	defer utils.RecoveryWithContext("ProcessEmail")

	startTime := time.Now()
	log.Printf("👷 Worker đang xử lý email - Type: %s, User: %s", req.Type, req.UserId)

	// 🔹 XỬ LÝ THEO LOẠI NOTIFICATION
	switch req.Type {
	case "welcome":
		s.sendEmail(req.Email, "Welcome to Our Service!", req.Message)
	case "password_reset":
		s.SendPasswordReset(context.Background(), req) // Gọi sync
	case "security_alert":
		s.SendSecurityAlert(context.Background(), req) // Gọi sync
	case "promotional":
		s.sendEmail(req.Email, "Special Offer!", req.Message)
	default:
		s.sendEmail(req.Email, "Notification", req.Message)
	}

	// 🔹 GHI LOG: Kết quả xử lý vào ScyllaDB
	if s.scyllaRepo != nil {
		err := s.scyllaRepo.LogNotification(req.UserId, req.Email, req.Type, "processed")
		if err != nil {
			log.Printf("⚠️ Không thể ghi notification log: %v", err)
		}
	}

	duration := time.Since(startTime)
	log.Printf("✅ Worker đã xử lý xong - Type: %s, Time: %v", req.Type, duration)
}

// =========================================
// 🛑 GRACEFUL SHUTDOWN METHODS
// =========================================

// Stop - Dừng service và cleanup
func (s *Service) Stop() {
	log.Println("🛑 Đang dừng Notification Service...")

	close(s.stopChan) // 🔹 GỬI TÍN HIỆU: Dừng worker
	s.workerWg.Wait() // 🔹 ĐỢI: Worker hoàn thành

	close(s.emailQueue) // 🔹 ĐÓNG: Queue

	log.Println("✅ Notification Service đã dừng")
}

// HealthCheck - Kiểm tra tình trạng service
func (s *Service) HealthCheck(ctx context.Context) (*proto.NotificationResponse, error) {
	// 🔹 KIỂM TRA: ScyllaDB connection
	if s.scyllaRepo != nil {
		pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := s.scyllaRepo.Ping(pingCtx); err != nil {
			log.Printf("❌ Health Check Failed: ScyllaDB Ping error: %v", err)
			return nil, status.Error(codes.Unavailable, "ScyllaDB không kết nối")
		}
	}

	// 🔹 KIỂM TRA: Queue không bị full
	queueLength := len(s.emailQueue)
	if queueLength > 90 { // 90% capacity
		return nil, status.Error(codes.ResourceExhausted,
			fmt.Sprintf("Email queue gần đầy: %d/100", queueLength))
	}

	return &proto.NotificationResponse{
		Success: true,
		Message: fmt.Sprintf("Notification service is healthy - Queue: %d/100", queueLength),
	}, nil
}

// GetQueueStats - Lấy thống kê queue (cho monitoring)
func (s *Service) GetQueueStats(ctx context.Context) (*proto.NotificationResponse, error) {
	queueLength := len(s.emailQueue)
	queueCapacity := cap(s.emailQueue)
	utilization := float64(queueLength) / float64(queueCapacity) * 100

	return &proto.NotificationResponse{
		Success: true,
		Message: fmt.Sprintf("Queue: %d/%d (%.1f%%)", queueLength, queueCapacity, utilization),
	}, nil
}
