package scheduler

import (
	"context"
	"errors"
	"log"
	"runtime" // 🔹 THÊM: Import runtime
	"sync"
	"time"

	"user-management-grpc/internal/auth"
	"user-management-grpc/internal/user"
	"user-management-grpc/internal/utils"

	"github.com/robfig/cron/v3" // 🔹 SỬA: Import đúng path
)

// ⏰ SCHEDULER SERVICE - BACKGROUND JOBS

// ScyllaRepository định nghĩa các hành vi mà scheduler cần từ ScyllaDB.
type ScyllaRepository interface {
	LogUserActivity(userID, activity string) error
	Ping(ctx context.Context) error
}

// Scheduler - Quản lý các công việc chạy định kỳ
type Scheduler struct {
	userRepo    user.Repository
	authService *auth.Service
	scyllaRepo  ScyllaRepository
	cron        *cron.Cron // 🔹 SỬA: cron.Cron thay vì cron
	mu          sync.RWMutex
	jobs        map[cron.EntryID]string // 🔹 THEO DÕI: ID và tên các job
}

// NewScheduler - Khởi tạo scheduler với các dependencies
func NewScheduler(userRepo user.Repository, authService *auth.Service, scyllaRepo ScyllaRepository) *Scheduler {
	return &Scheduler{
		userRepo:    userRepo,
		authService: authService,
		scyllaRepo:  scyllaRepo,
		cron:        cron.New(cron.WithChain(cron.Recover(cron.DefaultLogger))),
		jobs:        make(map[cron.EntryID]string),
	}
}

// Start - Khởi chạy scheduler với các job định kỳ
func (s *Scheduler) Start(ctx context.Context) {
	log.Println("🚀 Starting scheduler...")

	// 🔹 JOB 1: Cleanup expired tokens mỗi 30 phút
	jobID, err := s.cron.AddFunc("@every 2m", s.cleanupExpiredTokens)
	if err != nil {
		log.Printf("❌ Failed to add token cleanup job: %v", err)
	} else {
		s.jobs[jobID] = "Token Cleanup"
		log.Println("✅ Registered job: Token Cleanup (every 30m)")
	}

	// 🔹 JOB 2: Backup user stats hàng ngày lúc 2h sáng
	jobID, err = s.cron.AddFunc("@every 2m", s.backupUserStats)
	// "0 2 * * *"
	if err != nil {
		log.Printf("❌ Failed to add backup job: %v", err)
	} else {
		s.jobs[jobID] = "User Stats Backup"
		log.Println("✅ Registered job: User Stats Backup (daily at 2:00 AM)")
	}

	// 🔹 JOB 3: Cleanup inactive users mỗi chủ nhật lúc 3h sáng
	jobID, err = s.cron.AddFunc("@every 2m", s.cleanupInactiveUsers)
	// 0 3 * * 0
	if err != nil {
		log.Printf("❌ Failed to add user cleanup job: %v", err)
	} else {
		s.jobs[jobID] = "Inactive Users Cleanup"
		log.Println("✅ Registered job: Inactive Users Cleanup (weekly on Sunday at 3:00 AM)")
	}

	// 🔹 JOB 4: Health check mỗi 5 phút
	jobID, err = s.cron.AddFunc("@every 2m", s.healthCheck)

	// @every 5m
	if err != nil {
		log.Printf("❌ Failed to add health check job: %v", err)
	} else {
		s.jobs[jobID] = "System Health Check"
		log.Println("✅ Registered job: System Health Check (every 5m)")
	}

	// 🔹 JOB 5: Log system stats mỗi giờ
	jobID, err = s.cron.AddFunc("@every 2m", s.logSystemStats)
	// 0 * * * *
	if err != nil {
		log.Printf("❌ Failed to add system stats job: %v", err)
	} else {
		s.jobs[jobID] = "System Stats Logger"
		log.Println("✅ Registered job: System Stats Logger (hourly)")
	}

	// 🔹 KHỞI CHẠY: Cron scheduler
	s.cron.Start()

	// 🔹 GRACEFUL SHUTDOWN: Goroutine để dừng scheduler khi context cancel
	go func() {
		<-ctx.Done()
		log.Println("🛑 Stopping scheduler...")
		s.cron.Stop()
		log.Printf("✅ Scheduler stopped with %d jobs", len(s.jobs))
	}()

	log.Printf("🎯 Scheduler started successfully with %d jobs", len(s.cron.Entries()))
}

// =========================================
// 🧹 TOKEN MANAGEMENT JOBS
// =========================================

// cleanupExpiredTokens - Dọn dẹp token hết hạn
func (s *Scheduler) cleanupExpiredTokens() {
	defer utils.RecoveryWithContext("CleanupExpiredTokens")
	start := time.Now()
	log.Println("🧹 [JOB] Starting expired tokens cleanup...")

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	if s.authService != nil {
		// Gọi method thật (đã thêm vào auth.Service)
		deletedCount, err := s.authService.CleanupExpiredTokens(ctx)
		if err != nil {
			log.Printf("❌ [JOB] Token cleanup failed: %v", err)
		} else {
			log.Printf("✅ [JOB] Token cleanup completed. Removed %d expired revoked tokens.", deletedCount)
		}
	} else {
		log.Println("⚠️ Auth service not available for token cleanup")
	}

	duration := time.Since(start)
	log.Printf("✅ [JOB] Token cleanup finished in %v", duration)
}

// 💾 DATA BACKUP & STATISTICS JOBS


// backupUserStats - Backup thống kê user vào ScyllaDB
func (s *Scheduler) backupUserStats() {

	defer utils.RecoveryWithContext("BackupUserStats")

	start := time.Now()
	log.Println("💾 [JOB] Starting user stats backup...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 🔹 LẤY DỮ LIỆU: User data từ repository
	users, total, err := s.userRepo.List(ctx, 1, 1000) // Lấy 1000 user đầu tiên
	if err != nil {
		log.Printf("❌ [JOB] Failed to get users for backup: %v", err)
		return
	}

	// 🔹 XỬ LÝ SONG SONG: Sử dụng goroutine để tính toán stats
	var wg sync.WaitGroup
	stats := make(map[string]int)
	var mu sync.Mutex
	// 🔹 GOROUTINE 1: Thống kê referral users
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer utils.RecoveryWithContext("ReferralStats")

		referralCount := 0
		for _, user := range users {
			if user.ReferrerID != nil && *user.ReferrerID != "" {
				referralCount++
			}
		}
		mu.Lock()
		stats["referral_users"] = referralCount
		mu.Unlock()
		log.Printf("📊 Referral users: %d", referralCount)
	}()

	// 🔹 GOROUTINE 2: Thống kê user mới trong 7 ngày
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer utils.RecoveryWithContext("RecentUsersStats")

		recentUsers := 0
		weekAgo := time.Now().AddDate(0, 0, -7)
		for _, user := range users {
			if user.CreatedAt.After(weekAgo) {
				recentUsers++
			}
		}
		mu.Lock()
		stats["recent_users"] = recentUsers
		mu.Unlock()
		log.Printf("📊 Recent users (7 days): %d", recentUsers)
	}()

	// 🔹 GOROUTINE 3: Thống kê active users (giả lập)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer utils.RecoveryWithContext("ActiveUsersStats")

		thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
		log.Println("⏳ [JOB-BACKUP] Chuẩn bị gọi GetActiveUsersCount...")

		activeCount, err := s.userRepo.GetActiveUsersCount(ctx, thirtyDaysAgo)
		log.Printf("ℹ️ [JOB-BACKUP] GetActiveUsersCount trả về: count=%d, err=%v", activeCount, err)
		if err != nil {
			log.Printf("❌ [JOB] Failed to get active users count: %v", err)
			return
		}
		log.Println("⏳ [JOB-BACKUP][G3] Chuẩn bị gọi mu.Lock()...")
		mu.Lock() // ⬅️ SỬA: Khóa
		log.Println("✅ [JOB-BACKUP][G3] Đã gọi mu.Lock() thành công.")
		stats["active_users"] = int(activeCount)
		mu.Unlock() // ⬅️ SỬA: Mở khóa
		log.Println("✅ [JOB-BACKUP][G3] Đã gọi mu.Unlock().")
		log.Printf("📊 Active users (30 days): %d", activeCount)
		log.Println("✅ [JOB-BACKUP][G3] Goroutine 3 hoàn thành.") // Log cuối cùng trước khi defer wg.Done() chạy

	}()

	wg.Wait()
	// 🔹 TỔNG HỢP: Final statistics
	mu.Lock()
	stats["total_users"] = int(total)
	stats["sampled_users"] = len(users)
	stats["backup_timestamp"] = int(time.Now().Unix())
	mu.Unlock()
	// 🔹 GHI LOG: Backup results vào ScyllaDB
	if s.scyllaRepo != nil {
		err := s.scyllaRepo.LogUserActivity("system_scheduler", "backup_completed")
		if err != nil {
			log.Printf("⚠️ [JOB] Failed to log backup to Scylla: %v", err)
		} else {
			log.Println("📝 Backup logged to ScyllaDB successfully")
		}
	}

	duration := time.Since(start)
	log.Printf("✅ [JOB] Backup completed: %+v (took %v)", stats, duration)
}

// =========================================
// 👥 USER MANAGEMENT JOBS
// =========================================

// cleanupInactiveUsers - Dọn dẹp users không hoạt động bằng logic thật.
func (s *Scheduler) cleanupInactiveUsers() {
	defer utils.RecoveryWithContext("CleanupInactiveUsers")
	start := time.Now()
	log.Println("👥 [JOB] Starting inactive users cleanup...")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	// Định nghĩa "không hoạt động": user được tạo cách đây hơn 30 ngày.
	// Để test, bạn có thể tạm thời dùng 1 phút: time.Now().Add(-1 * time.Minute)
	inactiveThreshold := time.Now().AddDate(0, 0, -30)

	// Gọi method mới của repository.
	deletedCount, err := s.userRepo.DeleteInactive(ctx, inactiveThreshold)
	if err != nil {
		log.Printf("❌ [JOB] Inactive user cleanup failed: %v", err)
		if s.scyllaRepo != nil {
			s.scyllaRepo.LogUserActivity("system_scheduler", "cleanup_inactive_users_failed")
		}
		return
	}

	if deletedCount > 0 {
		log.Printf("✅ [JOB] Successfully deleted %d inactive users.", deletedCount)
		if s.scyllaRepo != nil {
			s.scyllaRepo.LogUserActivity("system_scheduler", "cleanup_inactive_users_success")
		}
	} else {
		log.Println("✅ [JOB] No inactive users found to delete.")
	}

	log.Printf("✅ [JOB] Inactive users cleanup completed in %v", time.Since(start))
}

// =========================================
// 🩺 SYSTEM HEALTH & MONITORING JOBS
// =========================================

// healthCheck - Kiểm tra sức khỏe hệ thống
func (s *Scheduler) healthCheck() {
	defer utils.RecoveryWithContext("HealthCheck")

	log.Println("❤️ [JOB] Starting system health check...")

	// 🔹 KIỂM TRA SONG SONG: Tất cả services
	var wg sync.WaitGroup
	services := []string{"MySQL", "Redis", "Scylla"}
	results := make(map[string]bool)
	var mu sync.Mutex

	for _, service := range services {
		wg.Add(1)
		go func(svc string) {
			defer wg.Done()
			defer utils.RecoveryWithContext("HealthCheck-" + svc)

			// 🔹 GIẢ LẬP: Health check với timeout
			checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer checkCancel()

			healthy := s.checkServiceHealth(checkCtx, svc)

			mu.Lock()
			results[svc] = healthy
			mu.Unlock()

			if healthy {
				log.Printf("✅ [HEALTH] %s: HEALTHY", svc)
			} else {
				log.Printf("❌ [HEALTH] %s: UNHEALTHY", svc)
			}
		}(service)
	}

	wg.Wait()

	// 🔹 GHI LOG: Health check results
	if s.scyllaRepo != nil {
		status := "healthy"
		for _, healthy := range results {
			if !healthy {
				status = "degraded"
				break
			}
		}
		s.scyllaRepo.LogUserActivity("system_scheduler", "health_check_"+status)
	}

	log.Printf("📊 Health check completed: %+v", results)
}

// checkServiceHealth - Kiểm tra sức khỏe của từng service

func (s *Scheduler) checkServiceHealth(ctx context.Context, service string) bool {
	var err error
	switch service {
	case "MySQL":
		if s.userRepo != nil {
			// ⚠️ YÊU CẦU: Cần có hàm `Ping` trong user.Repository
			err = s.userRepo.Ping(ctx)
		} else {
			err = errors.New("userRepo (MySQL) is nil")
		}
	case "Redis":
		if s.authService != nil {
			err = s.authService.Ping(ctx) // Đã thêm vào auth.Service
		} else {
			err = errors.New("authService (Redis) is nil")
		}
	case "Scylla":
		if s.scyllaRepo != nil {
			err = s.scyllaRepo.Ping(ctx) // Đã thêm vào interface ScyllaRepository
		} else {
			err = errors.New("scyllaRepo is nil")
		}
	default:
		return false
	}

	if err != nil {
		log.Printf("⚠️ [HEALTH] Ping failed for %s: %v", service, err)
		return false
	}
	return true
}

// logSystemStats - Ghi log thống kê hệ thống
func (s *Scheduler) logSystemStats() {
	defer utils.RecoveryWithContext("LogSystemStats")

	stats := map[string]interface{}{
		"timestamp":     time.Now().Format(time.RFC3339),
		"num_goroutine": runtime.NumGoroutine(), // 🔹 SỬA: Đã có import runtime
		"active_jobs":   len(s.jobs),
	}

	// 🔹 THÊM: Memory statistics
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	stats["memory_alloc_mb"] = m.Alloc / 1024 / 1024
	stats["memory_sys_mb"] = m.Sys / 1024 / 1024
	stats["num_gc"] = m.NumGC

	log.Printf("📈 System Stats: %+v", stats)

	// 🔹 GHI LOG: System stats vào Scylla
	if s.scyllaRepo != nil {
		s.scyllaRepo.LogUserActivity("system", "system_stats_logged")
	}
}

// =========================================
// 🛠️ PUBLIC HELPER FUNCTIONS
// =========================================

// StartScheduler - Helper function để start scheduler từ main.go
func StartScheduler(ctx context.Context, userRepo user.Repository, authService *auth.Service, scyllaRepo ScyllaRepository) {
	scheduler := NewScheduler(userRepo, authService, scyllaRepo)
	scheduler.Start(ctx)
}

// GetJobStatus - Lấy trạng thái các job (cho monitoring)
func (s *Scheduler) GetJobStatus() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := make(map[string]string)
	entries := s.cron.Entries()

	for _, entry := range entries {
		jobName := s.jobs[entry.ID]
		if jobName != "" {
			nextRun := entry.Next.Format("2006-01-02 15:04:05")
			status[jobName] = "Next run: " + nextRun
		}
	}

	return status
}

// Stop - Dừng scheduler
func (s *Scheduler) Stop() {
	log.Println("🛑 Stopping scheduler...")
	s.cron.Stop()
	log.Println("✅ Scheduler stopped")
}
