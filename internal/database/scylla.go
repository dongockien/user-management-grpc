package database

import (
	"context"
	"fmt"
	"log"
	"sync" // ⬅️ THÊM: Cần cho GetNotificationStats
	"time"

	"github.com/gocql/gocql" // ⬅️ THÊM: Driver ScyllaDB/Cassandra thật
)


// 🗃️ SCYLLA DB REPOSITORY


// ScyllaRepo - Triển khai thật, chứa session kết nối
type ScyllaRepo struct {
	session *gocql.Session // ⬅️ SỬA: Dùng session thật
}

// NewScylla - Khởi tạo kết nối ScyllaDB thật
func NewScylla(hosts []string, keyspace string) (*ScyllaRepo, error) {
	log.Printf("🔗 Đang kết nối ScyllaDB tại: %v", hosts, keyspace)

	cluster := gocql.NewCluster(hosts...)
	cluster.Keyspace = keyspace
	cluster.Consistency = gocql.Quorum
	cluster.Timeout = 5 * time.Second

	// Tạo session
    session, err := cluster.CreateSession()
    if err != nil {
        log.Printf("❌ Không thể tạo session ScyllaDB: %v", err)
        return nil, err
    }

    // ⬅️ THÊM: Kiểm tra kết nối và keyspace (tùy chọn nhưng hữu ích)
    // Thử chạy một query đơn giản để xác nhận keyspace hoạt động
    ctxCheck, cancelCheck := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancelCheck()
    err = session.Query("SELECT keyspace_name FROM system_schema.keyspaces WHERE keyspace_name = ?", keyspace).WithContext(ctxCheck).Exec()
    if err != nil {
         session.Close() // Đóng session nếu keyspace không hợp lệ
         log.Printf("❌ Keyspace '%s' không tồn tại hoặc không truy cập được: %v", keyspace, err)
         return nil, fmt.Errorf("keyspace '%s' invalid: %w", keyspace, err)
    }

    log.Printf("✅ Đã kết nối ScyllaDB và xác nhận keyspace '%s'", keyspace)
    return &ScyllaRepo{session: session}, nil
}
// LogUserActivity - Ghi log hoạt động user vào ScyllaDB (Logic thật)
func (r *ScyllaRepo) LogUserActivity(userID, action string) error {
	//  Logic thật
	// Lưu ý: struct UserActivity có Metadata, nhưng interface này không nhận.
	// Chúng ta sẽ insert NULL cho metadata.
	query := `INSERT INTO user_activity (id, user_id, action, timestamp, metadata) VALUES (now(), ?, ?, ?, ?)`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := r.session.Query(query, userID, action, time.Now(), nil).WithContext(ctx).Exec(); err != nil {
		log.Printf("⚠️ Lỗi ghi log Scylla [user_activity]: %v", err)
		return err
	}
	return nil
}

// LogNotification - Ghi log notification vào ScyllaDB (Logic thật)
func (r *ScyllaRepo) LogNotification(userID, email, notificationType, status string) error {
	// ⬅️ SỬA: Logic thật
	query := `INSERT INTO notification_logs (id, user_id, email, type, status, timestamp) VALUES (now(), ?, ?, ?, ?, ?)`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := r.session.Query(query, userID, email, notificationType, status, time.Now()).WithContext(ctx).Exec(); err != nil {
		log.Printf("⚠️ Lỗi ghi log Scylla [notification_logs]: %v", err)
		return err
	}
	return nil
}

// QueryUserActivity - Triển khai thật
func (r *ScyllaRepo) QueryUserActivity(userID string, startTime, endTime time.Time) ([]UserActivity, error) {
	query := `SELECT user_id, action, timestamp, metadata FROM user_activity WHERE user_id = ? AND timestamp >= ? AND timestamp <= ?`

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	iter := r.session.Query(query, userID, startTime, endTime).WithContext(ctx).Iter()

	var activities []UserActivity
	var activity UserActivity
	// gocql.Iter.Scan() sẽ tự động điền các giá trị, kể cả metadata (nếu là NULL)
	for iter.Scan(&activity.UserID, &activity.Action, &activity.Timestamp, &activity.Metadata) {
		activities = append(activities, activity)
	}

	if err := iter.Close(); err != nil {
		log.Printf("⚠️ Lỗi khi đóng iter [QueryUserActivity]: %v", err)
		return nil, err
	}

	log.Printf("🔍 Query user activity: %s, found %d records", userID, len(activities))
	return activities, nil
}

// GetNotificationStats - Triển khai thật (Concurrent)
func (r *ScyllaRepo) GetNotificationStats(userID string) (*NotificationStats, error) {
	stats := &NotificationStats{UserID: userID}
	var wg sync.WaitGroup
	var mu sync.Mutex // Bảo vệ stats
	var errs []error  // Thu thập lỗi

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. TotalSent
	wg.Add(1)
	go func() {
		defer wg.Done()
		var count int
		query := `SELECT COUNT(*) FROM notification_logs WHERE user_id = ?`
		if err := r.session.Query(query, userID).WithContext(ctx).Scan(&count); err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("count total: %v", err))
			mu.Unlock()
			return
		}
		mu.Lock()
		stats.TotalSent = count
		mu.Unlock()
	}()

	// 2. WelcomeEmails
	wg.Add(1)
	go func() {
		defer wg.Done()
		var count int
		query := `SELECT COUNT(*) FROM notification_logs WHERE user_id = ? AND type = 'welcome'` // Giả sử type là 'welcome'
		if err := r.session.Query(query, userID).WithContext(ctx).Scan(&count); err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("count welcome: %v", err))
			mu.Unlock()
			return
		}
		mu.Lock()
		stats.WelcomeEmails = count
		mu.Unlock()
	}()

	// 3. PasswordResets
	wg.Add(1)
	go func() {
		defer wg.Done()
		var count int
		query := `SELECT COUNT(*) FROM notification_logs WHERE user_id = ? AND type = 'reset'` // Giả sử type là 'reset'
		if err := r.session.Query(query, userID).WithContext(ctx).Scan(&count); err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("count reset: %v", err))
			mu.Unlock()
			return
		}
		mu.Lock()
		stats.PasswordResets = count
		mu.Unlock()
	}()

	// 4. Promotional
	wg.Add(1)
	go func() {
		defer wg.Done()
		var count int
		query := `SELECT COUNT(*) FROM notification_logs WHERE user_id = ? AND type = 'promo'` // Giả sử type là 'promo'
		if err := r.session.Query(query, userID).WithContext(ctx).Scan(&count); err != nil {
			mu.Lock()
			errs = append(errs, fmt.Errorf("count promo: %v", err))
			mu.Unlock()
			return
		}
		mu.Lock()
		stats.Promotional = count
		mu.Unlock()
	}()

	// 5. LastNotification (Lấy bản ghi mới nhất)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var ts time.Time
		// Bảng này có CLUSTERING ORDER BY (timestamp DESC)
		query := `SELECT timestamp FROM notification_logs WHERE user_id = ? LIMIT 1`
		if err := r.session.Query(query, userID).WithContext(ctx).Scan(&ts); err != nil {
			// Không tìm thấy (ErrNotFound) không phải là lỗi, chỉ là chưa có log
			if err != gocql.ErrNotFound {
				mu.Lock()
				errs = append(errs, fmt.Errorf("get last notification: %v", err))
				mu.Unlock()
			}
			return
		}
		mu.Lock()
		stats.LastNotification = ts
		mu.Unlock()
	}()

	wg.Wait()

	if len(errs) > 0 {
		log.Printf("❌ Lỗi khi lấy Scylla stats cho user %s: %v", userID, errs[0])
		return nil, errs[0] // Trả về lỗi đầu tiên
	}

	return stats, nil
}

// Ping - Kiểm tra sức khỏe (Logic thật cho Scheduler)
func (r *ScyllaRepo) Ping(ctx context.Context) error {
	// ⬅️ THÊM: Logic thật
	return r.session.Query("SELECT release_version FROM system.local").WithContext(ctx).Exec()
}

// Close - Đóng kết nối ScyllaDB
func (r *ScyllaRepo) Close() {
	if r.session != nil {
		r.session.Close()
		log.Println("🔌 Đã đóng kết nối ScyllaDB")
	}
}

// =========================================
// 🏷️ DATA MODELS CHO SCYLLA DB (Giữ nguyên)
// =========================================

type UserActivity struct {
	UserID    string    `json:"user_id"`
	Action    string    `json:"action"`
	Timestamp time.Time `json:"timestamp"`
	Metadata  string    `json:"metadata,omitempty"`
}

type NotificationStats struct {
	UserID           string    `json:"user_id"`
	TotalSent        int       `json:"total_sent"`
	WelcomeEmails    int       `json:"welcome_emails"`
	PasswordResets   int       `json:"password_resets"`
	Promotional      int       `json:"promotional"`
	LastNotification time.Time `json:"last_notification"`
}

type NotificationLog struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Type      string    `json:"type"`
	Status    string    `json:"status"`
	Subject   string    `json:"subject,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Error     string    `json:"error,omitempty"`
}
