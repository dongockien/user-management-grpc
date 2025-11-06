package user

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"user-management-grpc/internal/utils" // ✅ dùng utils thay cho bcrypt trực tiếp

	"github.com/google/uuid"
)

// Cấu trúc Repository
type MySQLRepository struct {
	db *sql.DB
}

// Hàm khởi tạo
func NewMySQLRepository(db *sql.DB) *MySQLRepository {
	return &MySQLRepository{db: db}
}

// 🔹 CREATE USER

func (r *MySQLRepository) Create(ctx context.Context, u *User) error {
	// ✅ Tạo context có timeout để tránh truy vấn treo lâu
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Tạo ID và thời gian nếu chưa có
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now()
	}
	if u.Role == "" {
		u.Role = "user"
	}
	// ✅ Dùng utils.HashPassword thay cho bcrypt trực tiếp
	hashedPassword, err := utils.HashPassword(u.Password)
	if err != nil {
		return fmt.Errorf("lỗi mã hóa mật khẩu: %v", err)
	}

	query := `
		INSERT INTO users (id, email, password, full_name, referrer_id, created_at, role)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	_, err = r.db.ExecContext(ctx, query,
		u.ID,
		u.Email,
		hashedPassword,
		u.FullName,
		u.ReferrerID,
		u.CreatedAt,
		u.Role,
	)
	if err != nil {
		return fmt.Errorf("lỗi khi tạo user: %v", err)
	}

	log.Printf("✅ Đã tạo user: %s", u.Email)
	return nil
}

// 🔹 GET USER BY ID

func (r *MySQLRepository) GetByID(ctx context.Context, id string) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	query := `
		SELECT id, email, password, full_name, referrer_id, created_at, role
		FROM users WHERE id = ?
	`

	var user User
	var referrerID sql.NullString
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.FullName,
		&referrerID,
		&user.CreatedAt,
		&user.Role,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user không tồn tại: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("lỗi truy vấn user: %v", err)
	}
	if referrerID.Valid {
		user.ReferrerID = &referrerID.String
	}

	return &user, nil
}

// 🔹 GET USER BY EMAIL

func (r *MySQLRepository) GetByEmail(ctx context.Context, email string) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	query := `
		SELECT id, email, password, full_name, referrer_id, created_at, role
		FROM users WHERE email = ?
	`

	var user User
	var referrerID sql.NullString
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.FullName,
		&referrerID,
		&user.CreatedAt,
		&user.Role,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user không tồn tại: %s", email)
	}
	if err != nil {
		return nil, fmt.Errorf("lỗi truy vấn user: %v", err)
	}
	if referrerID.Valid {
		user.ReferrerID = &referrerID.String
	}

	return &user, nil
}

// 🔹 UPDATE USER

func (r *MySQLRepository) Update(ctx context.Context, u *User) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	query := `
		UPDATE users
		SET full_name = ?, role = ?
		WHERE id = ?
	`
	result, err := r.db.ExecContext(ctx, query, u.Email, u.FullName, u.ID)
	if err != nil {
		return fmt.Errorf("lỗi cập nhật user: %v", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("lỗi kiểm tra kết quả update: %v", err)
	}
	if rows == 0 {
		return fmt.Errorf("user không tồn tại: %s", u.ID)
	}

	log.Printf("✅ Đã cập nhật user: %s", u.ID)
	return nil
}

// 🔹 DELETE USER

func (r *MySQLRepository) Delete(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	query := `DELETE FROM users WHERE id = ?`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("lỗi xóa user: %v", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("lỗi kiểm tra kết quả delete: %v", err)
	}
	if rows == 0 {
		return fmt.Errorf("user không tồn tại: %s", id)
	}

	log.Printf("✅ Đã xóa user: %s", id)
	return nil
}

// 🔹 LIST USERS (phân trang)

func (r *MySQLRepository) List(ctx context.Context, page, pageSize int32) ([]*User, int32, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	// Đếm tổng số users
	var total int32
	countQuery := `SELECT COUNT(*) FROM users`
	err := r.db.QueryRowContext(ctx, countQuery).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("lỗi đếm users: %v", err)
	}

	// Lấy danh sách user
	query := `
		SELECT id, email, password, full_name, referrer_id, created_at, role
		FROM users
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`
	rows, err := r.db.QueryContext(ctx, query, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("lỗi truy vấn danh sách users: %v", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var user User
		var referrerID sql.NullString
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Password,
			&user.FullName,
			&referrerID,
			&user.CreatedAt,
			&user.Role,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("lỗi scan user: %v", err)
		}
		if referrerID.Valid {
			user.ReferrerID = &referrerID.String
		}
		users = append(users, &user)
	}

	return users, total, nil
}

// 🔹 GET REFERRALS

func (r *MySQLRepository) GetReferrals(ctx context.Context, userID string) ([]*User, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	query := `
		SELECT id, email, password, full_name, referrer_id, created_at, role
		FROM users
		WHERE referrer_id = ?
		ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("lỗi truy vấn referrals: %v", err)
	}
	defer rows.Close()

	var referrals []*User
	for rows.Next() {
		var user User
		var referrerID sql.NullString
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Password,
			&user.FullName,
			&referrerID,
			&user.CreatedAt,
			&user.Role,
		)
		if err != nil {
			return nil, fmt.Errorf("lỗi scan referral: %v", err)
		}
		if referrerID.Valid {
			user.ReferrerID = &referrerID.String
		}
		referrals = append(referrals, &user)
	}

	return referrals, nil
}

// DeleteInactive xóa các user được tạo trước một mốc thời gian
func (r *MySQLRepository) DeleteInactive(ctx context.Context, threshold time.Time) (int64, error) {
	query := `DELETE FROM users WHERE created_at < ? AND last_login_at IS NULL`
	result, err := r.db.ExecContext(ctx, query, threshold)
	if err != nil {
		return 0, fmt.Errorf("lỗi khi xóa user không hoạt động: %v", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("lỗi khi lấy số dòng bị ảnh hưởng: %v", err)
	}
	return rowsAffected, nil
}

// Hàm Ping cho Health Check
func (r *MySQLRepository) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second) // Ping nên có timeout ngắn
	defer cancel()
	return r.db.PingContext(ctx)
}

// Hàm cập nhật thời gian login
func (r *MySQLRepository) UpdateLastLogin(ctx context.Context, userID string) error {
	query := `UPDATE users SET last_login_at = ? WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("lỗi cập nhật last_login_at: %v", err)
	}
	return nil
}

// Hàm đếm user active
func (r *MySQLRepository) GetActiveUsersCount(ctx context.Context, since time.Time) (int64, error) {
	var count int64
	query := `SELECT COUNT(DISTINCT id) FROM users WHERE last_login_at >= ?`
	err := r.db.QueryRowContext(ctx, query, since).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("lỗi đếm active users: %v", err)
	}
	return count, nil
}
