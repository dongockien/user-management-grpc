package database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func NewMySQL(dsn string) (*sql.DB, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("Không thể kết nối MYSQL: %v", err)
	}

	// ⚙️ Cấu hình connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(2 * time.Minute)

	// 🧠 Kiểm tra kết nối
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("Không thể ping MySQL: %v", err)
	}
	log.Println("✅ Đã kết nối MySQL thành công")
	return db, nil
}

// 🧱 Tạo bảng nếu chưa có
func CreateUserTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id VARCHAR(36) PRIMARY KEY,
		email VARCHAR(255) UNIQUE NOT NULL,
		password VARCHAR(255) NOT NULL,
		full_name VARCHAR(255) NOT NULL,
		referrer_id VARCHAR(36),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		INDEX idx_email (email),
		INDEX idx_referrer (referrer_id),
		INDEX idx_created_at (created_at)
	)`
	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("không thể tạo bảng users: %v", err)
	}
	log.Println("✅ Đã tạo/kiểm tra bảng users")
	return nil
}

// 🩺 Health check
func CheckMySQLHealth(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return db.PingContext(ctx)
}

// 🧹 Đóng kết nối
func CloseMySQL(db *sql.DB) {
	if db != nil {
		_ = db.Close()
		log.Println("🔌 Đã đóng kết nối MySQL")
	}
}
