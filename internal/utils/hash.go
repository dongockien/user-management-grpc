package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword - Mã hóa mật khẩu bằng bcrypt.
// Trả về chuỗi đã hash (bcrypt) hoặc lỗi nếu có vấn đề.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password thất bại: %w", err)
	}
	return string(bytes), nil
}

// VerifyPassword - Kiểm tra mật khẩu người dùng với hash lưu trữ.
func VerifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// GenerateRandomString - Sinh chuỗi ngẫu nhiên an toàn (dùng crypto/rand).
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("không thể tạo chuỗi ngẫu nhiên: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateAPIKey - Sinh API key 64 ký tự ngẫu nhiên.
func GenerateAPIKey() (string, error) {
	return GenerateRandomString(32)
}

// CurrentTimestamp - Trả về timestamp ISO 8601 (RFC3339).
func CurrentTimestamp() string {
	return time.Now().Format(time.RFC3339)
}
