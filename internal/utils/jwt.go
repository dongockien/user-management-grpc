package utils

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("token không hợp lệ")
	ErrExpiredToken = errors.New("token đã hết hạn")
)

// Claims - Dữ liệu bên trong JWT.
// (Struct này đã đúng, vì nó embed jwt.RegisteredClaims, vốn đã có trường `ID` cho JTI)
type Claims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

// GenerateJWT - Tạo JWT Token mới.
func GenerateJWT(userID, secret string, expiry time.Duration, jti string) (string, error) {
	now := time.Now()
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "user-management-service",
			ID: jti,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("lỗi khi ký JWT: %w", err)
	}
	return signed, nil
}

// VerifyJWT - Xác thực token và trả về Claims nếu hợp lệ.
func VerifyJWT(tokenString, secret string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return []byte(secret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, jwt.ErrTokenExpired
		}
		return nil, fmt.Errorf("xác thực token thất bại: %w", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, ErrInvalidToken
}

// ExtractUserID - Trích xuất userID từ token (nếu hợp lệ)
func ExtractUserID(tokenStr, secret string) (string, error) {
	claims, err := VerifyJWT(tokenStr, secret)
	if err != nil {
		return "", err
	}
	return claims.UserID, nil
}
