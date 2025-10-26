package user

import (
	"time"
	"user-management-grpc/internal/utils"
)

type User struct {
	ID          string     `db:"id" json:"id"`
	Email       string     `db:"email" json:"email"`
	FullName    string     `db:"full_name" json:"full_name"`
	Password    string     `db:"password" json:"-"`
	ReferrerID  *string    `db:"referrer_id" json:"referrer_id,omitempty"`
	CreatedAt   time.Time  `db:"created_at" json:"created_at"`
	LastLoginAt *time.Time `db:"last_login_at"`
}

// VerifyPassword kiểm tra mật khẩu — gọi helper chung trong utils
func (u *User) VerifyPassword(password string) error {
	return utils.VerifyPassword(u.Password, password)
}
