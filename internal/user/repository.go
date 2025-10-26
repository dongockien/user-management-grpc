package user

import (
	"context"
	"time"
)

type Repository interface {
	Create(ctx context.Context, u *User) error
	GetByID(ctx context.Context, id string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	Update(ctx context.Context, u *User) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, page, pageSize int32) ([]*User, int32, error)
	GetReferrals(ctx context.Context, userID string) ([]*User, error)
	DeleteInactive(ctx context.Context, threshold time.Time) (int64, error)

	// Cần thiết cho Health Check của Scheduler
	Ping(ctx context.Context) error

	// Cần thiết cho Job "backupUserStats" và "cleanupInactiveUsers"
	UpdateLastLogin(ctx context.Context, userID string) error
	GetActiveUsersCount(ctx context.Context, since time.Time) (int64, error)
}
