// File: internal/user/repository_redis_helpers.go
package user

import (
	"fmt"
	"strconv"
	"time"
)

// marshalRedisHash chuyển Struct *User sang map[string]interface{} để HSet
// (Không export hàm này, chỉ dùng nội bộ)
func (u *User) marshalRedisHash() (map[string]interface{}, error) {
	// (Giả định struct User của bạn có các trường này)
	// Cần thêm 1 file user.go nữa
	
	data := map[string]interface{}{
		"id":         u.ID,
		"email":      u.Email,
		"password":   u.Password,
		"full_name":  u.FullName,
		"created_at": u.CreatedAt.Unix(),
		"role": u.Role,
		
	}

	// Xử lý các trường có thể là nil (pointers)
	if u.ReferrerID != nil {
		data["referrer_id"] = *u.ReferrerID
	}
	
	// Lấy giá trị từ Time (nếu có)
	if u.LastLoginAt != nil {
		data["last_login_at"] = u.LastLoginAt.Unix()
	}

	return data, nil
}

// unmarshalRedisHash chuyển map[string]string (từ HGetAll) sang *User
func unmarshalRedisHash(data map[string]string) (*User, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data map rỗng")
	}

	u := &User{}
	u.ID = data["id"]
	u.Email = data["email"]
	u.Password = data["password"]
	u.FullName = data["full_name"]
	u.Role = data["role"]

	// Chuyển string timestamp (Unix) về time.Time
	if createdAtStr, ok := data["created_at"]; ok {
		createdAt, _ := strconv.ParseInt(createdAtStr, 10, 64)
		u.CreatedAt = time.Unix(createdAt, 0)
	}

	// Xử lý trường nil (pointers)
	if referrerID, ok := data["referrer_id"]; ok {
		u.ReferrerID = &referrerID
	}
	
	if lastLoginStr, ok := data["last_login_at"]; ok {
		lastLogin, _ := strconv.ParseInt(lastLoginStr, 10, 64)
		// Chỉ gán nếu lastLogin > 0 (vì 0 là giá trị "chưa login")
		if lastLogin > 0 {
			t := time.Unix(lastLogin, 0)
			u.LastLoginAt = &t
		}
	}

	return u, nil
}