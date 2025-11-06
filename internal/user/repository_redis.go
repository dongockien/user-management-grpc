// File: internal/user/repository_redis.go
package user

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"user-management-grpc/internal/utils" // Import utils để hash password

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// --- CÁC HẰNG SỐ KEY CỦA REDIS ---
// Dùng hằng số giúp quản lý key tập trung, tránh gõ sai
const (
	keyUserPrefix     = "user:profile:"       // (HASH) user:profile:{id} -> {user_data}
	keyIndexEmailToID = "users:by_email"      // (HASH) users:by_email -> {email} -> {id}
	keySetReferrals   = "user:referrals:"     // (SET)  user:referrals:{id} -> SET[{id_1}, {id_2}]
	keyZSetCreatedAt  = "users:by_created_at" // (ZSET) users:by_created_at -> {created_at_score} -> {user_key}
	keyZSetLastLogin  = "users:by_last_login" // (ZSET) users:by_last_login -> {last_login_score} -> {user_key}
)

// Cấu trúc Repository
type RedisRepository struct {
	client *redis.Client
}

// Hàm khởi tạo
// Chú ý: Hàm này trả về interface 'Repository', không phải *RedisRepository
func NewRedisRepository(client *redis.Client) Repository {
	return &RedisRepository{client: client}
}

// --- HÀM HELPER: Lấy Key chuẩn ---
func userKey(id string) string {
	return keyUserPrefix + id
}

// === TRIỂN KHAI INTERFACE REPOSITORY ===

// 🔹 1. CREATE USER
// Phân tích: Đây là hàm phức tạp nhất.
// 1. Phải hash password.
// 2. Phải kiểm tra email tồn tại (dùng index 'users:by_email')
// 3. Phải ghi 4 CSDL cùng lúc:
//   - HASH (Hồ sơ user)
//   - HASH (Index Email -> ID)
//   - ZSET (Index CreatedAt)
//   - ZSET (Index LastLogin, mặc định là 0)
//   - SET (Nếu có người giới thiệu)
//
// 4. Dùng Pipeline (đường ống) để gom tất cả lệnh ghi lại, tăng tốc độ.
func (r *RedisRepository) Create(ctx context.Context, u *User) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second) // Redis nhanh, nhưng 5s cho an toàn
	defer cancel()

	// Tạo ID và thời gian
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now()
	}

	// === BƯỚC 1: KIỂM TRA EMAIL TỒN TẠI (ATOMIC) ===
	// Dùng HSetNX (Hash Set If Not Exists)
	// Lệnh này sẽ set email->id CHỈ KHI email đó chưa tồn tại.
	emailClaimed, err := r.client.HSetNX(ctx, keyIndexEmailToID, u.Email, u.ID).Result()
	if err != nil {
		return fmt.Errorf("lỗi kiểm tra email HSetNX: %v", err)
	}
	if !emailClaimed {
		// HSetNX trả về false, nghĩa là email này đã tồn tại trong HASH
		return fmt.Errorf("email đã tồn tại: %s", u.Email)
	}

	// === BƯỚC 2: EMAIL LÀ CỦA CHÚNG TA -> TIẾN HÀNH TẠO USER ===
	// Hash password
	hashedPassword, err := utils.HashPassword(u.Password)
	if err != nil {
		// Lỗi: Phải xóa "claim" email đã
		r.client.HDel(ctx, keyIndexEmailToID, u.Email) // Cố gắng dọn dẹp
		return fmt.Errorf("lỗi mã hóa mật khẩu: %v", err)
	}
	u.Password = hashedPassword // Cập nhật password đã hash vào struct

	// Chuẩn bị key chính
	key := userKey(u.ID)
	createdAtScore := float64(u.CreatedAt.Unix())

	// Chuyển struct User sang map để lưu HASH
	userData, err := u.marshalRedisHash() // Dùng hàm helper (ở cuối file)
	if err != nil {
		r.client.HDel(ctx, keyIndexEmailToID, u.Email) // Cố gắng dọn dẹp
		return fmt.Errorf("lỗi marshal user: %v", err)
	}

	// === BƯỚC 3: DÙNG PIPELINE ĐỂ GHI TẤT CẢ DỮ LIỆU ===
	pipe := r.client.Pipeline()

	// 1. (HASH) Ghi hồ sơ user
	pipe.HSet(ctx, key, userData)

	// 2. (ZSET) Ghi vào bảng xếp hạng "User mới nhất"
	pipe.ZAdd(ctx, keyZSetCreatedAt, redis.Z{
		Score:  createdAtScore,
		Member: key, // Member là "user:profile:uuid-123"
	})

	// 3. (ZSET) Ghi vào bảng xếp hạng "Last Login" (mặc định là 0)
	// Điều này RẤT QUAN TRỌNG cho job 'DeleteInactive'
	pipe.ZAdd(ctx, keyZSetLastLogin, redis.Z{
		Score:  0, // 0 = chưa bao giờ login
		Member: key,
	})

	// 4. (SET) Cập nhật danh sách người giới thiệu (nếu có)
	if u.ReferrerID != nil && *u.ReferrerID != "" {
		referralKey := keySetReferrals + *u.ReferrerID
		pipe.SAdd(ctx, referralKey, u.ID) // Thêm ID của user này vào SET của người giới thiệu
	}

	// Thực thi tất cả lệnh
	// Nếu 1 trong các lệnh này lỗi, user sẽ ở trạng thái "nửa vời"
	// (Đây là điểm yếu của NoSQL so với ACID của MySQL)
	_, err = pipe.Exec(ctx)
	if err != nil {
		// Cố gắng dọn dẹp (Rollback)
		r.client.HDel(ctx, keyIndexEmailToID, u.Email)
		r.client.Del(ctx, key)
		r.client.ZRem(ctx, keyZSetCreatedAt, key)
		r.client.ZRem(ctx, keyZSetLastLogin, key)
		// (Việc dọn dẹp SET Referrer rất phức tạp, tạm bỏ qua)
		return fmt.Errorf("lỗi khi ghi pipeline tạo user: %v", err)
	}

	log.Printf("✅ [Redis] Đã tạo user: %s", u.Email)
	return nil
}

// 🔹 2. GET USER BY ID
// Phân tích: Rất đơn giản, chỉ cần HGETALL từ key
func (r *RedisRepository) GetByID(ctx context.Context, id string) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	key := userKey(id)
	// HGetAll trả về map[string]string
	userDataMap, err := r.client.HGetAll(ctx, key).Result()

	if err != nil {
		// Lỗi kết nối
		return nil, fmt.Errorf("lỗi redis HGetAll: %v", err)
	}
	if len(userDataMap) == 0 {
		// Key không tồn tại, hoặc HASH rỗng
		return nil, fmt.Errorf("user không tồn tại: %s", id)
	}

	// Chuyển map[string]string sang struct User
	return unmarshalRedisHash(userDataMap) // Dùng hàm helper (ở cuối file)
}

// 🔹 3. GET USER BY EMAIL
// Phân tích: Dùng "chỉ mục" (index) HASH 'users:by_email'
func (r *RedisRepository) GetByEmail(ctx context.Context, email string) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Bước A: Lấy ID từ "chỉ mục" email
	userID, err := r.client.HGet(ctx, keyIndexEmailToID, email).Result()
	if err == redis.Nil {
		// Không có field 'email' này trong HASH
		return nil, fmt.Errorf("email không tồn tại: %s", email)
	}
	if err != nil {
		return nil, fmt.Errorf("lỗi redis HGet email index: %v", err)
	}

	// Bước B: Dùng ID lấy được để gọi hàm GetByID (Tái sử dụng code)
	return r.GetByID(ctx, userID)
}

// 🔹 4. UPDATE USER
// Phân tích: Giống MySQL, chỉ cập nhật email và full_name
// VẤN ĐỀ: Nếu đổi email thì sao? Phải cập nhật "chỉ mục" email!
func (r *RedisRepository) Update(ctx context.Context, u *User) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	key := userKey(u.ID)

	// Bước 1: Lấy user CŨ để biết email CŨ là gì
	oldUser, err := r.GetByID(ctx, u.ID)
	if err != nil {
		return err // User không tồn tại
	}

	// === Dùng Pipeline để cập nhật ===
	pipe := r.client.Pipeline()

	// Bước 2: Cập nhật HASH chính
	pipe.HSet(ctx, key, "full_name", u.FullName)

	// Bước 3: Xử lý logic đổi email (nếu có)
	if oldUser.Email != u.Email {
		// Email đã thay đổi
		// 1. Xóa "chỉ mục" email CŨ
		pipe.HDel(ctx, keyIndexEmailToID, oldUser.Email)
		// 2. Thêm "chỉ mục" email MỚI
		// (Bỏ qua kiểm tra HSetNX ở đây cho đơn giản, giả định Service đã check)
		pipe.HSet(ctx, keyIndexEmailToID, u.Email, u.ID)
		// 3. Cập nhật email MỚI vào HASH
		pipe.HSet(ctx, key, "email", u.Email)
	}

	// Bước 4: Thực thi
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("lỗi pipeline cập nhật user: %v", err)
	}

	log.Printf("✅ [Redis] Đã cập nhật user: %s", u.ID)
	return nil
}

// 🔹 5. DELETE USER
// Phân tích: Phải "dọn dẹp" ở TẤT CẢ các nơi user này xuất hiện
// 1. Xóa HASH (Hồ sơ)
// 2. Xóa HASH (Index Email)
// 3. Xóa ZSET (Index CreatedAt)
// 4. Xóa ZSET (Index LastLogin)
// 5. Xóa SET (Nếu user này là 1 referral)
func (r *RedisRepository) Delete(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	key := userKey(id)

	// Bước 1: Lấy user CŨ (để biết email, referrerID)
	user, err := r.GetByID(ctx, id)
	if err != nil {
		return err // User không tồn tại
	}

	// === Dùng Pipeline để xóa ===
	pipe := r.client.Pipeline()

	// 1. Xóa HASH (Hồ sơ chính)
	pipe.Del(ctx, key)
	// 2. Xóa "chỉ mục" email
	pipe.HDel(ctx, keyIndexEmailToID, user.Email)
	// 3. Xóa khỏi ZSET "User mới nhất"
	pipe.ZRem(ctx, keyZSetCreatedAt, key)
	// 4. Xóa khỏi ZSET "Last Login"
	pipe.ZRem(ctx, keyZSetLastLogin, key)
	// 5. Xóa khỏi SET "Referrals" (nếu có)
	if user.ReferrerID != nil && *user.ReferrerID != "" {
		referralKey := keySetReferrals + *user.ReferrerID
		pipe.SRem(ctx, referralKey, user.ID)
	}

	// Bước 2: Thực thi
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("lỗi pipeline xóa user: %v", err)
	}

	log.Printf("✅ [Redis] Đã xóa user: %s", id)
	return nil
}

// 🔹 6. LIST USERS (phân trang)
// Phân tích: Dùng ZSET 'users:by_created_at'
func (r *RedisRepository) List(ctx context.Context, page, pageSize int32) ([]*User, int32, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	// ZSET index là 0-based
	start := int64(page-1) * int64(pageSize)
	stop := start + int64(pageSize) - 1

	// === Dùng Pipeline để lấy TỔNG SỐ và DANH SÁCH ===
	pipe := r.client.Pipeline()

	// 1. Lấy tổng số (ZCard = ZSET Count)
	totalCmd := pipe.ZCard(ctx, keyZSetCreatedAt)

	// 2. Lấy danh sách ID (ZRevRange = ZSET Reverse Range, vì điểm cao = mới nhất)
	userKeysCmd := pipe.ZRevRange(ctx, keyZSetCreatedAt, start, stop)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("lỗi pipeline List: %v", err)
	}

	total := totalCmd.Val()
	userKeys := userKeysCmd.Val()

	if len(userKeys) == 0 {
		return []*User{}, int32(total), nil
	}

	// === Bước B: LẤY CHI TIẾT TỪNG USER (Dùng Pipeline) ===
	pipeGetUsers := r.client.Pipeline()
	cmds := make([]*redis.MapStringStringCmd, len(userKeys))
	for i, key := range userKeys {
		cmds[i] = pipeGetUsers.HGetAll(ctx, key)
	}
	_, err = pipeGetUsers.Exec(ctx)
	if err != nil && err != redis.Nil {
		return nil, 0, fmt.Errorf("lỗi pipeline HGetAll list: %v", err)
	}

	// 3. Đọc kết quả
	var users []*User
	for _, cmd := range cmds {
		userData, err := cmd.Result()
		if err == nil && len(userData) > 0 {
			user, err := unmarshalRedisHash(userData)
			if err == nil {
				users = append(users, user)
			}
		}
	}

	return users, int32(total), nil
}

// 🔹 7. GET REFERRALS
// Phân tích: Dùng SET 'user:referrals:{id}'
func (r *RedisRepository) GetReferrals(ctx context.Context, userID string) ([]*User, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	referralKey := keySetReferrals + userID

	// Bước A: Lấy danh sách ID từ SET
	referralIDs, err := r.client.SMembers(ctx, referralKey).Result()
	if err != nil {
		return nil, fmt.Errorf("lỗi SMembers: %v", err)
	}

	if len(referralIDs) == 0 {
		return []*User{}, nil
	}

	// Bước B: Lấy chi tiết từng user (Dùng Pipeline)
	pipe := r.client.Pipeline()
	cmds := make([]*redis.MapStringStringCmd, len(referralIDs))
	for i, id := range referralIDs {
		cmds[i] = pipe.HGetAll(ctx, userKey(id))
	}
	_, err = pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("lỗi pipeline HGetAll referrals: %v", err)
	}

	// 3. Đọc kết quả
	var users []*User
	for _, cmd := range cmds {
		userData, err := cmd.Result()
		if err == nil && len(userData) > 0 {
			user, err := unmarshalRedisHash(userData)
			if err == nil {
				users = append(users, user)
			}
		}
	}

	return users, nil
}

// 🔹 8. DELETE INACTIVE
// Phân tích: Xóa user (created_at < threshold) VÀ (last_login_at IS NULL)
// Dùng ZSET 'users:by_last_login'
func (r *RedisRepository) DeleteInactive(ctx context.Context, threshold time.Time) (int64, error) {
	// Lấy tất cả user CÓ ĐIỂM = 0 (tức là chưa bao giờ login)
	keysOfNeverLoggedIn, err := r.client.ZRangeByScore(ctx, keyZSetLastLogin, &redis.ZRangeBy{
		Min: "0",
		Max: "0",
	}).Result()
	if err != nil {
		return 0, fmt.Errorf("lỗi ZRangeByScore: %v", err)
	}

	if len(keysOfNeverLoggedIn) == 0 {
		return 0, nil
	}

	// === Bước B: Kiểm tra CreatedAt của các user này ===
	// Chúng ta cần 'user:profile:id' (là member)
	// chứ không phải 'id'

	thresholdUnix := threshold.Unix()
	keysToActuallyDelete := []string{} // Danh sách các userKey (user:profile:id)

	// Dùng Pipeline để check HGET 1 loạt
	pipe := r.client.Pipeline()
	cmds := make([]*redis.StringCmd, len(keysOfNeverLoggedIn))
	for i, key := range keysOfNeverLoggedIn {
		cmds[i] = pipe.HGet(ctx, key, "created_at")
	}
	_, err = pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return 0, fmt.Errorf("lỗi pipeline HGet created_at: %v", err)
	}

	// Lọc ra những user thỏa mãn cả 2 điều kiện
	for i, cmd := range cmds {
		createdAtStr, err := cmd.Result()
		if err == nil {
			createdAt, _ := strconv.ParseInt(createdAtStr, 10, 64)
			if createdAt < thresholdUnix {
				// ĐÚNG LÀ USER CẦN XÓA!
				keysToActuallyDelete = append(keysToActuallyDelete, keysOfNeverLoggedIn[i])
			}
		}
	}

	if len(keysToActuallyDelete) == 0 {
		return 0, nil
	}

	// === Bước C: Xóa tất cả (Dùng hàm Delete() đã viết) ===
	// Chạy tuần tự để đảm bảo logic dọn dẹp phức tạp được chạy đúng
	var deletedCount int64
	for _, key := range keysToActuallyDelete {
		// 'key' ở đây là 'user:profile:id'. Cần trích xuất 'id'
		id := key[len(keyUserPrefix):]
		if err := r.Delete(ctx, id); err == nil {
			deletedCount++
		} else {
			log.Printf("⚠️ [Redis] Lỗi khi xóa inactive user %s: %v", id, err)
		}
	}

	log.Printf("✅ [Redis] Đã xóa %d inactive users", deletedCount)
	return deletedCount, nil
}

// 🔹 9. PING
func (r *RedisRepository) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return r.client.Ping(ctx).Err()
}

// 🔹 10. UPDATE LAST LOGIN
// Phân tích: Cập nhật cả HASH và ZSET 'users:by_last_login'
func (r *RedisRepository) UpdateLastLogin(ctx context.Context, userID string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	key := userKey(userID)
	now := time.Now()
	loginScore := float64(now.Unix())

	pipe := r.client.Pipeline()

	// 1. (HASH) Cập nhật hồ sơ
	pipe.HSet(ctx, key, "last_login_at", loginScore)

	// 2. (ZSET) Cập nhật bảng xếp hạng "Last Login"
	pipe.ZAdd(ctx, keyZSetLastLogin, redis.Z{
		Score:  loginScore,
		Member: key,
	})

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("lỗi pipeline cập nhật last_login: %v", err)
	}
	return nil
}

// 🔹 11. GET ACTIVE USERS COUNT
// Phân tích: Dùng ZSET 'users:by_last_login'
func (r *RedisRepository) GetActiveUsersCount(ctx context.Context, since time.Time) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	minScore := strconv.FormatInt(since.Unix(), 10)

	// ZCount đếm số member có score trong khoảng [min, max]
	count, err := r.client.ZCount(ctx, keyZSetLastLogin, minScore, "+inf").Result()
	if err != nil {
		return 0, fmt.Errorf("lỗi ZCount: %v", err)
	}
	return count, nil
}
