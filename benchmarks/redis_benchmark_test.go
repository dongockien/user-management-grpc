// // File: internal/benchmarks/redis_benchmark_test.go
// package benchmarks

// import (
// 	"context"
// 	"fmt"
// 	"math/rand" // ⬅️ THÊM IMPORT
// 	"strconv"
// 	"testing" // ⬅️ Dùng 'testing' cho cả 'b' (Benchmark) và 't' (Test)
// 	"time"

// 	"github.com/redis/go-redis/v9"
// )

// var (
// 	redisClient *redis.Client
// 	ctx         = context.Background()
// 	// (Chúng ta dùng hàm rand mới của Go 1.20+)
// 	r = rand.New(rand.NewSource(time.Now().UnixNano()))
// )

// // Khởi tạo kết nối 1 lần duy nhất
// func init() {
// 	redisClient = redis.NewClient(&redis.Options{
// 		Addr:     "localhost:6379", // Đây chính là Redis local của bạn
// 		Password: "",
// 		DB:       0,
// 	})

// 	_, err := redisClient.Ping(ctx).Result()
// 	if err != nil {
// 		panic(fmt.Sprintf("Không thể kết nối Redis: %v", err))
// 	}

// 	// Xóa sạch DB trước khi test
// 	redisClient.FlushDB(ctx).Err()
// 	fmt.Println("Khởi tạo kết nối Redis và FlushDB thành công.")
// }

// // === PHẦN 1: MICRO-BENCHMARKS (Đo ns/op và allocs) ===
// // (6 hàm này giữ nguyên 100% như cũ)

// // --- BÀI TEST 1A: CHƯA TỐI ƯU (HSET) ---
// func BenchmarkWriteUserProfile_HSET_NonOptimized(b *testing.B) {
// 	b.ReportAllocs()
// 	for i := 0; i < b.N; i++ {
// 		userIDKey := "user:profile:" + strconv.Itoa(i)
// 		userData := map[string]interface{}{
// 			"username":   "user_" + strconv.Itoa(i),
// 			"email":      "user" + strconv.Itoa(i) + "@example.com",
// 			"last_login": time.Now().Unix(),
// 			"credits":    100,
// 		}
// 		err := redisClient.HSet(ctx, userIDKey, userData).Err()
// 		if err != nil {
// 			b.Fatalf("Lỗi HSET: %v", err)
// 		}
// 	}
// }

// // --- BÀI TEST 1B: ĐÃ TỐI ƯU (HSET) ---
// func BenchmarkWriteUserProfile_HSET_Optimized(b *testing.B) {
// 	b.ReportAllocs()
// 	staticUserData := map[string]interface{}{
// 		"username":   "benchmark_user",
// 		"email":      "benchmark@example.com",
// 		"last_login": 1234567890,
// 		"credits":    100,
// 	}
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		userIDKey := "user:profile:" + strconv.Itoa(i)
// 		err := redisClient.HSet(ctx, userIDKey, staticUserData).Err()
// 		if err != nil {
// 			b.Fatalf("Lỗi HSET: %v", err)
// 		}
// 	}
// }

// // --- BÀI TEST 2: ĐỌC HỒ SƠ (HGETALL) ---
// func BenchmarkReadUserProfile_HGETALL(b *testing.B) {
// 	sampleUserID := "user:profile:read_test"
// 	redisClient.HSet(ctx, sampleUserID, "name", "Test User", "email", "test@user.com")
// 	b.ReportAllocs()
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		_, err := redisClient.HGetAll(ctx, sampleUserID).Result()
// 		if err != nil {
// 			b.Fatalf("Lỗi HGETALL: %v", err)
// 		}
// 	}
// }

// // --- BÀI TEST 3A: CHƯA TỐI ƯU (ZADD) ---
// func BenchmarkUpdateUserScore_ZADD_NonOptimized(b *testing.B) {
// 	b.ReportAllocs()
// 	for i := 0; i < b.N; i++ {
// 		userID := "user:profile:" + strconv.Itoa(i)
// 		score := float64(time.Now().Unix())
// 		err := redisClient.ZAdd(ctx, "leaderboard:activity", redis.Z{
// 			Score:  score,
// 			Member: userID,
// 		}).Err()
// 		if err != nil {
// 			b.Fatalf("Lỗi ZADD: %v", err)
// 		}
// 	}
// }

// // --- BÀI TEST 3B: ĐÃ TỐI ƯU (ZADD) ---
// func BenchmarkUpdateUserScore_ZADD_Optimized(b *testing.B) {
// 	b.ReportAllocs()
// 	staticScore := float64(time.Now().Unix())
// 	staticZ := redis.Z{Score: staticScore}
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		userID := "user:profile:" + strconv.Itoa(i)
// 		staticZ.Member = userID
// 		err := redisClient.ZAdd(ctx, "leaderboard:activity", staticZ).Err()
// 		if err != nil {
// 			b.Fatalf("Lỗi ZADD: %v", err)
// 		}
// 	}
// }

// // --- BÀI TEST 4: ĐỌC TOP 10 (ZREVRANGE) ---
// func BenchmarkGetTop10Users_ZREVRANGE(b *testing.B) {
// 	if redisClient.ZCard(ctx, "leaderboard:activity").Val() < 1000 {
// 		for i := 0; i < 1000; i++ {
// 			redisClient.ZAdd(ctx, "leaderboard:activity", redis.Z{
// 				Score:  float64(i),
// 				Member: "user:profile:" + strconv.Itoa(i),
// 			})
// 		}
// 	}
// 	b.ReportAllocs()
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		_, err := redisClient.ZRevRange(ctx, "leaderboard:activity", 0, 9).Result()
// 		if err != nil {
// 			b.Fatalf("Lỗi ZREVRANGE: %v", err)
// 		}
// 	}
// }

// // === PHẦN 2: MACRO-BENCHMARKS (Đo Tổng Thời gian Kịch bản) ===
// // (Đây là code mới bạn yêu cầu)

// // timeTaskHelper là hàm helper mới, dùng 't.Logf' để in log
// func timeTaskHelper(t *testing.T, taskName string, taskFunc func()) {
// 	t.Logf("--- [BẮT ĐẦU] Kịch bản: %s ---", taskName)
// 	start := time.Now()

// 	taskFunc() // Chạy công việc

// 	elapsed := time.Since(start)
// 	t.Logf("--- [KẾT THÚC] Kịch bản: %s ---", taskName)

// 	// IN KẾT QUẢ RA TERMINAL (Điều mentor muốn)
// 	t.Logf("===> 🚀 TỔNG THỜI GIAN: %v\n", elapsed)
// }

// // Kịch bản 1: "sửa một cái key mất bao nhiêu thời gian" (HSET)
// func TestScenario_Update1Key(t *testing.T) {
// 	timeTaskHelper(t, "Sửa 1 Key (1 lệnh HSET)", func() {
// 		err := redisClient.HSet(ctx, "user:profile:single_key", "fullName", "Kien Updated").Err()
// 		if err != nil {
// 			t.Fatalf("Lỗi HSET: %v", err)
// 		}
// 	})
// }

// // Kịch bản 2: "10000 cái key mất bao nhiêu thời gian" (Pipeline HSET)
// func TestScenario_Update10kKeys(t *testing.T) {
// 	taskName := "Sửa/Tạo 10,000 Keys (dùng 1 Pipeline HSET)"
// 	timeTaskHelper(t, taskName, func() {
// 		pipe := redisClient.Pipeline()
// 		for i := 0; i < 10000; i++ {
// 			key := "user:profile:" + strconv.Itoa(i)
// 			pipe.HSet(ctx, key, "fullName", "Kien Batch Update")
// 		}

// 		_, err := pipe.Exec(ctx)
// 		if err != nil {
// 			t.Fatalf("Lỗi Pipeline HSET: %v", err)
// 		}
// 	})
// }

// // Kịch bản 3: "Zscore chưa 5000 key value"
// func TestScenario_ZScoreFrom5k(t *testing.T) {
// 	taskName := "Đọc 1 ZScore (từ 1 ZSET có 5000 members)"

// 	// --- Setup (Chuẩn bị) ---
// 	t.Log("...[Setup] Đang bơm 5000 members vào ZSET 'test:leaderboard'...")
// 	pipe := redisClient.Pipeline()
// 	for i := 0; i < 5000; i++ {
// 		pipe.ZAdd(ctx, "test:leaderboard", redis.Z{
// 			Score:  float64(i),
// 			Member: "user:" + strconv.Itoa(i),
// 		})
// 	}
// 	pipe.Exec(ctx)

// 	// --- Đo giờ (Chạy task) ---
// 	timeTaskHelper(t, taskName, func() {
// 		memberToFind := "user:" + strconv.Itoa(r.Intn(5000))
// 		score, err := redisClient.ZScore(ctx, "test:leaderboard", memberToFind).Result()
// 		if err != nil {
// 			t.Fatalf("Lỗi ZScore: %v", err)
// 		} else {
// 			t.Logf("...[Kết quả] Tìm thấy %s, score: %f", memberToFind, score)
// 		}
// 	})
// }

// // Kịch bản 4: "Lấy top 10 ra mất bao nhiêu thời gian" (ZREVRANGE)
// // (Chúng ta sẽ test với 1 triệu members, vì 10 triệu bơm quá lâu)
// func TestScenario_GetTop10From1M(t *testing.T) {
// 	taskName := "Lấy Top 10 (từ 1 ZSET có 1 Triệu members)"
// 	totalMembers := 1000000 // 1 Triệu

// 	// --- Setup (Chuẩn bị) ---
// 	t.Logf("...[Setup] Đang bơm %d members (1 Triệu) vào ZSET 'test:big_leaderboard'...", totalMembers)
// 	t.Log("...[Setup] (Việc này sẽ mất vài giây, vui lòng chờ...)")

// 	pipe := redisClient.Pipeline()
// 	for i := 0; i < totalMembers; i++ {
// 		pipe.ZAdd(ctx, "test:big_leaderboard", redis.Z{
// 			Score:  float64(i),
// 			Member: "user:" + strconv.Itoa(i),
// 		})
// 		if i%1000 == 0 { // Cứ 1000 lệnh thì Exec 1 lần
// 			pipe.Exec(ctx)
// 			pipe = redisClient.Pipeline()
// 		}
// 	}
// 	pipe.Exec(ctx) // Gửi nốt
// 	t.Log("...[Setup] Đã bơm 1 Triệu members.")

// 	// --- Đo giờ (Chạy task) ---
// 	timeTaskHelper(t, taskName, func() {
// 		members, err := redisClient.ZRevRangeWithScores(ctx, "test:big_leaderboard", 0, 9).Result()
// 		if err != nil {
// 			t.Fatalf("Lỗi ZRevRange: %v", err)
// 		} else {
// 			t.Logf("...[Kết quả] Lấy Top 10 thành công (User Top 1 là %s, điểm %f)", members[0].Member, members[0].Score)
// 		}
// 	})
// }

// FILE: benchmarks/redis_benchmark_test.go
// Mô tả: Bộ test benchmark cho Redis Sorted Set (ZSET)
// - Có thể cấu hình bằng biến môi trường
// - Kịch bản: warmup, read-single (ZSCORE trên N members), update 1 key, update 10k (so sánh non-pipeline/pipeline), TopK, mixed concurrent
// - Ghi kết quả ra bench_results.csv và bench_results.json (append)
// - Lưu snapshot Redis INFO vào file info_<scenario>_<timestamp>.txt
// - Logging terminal Tiếng Việt, dễ đọc, có giải thích ngắn trong ngoặc
// FILE: benchmarks/redis_benchmark_test.go
// Mô tả: Bộ test benchmark cho Redis Sorted Set (ZSET)
// (phiên bản đã sửa: fix unused var & closure capture)

package benchmarks

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

/*
HƯỚNG DẪN NGẮT GỌN:
- Tùy biến tham số bằng ENV (ví dụ):
  export ZSET_MEMBERS=5000
  export ZSCORE_QUERIES=1000
  export REDIS_ADDR=127.0.0.1:6379
  export RUN_HEAVY=1    # cần đặt để chạy test nặng (TOPK 1M)
- Chạy test (ví dụ):
  go test ./benchmarks -run Test_Run_ReadHeavy -v
*/

var (
	ctx    = context.Background()
	fileMu sync.Mutex // bảo vệ ghi file CSV/JSON
	// thống kê toàn cục (nếu cần)
	globalSuccess uint64
	globalFail    uint64
	// run id để trace
	runID = getEnvStr("BENCH_RUN_ID", time.Now().Format("20060102_150405"))
)

// -------------------- Cấu hình: đọc từ biến môi trường (có default) --------------------
func getEnvInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return i
}

func getEnvStr(name string, def string) string {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	return v
}

// Các biến cấu hình (ENV override)
var (
	ZSET_MEMBERS   = getEnvInt("ZSET_MEMBERS", 5000)
	ZSCORE_QUERIES = getEnvInt("ZSCORE_QUERIES", 1000)
	UPDATE1_ITERS  = getEnvInt("UPDATE1_ITERS", 1000)
	UPDATE10K_N    = getEnvInt("UPDATE10K_N", 10000)
	TOPK_MEMBERS   = getEnvInt("TOPK_MEMBERS", 1000000)
	TOPK_RUNS      = getEnvInt("TOPK_RUNS", 50)
	MIXED_SEED     = getEnvInt("MIXED_SEED", 100000)
	MIXED_CONC     = getEnvInt("MIXED_CONC", 50)
	MIXED_OPS      = getEnvInt("MIXED_OPS_PER", 1000)
	PIPE_BATCH1    = getEnvInt("PIPE_BATCH1", 1000)
	PIPE_BATCH2    = getEnvInt("PIPE_BATCH2", 10000)
	TOPK_K         = getEnvInt("TOPK_K", 10)
	// Redis client tuning
	REDIS_POOL     = getEnvInt("REDIS_POOL", 100)
	REDIS_MIN_IDLE = getEnvInt("REDIS_MIN_IDLE", 10)
)

func newClient() *redis.Client {
	// ưu tiên REDIS_ADDR nếu set
	if addr := getEnvStr("REDIS_ADDR", ""); addr != "" {
		return redis.NewClient(&redis.Options{
			Addr:         addr,
			Password:     getEnvStr("REDIS_PASSWORD", ""), // nếu có mật khẩu
			DB:           getEnvInt("REDIS_DB", 0),
			PoolSize:     REDIS_POOL,
			MinIdleConns: REDIS_MIN_IDLE,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		})
	}
	// nếu REDIS_ADDR không set, build từ host+port
	host := getEnvStr("REDIS_HOST", "127.0.0.1")
	port := getEnvStr("REDIS_PORT", "6379")
	addr := fmt.Sprintf("%s:%s", host, port)
	return redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     getEnvStr("REDIS_PASSWORD", ""),
		DB:           getEnvInt("REDIS_DB", 0),
		PoolSize:     REDIS_POOL,
		MinIdleConns: REDIS_MIN_IDLE,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	})
}

// -------------------- Helpers: INFO & file --------------------
func parseInfoSection(s string) map[string]string {
	m := map[string]string{}
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		parts := strings.SplitN(ln, ":", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return m
}

func collectAndSaveInfo(client *redis.Client, scenario string) (usedMemory string, instOps string, snapshotFile string) {
	mem, _ := client.Info(ctx, "memory").Result()
	stats, _ := client.Info(ctx, "stats").Result()
	mm := parseInfoSection(mem)
	sm := parseInfoSection(stats)
	usedMemory = mm["used_memory_human"]
	if usedMemory == "" {
		usedMemory = mm["used_memory"]
	}
	instOps = sm["instantaneous_ops_per_sec"]
	if instOps == "" {
		instOps = "-"
	}

	// Lưu snapshot INFO ra file để tra cứu sau
	ts := time.Now().Format("20060102_150405")
	fname := fmt.Sprintf("info_%s_%s_%s.txt", scenario, runID, ts)
	f, _ := os.Create(fname)
	defer f.Close()
	f.WriteString("# INFO memory\n")
	f.WriteString(mem + "\n")
	f.WriteString("# INFO stats\n")
	f.WriteString(stats + "\n")
	return usedMemory, instOps, fname
}

func ensureFileExists(path string) error {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		f.Close()
	}
	return nil
}

var csvHeader = []string{"run_id", "timestamp", "scenario", "param", "total_time_ms", "ops_per_sec", "mean_ms", "p50_ms", "p95_ms", "p99_ms", "p999_ms", "used_memory", "instant_ops_per_sec", "info_snapshot", "notes"}

func writeCSV(path string, rec []string) error {
	fileMu.Lock()
	defer fileMu.Unlock()
	if err := ensureFileExists(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	st, _ := f.Stat()
	if st.Size() == 0 {
		if err := w.Write(csvHeader); err != nil {
			return err
		}
	}
	return w.Write(rec)
}

func writeJSON(path string, obj interface{}) error {
	fileMu.Lock()
	defer fileMu.Unlock()
	if err := ensureFileExists(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	return enc.Encode(obj)
}

// -------------------- Metrics helpers --------------------
// func percentileFromSortedUs(slice []int64, p float64) float64 {
func percentileFromSortedInt64(slice []int64, p float64) float64 {
	if len(slice) == 0 {
		return 0
	}
	if p <= 0 {
		return float64(slice[0])
	}
	if p >= 100 {
		return float64(slice[len(slice)-1])
	}
	rank := p / 100.0 * float64(len(slice)-1)
	low := int(math.Floor(rank))
	high := int(math.Ceil(rank))
	if low == high {
		return float64(slice[low])
	}
	fraction := rank - float64(low)
	return float64(slice[low])*(1-fraction) + float64(slice[high])*fraction
}

func computePercentiles(latNs []int64) (meanMs, p50ms, p95ms, p99ms, p999ms float64) {
	if len(latNs) == 0 {
		return 0, 0, 0, 0, 0
	}
	sort.Slice(latNs, func(i, j int) bool { return latNs[i] < latNs[j] })
	var sum int64
	for _, v := range latNs {
		sum += v
	}
	meanNs := float64(sum) / float64(len(latNs))
	// percentileFromSortedUs (maybe)
	p50 := percentileFromSortedInt64(latNs, 50.0)
	p95 := percentileFromSortedInt64(latNs, 95.0)
	p99 := percentileFromSortedInt64(latNs, 99.0)
	p999 := percentileFromSortedInt64(latNs, 99.9)
	// return mean / 1000.0, p50 / 1000.0, p95 / 1000.0, p99 / 1000.0, p999 / 1000.0
	// convert ns -> ms
	return meanNs / 1e6, p50 / 1e6, p95 / 1e6, p99 / 1e6, p999 / 1e6
}

// debug helper: kiểm tra slice raw (units = nanoseconds)
func analyzeSamples(name string, samples []int64) {
	if samples == nil {
		fmt.Printf("DEBUG %s: samples = nil\n", name)
		return
	}
	n := len(samples)
	if n == 0 {
		fmt.Printf("DEBUG %s: samples empty\n", name)
		return
	}
	min := samples[0]
	max := samples[0]
	var zeros int
	var sum int64
	for _, v := range samples {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
		if v == 0 {
			zeros++
		}
		sum += v
	}
	meanNs := float64(sum) / float64(n)
	fmt.Printf("DEBUG %s: count=%d zeros=%d min=%d ns (%.3f µs, %.6f ms) max=%d ns (%.3f µs, %.6f ms) mean=%.3f µs (%.6f ms)\n",
		name, n, zeros, min, float64(min)/1e3, float64(min)/1e6, max, float64(max)/1e3, float64(max)/1e6, meanNs/1e3, meanNs/1e6)
}

// -------------------- Redis ops helpers --------------------
func bulkZAdd(ctx context.Context, client *redis.Client, key string, n int, batch int) (time.Duration, error) {
	if batch <= 0 {
		batch = 1000
	}
	if batch > 10000 {
		batch = 10000
	}
	start := time.Now()
	for i := 0; i < n; i += batch {
		end := i + batch
		if end > n {
			end = n
		}
		pipe := client.Pipeline()
		for j := i; j < end; j++ {
			pipe.ZAdd(ctx, key, redis.Z{Score: float64(j), Member: "user:" + strconv.Itoa(j)})
		}
		if _, err := pipe.Exec(ctx); err != nil {
			// Thêm: Kiểm tra xem lỗi có phải do context bị hủy (timeout/cancel) không
			if err == context.DeadlineExceeded || err == context.Canceled {
				return 0, fmt.Errorf("context cancelled during pipeline exec: %w", err)
			}
			return 0, err
		}
	}
	return time.Since(start), nil
}

func measureZScoreLatencies(client *redis.Client, key string, members int, queries int) ([]int64, error) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	lat := make([]int64, 0, queries)
	for i := 0; i < queries; i++ {
		idx := r.Intn(members)
		member := "user:" + strconv.Itoa(idx)
		t0 := time.Now()
		if _, err := client.ZScore(ctx, key, member).Result(); err != nil && err != redis.Nil {
			return nil, err
		}
		d := time.Since(t0).Nanoseconds()
		if d == 0 {
			d = 1 // tránh 0 ns gây méo percentiles
		}
		lat = append(lat, d)
	}
	return lat, nil
}

func measureTopKAvg(client *redis.Client, key string, k int, runs int) (time.Duration, []time.Duration, error) {
	var total time.Duration
	runsDur := make([]time.Duration, 0, runs)
	for i := 0; i < runs; i++ {
		t0 := time.Now()
		if _, err := client.ZRevRangeWithScores(ctx, key, 0, int64(k-1)).Result(); err != nil && err != redis.Nil {
			return 0, nil, err
		}
		d := time.Since(t0)
		runsDur = append(runsDur, d)
		total += d
	}
	return total / time.Duration(runs), runsDur, nil
}

// -------------------- Pretty logging (Tiếng Việt) --------------------
func bannerStart(title, details string) {
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("🏷️  Kịch bản: %s  |  %s\n", title, details)
	fmt.Println("⏱️  Trạng thái: [BẮT ĐẦU]")
	fmt.Println(strings.Repeat("-", 80))
}

func bannerEnd(title string) {
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("✅ KẾT THÚC: %s\n", title)
	fmt.Println(strings.Repeat("=", 80))
}

func tableHeader() {
	fmt.Printf("%-22s %-12s %-8s %-10s %-10s %-10s %-10s\n", "Scenario", "members", "conc", "mean(ms)", "p50(ms)", "p95(ms)", "p99(ms)")
	fmt.Println(strings.Repeat("-", 80))
}

func tableRow(scenario string, members int, conc int, mean, p50, p95, p99 float64) {
	fmt.Printf("%-22s %-12d %-8d %-12.6f %-12.6f %-12.6f %-12.6f\n", scenario, members, conc, mean, p50, p95, p99)
}

func printMsUsLabel(prefix string, meanMs, p50Ms, p95Ms, p99Ms float64) {
	// meanMs, p50Ms... được truyền vào ở đơn vị milliseconds (ms)
	// meanUs, p50Us... là microseconds (µs), giữ 3 chữ số thập phân cho µs
	meanUs := meanMs * 1000.0
	p50Us := p50Ms * 1000.0
	p95Us := p95Ms * 1000.0
	p99Us := p99Ms * 1000.0
	fmt.Printf("%s mean=%.6f ms (%.3f µs) | p50=%.6f ms (%.3f µs) | p95=%.6f ms (%.3f µs) | p99=%.6f ms (%.3f µs)\n",
		prefix, meanMs, meanUs, p50Ms, p50Us, p95Ms, p95Us, p99Ms, p99Us)
}

// -------------------- JSON record --------------------
type BenchRecord struct {
	RunID     string                 `json:"run_id"`
	Timestamp string                 `json:"timestamp"`
	Scenario  string                 `json:"scenario"`
	Params    map[string]interface{} `json:"params"`
	Results   map[string]float64     `json:"results"`
	Server    map[string]string      `json:"server"`
	InfoFile  string                 `json:"info_file"`
	Notes     string                 `json:"notes"`
}

// -------------------- Tests (dùng biến cấu hình) --------------------

// Warm-up: ops = 5000, read=90% write=10%
func Test_Run_Warmup(t *testing.T) {
	client := newClient()
	defer client.Close()
	client.FlushDB(ctx)
	bannerStart("WARMUP", fmt.Sprintf("ops=5000, read=90%% write=10%% (warm-up để ổn định cache)"))
	for i := 0; i < 5000; i++ {
		if i%10 == 0 {
			client.ZAdd(ctx, "bench:warmup", redis.Z{Score: float64(i), Member: fmt.Sprintf("user:%d", i)})
		} else {
			client.ZScore(ctx, "bench:warmup", fmt.Sprintf("user:%d", i))
		}
	}
	usedMem, ops, infoFile := collectAndSaveInfo(client, "WARMUP")
	fmt.Printf("Warmup hoàn tất. Server: used_memory=%s | instantaneous_ops_per_sec=%s | snapshot=%s\n", usedMem, ops, infoFile)
	bannerEnd("WARMUP")
}

// READ: ZSCORE trên ZSET có ZSET_MEMBERS, ZSCORE_QUERIES
func Test_Run_ReadHeavy(t *testing.T) {
	client := newClient()
	defer client.Close()
	client.FlushDB(ctx)
	key := "bench:zset_read"
	bannerStart("READ_ZSCORE", fmt.Sprintf("members=%d, queries=%d, conc=1 (Đọc nhiều, đo percentiles)", ZSET_MEMBERS, ZSCORE_QUERIES))
	// setup
	durSetup, err := bulkZAdd(ctx, client, key, ZSET_MEMBERS, 2000)
	if err != nil {
		t.Fatalf("Setup fail: %v", err)
	}
	fmt.Printf("...[SETUP] Bơm %d members (took %s)\n", ZSET_MEMBERS, durSetup)
	// warmup ngắn
	for i := 0; i < 2000; i++ {
		client.ZScore(ctx, key, fmt.Sprintf("user:%d", i%ZSET_MEMBERS))
	}

	lat, err := measureZScoreLatencies(client, key, ZSET_MEMBERS, ZSCORE_QUERIES)
	if err != nil {
		t.Fatalf("Measure fail: %v", err)
	}
	analyzeSamples("READ_ZSCORE_raw", lat)
	mean, p50, p95, p99, p999 := computePercentiles(lat)
	// in chi tiết bằng hàm helper (giữ định dạng tốt hơn)
	printMsUsLabel("READ_ZSCORE:", mean, p50, p95, p99)
	usedMem, instOps, infoFile := collectAndSaveInfo(client, "READ_ZSCORE")
	// CSV/JSON
	rec := []string{runID, time.Now().Format(time.RFC3339), "READ_ZSCORE", fmt.Sprintf("members=%d,queries=%d", ZSET_MEMBERS, ZSCORE_QUERIES), "", "", fmt.Sprintf("%.6f", mean), fmt.Sprintf("%.6f", p50), fmt.Sprintf("%.6f", p95), fmt.Sprintf("%.6f", p99), fmt.Sprintf("%.6f", p999), usedMem, instOps, infoFile, ""}
	writeCSV("bench_results.csv", rec)
	recJSON := BenchRecord{RunID: runID, Timestamp: time.Now().Format(time.RFC3339), Scenario: "READ_ZSCORE", Params: map[string]interface{}{"members": ZSET_MEMBERS, "queries": ZSCORE_QUERIES}, Results: map[string]float64{"mean_ms": mean, "p50_ms": p50, "p95_ms": p95, "p99_ms": p99, "p999_ms": p999}, Server: map[string]string{"used_memory": usedMem, "instant_ops": instOps}, InfoFile: infoFile, Notes: "warmup=2k"}
	writeJSON("bench_results.json", recJSON)
	// pretty
	tableHeader()
	tableRow("READ_ZSCORE", ZSET_MEMBERS, 1, mean, p50, p95, p99)
	fmt.Printf("(Giải thích) mean = độ trễ trung bình; p95/p99 = tail latency\n")
	fmt.Printf("Server: used_memory=%s | instantaneous_ops_per_sec=%s | snapshot=%s\n", usedMem, instOps, infoFile)
	bannerEnd("READ_ZSCORE")
}

// UPDATE 1 key (lặp UPDATE1_ITERS lần)
func Test_Update_1Key(t *testing.T) {
	client := newClient()
	defer client.Close()
	client.FlushDB(ctx)
	key := "bench:zset_update1"
	bulkZAdd(ctx, client, key, ZSET_MEMBERS, 2000)
	bannerStart("UPDATE_1KEY", fmt.Sprintf("member=user:123, updates=%d (Đo latency cho 1 thao tác ghi lặp)", UPDATE1_ITERS))
	lat := make([]int64, 0, UPDATE1_ITERS)
	for i := 0; i < UPDATE1_ITERS; i++ {
		t0 := time.Now()
		if _, err := client.ZIncrBy(ctx, key, 1.0, "user:123").Result(); err != nil {
			atomic.AddUint64(&globalFail, 1)
			t.Fatalf("ZIncrBy fail: %v", err)
		} else {
			atomic.AddUint64(&globalSuccess, 1)
		}
		d := time.Since(t0).Nanoseconds()
		if d == 0 {
			d = 1
		}
		lat = append(lat, d)

	}
	// debug / analyze (sau khi đã thu thập)
	analyzeSamples("UPDATE_1KEY_raw", lat)
	mean, p50, p95, p99, p999 := computePercentiles(lat)
	printMsUsLabel("UPDATE_1KEY:", mean, p50, p95, p99)
	usedMem, instOps, infoFile := collectAndSaveInfo(client, "UPDATE_1KEY")
	// CSV/JSON
	rec := []string{runID, time.Now().Format(time.RFC3339), "UPDATE_1KEY", fmt.Sprintf("member=user:123,n=%d", UPDATE1_ITERS), "", "", fmt.Sprintf("%.6f", mean), fmt.Sprintf("%.6f", p50), fmt.Sprintf("%.6f", p95), fmt.Sprintf("%.6f", p99), fmt.Sprintf("%.6f", p999), usedMem, instOps, infoFile, "ZINCRBY repeated"}
	writeCSV("bench_results.csv", rec)
	recJSON := BenchRecord{RunID: runID, Timestamp: time.Now().Format(time.RFC3339), Scenario: "UPDATE_1KEY", Params: map[string]interface{}{"member": "user:123", "n": UPDATE1_ITERS}, Results: map[string]float64{"mean_ms": mean, "p50_ms": p50, "p95_ms": p95, "p99_ms": p99, "p999_ms": p999}, Server: map[string]string{"used_memory": usedMem, "instant_ops": instOps}, InfoFile: infoFile, Notes: "ZINCRBY repeated"}
	writeJSON("bench_results.json", recJSON)
	// print
	tableHeader()
	tableRow("UPDATE_1KEY", ZSET_MEMBERS, 1, mean, p50, p95, p99)
	fmt.Printf("(Giải thích) ops thành công=%d | ops thất bại=%d\n", atomic.LoadUint64(&globalSuccess), atomic.LoadUint64(&globalFail))
	fmt.Printf("Server: used_memory=%s | instantaneous_ops_per_sec=%s | snapshot=%s\n", usedMem, instOps, infoFile)
	bannerEnd("UPDATE_1KEY")
}

// UPDATE 10k: so sánh non-pipeline vs pipeline
func Test_Run_WriteHeavy(t *testing.T) {
	client := newClient()
	defer client.Close()
	// timeout cho test nặng
	ctxT, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	client.FlushDB(ctx)
	bannerStart("UPDATE_10K", fmt.Sprintf("n=%d, compare non-pipe vs pipe (batch sizes)", UPDATE10K_N))
	n := UPDATE10K_N
	modes := []struct {
		name  string
		batch int
	}{{"non-pipeline", 1}, {"pipeline-1k", PIPE_BATCH1}, {"pipeline-10k", PIPE_BATCH2}}
	for _, m := range modes {
		dur, err := bulkZAdd(ctxT, client, "bench:update_10k_"+m.name, n, m.batch)
		if err != nil {
			t.Fatalf("bulkZAdd %s fail: %v", m.name, err)
		}
		// float64(dur.Microseconds())
		totalMs := dur.Seconds() * 1000.0
		totalSec := dur.Seconds()
		opsPerSec := float64(n) / totalSec
		usedMem, instOps, infoFile := collectAndSaveInfo(client, "UPDATE_10K_"+m.name)
		// CSV/JSON
		rec := []string{runID, time.Now().Format(time.RFC3339), "UPDATE_10K", fmt.Sprintf("mode=%s,n=%d,batch=%d", m.name, n, m.batch), fmt.Sprintf("%.6f", totalMs), fmt.Sprintf("%.3f", opsPerSec), "", "", "", "", usedMem, instOps, infoFile, "compare pipeline"}
		writeCSV("bench_results.csv", rec)
		recJSON := BenchRecord{RunID: runID, Timestamp: time.Now().Format(time.RFC3339), Scenario: "UPDATE_10K", Params: map[string]interface{}{"mode": m.name, "n": n, "batch": m.batch}, Results: map[string]float64{"total_ms": totalMs, "ops_per_sec": opsPerSec}, Server: map[string]string{"used_memory": usedMem, "instant_ops": instOps}, InfoFile: infoFile, Notes: "compare pipeline"}
		writeJSON("bench_results.json", recJSON)
		// print
		fmt.Printf("Mode=%s -> Tổng: %.3f ms | ops/sec=%.0f | used_mem=%s | instantaneous_ops=%s | snapshot=%s\n", m.name, totalMs, opsPerSec, usedMem, instOps, infoFile)
	}
	bannerEnd("UPDATE_10K")
}

// TOPK on TOPK_MEMBERS (có thể lớn: mặc định 1M)
func Test_Run_TopK(t *testing.T) {
	// guard heavy runs unless RUN_HEAVY=1
	if TOPK_MEMBERS > 500000 && getEnvStr("RUN_HEAVY", "0") != "1" {
		t.Skipf("TOPK_MEMBERS=%d lớn — để chạy hãy đặt RUN_HEAVY=1\n", TOPK_MEMBERS)
	}
	client := newClient()
	defer client.Close()
	client.FlushDB(ctx)
	key := "bench:zset_topk"
	bannerStart("TOPK", fmt.Sprintf("members=%d, topk=%d, runs=%d (Lấy top-k nhiều lần để lấy percentiles)", TOPK_MEMBERS, TOPK_K, TOPK_RUNS))
	// bulk insert
	start := time.Now()
	if _, err := bulkZAdd(ctx, client, key, TOPK_MEMBERS, 10000); err != nil {
		t.Fatalf("bulkZAdd fail: %v", err)
	}
	fmt.Printf("...[SETUP] Đã bơm %d members (took %s)\n", TOPK_MEMBERS, time.Since(start))

	avgDur, runsDur, err := measureTopKAvg(client, key, TOPK_K, TOPK_RUNS)
	if err != nil {
		t.Fatalf("measureTopKAvg fail: %v", err)
	}
	usedMem, instOps, infoFile := collectAndSaveInfo(client, "TOPK")
	// convert runsDur to slice for percentiles
	runsNs := make([]int64, 0, len(runsDur))
	for _, d := range runsDur {
		runsNs = append(runsNs, d.Nanoseconds())
	}
	analyzeSamples("TOPK_runs_raw", runsNs)
	meanMs, p50, p95, p99, p999 := computePercentiles(runsNs)
	printMsUsLabel("TOPK:", meanMs, p50, p95, p99)
	meanUs := meanMs * 1000
	fmt.Printf("mean=%.6f ms (%.0f µs)\n", meanMs, meanUs)
	// avgMs := float64(avgDur.Nanoseconds()) * 1000.0
	avgMs := avgDur.Seconds() * 1000.0
	// sample top1
	res, _ := client.ZRevRangeWithScores(ctx, key, 0, 0).Result()
	var top1 string
	var top1Score float64
	if len(res) > 0 {
		top1 = fmt.Sprintf("%v", res[0].Member)
		top1Score = res[0].Score
	}
	// CSV/JSON
	rec := []string{runID, time.Now().Format(time.RFC3339), "TOPK", fmt.Sprintf("members=%d,topk=%d,runs=%d", TOPK_MEMBERS, TOPK_K, TOPK_RUNS), fmt.Sprintf("%.6f", avgMs), "", fmt.Sprintf("%.6f", meanMs), fmt.Sprintf("%.6f", p50), fmt.Sprintf("%.6f", p95), fmt.Sprintf("%.6f", p99), fmt.Sprintf("%.6f", p999), usedMem, instOps, infoFile, fmt.Sprintf("top1=%s,score=%.0f", top1, top1Score)}
	writeCSV("bench_results.csv", rec)
	recJSON := BenchRecord{RunID: runID, Timestamp: time.Now().Format(time.RFC3339), Scenario: "TOPK", Params: map[string]interface{}{"members": TOPK_MEMBERS, "topk": TOPK_K, "runs": TOPK_RUNS}, Results: map[string]float64{"avg_ms": avgMs, "mean_ms": meanMs, "p50_ms": p50, "p95_ms": p95, "p99_ms": p99, "p999_ms": p999}, Server: map[string]string{"used_memory": usedMem, "instant_ops": instOps}, InfoFile: infoFile, Notes: fmt.Sprintf("top1=%s,score=%.0f", top1, top1Score)}
	writeJSON("bench_results.json", recJSON)
	// print
	tableHeader()
	tableRow("TOPK", TOPK_MEMBERS, 1, meanMs, p50, p95, p99)
	fmt.Printf("(Giải thích) avg_ms = trung bình của các lần gọi TopK; p95/p99 là tail latency\n")
	fmt.Printf("Top1 sample: %s (score=%.0f)\n", top1, top1Score)
	fmt.Printf("Server: used_memory=%s | instantaneous_ops_per_sec=%s | snapshot=%s\n", usedMem, instOps, infoFile)
	bannerEnd("TOPK")
}

// MIXED concurrent workload: seed MIXED_SEED, conc=MIXED_CONC, opsPerClient=MIXED_OPS
func Test_Run_Mixed_Concurrent(t *testing.T) {
	client := newClient()
	defer client.Close()
	client.FlushDB(ctx)
	key := "bench:mixed"
	// seed data
	if _, err := bulkZAdd(ctx, client, key, MIXED_SEED, 5000); err != nil {
		t.Fatalf("seed fail: %v", err)
	}
	bannerStart("MIXED", fmt.Sprintf("members=%d, conc=%d, opsPerClient=%d (read:write = 90:10)", MIXED_SEED, MIXED_CONC, MIXED_OPS))
	// per-goroutine local slices để tránh lock liên tục
	per := make([][]int64, MIXED_CONC)
	var wg sync.WaitGroup
	for c := 0; c < MIXED_CONC; c++ {
		wg.Add(1)
		// capture loop variable safely by copying vào local `cid`
		cid := c
		go func(cid int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(cid)))
			local := make([]int64, 0, MIXED_OPS)
			for i := 0; i < MIXED_OPS; i++ {
				if r.Intn(100) < 90 { // 90% đọc
					idx := r.Intn(MIXED_SEED)
					start := time.Now()
					client.ZScore(ctx, key, fmt.Sprintf("user:%d", idx))
					d := time.Since(start).Nanoseconds()
					if d == 0 {
						d = 1
					}
					local = append(local, d)
				} else { // 10% ghi
					start := time.Now()
					client.ZAdd(ctx, key, redis.Z{Score: float64(r.Intn(1000000)), Member: fmt.Sprintf("user:write:%d", r.Intn(1000000))})
					d := time.Since(start).Nanoseconds()
					if d == 0 {
						d = 1
					}
					local = append(local, d)
				}
			}
			per[cid] = local
		}(cid)
	}
	wg.Wait()
	// merge
	total := 0
	all := make([]int64, 0, MIXED_CONC*MIXED_OPS)
	for _, s := range per {
		total += len(s)
		all = append(all, s...)
	}
	analyzeSamples("MIXED_raw", all)
	mean, p50, p95, p99, p999 := computePercentiles(all)
	printMsUsLabel("MIXED:", mean, p50, p95, p99)
	usedMem, instOps, infoFile := collectAndSaveInfo(client, "MIXED")
	rec := []string{runID, time.Now().Format(time.RFC3339), "MIXED", fmt.Sprintf("members=%d,conc=%d,opsPerClient=%d", MIXED_SEED, MIXED_CONC, MIXED_OPS), "", "", fmt.Sprintf("%.6f", mean), fmt.Sprintf("%.6f", p50), fmt.Sprintf("%.6f", p95), fmt.Sprintf("%.6f", p99), fmt.Sprintf("%.6f", p999), usedMem, instOps, infoFile, "readRatio=90/10"}
	writeCSV("bench_results.csv", rec)
	recJSON := BenchRecord{RunID: runID, Timestamp: time.Now().Format(time.RFC3339), Scenario: "MIXED", Params: map[string]interface{}{"members": MIXED_SEED, "conc": MIXED_CONC, "opsPerClient": MIXED_OPS}, Results: map[string]float64{"mean_ms": mean, "p50_ms": p50, "p95_ms": p95, "p99_ms": p99, "p999_ms": p999}, Server: map[string]string{"used_memory": usedMem, "instant_ops": instOps}, InfoFile: infoFile, Notes: "readRatio=90/10"}
	writeJSON("bench_results.json", recJSON)
	// print
	tableHeader()
	tableRow("MIXED", MIXED_SEED, MIXED_CONC, mean, p50, p95, p99)
	fmt.Printf("(Giải thích) total samples=%d | mean/p50/p95/p99 (ms)\n", total)
	fmt.Printf("Server: used_memory=%s | instantaneous_ops_per_sec=%s | snapshot=%s\n", usedMem, instOps, infoFile)
	bannerEnd("MIXED")
}

// EOF

// TEST: READ CONCURRENT (đo throughput)
// Đo thông lượng 100% ZSCORE, sử dụng các biến MIXED_* để cấu hình
func Test_Run_Read_Concurrent(t *testing.T) {
	client := newClient()
	defer client.Close()
	client.FlushDB(ctx)
	key := "bench:read_conc"

	// Reset bộ đếm toàn cục
	atomic.StoreUint64(&globalSuccess, 0)
	atomic.StoreUint64(&globalFail, 0)

	// 1. SETUP: Dùng MIXED_SEED (mặc định 100k)
	if _, err := bulkZAdd(ctx, client, key, MIXED_SEED, 5000); err != nil {
		t.Fatalf("seed fail: %v", err)
	}

	bannerStart("READ_CONC", fmt.Sprintf("members=%d, conc=%d, opsPerClient=%d (Đo throughput 100%% ZSCORE)", MIXED_SEED, MIXED_CONC, MIXED_OPS))

	per := make([][]int64, MIXED_CONC) // Vẫn thu thập latency
	var wg sync.WaitGroup

	// TÍNH TOÁN CHO THROUGHPUT
	totalOps := uint64(MIXED_CONC * MIXED_OPS)

	// BẮT ĐẦU ĐO THỜI GIAN
	t0 := time.Now()

	for c := 0; c < MIXED_CONC; c++ {
		wg.Add(1)
		cid := c
		go func(cid int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(cid)))
			local := make([]int64, 0, MIXED_OPS)

			for i := 0; i < MIXED_OPS; i++ {
				idx := r.Intn(MIXED_SEED)
				member := "user:" + strconv.Itoa(idx)
				start := time.Now()
				if _, err := client.ZScore(ctx, key, member).Result(); err != nil && err != redis.Nil {
					atomic.AddUint64(&globalFail, 1)
				} else {
					atomic.AddUint64(&globalSuccess, 1)
				}
				d := time.Since(start).Nanoseconds()
				if d == 0 {
					d = 1
				}
				local = append(local, d)

			}
			per[cid] = local
		}(cid)
	}

	// CHỜ TẤT CẢ HOÀN THÀNH
	wg.Wait()

	// KẾT THÚC ĐO THỜI GIAN
	totalDur := time.Since(t0)
	totalDurSec := totalDur.Seconds()
	opsPerSec := float64(totalOps) / totalDurSec
	totalMs := totalDur.Seconds() * 1000.0

	// 2. TÍNH TOÁN LATENCY (như cũ)
	all := make([]int64, 0, totalOps)
	for _, s := range per {
		all = append(all, s...)
	}
	analyzeSamples("READ_CONC_raw", all)
	mean, p50, p95, p99, p999 := computePercentiles(all)
	printMsUsLabel("READ_CONC:", mean, p50, p95, p99)
	// 3. GHI LOG
	usedMem, instOps, infoFile := collectAndSaveInfo(client, "READ_CONC")

	// CSV/JSON
	rec := []string{
		runID, time.Now().Format(time.RFC3339), "READ_CONC",
		fmt.Sprintf("members=%d,conc=%d,opsPerClient=%d", MIXED_SEED, MIXED_CONC, MIXED_OPS),
		fmt.Sprintf("%.6f", totalMs), fmt.Sprintf("%.3f", opsPerSec), // Ghi lại total_ms và ops_per_sec
		fmt.Sprintf("%.6f", mean), fmt.Sprintf("%.6f", p50), fmt.Sprintf("%.6f", p95), fmt.Sprintf("%.6f", p99), fmt.Sprintf("%.6f", p999),
		usedMem, instOps, infoFile, "100% read",
	}
	writeCSV("bench_results.csv", rec)

	recJSON := BenchRecord{
		RunID:     runID,
		Timestamp: time.Now().Format(time.RFC3339),
		Scenario:  "READ_CONC",
		Params:    map[string]interface{}{"members": MIXED_SEED, "conc": MIXED_CONC, "opsPerClient": MIXED_OPS},
		// Ghi lại cả throughput và latency
		Results:  map[string]float64{"total_ms": totalMs, "ops_per_sec": opsPerSec, "mean_ms": mean, "p50_ms": p50, "p95_ms": p95, "p99_ms": p99, "p999_ms": p999},
		Server:   map[string]string{"used_memory": usedMem, "instant_ops": instOps},
		InfoFile: infoFile,
		Notes:    "100% read throughput",
	}
	writeJSON("bench_results.json", recJSON)

	// 4. IN KẾT QUẢ
	// In bảng latency (như cũ)
	tableHeader()
	tableRow("READ_CONC", MIXED_SEED, MIXED_CONC, mean, p50, p95, p99)
	fmt.Println(strings.Repeat("-", 80))

	// In kết quả Throughput
	fmt.Printf("📊 KẾT QUẢ THÔNG LƯỢNG (Throughput):\n")
	fmt.Printf("   Tổng thời gian: %.3f ms\n", totalMs)
	fmt.Printf("   Tổng ops: %d (thành công: %d, thất bại: %d)\n", totalOps, atomic.LoadUint64(&globalSuccess), atomic.LoadUint64(&globalFail))
	fmt.Printf("   Thông lượng: %.2f ops/sec\n", opsPerSec)

	fmt.Printf("Server: used_memory=%s | instantaneous_ops_per_sec=%s | snapshot=%s\n", usedMem, instOps, infoFile)
	bannerEnd("READ_CONC")
}
