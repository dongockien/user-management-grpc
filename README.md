# User Management gRPC Service

## Giới thiệu 🚀

Project này là một microservice quản lý người dùng được xây dựng bằng Go, sử dụng gRPC làm giao thức giao tiếp chính và cung cấp cả HTTP API công khai thông qua Gin framework (hoặc bạn có thể dùng gRPC-Gateway). Dịch vụ bao gồm các chức năng đăng ký, đăng nhập, quản lý thông tin người dùng cơ bản, xác thực bằng JWT (với cơ chế blacklist), và sử dụng đa dạng cơ sở dữ liệu (MySQL, ScyllaDB, Redis). Ngoài ra, project còn có tính năng lập lịch (Scheduler) cho các tác vụ nền và tích hợp các công cụ profiling (PProf) và benchmark.

## Công nghệ sử dụng 🛠️

- **Ngôn ngữ:** Go (Golang)
- **API:** gRPC + HTTP (Gin)
- **Database:**
  - MySQL: Lưu trữ thông tin người dùng (users).
  - ScyllaDB: Lưu trữ logs hoạt động và thông báo (activity logs, notification logs).
  - Redis: Lưu trữ danh sách đen token JWT đã bị thu hồi (JWT blacklist).
- **Xác thực:** JWT (với JTI và blacklist) + Password Hashing (bcrypt).
- **Lập lịch:** Thư viện `robfig/cron/v3`.
- **Profiling & Benchmark:** `net/http/pprof`, `go test -bench`.
- **Containerization:** Docker, Docker Compose.

## Các chức năng đã hoàn thành ✅

Dưới đây là các chức năng chính đã được triển khai, đối chiếu với 11 yêu cầu ban đầu:

1.  **Microservice gRPC + HTTP API:**
    - Đã định nghĩa các service (`AuthService`, `UserService`, `NotificationService`) bằng Protobuf (`api/proto/user.proto`).
    - Khởi chạy gRPC server (`cmd/server/main.go`).
    - Khởi chạy HTTP server (Gin) với các handler gọi trực tiếp vào các service (`cmd/server/main.go`, `internal/user/handler.go` - kiến trúc Monolith). _(Yêu cầu 1)_
2.  **Login & Xác thực JWT:**
    - API `POST /api/v1/auth/login` thực hiện xác thực email/password (dùng bcrypt) và trả về token JWT.
    - JWT chứa UserID và JTI (JWT ID).
    - Sử dụng cơ chế **Blacklist** trên Redis (ZSET `revoked_tokens`) để vô hiệu hóa token khi logout.
    - Middleware (`httpAuthMiddleware`, `authInterceptor`) kiểm tra tính hợp lệ của token (chữ ký, thời hạn, blacklist) cho các API private. _(Yêu cầu 2)_
3.  **Sử dụng Đa dạng DB:**
    - **MySQL:** Lưu thông tin user (bảng `users`) qua `internal/user/repository_mysql.go`.
    - **ScyllaDB:** Ghi log hoạt động (`user_activity`) và log thông báo (`notification_logs`) qua `internal/database/scylla.go` (đã dùng `gocql`).
    - **Redis:** Lưu JTI của token đã logout vào ZSET `revoked_tokens` qua `internal/database/redis.go` (dùng `go-redis`). _(Yêu cầu 3)_
4.  **Scheduler:**
    - Sử dụng `robfig/cron/v3` để chạy các job nền (`internal/scheduler/jobs.go`).
    - Các job đã có logic thật:
      - `cleanupExpiredTokens`: Dọn dẹp JTI hết hạn khỏi blacklist Redis.
      - `backupUserStats`: Thống kê (referral, recent, active) và ghi log vào ScyllaDB.
      - `cleanupInactiveUsers`: Xóa user cũ và chưa login khỏi MySQL.
      - `healthCheck`: Kiểm tra kết nối MySQL, Redis, ScyllaDB và ghi log vào ScyllaDB.
      - `logSystemStats`: Ghi thông số hệ thống (goroutine, memory) vào log và ScyllaDB. _(Yêu cầu 4)_
5.  **CRUD User:**
    - API `POST /users` (Create), `GET /users/:id` (Get), `PUT /users/:id` (Update), `DELETE /users/:id` (Delete), `GET /users` (List) đã được triển khai và hoạt động. _(Yêu cầu 5)_
6.  **Liên kết User:**
    - Bảng `users` có cột `referrer_id` (cho phép NULL).
    - API CreateUser nhận `referrer_id` tùy chọn.
    - API GetUserReferrals (gRPC, có thể thêm HTTP) để lấy danh sách user được giới thiệu. _(Yêu cầu 6)_
7.  **Goroutine & Kiểm soát Bất đồng bộ:**
    - Scheduler `backupUserStats` dùng `sync.WaitGroup` và `sync.Mutex` để tính toán song song.
    - Scheduler `healthCheck` dùng `sync.WaitGroup` và `sync.Mutex` để kiểm tra song song.
    - `UserService` (khi tạo user) gọi `NotificationService` bất đồng bộ (`go s.sendWelcomeEmail(user)`).
    - `NotificationService` dùng `channel` (`emailQueue`) và `sync.WaitGroup` để xử lý gửi email bất đồng bộ qua worker.
    - Sử dụng `context.WithTimeout` cho các truy vấn DB và gọi gRPC/HTTP để tránh treo. _(Yêu cầu 7)_
8.  **Kỹ thuật Go:**
    - **map:** Dùng trong cache (`UserCache`), scheduler (`jobs`, `stats`), interceptor (`publicMethods`, `adminMethods`).
    - **lock:** `sync.Mutex` và `sync.RWMutex` được dùng để bảo vệ map (`stats`, `UserCache`) và các cấu trúc dữ liệu chia sẻ khác.
    - **defer:** Sử dụng rộng rãi để đảm bảo `cancel()` context, `Unlock()` mutex, `Done()` WaitGroup, `Close()` database rows, và gọi `recover()`.
    - **recovery:** Hàm tiện ích `utils.Recovery()` (chứa `recover()`) được `defer` ở đầu các handler và goroutine để bắt panic và ghi log, ngăn server crash. _(Yêu cầu 8)_
9.  **Tracing Tool PProf:**
    - Đã tích hợp `internal/tracing/pprof.go` để khởi chạy server PProf riêng biệt (ví dụ: port 6060).
    - Cung cấp endpoint chuẩn `/debug/pprof/` và các endpoint tùy chỉnh. _(Yêu cầu 9)_
10. **Benchmark:**
    - File `benchmarks/benchmark_test.go` chứa các benchmark cho `Login` và `ValidateToken`.
    - Đã chạy và có kết quả baseline (`go test -bench=. -benchmem ./benchmarks`). _(Yêu cầu 10)_
11. **Tối ưu Performance:**
    - Đã thu thập dữ liệu benchmark baseline và pprof (CPU, Heap).
    - **Đang ở giai đoạn chuẩn bị tối ưu.** _(Yêu cầu 11)_

## Hướng dẫn Kiểm thử (Testing) 🧪

_(Phần này tóm tắt lại các bước bạn đã làm)_

### A. Chuẩn bị

1.  **Chạy Docker:** Đảm bảo các container `user-mysql`, `user-redis`, `user-scylla` đang chạy (`docker-compose up -d`). Chờ chúng chuyển sang trạng thái `(healthy)`.
2.  **Chạy Ứng dụng:** Mở terminal, `cd` vào thư mục project, chạy `go run ./cmd/server/main.go`. Quan sát log khởi động.
3.  **Công cụ:** Mở Postman (với Collection và Environment đã tạo), DBeaver (kết nối MySQL `userdb` tại `localhost:3307`), và một terminal khác cho các lệnh `docker exec`.

### B. Test API bằng Postman

_(Thực hiện các request trong Collection "User Management GRPC")_

1.  **Đăng ký:** `POST /api/v1/users` (User A, User B, Admin). Kiểm tra DB và Log.
2.  **Login:** `POST /api/v1/auth/login` (User A, Admin). Kiểm tra `authToken` được lưu, DB `last_login_at`. Test cả trường hợp sai pass, sai email.
3.  **Xác thực Token:**
    - `GET /api/v1/users/me` (dùng token hợp lệ -> 200 OK).
    - `GET /api/v1/users/me` (không token -> 401).
    - `GET /api/v1/users/me` (token sai -> 401).
4.  **Logout:** `POST /api/v1/auth/logout` (dùng token hợp lệ -> 200 OK). Kiểm tra Redis blacklist (`docker exec -it user-redis redis-cli ZRANGE revoked_tokens 0 -1`).
5.  **Validate Token đã Logout:** `GET /api/v1/users/me` (dùng token đã logout -> 401).
6.  **Get User by ID:**
    - Admin lấy thông tin User A (`GET /users/<id_A>`, dùng token Admin -> 200 OK).
    - User B lấy thông tin User A (`GET /users/<id_A>`, dùng token B -> 403).
7.  **Update User:** `PUT /users/<id_A>` (User A tự cập nhật -> 200 OK). Kiểm tra DB.
8.  **List Users:**
    - User A gọi (`GET /users` -> 403).
    - Admin gọi (`GET /users` -> 200 OK).
9.  **Delete User:**
    - User A xóa User B (`DELETE /users/<id_B>` -> 403).
    - Admin xóa User B (`DELETE /users/<id_B>` -> 200 OK). Kiểm tra DB.
10. **Bulk Create Users:** `POST /admin/users/bulk` (Admin, dùng danh sách user, có cả email trùng -> 207). Kiểm tra DB và Log.
11. **Refresh Token:** `POST /auth/refresh` (dùng token hợp lệ).

### C. Test Scheduler Jobs (Terminal & Log)

_(Có thể tạm sửa lịch cron thành `@every 1m` trong `scheduler/jobs.go` để test nhanh)_

1.  **Quan sát Log:** Theo dõi log ứng dụng Go (`go run ...`) để xem các job có bắt đầu và kết thúc không.
2.  **`cleanupExpiredTokens`:** Login -> Logout -> Chờ job -> Kiểm tra Redis (`docker exec ... ZRANGE revoked_tokens ...`).
3.  **`backupUserStats`:** Chờ job -> Kiểm tra Log Go -> Kiểm tra Scylla (`docker exec ... cqlsh -e "SELECT ... WHERE action = 'backup_completed' ... ALLOW FILTERING;"`).
4.  **`cleanupInactiveUsers`:** DBeaver tạo user cũ -> Chờ job -> Kiểm tra DBeaver (user biến mất) -> Kiểm tra Scylla (`... action = 'cleanup_inactive_users_success' ... ALLOW FILTERING;`).
5.  **`healthCheck`:** Quan sát log -> `docker stop user-redis` -> Log (UNHEALTHY) -> Kiểm tra Scylla (`... action = 'health_check_degraded' ... ALLOW FILTERING;`) -> `docker start user-redis` -> Log (HEALTHY) -> Kiểm tra Scylla (`... action = 'health_check_healthy' ... ALLOW FILTERING;`).
6.  **`logSystemStats`:** Chờ job -> Kiểm tra Log Go -> Kiểm tra Scylla (`... user_id = 'system' AND action = 'system_stats_logged' ... ALLOW FILTERING;`).
7.  **Hoàn tác lịch cron** về giá trị gốc và khởi động lại Go app.

### D. Test PProf

- Truy cập `http://localhost:6060/debug/pprof/` trên trình duyệt. Kiểm tra trang hiển thị.

### E. Chạy Benchmark

- Dừng ứng dụng Go.
- Chạy: `go test -bench=. -benchmem ./benchmarks`. Lưu kết quả.

BỔ SUNG 
# Redis ZSET Performance Benchmarks (Go)

Bộ công cụ benchmark (kiểm thử hiệu năng) này được viết bằng Go để đo lường và phân tích hiệu suất của các thao tác trên **Redis Sorted Set (ZSET)** dưới nhiều loại tải (workload) khác nhau.

Mục tiêu là để mô phỏng các kịch bản thực tế (đọc nhiều, ghi nhiều, tải hỗn hợp) và cung cấp các số liệu chi tiết về độ trễ (latency) và thông lượng (throughput).

## 🚀 Tính năng

* **Đa dạng kịch bản:** Bao gồm các bài test cho:
    * **Read-heavy (Đọc nhiều):** Đo độ trễ của lệnh `ZSCORE`.
    * **Write-heavy (Ghi nhiều):** So sánh hiệu năng `ZADD` khi dùng và không dùng Pipelining.
    * **Update (Cập nhật):** Đo độ trễ của lệnh `ZINCRBY` (cập nhật điểm số lặp lại).
    * **Top-K Queries:** Đo độ trễ của `ZREVRANGE` (lấy top-K phần tử) trên tập dữ liệu lớn.
    * **Mixed Concurrent (Tải hỗn hợp):** Mô phỏng nhiều client cùng lúc thực hiện 90% đọc và 10% ghi.
* **Cấu hình linh hoạt:** Dễ dàng tùy chỉnh mọi tham số (số lượng members, số truy vấn, Redis address...) thông qua biến môi trường (Environment Variables).
* **Số liệu chi tiết:** Ghi lại các số liệu quan trọng bao gồm độ trễ trung bình (mean) và các phân vị (percentiles) `p50`, `p95`, `p99`, `p999`.
* **Ghi log tự động:** Tự động lưu kết quả ra file `bench_results.csv` và `bench_results.json` để phân tích sau.
* **Giám sát Server:** Chụp lại thông tin `INFO memory` và `INFO stats` của Redis server tại thời điểm chạy test để đối chiếu.

## ⚙️ Cấu hình

Trước khi chạy, bạn cần thiết lập các biến môi trường để trỏ đến Redis server và tùy chỉnh các tham số benchmark.

### Biến môi trường chính

* `REDIS_ADDR`: Địa chỉ và port của Redis server (ví dụ: `127.0.0.1:6379`).
* `REDIS_PASSWORD`: Mật khẩu Redis (nếu có).
* `REDIS_DB`: Chỉ số DB Redis (ví dụ: `0`).

### Biến môi trường cho Test

* `ZSET_MEMBERS`: Số lượng phần tử khởi tạo cho ZSET (mặc định: 5000).
* `ZSCORE_QUERIES`: Số lượng truy vấn `ZSCORE` trong bài test đọc (mặc định: 1000).
* `TOPK_MEMBERS`: Số lượng phần tử cho bài test Top-K (mặc định: 1,000,000).
* `MIXED_CONC`: Số lượng client chạy đồng thời trong bài test hỗn hợp (mặc định: 50).
* `RUN_HEAVY`: Đặt là `1` để cho phép chạy các bài test nặng (như `TOPK_MEMBERS` > 500k).
    * Ví dụ: `export RUN_HEAVY=1`

## 🏁 Cách chạy Tests

Bạn có thể chạy tất cả các bài test hoặc chạy từng kịch bản riêng lẻ bằng cách sử dụng cờ `-run` của Go.

```bash
# Cấu hình địa chỉ Redis (ví dụ)
export REDIS_ADDR=127.0.0.1:6379

# Chạy một kịch bản cụ thể (ví dụ: ReadHeavy)
go test ./benchmarks -run Test_Run_ReadHeavy -v

# Chạy kịch bản Top-K (nặng), cần đặt cờ RUN_HEAVY
export RUN_HEAVY=1
export TOPK_MEMBERS=1000000
go test ./benchmarks -run Test_Run_TopK -v

# Chạy kịch bản tải hỗn hợp (concurrent)
export MIXED_SEED=100000
export MIXED_CONC=50
go test ./benchmarks -run Test_Run_Mixed_Concurrent -v

# Chạy tất cả các bài test
go test ./benchmarks -v
```
*(Lưu ý: Thay thế `./benchmarks` bằng đường dẫn thực tế đến thư mục chứa code test của bạn nếu cần)*

## 📊 Hiểu kết quả

### 1. Console Output

Trong quá trình chạy, bạn sẽ thấy các bảng tóm tắt in ra console:

```
================================================================================
🏷️  Kịch bản: READ_ZSCORE   |  members=5000, queries=1000, conc=1 (Đọc nhiều, đo percentiles)
⏱️  Trạng thái: [BẮT ĐẦU]
--------------------------------------------------------------------------------
...[SETUP] Bơm 5000 members (took 25.101ms)
Scenario               members      conc       mean(ms)   p50(ms)    p95(ms)    p99(ms)
--------------------------------------------------------------------------------
READ_ZSCORE            5000         1          0.045      0.044      0.052      0.000
(Giải thích) mean = độ trễ trung bình; p95/p99 = tail latency
Server: used_memory=1.13M | instantaneous_ops_per_sec=423 | snapshot=info_READ_ZSCORE_...
--------------------------------------------------------------------------------
✅ KẾT THÚC: READ_ZSCORE
================================================================================
```

* **mean(ms), p50(ms), p95(ms):** Là các số liệu độ trễ (tính bằng mili giây) của các thao tác. `p95=0.052` có nghĩa là 95% các truy vấn hoàn thành dưới 0.052ms.

### 2. File kết quả

Kết quả chi tiết được tự động ghi vào các file sau:

* `bench_results.csv`: Dữ liệu thô ở định dạng CSV, dễ dàng nhập vào Excel hoặc Google Sheets để vẽ biểu đồ.
* `bench_results.json`: Dữ liệu ở định dạng JSON, mỗi dòng là một bản ghi kết quả.
* `info_*.txt`: Các file snapshot chứa kết quả `INFO memory` và `INFO stats` của Redis server tại thời điểm test, giúp bạn đối chiếu tình trạng server (ví dụ: bộ nhớ sử dụng, số ops/sec) với kết quả benchmark.
