package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config chứa toàn bộ cấu hình ứng dụng.
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	AppEnv   string
}

type ServerConfig struct {
	GRPCPort  string
	HTTPPort  string
	PProfPort string
}

type DatabaseConfig struct {
	MySQLDSN   string // Sẽ được xây dựng động
	RedisAddr  string
	RedisPass  string
	RedisDB    int
	ScyllaAddr string
	ScyllaKeyspace string
}

type JWTConfig struct {
	Secret string
	Expiry time.Duration
}

// LoadConfig tải cấu hình từ file .env và biến môi trường.
func LoadConfig() (*Config, error) {
	// Chỉ load .env nếu không phải đang chạy trong môi trường Docker
	if os.Getenv("APP_ENV") != "docker" {
		if err := godotenv.Load(); err != nil {
			log.Println("⚠️  Không tìm thấy file .env, sẽ dùng giá trị môi trường.")
		}
	}

	jwtExpiry, err := time.ParseDuration(getEnv("JWT_EXPIRY", "24h"))
	if err != nil {
		log.Printf("⚠️  Giá trị JWT_EXPIRY không hợp lệ, dùng mặc định 24h. Lỗi: %v", err)
		jwtExpiry = 24 * time.Hour
	}

	// 🔹 SỬA: Xây dựng chuỗi DSN từ các biến môi trường riêng lẻ
	// Đây là bước quan trọng nhất để khắc phục lỗi Scan
	mysqlDSN := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		getEnv("MYSQL_USER", "root"),
		getEnv("MYSQL_PASSWORD", "root"),
		getEnv("MYSQL_HOST", "localhost"), // Default là localhost khi chạy local
		getEnv("MYSQL_PORT", "3306"),
		getEnv("MYSQL_DB", "userdb"),
	)

	redisAddr := fmt.Sprintf("%s:%s",
		getEnv("REDIS_HOST", "localhost"),
		getEnv("REDIS_PORT", "6379"),
	)

	cfg := &Config{
		Server: ServerConfig{
			GRPCPort:  getEnv("GRPC_PORT", "50051"),
			HTTPPort:  getEnv("HTTP_PORT", "8080"),
			PProfPort: getEnv("PPROF_PORT", "6060"),
		},
		Database: DatabaseConfig{
			MySQLDSN:   mysqlDSN, // Gán DSN đã được xây dựng đúng
			RedisAddr:  redisAddr,
			RedisPass:  getEnv("REDIS_PASSWORD", ""),
			RedisDB:    getEnvAsInt("REDIS_DB", 0),
			ScyllaAddr: getEnv("SCYLLA_HOSTS", "localhost:9042"),
		ScyllaKeyspace: getEnv("SCYLLA_KEYSPACE", "user_keyspace"),
		},
		JWT: JWTConfig{
			Secret: getEnv("JWT_SECRET", "supersecretkey123"),
			Expiry: jwtExpiry,
		},
		AppEnv: strings.ToLower(getEnv("APP_ENV", "dev")),
	}

	return cfg, nil
}

// getEnv helper function
func getEnv(key, defaultVal string) string {
	if val, exists := os.LookupEnv(key); exists && val != "" {
		return val
	}
	return defaultVal
}

// getEnvAsInt helper function
func getEnvAsInt(key string, defaultVal int) int {
	valStr := getEnv(key, "")
	if val, err := strconv.Atoi(valStr); err == nil {
		return val
	}
	return defaultVal
}
