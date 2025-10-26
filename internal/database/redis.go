package database

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

// 🔹 1. Hàm tạo client Redis thật

func NewRedis(addr, password string, db int) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("không thể kết nối Redis: %v", err)
	}

	log.Println("✅ Đã kết nối Redis thành công")
	return client, nil
}

// 🧩 2. Adapter: giúp Redis thật tương thích với interface RedisClient trong auth/service.go

type RedisAdapter struct {
	Client *redis.Client
}

// NewRedisAdapter chuyển *redis.Client → RedisAdapter
func NewRedisAdapter(client *redis.Client) *RedisAdapter {
	return &RedisAdapter{Client: client}
}

// Ping - Triển khai interface cho health check
func (r *RedisAdapter) Ping(ctx context.Context) error {
	return r.Client.Ping(ctx).Err() // ⬅️ SỬA: 'client' -> 'Client'
}

// Set giá trị có thời hạn
func (r *RedisAdapter) Set(ctx context.Context, key, value string, expiration time.Duration) error {
	return r.Client.Set(ctx, key, value, expiration).Err()
}

// Get giá trị theo key
func (r *RedisAdapter) Get(ctx context.Context, key string) (string, error) {
	return r.Client.Get(ctx, key).Result()
}

// Delete xóa key khỏi Redis
func (r *RedisAdapter) Delete(ctx context.Context, key string) error {
	return r.Client.Del(ctx, key).Err()
}

// Close đóng kết nối Redis (để tương thích với RedisClient interface)
func (r *RedisAdapter) Close() error {
	if r.Client != nil {
		return r.Client.Close()
	}
	return nil
}

// ⬅️ THÊM: Triển khai các hàm ZSET cho logic Blacklist
func (r *RedisAdapter) ZAdd(ctx context.Context, key string, score float64, member string) error {
	// go-redis v9 dùng struct redis.Z
	return r.Client.ZAdd(ctx, key, redis.Z{Score: score, Member: member}).Err()
}

func (r *RedisAdapter) ZRemRangeByScore(ctx context.Context, key, min, max string) (int64, error) {
	return r.Client.ZRemRangeByScore(ctx, key, min, max).Result()
}

func (r *RedisAdapter) ZScore(ctx context.Context, key, member string) (float64, error) {
	return r.Client.ZScore(ctx, key, member).Result()
}


// 🩺 3. Health check & đóng kết nối

func CheckRedisHealth(client *redis.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return client.Ping(ctx).Err()
}

func CloseRedis(client *redis.Client) {
	if client != nil {
		_ = client.Close()
		log.Println("🔌 Đã đóng kết nối Redis")
	}
}