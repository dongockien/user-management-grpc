package utils

import "sync"

// SafeMap - Map an toàn cho goroutine (thread-safe)
type SafeMap struct {
	mu sync.RWMutex
	m  map[string]interface{}
}

// NewSafeMap - Tạo SafeMap mới
func NewSafeMap() *SafeMap {
	return &SafeMap{
		m: make(map[string]interface{}),
	}
}

// Get - Lấy giá trị theo key
func (s *SafeMap) Get(key string) (interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, exists := s.m[key]
	return value, exists
}

// Set - Gán giá trị cho key
func (s *SafeMap) Set(key string, value interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = value
}

// Delete - Xóa key khỏi map
func (s *SafeMap) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
}

// Len - Đếm số phần tử
func (s *SafeMap) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

// Keys - Trả về danh sách key
func (s *SafeMap) Keys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]string, 0, len(s.m))
	for k := range s.m {
		keys = append(keys, k)
	}
	return keys
}

// Range - Duyệt qua tất cả key/value
func (s *SafeMap) Range(fn func(key string, value interface{})) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k, v := range s.m {
		fn(k, v)
	}
}
