package tracing

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"sync"
	"time"
)

type Profiler struct {
	server *http.Server
	mu     sync.RWMutex
}

// NewProfiler - Khởi tạo Profiler với port tuỳ chọn
func NewProfiler(port string) *Profiler {
	mux := http.NewServeMux()

	// 🔹 Bảo toàn pprof chuẩn
	mux.Handle("/debug/pprof/", http.DefaultServeMux)
	mux.Handle("/debug/pprof/cmdline", http.DefaultServeMux)
	mux.Handle("/debug/pprof/profile", http.DefaultServeMux)
	mux.Handle("/debug/pprof/symbol", http.DefaultServeMux)
	mux.Handle("/debug/pprof/trace", http.DefaultServeMux)

	// 🔹 Custom endpoints
	mux.HandleFunc("/debug/pprof/goroutines", goroutineHandler)
	mux.HandleFunc("/debug/pprof/memory", memoryHandler)
	mux.HandleFunc("/debug/pprof/stats", statsHandler)

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return &Profiler{
		server: server,
	}
}

// Start - Chạy PProf server bất đồng bộ
func (p *Profiler) Start() {
	go func() {
		log.Printf("📊 PProf server started on %s", p.server.Addr)
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("❌ PProf server error: %v", err)
		}
	}()
}

// Stop - Dừng PProf server an toàn
func (p *Profiler) Stop() {
	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := p.server.Shutdown(ctx); err != nil {
			log.Printf("❌ PProf shutdown error: %v", err)
		} else {
			log.Println("✅ PProf server stopped")
		}
	}
}


// Custom Handlers


func goroutineHandler(w http.ResponseWriter, r *http.Request) {
	num := runtime.NumGoroutine()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"timestamp":  time.Now().Format(time.RFC3339),
		"goroutines": num,
		"status":     "success",
	})
}

func memoryHandler(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"memory": map[string]uint64{
			"alloc":       m.Alloc,
			"total_alloc": m.TotalAlloc,
			"sys":         m.Sys,
			"num_gc":      uint64(m.NumGC),
		},
		"status": "success",
	})
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	stats := map[string]interface{}{
		"timestamp":    time.Now().Format(time.RFC3339),
		"goroutines":   runtime.NumGoroutine(),
		"memory_alloc": m.Alloc,
		"memory_sys":   m.Sys,
		"num_cpu":      runtime.NumCPU(),
		"num_cgo_call": runtime.NumCgoCall(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}


// Memory & Goroutine Monitoring


func StartMemoryMonitor(ctx context.Context, interval time.Duration, thresholdMB uint64) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				monitorMemory(thresholdMB)
			case <-ctx.Done():
				log.Println("✅ Memory monitor stopped")
				return
			}
		}
	}()
}

func monitorMemory(thresholdMB uint64) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("🚑 Recovery in memory monitor: %v", r)
		}
	}()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	if m.Alloc > thresholdMB*1024*1024 {
		log.Printf("⚠️ High memory usage: %.2f MB (threshold %d MB)", float64(m.Alloc)/1024/1024, thresholdMB)
	}
}
