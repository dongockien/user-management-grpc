package utils

import (
	"log"
	"runtime/debug"
)

// Recovery - Xử lý panic cơ bản
func Recovery() {
	if r := recover(); r != nil {
		log.Printf("[RECOVERY] Panic: %v\nStack:\n%s", r, string(debug.Stack()))
	}
}

// RecoveryWithContext - Xử lý panic kèm ngữ cảnh
func RecoveryWithContext(context string) {
	if r := recover(); r != nil {
		log.Printf("[RECOVERY] Context: %s\nPanic: %v\nStack:\n%s", context, r, string(debug.Stack()))
	}
}

// RecoveryWithHandler - Xử lý panic với handler tùy chỉnh
func RecoveryWithHandler(handler func(interface{})) {
	if r := recover(); r != nil {
		log.Printf("[RECOVERY] Panic: %v\nStack:\n%s", r, string(debug.Stack()))
		handler(r)
	}
}

// SafeGo - Chạy goroutine với recovery tự động
func SafeGo(fn func()) {
	go func() {
		defer Recovery()
		fn()
	}()
}

// SafeGoWithContext - Chạy goroutine có context và recovery
func SafeGoWithContext(context string, fn func()) {
	go func() {
		defer RecoveryWithContext(context)
		fn()
	}()
}
