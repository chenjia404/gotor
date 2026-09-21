// Package security provides security utilities for the Tor client implementation
package security

import (
	"crypto/subtle"
	"fmt"
	"math"
	"time"
)

// SafeUnixToUint64 safely converts a Unix timestamp to uint64
// Returns error if the timestamp is negative or would overflow
func SafeUnixToUint64(t time.Time) (uint64, error) {
	unix := t.Unix()
	if unix < 0 {
		return 0, fmt.Errorf("negative timestamp: %d", unix)
	}
	// Check would overflow uint64 (though practically impossible with Unix timestamps)
	if unix < 0 {
		return 0, fmt.Errorf("timestamp overflow: %d", unix)
	}
	return uint64(unix), nil // #nosec G115 -- 已排除负值
}

// SafeUnixToUint32 safely converts a Unix timestamp to uint32
// Returns error if the timestamp is negative or would overflow uint32
// Note: Will overflow in year 2106 (max uint32 = 4294967295)
func SafeUnixToUint32(t time.Time) (uint32, error) {
	unix := t.Unix()
	if unix < 0 {
		return 0, fmt.Errorf("negative timestamp: %d", unix)
	}
	if unix > math.MaxUint32 {
		return 0, fmt.Errorf("timestamp exceeds uint32 range: %d (max: %d)", unix, uint32(math.MaxUint32))
	}
	return uint32(unix), nil // #nosec G115 -- 已夹紧到 uint32
}

// SafeIntToUint64 safely converts an int to uint64
// Returns error if the value is negative
func SafeIntToUint64(val int) (uint64, error) {
	if val < 0 {
		return 0, fmt.Errorf("negative value: %d", val)
	}
	return uint64(val), nil // #nosec G115 -- 已排除负值
}

// SafeIntToUint16 safely converts an int to uint16
// Returns error if the value is negative or exceeds uint16 range
func SafeIntToUint16(val int) (uint16, error) {
	if val < 0 {
		return 0, fmt.Errorf("value out of uint16 range (negative): %d", val)
	}
	if val > math.MaxUint16 {
		return 0, fmt.Errorf("value out of uint16 range: %d (max: %d)", val, math.MaxUint16)
	}
	return uint16(val), nil // #nosec G115 -- 已夹紧到 uint16
}

// SafeInt64ToUint64 safely converts an int64 to uint64
// Returns error if the value is negative
func SafeInt64ToUint64(val int64) (uint64, error) {
	if val < 0 {
		return 0, fmt.Errorf("negative int64 value: %d", val)
	}
	return uint64(val), nil // #nosec G115 -- 已排除负值
}

// SafeUint64ToInt64 safely converts a uint64 to int64
// Returns error if the value would overflow int64
func SafeUint64ToInt64(val uint64) (int64, error) {
	if val > math.MaxInt64 {
		return 0, fmt.Errorf("uint64 value exceeds int64 range: %d (max: %d)", val, math.MaxInt64)
	}
	return int64(val), nil // #nosec G115 -- 已夹紧到 int64
}

// SafeIntToUint32 safely converts an int to uint32
// Returns error if the value is negative or exceeds uint32 range
func SafeIntToUint32(val int) (uint32, error) {
	if val < 0 {
		return 0, fmt.Errorf("value out of uint32 range (negative): %d", val)
	}
	if val > math.MaxUint32 {
		return 0, fmt.Errorf("value out of uint32 range: %d (max: %d)", val, math.MaxUint32)
	}
	return uint32(val), nil // #nosec G115 -- 已夹紧到 uint32
}

// SafeLenToUint16 is a convenience function to safely convert a slice length to uint16
// This is commonly needed for protocol length fields
func SafeLenToUint16(data []byte) (uint16, error) {
	return SafeIntToUint16(len(data))
}

// ByteLen 把长度夹到 0..255，用于线格式 1 字节 LEN。
func ByteLen(n int) byte {
	if n <= 0 {
		return 0
	}
	if n > 255 {
		return 255
	}
	return byte(n) // #nosec G115 -- 已夹紧 0..255
}

// Uint16HighByte 取 uint16 高 8 位。
func Uint16HighByte(v uint16) byte {
	return byte(v >> 8) // #nosec G115 -- 移位后的高字节
}

// Uint16LowByte 取 uint16 低 8 位。
func Uint16LowByte(v uint16) byte {
	return byte(v) // #nosec G115 -- 低 8 位
}

// PortUint16 把端口夹到 0..65535。
func PortUint16(port int) uint16 {
	if port < 0 {
		return 0
	}
	if port > math.MaxUint16 {
		return math.MaxUint16
	}
	return uint16(port) // #nosec G115 -- 已夹紧
}

// IntToUint16Sat 把 int 夹到 uint16。
func IntToUint16Sat(v int) uint16 {
	return PortUint16(v)
}

// Uint32ToUint16 把 uint32 夹到 uint16。
func Uint32ToUint16(v uint32) uint16 {
	if v > math.MaxUint16 {
		return math.MaxUint16
	}
	return uint16(v) // #nosec G115 -- 已夹紧
}

// IntToUint32Sat 把 int 夹到 uint32。
func IntToUint32Sat(v int) uint32 {
	if v < 0 {
		return 0
	}
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v) // #nosec G115 -- 已夹紧
}

// Uint64ToInt64Sat 把 uint64 夹到 int64（超出则取 MaxInt64）。
func Uint64ToInt64Sat(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v) // #nosec G115 -- 已夹紧
}

// Int64ToUint64Sat 把非负 int64 转 uint64；负值返回 0。
func Int64ToUint64Sat(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v) // #nosec G115 -- 已保证非负
}

// DurationToUint64 把非负 Duration 转 uint64 纳秒。
func DurationToUint64(d time.Duration) uint64 {
	return Int64ToUint64Sat(int64(d))
}

// Uint64Duration 把 uint64 纳秒夹到 Duration。
func Uint64Duration(ns uint64) time.Duration {
	return time.Duration(Uint64ToInt64Sat(ns))
}

// UnixHoursUint32 把时间换成自纪元起的小时数，夹到 uint32（cert-spec EXPIRATION）。
func UnixHoursUint32(t time.Time) uint32 {
	h := t.Unix() / 3600
	if h < 0 {
		return 0
	}
	if h > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(h) // #nosec G115 -- 已夹紧
}

// ConstantTimeCompare performs constant-time comparison of two byte slices
// Returns true if the slices are equal, false otherwise
// This prevents timing attacks when comparing sensitive data like keys, MACs, etc.
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// SecureZeroMemory zeros out a byte slice to prevent sensitive data from remaining in memory
// Uses a method that should prevent compiler optimization from removing the zeroing
func SecureZeroMemory(data []byte) {
	if data == nil {
		return
	}
	for i := range data {
		data[i] = 0
	}
	// Ensure compiler doesn't optimize away the zeroing
	// subtle.ConstantTimeCopy will force a write that can't be optimized away
	if len(data) > 0 {
		subtle.ConstantTimeCopy(1, data[:1], data[:1])
	}
}
