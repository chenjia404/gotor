// Package debug 提供开发用 Tor cell 追踪。默认关闭，且不记录用户明文或密钥。
package debug

import (
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	enabledOnce sync.Once
	enabled     bool
	logger      *slog.Logger
)

func enabledTrace() bool {
	enabledOnce.Do(func() {
		v := strings.ToLower(os.Getenv("GOTOR_CELL_TRACE"))
		enabled = v == "1" || v == "true" || v == "debug"
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	return enabled
}

// TraceTX 记录发出的 cell 元数据（不含 payload）。
func TraceTX(peer string, circID uint32, command string, relayCommand byte, length int) {
	if !enabledTrace() {
		return
	}
	logger.Debug("TX",
		"peer", peer,
		"circuit", circID,
		"command", command,
		"relay_command", relayCommandName(relayCommand),
		"length", length,
	)
}

// TraceRX 记录收到的 cell 元数据。
func TraceRX(peer string, circID uint32, command string, relayCommand byte, length int, recognized, digestOK bool) {
	if !enabledTrace() {
		return
	}
	logger.Debug("RX",
		"peer", peer,
		"circuit", circID,
		"command", command,
		"relay_command", relayCommandName(relayCommand),
		"length", length,
		"recognized", recognized,
		"digest", digestOK,
	)
}

func relayCommandName(cmd byte) string {
	switch cmd {
	case 0:
		return ""
	case 1:
		return "BEGIN"
	case 2:
		return "DATA"
	case 3:
		return "END"
	case 4:
		return "CONNECTED"
	case 5:
		return "SENDME"
	case 6:
		return "EXTEND"
	case 7:
		return "EXTENDED"
	case 8:
		return "TRUNCATE"
	case 9:
		return "TRUNCATED"
	case 10:
		return "DROP"
	case 11:
		return "RESOLVE"
	case 12:
		return "RESOLVED"
	case 13:
		return "BEGIN_DIR"
	case 14:
		return "EXTEND2"
	case 15:
		return "EXTENDED2"
	default:
		return "UNKNOWN"
	}
}
