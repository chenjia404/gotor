// Package relay — 出口策略（复用 directory.ExitPolicy 规则语义）。
package relay

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/opd-ai/go-tor/pkg/cell"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/logger"
)

// 精简默认出口策略（对照 C Tor DEFAULT_EXIT_POLICY 子集 + ReduceExitPolicy 常用端口）
var reducedExitPolicyLines = []string{
	"reject *:25",
	"reject *:119",
	"reject *:135-139",
	"reject *:445",
	"reject *:563",
	"reject *:1214",
	"reject *:4661-4666",
	"reject *:6346-6429",
	"reject *:6699",
	"reject *:6881-6999",
	"accept *:80",
	"accept *:443",
	"reject *:*",
}

var defaultRejectAll = []string{"reject *:*"}

// ExitPolicy 封装出口判定。
type ExitPolicy struct {
	AllowExit bool
	rules     *directory.ExitPolicy
	ipv6OK    bool // IPv6Exit

	rejectedConnections uint64
	logger              *logger.Logger
}

// NewExitPolicy 默认拒绝全部（非出口）。
func NewExitPolicy(log *logger.Logger) *ExitPolicy {
	if log == nil {
		log = logger.NewDefault()
	}
	pol, _, _ := directory.ParseExitPolicyLines(defaultRejectAll)
	return &ExitPolicy{
		AllowExit: false,
		rules:     pol,
		logger:    log.Component("exit-policy"),
	}
}

// NewExitPolicyFromConfig 根据 ExitRelay / ExitPolicy / ReduceExitPolicy / IPv6Exit 构建。
func NewExitPolicyFromConfig(exitRelay bool, lines []string, reduce, ipv6Exit bool, log *logger.Logger) *ExitPolicy {
	p := NewExitPolicy(log)
	p.ipv6OK = ipv6Exit
	if !exitRelay {
		return p
	}
	p.AllowExit = true
	use := append([]string(nil), lines...)
	if len(use) == 0 {
		if reduce {
			use = append([]string(nil), reducedExitPolicyLines...)
		} else {
			// C Tor ExitRelay 1 且无显式策略时默认较宽松；此处用 reduce 子集更安全
			use = append([]string(nil), reducedExitPolicyLines...)
			p.logger.Info("ExitRelay 1 未配置 ExitPolicy，使用 ReduceExitPolicy 风格默认集")
		}
	} else if reduce {
		// ReduceExitPolicy 在自定义策略前附加拒绝高危端口
		use = append([]string{
			"reject *:25", "reject *:119", "reject *:135-139", "reject *:445",
		}, use...)
	}
	pol, _, err := directory.ParseExitPolicyLines(use)
	if err != nil {
		p.logger.Warn("ExitPolicy 解析失败，回退 reject *:*", "error", err)
		return NewExitPolicy(log)
	}
	p.rules = pol
	return p
}

// CheckExitAllowed 判断是否允许向 address:port 出口。
func (p *ExitPolicy) CheckExitAllowed(address string, port uint16) (bool, byte) {
	if p == nil || !p.AllowExit {
		if p != nil {
			atomic.AddUint64(&p.rejectedConnections, 1)
		}
		return false, cell.EndReasonExitPolicy
	}
	if port == 0 {
		atomic.AddUint64(&p.rejectedConnections, 1)
		return false, cell.EndReasonExitPolicy
	}

	host := address
	if h, _, err := net.SplitHostPort(address); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	var ok bool
	if ip == nil {
		ok = p.rules != nil && p.rules.AllowsUnknown(int(port))
	} else {
		if ip.To4() == nil && !p.ipv6OK {
			ok = false
		} else {
			ok = p.rules != nil && p.rules.Allows(ip, int(port))
		}
	}
	if !ok {
		atomic.AddUint64(&p.rejectedConnections, 1)
		p.logger.Debug("exit rejected by policy", "address", address, "port", port)
		return false, cell.EndReasonExitPolicy
	}
	return true, 0
}

// GetRejectedCount 拒绝次数。
func (p *ExitPolicy) GetRejectedCount() uint64 {
	if p == nil {
		return 0
	}
	return atomic.LoadUint64(&p.rejectedConnections)
}

func (p *ExitPolicy) String() string {
	if p == nil || !p.AllowExit {
		return "reject *:*"
	}
	return p.GetExitPolicyString()
}

// GetExitPolicyString 返回简要策略描述。
func (p *ExitPolicy) GetExitPolicyString() string {
	if p == nil || !p.AllowExit {
		return "reject *:*"
	}
	return "accept (configured ExitPolicy)"
}

// ValidateExitAttempt 校验 BEGIN/BEGIN_DIR。
func (p *ExitPolicy) ValidateExitAttempt(command byte, address string, port uint16) error {
	if command == cell.RelayBeginDir {
		if p == nil || !p.AllowExit {
			atomic.AddUint64(&p.rejectedConnections, 1)
			return &ExitPolicyViolation{Address: address, Port: port, Reason: cell.EndReasonExitPolicy}
		}
		return nil
	}
	if command != cell.RelayBegin {
		return nil
	}
	allowed, reason := p.CheckExitAllowed(address, port)
	if !allowed {
		return &ExitPolicyViolation{Address: address, Port: port, Reason: reason}
	}
	return nil
}

// ExitPolicyViolation 策略拒绝。
type ExitPolicyViolation struct {
	Address string
	Port    uint16
	Reason  byte
}

func (e *ExitPolicyViolation) Error() string {
	return fmt.Sprintf("exit policy rejected %s:%d (%s)", e.Address, e.Port, endReasonString(e.Reason))
}

func (e *ExitPolicyViolation) GetReason() byte { return e.Reason }

func endReasonString(reason byte) string {
	switch reason {
	case cell.EndReasonMisc:
		return "MISC"
	case cell.EndReasonResolveFailed:
		return "RESOLVEFAILED"
	case cell.EndReasonConnRefused:
		return "CONNECTREFUSED"
	case cell.EndReasonExitPolicy:
		return "EXITPOLICY"
	case cell.EndReasonDestroy:
		return "DESTROY"
	case cell.EndReasonDone:
		return "DONE"
	case cell.EndReasonTimeout:
		return "TIMEOUT"
	case cell.EndReasonNoRoute:
		return "NOROUTE"
	case cell.EndReasonHibernating:
		return "HIBERNATING"
	case cell.EndReasonInternal:
		return "INTERNAL"
	case cell.EndReasonResourceLimit:
		return "RESOURCELIMIT"
	case cell.EndReasonConnReset:
		return "CONNRESET"
	case cell.EndReasonProtocol:
		return "TORPROTOCOL"
	case cell.EndReasonNotDirectory:
		return "NOTDIRECTORY"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", reason)
	}
}

// ReasonToString 兼容别名。
func ReasonToString(reason byte) string { return endReasonString(reason) }

// IsExitPolicyError 类型断言。
func IsExitPolicyError(err error) bool {
	_, ok := err.(*ExitPolicyViolation)
	return ok
}

// FormatExitPolicyLines 将规则列表格式化为文档行。
func FormatExitPolicyLines(lines []string) string {
	return strings.Join(lines, "\n")
}
