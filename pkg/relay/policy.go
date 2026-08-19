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

// 私网/特殊用途：ExitRelay 启用时始终前置拒绝
var privateRejectLines = []string{
	"reject 0.0.0.0/8:*",
	"reject 127.0.0.0/8:*",
	"reject 10.0.0.0/8:*",
	"reject 172.16.0.0/12:*",
	"reject 192.168.0.0/16:*",
	"reject 169.254.0.0/16:*",
	"reject 100.64.0.0/10:*",
	"reject [::]/128:*",
	"reject [::1]/128:*",
	"reject [fe80::]/10:*",
	"reject [fc00::]/7:*",
	"reject [2001:db8::]/32:*",
	"reject *:25",
}

var reducedExitPolicyLines = []string{
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

var defaultRejectAll = []string{"reject *:*", "reject *6:*"}

// ExitPolicy 封装出口判定。
type ExitPolicy struct {
	AllowExit bool
	rules     *directory.ExitPolicy
	ipv6OK    bool

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

// NewExitPolicyFromConfig 构建出口策略。
// 始终前置私网拒绝；末尾 reject *6:*（IPv6Exit 时先插入 accept *6:80/443）。
func NewExitPolicyFromConfig(exitRelay bool, lines []string, reduce, ipv6Exit bool, log *logger.Logger) *ExitPolicy {
	p := NewExitPolicy(log)
	p.ipv6OK = ipv6Exit
	if !exitRelay {
		return p
	}
	p.AllowExit = true
	use := append([]string(nil), privateRejectLines...)
	if len(lines) == 0 {
		use = append(use, reducedExitPolicyLines...)
		p.logger.Info("ExitRelay 1 使用精简默认 ExitPolicy（含私网拒绝）")
	} else {
		if reduce {
			use = append(use, "reject *:119", "reject *:135-139", "reject *:445")
		}
		use = append(use, lines...)
	}
	if ipv6Exit {
		if len(lines) == 0 || reduce {
			use = append(use, "accept *6:80", "accept *6:443")
		}
	}
	// 封闭 IPv6：无匹配不得默认 accept（directory.Allows 无命中为 true）
	use = append(use, "reject *6:*")

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
	ip := net.ParseIP(strings.Trim(host, "[]"))
	var ok bool
	if ip == nil {
		ok = p.rules != nil && p.rules.AllowsUnknown(int(port))
	} else if ip.To4() == nil && !p.ipv6OK {
		ok = false
	} else {
		ok = p.rules != nil && p.rules.Allows(ip, int(port))
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
			if p != nil {
				atomic.AddUint64(&p.rejectedConnections, 1)
			}
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
