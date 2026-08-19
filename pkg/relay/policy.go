// Package relay — 出口策略（复用 directory.ExitPolicy 规则语义，对齐 C Tor 0.4.9 policies.c）。
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

// privateRejectLines 对齐 C Tor ExitPolicyRejectPrivate（地址族，不含端口 25）。
// 端口 25 属于 DEFAULT_EXIT_POLICY，不放在 RejectPrivate 里，以便用户显式 accept *:25。
var privateRejectLines = []string{
	"reject 0.0.0.0/8:*",
	"reject 127.0.0.0/8:*",
	"reject 10.0.0.0/8:*",
	"reject 172.16.0.0/12:*",
	"reject 192.168.0.0/16:*",
	"reject 169.254.0.0/16:*",
	"reject 100.64.0.0/10:*",
	"reject 192.0.2.0/24:*",
	"reject 198.51.100.0/24:*",
	"reject 203.0.113.0/24:*",
	"reject 224.0.0.0/4:*",
	"reject 240.0.0.0/4:*",
	"reject 255.255.255.255/32:*",
	"reject [::]/128:*",
	"reject [::1]/128:*",
	"reject [fe80::]/10:*",
	"reject [fc00::]/7:*",
	"reject [2001:db8::]/32:*",
	"reject [ff00::]/8:*",
}

// defaultExitPolicyLines 对齐 C Tor DEFAULT_EXIT_POLICY。
var defaultExitPolicyLines = []string{
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
	"accept *:*",
}

// reducedExitPolicyLines 对齐 C Tor 0.4.9 REDUCED_EXIT_POLICY。
var reducedExitPolicyLines = []string{
	"accept *:20-23",
	"accept *:43",
	"accept *:53",
	"accept *:79-81",
	"accept *:88",
	"accept *:110",
	"accept *:143",
	"accept *:194",
	"accept *:220",
	"accept *:389",
	"accept *:443",
	"accept *:464",
	"accept *:465",
	"accept *:531",
	"accept *:543-544",
	"accept *:554",
	"accept *:563",
	"accept *:587",
	"accept *:636",
	"accept *:706",
	"accept *:749",
	"accept *:873",
	"accept *:902-904",
	"accept *:981",
	"accept *:989-995",
	"accept *:1194",
	"accept *:1220",
	"accept *:1293",
	"accept *:1500",
	"accept *:1533",
	"accept *:1677",
	"accept *:1723",
	"accept *:1755",
	"accept *:1863",
	"accept *:2082-2083",
	"accept *:2086-2087",
	"accept *:2095-2096",
	"accept *:2102-2104",
	"accept *:3128",
	"accept *:3389",
	"accept *:3690",
	"accept *:4321",
	"accept *:4643",
	"accept *:5050",
	"accept *:5190",
	"accept *:5222-5223",
	"accept *:5228",
	"accept *:5900",
	"accept *:6660-6669",
	"accept *:6679",
	"accept *:6697",
	"accept *:8000",
	"accept *:8008",
	"accept *:8074",
	"accept *:8080",
	"accept *:8082",
	"accept *:8087-8088",
	"accept *:8232-8233",
	"accept *:8332-8333",
	"accept *:8443",
	"accept *:8888",
	"accept *:9418",
	"accept *:9999",
	"accept *:10000",
	"accept *:11371",
	"accept *:18080-18081",
	"accept *:18089",
	"accept *:19294",
	"accept *:19638",
	"accept *:50002",
	"accept *:64738",
	"reject *:*",
}

var defaultRejectAll = []string{"reject *:*", "reject *6:*"}

// 权威判定 Exit flag 时常用的端口抽样（我们不自己宣告 Exit，仅用于本地警告）。
var exitFlagProbePorts = []uint16{80, 443, 6667}

// ExitPolicyOptions 构建出口策略的全部开关。
type ExitPolicyOptions struct {
	ExitRelay             bool
	Lines                 []string
	Reduce                bool
	IPv6Exit              bool
	RejectPrivate         bool
	RejectLocalInterfaces bool
}

// ExitPolicy 封装出口判定。
type ExitPolicy struct {
	AllowExit bool
	rules     *directory.ExitPolicy
	ipv6OK    bool
	descLines []string // 写入 server descriptor 的 accept/reject 行
	ipv6Line  string   // ipv6-policy 摘要（可空）

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
		descLines: []string{"reject *:*"},
		logger:    log.Component("exit-policy"),
	}
}

// NewExitPolicyFromConfig 构建出口策略。
// 默认启用 RejectPrivate 与 RejectLocalInterfaces（对齐 C Tor 0.4.9 默认 1）。
func NewExitPolicyFromConfig(exitRelay bool, lines []string, reduce, ipv6Exit bool, log *logger.Logger) *ExitPolicy {
	return NewExitPolicyFromOptions(ExitPolicyOptions{
		ExitRelay:             exitRelay,
		Lines:                 lines,
		Reduce:                reduce,
		IPv6Exit:              ipv6Exit,
		RejectPrivate:         true,
		RejectLocalInterfaces: true,
	}, log)
}

// NewExitPolicyFromOptions 按 C Tor 顺序组装：RejectPrivate / 本机接口 → 用户行 → 默认或精简策略。
// 用户行若以 accept *:* / reject *:*（或 *4）结尾则不再追加默认策略。
func NewExitPolicyFromOptions(opt ExitPolicyOptions, log *logger.Logger) *ExitPolicy {
	p := NewExitPolicy(log)
	p.ipv6OK = opt.IPv6Exit
	if !opt.ExitRelay {
		return p
	}

	use := make([]string, 0, 64)
	if opt.RejectPrivate {
		use = append(use, privateRejectLines...)
	} else {
		p.logger.Warn("ExitPolicyRejectPrivate 0：私网/环回/链路本地可由后续规则放行（SSRF 风险，仅在知情时使用）")
	}
	if opt.RejectLocalInterfaces {
		use = append(use, localInterfaceRejectLines()...)
	}

	user := normalizePolicyLines(opt.Lines)
	use = append(use, user...)

	var appended []string
	if !endsWithAbsolutePolicy(user) {
		if opt.Reduce {
			appended = reducedExitPolicyLines
			p.logger.Info("追加 C Tor ReducedExitPolicy")
		} else {
			appended = defaultExitPolicyLines
			p.logger.Info("追加 C Tor 默认 ExitPolicy")
		}
		use = append(use, appended...)
	}

	if opt.IPv6Exit {
		// 把 *:port 镜像为 *6:port（紧跟原规则顺序，避免 IPv4 通配抢先）
		use = interleaveStarIPv6(use)
	} else {
		// directory.Allows 无匹配为 accept，必须封闭 IPv6
		use = append(use, "reject *6:*")
	}

	pol, ipv6Sum, err := directory.ParseExitPolicyLines(use)
	if err != nil {
		p.logger.Warn("ExitPolicy 解析失败，回退 reject *:*", "error", err)
		return NewExitPolicy(log)
	}
	p.rules = pol
	p.descLines = descriptorPublishLines(use)
	if opt.IPv6Exit {
		p.ipv6Line = ipv6PolicySummaryLine(pol, ipv6Sum)
	} else {
		p.ipv6Line = "ipv6-policy reject 1-65535"
	}
	p.AllowExit = true // ExitRelay 1：按规则执行 BEGIN，不因无 Exit flag 短路
	if !wouldAnnounceExit(p) {
		p.logger.Warn("ExitRelay 1 但策略最终不会放行常见端口，权威不会给 Exit flag")
	}
	return p
}

func normalizePolicyLines(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, raw := range lines {
		s := strings.TrimSpace(raw)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if !strings.HasPrefix(s, "accept") && !strings.HasPrefix(s, "reject") {
			// torrc 值可能是 "accept *:80"
			s = strings.TrimSpace(s)
		}
		out = append(out, s)
	}
	return out
}

func endsWithAbsolutePolicy(lines []string) bool {
	for i := len(lines) - 1; i >= 0; i-- {
		f := strings.Fields(lines[i])
		if len(f) < 2 {
			continue
		}
		pat := f[1]
		// 只看最后一条有效规则：必须是通配结尾才不再追加默认/精简策略
		return pat == "*:*" || pat == "*4:*"
	}
	return false
}

func starIPv6Mirror(l string) string {
	f := strings.Fields(l)
	if len(f) < 2 {
		return ""
	}
	verb, pat := f[0], f[1]
	if strings.HasPrefix(pat, "*:") && !strings.HasPrefix(pat, "*4:") && !strings.HasPrefix(pat, "*6:") {
		return verb + " *6:" + pat[2:]
	}
	return ""
}

// interleaveStarIPv6 在每条 *:port 后立即插入 *6:port，对齐 C Tor IPv6Exit 展开。
func interleaveStarIPv6(lines []string) []string {
	out := make([]string, 0, len(lines)*2)
	for _, l := range lines {
		out = append(out, l)
		if m := starIPv6Mirror(l); m != "" {
			out = append(out, m)
		}
	}
	return out
}

func descriptorPublishLines(lines []string) []string {
	seen := make(map[string]struct{}, len(lines))
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		// *6: 只进 ipv6-policy 摘要，不写进 IPv4 accept/reject 行
		if f := strings.Fields(l); len(f) >= 2 && strings.HasPrefix(f[1], "*6:") {
			continue
		}
		if _, ok := seen[l]; ok {
			continue
		}
		seen[l] = struct{}{}
		out = append(out, l)
	}
	if len(out) == 0 {
		return []string{"reject *:*"}
	}
	return out
}

func ipv6PolicySummaryLine(pol *directory.ExitPolicy, _ *directory.ExitPolicySummary) string {
	if pol == nil {
		return "ipv6-policy reject 1-65535"
	}
	// 抽样常见端口生成 accept 列表
	var ports []string
	probe := []int{80, 443, 53, 6667, 9001}
	for _, p := range probe {
		if pol.Allows(net.ParseIP("2001:4860:4860::8888"), p) {
			ports = append(ports, fmt.Sprintf("%d", p))
		}
	}
	if len(ports) == 0 {
		return "ipv6-policy reject 1-65535"
	}
	return "ipv6-policy accept " + strings.Join(ports, ",")
}

func wouldAnnounceExit(p *ExitPolicy) bool {
	if p == nil || p.rules == nil {
		return false
	}
	probe := net.ParseIP("1.1.1.1")
	for _, port := range exitFlagProbePorts {
		if p.rules.Allows(probe, int(port)) {
			return true
		}
	}
	return false
}

// dangerousExitIP 标识默认不得出口的地址（私网/环回/链路本地/CGN/组播/文档网段）。
func dangerousExitIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsPrivate() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xc0 == 64 { // 100.64.0.0/10
			return true
		}
		if v4[0] == 192 && v4[1] == 0 && v4[2] == 2 { // 192.0.2.0/24
			return true
		}
		if v4[0] == 198 && v4[1] == 51 && v4[2] == 100 {
			return true
		}
		if v4[0] == 203 && v4[1] == 0 && v4[2] == 113 {
			return true
		}
		if v4[0] >= 240 { // 240.0.0.0/4 + broadcast
			return true
		}
		return false
	}
	// 文档前缀 2001:db8::/32、ULA fc00::/7
	if len(ip) == 16 && ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 {
		return true
	}
	return false
}

func localInterfaceRejectLines() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	seen := make(map[string]struct{})
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil || ipnet.IP.IsUnspecified() {
			continue
		}
		var line string
		if v4 := ipnet.IP.To4(); v4 != nil {
			line = "reject " + v4.String() + "/32:*"
		} else {
			line = "reject [" + ipnet.IP.String() + "]/128:*"
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	return out
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
	if len(p.descLines) > 0 {
		return strings.Join(p.descLines, ", ")
	}
	return "accept (configured ExitPolicy)"
}

// DescriptorLines 返回写入 server descriptor 的 accept/reject 行。
func (p *ExitPolicy) DescriptorLines() []string {
	if p == nil || len(p.descLines) == 0 {
		return []string{"reject *:*"}
	}
	return append([]string(nil), p.descLines...)
}

// IPv6PolicyLine 返回 ipv6-policy 行（不含换行）；空表示不写。
func (p *ExitPolicy) IPv6PolicyLine() string {
	if p == nil {
		return "ipv6-policy reject 1-65535"
	}
	return p.ipv6Line
}

// WouldAnnounceExit 策略是否足以被权威视为 Exit（常见端口）。
func (p *ExitPolicy) WouldAnnounceExit() bool {
	return p != nil && p.AllowExit && wouldAnnounceExit(p)
}

// ValidateExitAttempt 校验 BEGIN/BEGIN_DIR。
func (p *ExitPolicy) ValidateExitAttempt(command byte, address string, port uint16) error {
	if command == cell.RelayBeginDir {
		// BEGIN_DIR 走目录缓存，不受 ExitPolicy 约束（非出口中继也可提供）
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
