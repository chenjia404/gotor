package circuit

import "net"

// ExitFilter 判断本电路 Exit 是否允许发往该地址:端口。
// 由建路时绑定 directory.Relay；缺 p6 的 Exit 必须拒绝 IPv6 字面量。
type ExitFilter interface {
	AllowsExit(ip net.IP, port int) bool
}

// SetExitFilter 绑定出口策略。应在电路 OPEN 前后均可调用。
func (c *Circuit) SetExitFilter(f ExitFilter) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.exitFilter = f
	c.mu.Unlock()
}

// AllowsExit 报告当前 Exit 是否允许该目标。
// 未绑定过滤器时：IPv6 字面量拒绝（缺 p6 ≡ 拒绝全部 IPv6），其余放行以兼容旧测试桩。
func (c *Circuit) AllowsExit(ip net.IP, port int) bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	f := c.exitFilter
	c.mu.RUnlock()
	if f == nil {
		if ip != nil && ip.To4() == nil && len(ip) == net.IPv6len {
			return false
		}
		return port >= 1 && port <= 65535
	}
	return f.AllowsExit(ip, port)
}
