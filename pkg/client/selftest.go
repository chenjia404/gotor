package client

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/directory"
	"github.com/opd-ai/go-tor/pkg/path"
)

// ProbeORPortViaCircuit 对照 C Tor CIRCUIT_PURPOSE_TESTING：
// 选 Guard+Middle，把末跳换成 self（本中继宣告的 ORPort + 身份钥），再走已有建路路径 EXTEND2。
//
// 成功：某个 middle 能连上宣告地址并完成 CREATE2。
// 失败：不发布描述符（由 relay.Reachability 门闩处理）。
// 这不是权威 Running 测试，也不表示已进共识。
func (c *Client) ProbeORPortViaCircuit(ctx context.Context, self *directory.Relay) error {
	if c == nil {
		return fmt.Errorf("client is nil")
	}
	if c.config != nil && c.config.DisableNetwork {
		return fmt.Errorf("DisableNetwork is set")
	}
	if self == nil || !self.HasExtendKeys() {
		return fmt.Errorf("self hop missing EXTEND2 keys")
	}
	if self.Address == "" || self.ORPort <= 0 {
		return fmt.Errorf("self hop missing advertised OR address")
	}
	ip, err := advertisedORIP(self.Address)
	if err != nil {
		return err
	}
	target := *self
	target.Address = ip

	if c.pathSelector == nil || c.directory == nil || c.circuitMgr == nil {
		return fmt.Errorf("path selector not ready")
	}

	var selected *path.Path
	for attempt := 1; attempt <= maxCircuitPathAttempts; attempt++ {
		p, err := c.pathSelector.SelectPathFor(path.ExitTarget{Port: generalPurposeExitPort})
		if err != nil {
			return fmt.Errorf("select testing prefix: %w", err)
		}
		attached, err := attachTestingHop(p, &target)
		if err != nil {
			if attempt == maxCircuitPathAttempts {
				return err
			}
			continue
		}
		selected = attached
		break
	}
	if selected == nil {
		return fmt.Errorf("no testing path")
	}

	if err := c.directory.FetchMicrodescriptorsFor(ctx, []*directory.Relay{
		selected.Guard, selected.Middle,
	}); err != nil {
		return fmt.Errorf("fetch prefix microdescriptors: %w", err)
	}
	if !selected.Guard.HasNtorKeys() || !selected.Middle.HasExtendKeys() {
		return fmt.Errorf("testing prefix missing keys after microdesc fetch")
	}

	builder := circuit.NewBuilder(c.circuitMgr, c.logger)
	builder.SetCCParams(circuit.CCParamsFromConsensus(c.directory.LastConsensusParams()))
	if c.circuitRateLimiter != nil {
		builder.SetRateLimiter(c.circuitRateLimiter)
		builder.SetMetricsRecorder(c.metrics)
	}

	timeout := 60 * time.Second
	if c.config != nil && c.config.CircuitBuildTimeout > 0 {
		timeout = c.config.CircuitBuildTimeout
	}
	circ, err := builder.BuildCircuit(ctx, selected, timeout)
	if circ != nil {
		circ.Close()
	}
	if err != nil {
		return fmt.Errorf("testing circuit to own ORPort failed: %w", err)
	}
	return nil
}

// attachTestingHop 把普通 3-hop 的末跳换成 self。Guard/Middle 不得是自己。
func attachTestingHop(p *path.Path, self *directory.Relay) (*path.Path, error) {
	if p == nil || p.Guard == nil || p.Middle == nil {
		return nil, fmt.Errorf("incomplete testing prefix")
	}
	if self == nil || !self.HasExtendKeys() {
		return nil, fmt.Errorf("self hop missing EXTEND2 keys")
	}
	if sameTestingRelay(p.Guard, self) || sameTestingRelay(p.Middle, self) {
		return nil, fmt.Errorf("testing prefix includes self")
	}
	out := *p
	out.Exit = self
	return &out, nil
}

func sameTestingRelay(a, b *directory.Relay) bool {
	if a == nil || b == nil {
		return false
	}
	if a.Fingerprint != "" && b.Fingerprint != "" && strings.EqualFold(a.Fingerprint, b.Fingerprint) {
		return true
	}
	if len(a.RSAIdentity) == 20 && len(b.RSAIdentity) == 20 && bytes.Equal(a.RSAIdentity, b.RSAIdentity) {
		return true
	}
	return false
}

// advertisedORIP 把 Address 收成 EXTEND2 可用的 IP。
// 字面量 IP 不查网；主机名才 LookupIP（默认单测只用 TEST-NET 字面量）。
func advertisedORIP(addr string) (string, error) {
	host := strings.Trim(addr, "[]")
	if host == "" {
		return "", fmt.Errorf("empty advertised address")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() || ip.IsMulticast() {
			return "", fmt.Errorf("invalid advertised OR address")
		}
		return ip.String(), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("resolve advertised OR address: %w", err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil && !v4.IsUnspecified() && !v4.IsMulticast() {
			return v4.String(), nil
		}
	}
	for _, ip := range ips {
		if ip.To4() == nil && ip.To16() != nil && !ip.IsUnspecified() && !ip.IsMulticast() {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("advertised address resolved to no usable IP")
}
