package client

import (
	"sort"
	"strings"

	"github.com/opd-ai/go-tor/pkg/circuit"
	"github.com/opd-ai/go-tor/pkg/control"
	"github.com/opd-ai/go-tor/pkg/directory"
)

func (a *clientStatsAdapter) GetCircuitStatus() string {
	return a.client.controlCircuitStatus()
}

func (a *clientStatsAdapter) LookupNS(id string) (string, bool) {
	return a.client.controlNS(id)
}

func (a *clientStatsAdapter) LookupDesc(id string) (string, bool) {
	// 客户端默认只拉 microdescriptor，没有 server descriptor 缓存。
	_ = id
	return "", false
}

func (c *Client) controlCircuitStatus() string {
	if c == nil || c.circuitMgr == nil {
		return ""
	}
	ids := c.circuitMgr.ListCircuits()
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	nicks := c.relayNicknames()
	var lines []string
	for _, id := range ids {
		circ, err := c.circuitMgr.GetCircuit(id)
		if err != nil || circ == nil {
			continue
		}
		st := circ.GetState()
		if st == circuit.StateClosed {
			continue
		}
		hops := circ.GetHops()
		status, flags, purpose := controlCircuitMeta(st, hops)
		path := controlCircuitPath(hops, nicks)
		lines = append(lines, control.FormatCircuitStatusLine(id, status, path, flags, purpose, circ.CreatedAt))
	}
	return strings.Join(lines, "\n")
}

func (c *Client) controlNS(id string) (string, bool) {
	if c == nil || c.pathSelector == nil {
		return "", false
	}
	r := directory.FindRelayByID(c.pathSelector.GetRelays(), id)
	if r == nil {
		return "", false
	}
	return directory.FormatRouterStatus(r), true
}

func (c *Client) relayNicknames() map[string]string {
	out := make(map[string]string)
	if c.pathSelector == nil {
		return out
	}
	for _, r := range c.pathSelector.GetRelays() {
		hx := strings.ToUpper(strings.TrimPrefix(r.GetFingerprintHex(), "$"))
		if len(hx) == 40 && r.Nickname != "" {
			out[hx] = r.Nickname
		}
	}
	return out
}

func controlCircuitMeta(st circuit.State, hops []*circuit.Hop) (status, flags, purpose string) {
	purpose = "GENERAL"
	switch st {
	case circuit.StateOpen:
		status = "BUILT"
	case circuit.StateFailed:
		status = "FAILED"
	case circuit.StateBuilding:
		if len(hops) == 0 {
			status = "LAUNCHED"
		} else {
			status = "EXTENDED"
		}
	default:
		status = "LAUNCHED"
	}
	if len(hops) <= 1 {
		flags = "ONEHOP_TUNNEL,IS_INTERNAL"
	} else {
		flags = "NEED_CAPACITY"
	}
	if n := len(hops); n > 0 && hops[n-1] != nil && hops[n-1].Fingerprint == "hs-rendezvous" {
		purpose = "HS_CLIENT_REND"
		flags = "IS_INTERNAL"
	}
	return status, flags, purpose
}

func controlCircuitPath(hops []*circuit.Hop, nicks map[string]string) string {
	var parts []string
	for _, h := range hops {
		if h == nil {
			continue
		}
		fp := h.Fingerprint
		nick := nicks[strings.ToUpper(strings.TrimPrefix(fp, "$"))]
		if name := control.LongName(fp, nick); name != "" {
			parts = append(parts, name)
		}
	}
	return strings.Join(parts, ",")
}

func circuitEventPath(relays ...*directory.Relay) string {
	var parts []string
	for _, r := range relays {
		if r == nil {
			continue
		}
		if name := control.LongName(r.GetFingerprintHex(), r.Nickname); name != "" {
			parts = append(parts, name)
		}
	}
	return strings.Join(parts, ",")
}
