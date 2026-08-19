package directory

import (
	"strings"
)

// ApplyFallbackDirs 把 torrc FallbackDir 接到权威列表。
// useDefault=false 且有自定义条目时只用 FallbackDir。
func (c *Client) ApplyFallbackDirs(lines []string, useDefault bool) {
	if c == nil {
		return
	}
	var extras []string
	for _, line := range lines {
		if u := fallbackDirURL(line); u != "" {
			extras = append(extras, u)
		}
	}
	if len(extras) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !useDefault {
		c.authorities = extras
		return
	}
	c.authorities = append(extras, c.authorities...)
}

func fallbackDirURL(line string) string {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return ""
	}
	hostport := fields[0]
	if strings.Contains(hostport, "://") {
		return hostport
	}
	if !strings.Contains(hostport, ":") {
		return ""
	}
	return "http://" + hostport + "/tor/status-vote/current/consensus-microdesc"
}
