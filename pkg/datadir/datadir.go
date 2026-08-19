// Package datadir 提供 C Tor 风格 DataDirectory 路径、lock、PidFile 与 state 文件。
package datadir

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

const (
	LockFileName    = "lock"
	StateFileName   = "state"
	CookieFileName  = "control_auth_cookie"
	KeysDirName     = "keys"
	GuardJSONName   = "guard_state.json"
	CachedCertsName = "cached-certs"
	CachedConsName  = "cached-microdesc-consensus"
	CachedMDName    = "cached-microdescs"
	CachedMDNewName = "cached-microdescs.new"
)

// Paths 汇总 DataDirectory / CacheDirectory 下的标准文件名。
type Paths struct {
	DataDir  string
	CacheDir string
}

func NewPaths(dataDir, cacheDir string) Paths {
	if cacheDir == "" {
		cacheDir = dataDir
	}
	return Paths{DataDir: dataDir, CacheDir: cacheDir}
}

func (p Paths) Lock() string        { return filepath.Join(p.DataDir, LockFileName) }
func (p Paths) State() string       { return filepath.Join(p.DataDir, StateFileName) }
func (p Paths) Cookie() string      { return filepath.Join(p.DataDir, CookieFileName) }
func (p Paths) Keys() string        { return filepath.Join(p.DataDir, KeysDirName) }
func (p Paths) GuardJSON() string   { return filepath.Join(p.DataDir, GuardJSONName) }
func (p Paths) CachedCerts() string { return filepath.Join(p.CacheDir, CachedCertsName) }
func (p Paths) CachedConsensus() string {
	return filepath.Join(p.CacheDir, CachedConsName)
}
func (p Paths) CachedMicrodescs() string {
	return filepath.Join(p.CacheDir, CachedMDName)
}
func (p Paths) CachedMicrodescsNew() string {
	return filepath.Join(p.CacheDir, CachedMDNewName)
}

// Lock 是 DataDirectory/lock 的 flock。同一目录第二次加锁失败。
type Lock struct {
	fl   *flock.Flock
	path string
}

// TryLock 获取独占锁。失败表示目录已被占用。
func TryLock(dataDir string) (*Lock, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("empty DataDirectory")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create DataDirectory: %w", err)
	}
	path := filepath.Join(dataDir, LockFileName)
	fl := flock.New(path)
	locked, err := fl.TryLock()
	if err != nil {
		return nil, fmt.Errorf("DataDirectory lock: %w", err)
	}
	if !locked {
		return nil, fmt.Errorf("DataDirectory %s 已被占用（lock 获取失败）", dataDir)
	}
	return &Lock{fl: fl, path: path}, nil
}

// Unlock 释放锁。
func (l *Lock) Unlock() error {
	if l == nil || l.fl == nil {
		return nil
	}
	return l.fl.Unlock()
}

// Path 返回 lock 文件路径。
func (l *Lock) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// WritePidFile 把当前进程 PID 写入 path（权限 0600）。
func WritePidFile(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("pidfile dir: %w", err)
	}
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
}

// RemovePidFile 删除 PidFile（停止时调用）。
func RemovePidFile(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ValidRSAFingerprint 校验 C Tor 风格 40 位十六进制指纹（可带空格）。
func ValidRSAFingerprint(id string) bool {
	id = strings.ReplaceAll(id, " ", "")
	if len(id) != 40 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}

// GuardRecord 是 C Tor state 文件中的一条 Guard 行。
type GuardRecord struct {
	RSAID    string
	Nickname string
	Fields   map[string]string
}

// StateFile 是 C Tor key-value state（含 Guard 行）。
type StateFile struct {
	Pairs  []StatePair
	Guards []GuardRecord
}

// StatePair 是非 Guard 的 key value。
type StatePair struct {
	Key   string
	Value string
}

// ParseState 解析 C Tor state 文件。
func ParseState(data []byte) *StateFile {
	sf := &StateFile{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "Guard ") {
			sf.Guards = append(sf.Guards, parseGuardLine(line[6:]))
			continue
		}
		key, val, ok := strings.Cut(line, " ")
		if !ok {
			sf.Pairs = append(sf.Pairs, StatePair{Key: line})
			continue
		}
		sf.Pairs = append(sf.Pairs, StatePair{Key: key, Value: val})
	}
	return sf
}

func parseGuardLine(rest string) GuardRecord {
	g := GuardRecord{Fields: make(map[string]string)}
	for _, tok := range strings.Fields(rest) {
		k, v, ok := strings.Cut(tok, "=")
		if !ok {
			continue
		}
		g.Fields[k] = v
		switch k {
		case "rsa_id":
			g.RSAID = strings.ToUpper(v)
		case "nickname":
			g.Nickname = v
		}
	}
	return g
}

// Serialize 写出 C Tor 风格 state。
func (s *StateFile) Serialize(torVersion string) []byte {
	var b strings.Builder
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	fmt.Fprintf(&b, "# Tor state file last generated on %s UTC\n", now)
	fmt.Fprintf(&b, "# You *shall not* edit this file.\n\n")
	if torVersion == "" {
		torVersion = "Tor 0.4.9.11 (gotor)"
	}
	wroteVer := false
	wroteWritten := false
	for _, p := range s.Pairs {
		if p.Key == "TorVersion" {
			fmt.Fprintf(&b, "TorVersion %s\n", torVersion)
			wroteVer = true
			continue
		}
		if p.Key == "LastWritten" {
			fmt.Fprintf(&b, "LastWritten %s\n", now)
			wroteWritten = true
			continue
		}
		if p.Value == "" {
			fmt.Fprintf(&b, "%s\n", p.Key)
			continue
		}
		fmt.Fprintf(&b, "%s %s\n", p.Key, p.Value)
	}
	if !wroteVer {
		fmt.Fprintf(&b, "TorVersion %s\n", torVersion)
	}
	if !wroteWritten {
		fmt.Fprintf(&b, "LastWritten %s\n", now)
	}
	for _, g := range s.Guards {
		if g.Fields == nil {
			g.Fields = map[string]string{}
		}
		if g.RSAID != "" {
			g.Fields["rsa_id"] = strings.ToUpper(g.RSAID)
		}
		if g.Nickname != "" {
			g.Fields["nickname"] = g.Nickname
		}
		if _, ok := g.Fields["in"]; !ok {
			g.Fields["in"] = "default"
		}
		fmt.Fprintf(&b, "Guard")
		// 稳定顺序：in, rsa_id, nickname，其余按插入顺序不可靠，按 key 排序
		keys := make([]string, 0, len(g.Fields))
		for k := range g.Fields {
			keys = append(keys, k)
		}
		sortStateKeys(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, " %s=%s", k, g.Fields[k])
		}
		fmt.Fprintf(&b, "\n")
	}
	return []byte(b.String())
}

func sortStateKeys(keys []string) {
	prio := map[string]int{"in": 0, "rsa_id": 1, "nickname": 2}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			pi, okI := prio[keys[i]]
			if !okI {
				pi = 100
			}
			pj, okJ := prio[keys[j]]
			if !okJ {
				pj = 100
			}
			if pi > pj || (pi == pj && keys[i] > keys[j]) {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
}

// LoadState 读取 DataDirectory/state；不存在返回空对象。
func LoadState(path string) (*StateFile, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- DataDirectory/state 由操作者配置
	if err != nil {
		if os.IsNotExist(err) {
			return &StateFile{}, nil
		}
		return nil, err
	}
	return ParseState(data), nil
}

// SaveState 原子写入 state（0600）。
func SaveState(path string, sf *StateFile, torVersion string) error {
	if sf == nil {
		sf = &StateFile{}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data := sf.Serialize(torVersion)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// PrepareUnixSocket 删除陈旧 unix socket，并确保父目录存在。
func PrepareUnixSocket(path string) error {
	if path == "" {
		return fmt.Errorf("empty unix socket path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// IsWindows 便于测试与 daemon 分支。
func IsWindows() bool {
	return runtime.GOOS == "windows"
}
