package config

import "runtime"

// CompatTorVersion 是脚本/工具解析的 C Tor 风格版本号（gotor 作为 drop-in）。
const CompatTorVersion = "0.4.9.11"

// VersionString 对齐 C Tor：`Tor version 0.4.9.11 (gotor).`
func VersionString() string {
	return "Tor version " + CompatTorVersion + " (gotor)."
}

// SoftwareVersion 给 GETINFO version 与 state TorVersion：`Tor 0.4.9.11 (gotor)`。
func SoftwareVersion() string {
	return "Tor " + CompatTorVersion + " (gotor)"
}

// PlatformString 给 server descriptor 的 platform 行。
func PlatformString() string {
	return SoftwareVersion() + " on " + runtime.GOOS
}
