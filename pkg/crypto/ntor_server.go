// 服务端 ntor（relay CREATE2 响应）。hs-ntor 不使用本文件。
package crypto

// NtorServerHandshake 处理客户端 84 字节握手，返回 Y||AUTH 与 72 字节密钥。
// serverNodeID 必须是 20 字节 RSA fingerprint。
func NtorServerHandshake(clientHandshake, serverNtorPrivate, serverNodeID []byte) (response, keyMaterial []byte, err error) {
	return ntorServerHandshakeCore(clientHandshake, serverNtorPrivate, serverNodeID, nil)
}

func ntorServerHandshakeWithKeys(clientHandshake, serverNtorPrivate, serverNodeID, ephemeralPrivate []byte) (response, keyMaterial []byte, err error) {
	return ntorServerHandshakeCore(clientHandshake, serverNtorPrivate, serverNodeID, ephemeralPrivate)
}
