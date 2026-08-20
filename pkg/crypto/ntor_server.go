// 服务端 ntor（relay CREATE2 响应）。hs-ntor 不使用本文件。
package crypto

// NtorServerHandshake 处理客户端 84 字节握手，返回 Y||AUTH 与 72 字节密钥。
// serverNodeID 必须是 20 字节 RSA fingerprint。
func NtorServerHandshake(clientHandshake, serverNtorPrivate, serverNodeID []byte) (response, keyMaterial []byte, err error) {
	resp, expanded, err := ntorServerHandshakeCore(clientHandshake, serverNtorPrivate, serverNodeID, nil)
	if err != nil {
		return nil, nil, err
	}
	return resp, truncateNtorKeyMaterial(expanded), nil
}

// NtorServerHandshakeWithNonce 与 NtorServerHandshake 相同，并返回 20 字节 rend_circ_nonce。
func NtorServerHandshakeWithNonce(clientHandshake, serverNtorPrivate, serverNodeID []byte) (response, keyMaterial, circNonce []byte, err error) {
	resp, expanded, err := ntorServerHandshakeCore(clientHandshake, serverNtorPrivate, serverNodeID, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	km, cn, err := SplitNtorExpanded(expanded)
	if err != nil {
		return nil, nil, nil, err
	}
	return resp, km, cn, nil
}

func ntorServerHandshakeWithKeys(clientHandshake, serverNtorPrivate, serverNodeID, ephemeralPrivate []byte) (response, keyMaterial []byte, err error) {
	resp, expanded, err := ntorServerHandshakeCore(clientHandshake, serverNtorPrivate, serverNodeID, ephemeralPrivate)
	if err != nil {
		return nil, nil, err
	}
	return resp, truncateNtorKeyMaterial(expanded), nil
}

func truncateNtorKeyMaterial(expanded []byte) []byte {
	if len(expanded) > NtorKeyMaterialLen {
		return append([]byte(nil), expanded[:NtorKeyMaterialLen]...)
	}
	return expanded
}
