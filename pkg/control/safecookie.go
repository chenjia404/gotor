// Package control — SAFECOOKIE / AUTHCHALLENGE（control-spec §3.24）。
package control

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	safeCookieServerToController = "Tor safe cookie authentication server-to-controller hash"
	safeCookieControllerToServer = "Tor safe cookie authentication controller-to-server hash"
	safeCookieNonceLen           = 32
)

func hmacSHA256(key string, msg []byte) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write(msg)
	return mac.Sum(nil)
}

func decodeAuthToken(s string) ([]byte, error) {
	s = strings.Trim(s, `"`)
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty auth token")
	}
	// Prefer hex (SAFECOOKIE / COOKIE)
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	return []byte(s), nil
}

// handleAuthChallenge 处理 AUTHCHALLENGE SAFECOOKIE <ClientNonce>
func (s *Server) handleAuthChallenge(conn *connection, args []string) {
	if !s.cookieAuth || len(s.cookieBytes) != 32 {
		conn.writeReply(512, "AUTHCHALLENGE is only valid with CookieAuthentication")
		return
	}
	if len(args) < 2 || !strings.EqualFold(args[0], "SAFECOOKIE") {
		conn.writeReply(512, "Syntax error: expected AUTHCHALLENGE SAFECOOKIE <ClientNonce>")
		return
	}
	clientNonce, err := decodeAuthToken(strings.Join(args[1:], ""))
	if err != nil || len(clientNonce) != safeCookieNonceLen {
		// try args[1] alone
		clientNonce, err = decodeAuthToken(args[1])
		if err != nil || len(clientNonce) != safeCookieNonceLen {
			conn.writeReply(512, "ClientNonce must be 32 bytes")
			return
		}
	}

	serverNonce := make([]byte, safeCookieNonceLen)
	if _, err := rand.Read(serverNonce); err != nil {
		conn.writeReply(551, "Internal error generating nonce")
		return
	}

	msg := make([]byte, 0, 32+32+32)
	msg = append(msg, s.cookieBytes...)
	msg = append(msg, clientNonce...)
	msg = append(msg, serverNonce...)

	serverHash := hmacSHA256(safeCookieServerToController, msg)
	clientHash := hmacSHA256(safeCookieControllerToServer, msg)

	conn.mu.Lock()
	conn.safeCookieClientHash = clientHash
	conn.mu.Unlock()

	conn.writeReply(250, fmt.Sprintf("AUTHCHALLENGE SERVERHASH=%s SERVERNONCE=%s",
		strings.ToUpper(hex.EncodeToString(serverHash)),
		strings.ToUpper(hex.EncodeToString(serverNonce))))
}

func (s *Server) trySafeCookieAuthenticate(conn *connection, token []byte) bool {
	conn.mu.Lock()
	expected := conn.safeCookieClientHash
	conn.mu.Unlock()
	if len(expected) != 32 || len(token) != 32 {
		return false
	}
	return subtle.ConstantTimeCompare(expected, token) == 1
}
