// Package onion — HS credential / subcredential（rend-spec-v3 [SUBCRED]）。
package onion

import (
	"golang.org/x/crypto/sha3"
)

// ComputeHSCredential = SHA3_256("credential" || KP_hs_id)
func ComputeHSCredential(identityPubkey []byte) []byte {
	h := sha3.New256()
	_, _ = h.Write([]byte("credential"))
	_, _ = h.Write(identityPubkey)
	return h.Sum(nil)
}

// ComputeHSSubcredential = SHA3_256("subcredential" || N_hs_cred || blinded-public-key)
func ComputeHSSubcredential(identityPubkey, blindedPubkey []byte) []byte {
	cred := ComputeHSCredential(identityPubkey)
	h := sha3.New256()
	_, _ = h.Write([]byte("subcredential"))
	_, _ = h.Write(cred)
	_, _ = h.Write(blindedPubkey)
	return h.Sum(nil)
}
