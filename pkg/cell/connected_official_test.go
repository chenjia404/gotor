package cell

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type connectedVectorFile struct {
	Cases []struct {
		Name   string `json:"name"`
		Hex    string `json:"hex"`
		Family string `json:"family"`
		Addr   string `json:"addr"`
		TTL    int    `json:"ttl"`
		Error  bool   `json:"error"`
	} `json:"cases"`
	Create2 struct {
		Hex            string `json:"hex"`
		HandshakeType  int    `json:"handshake_type"`
		OnionSkinLen   int    `json:"onion_skin_len"`
	} `json:"create2_ntor_header"`
}

func loadConnectedVectors(t *testing.T) connectedVectorFile {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("Caller")
	}
	path := filepath.Join(filepath.Dir(thisFile), "../../testdata/ctor-official/cell_connected_vectors.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vf connectedVectorFile
	if err := json.Unmarshal(b, &vf); err != nil {
		t.Fatal(err)
	}
	return vf
}

func TestOfficialConnectedPayloadVectors(t *testing.T) {
	vf := loadConnectedVectors(t)
	for _, tc := range vf.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(tc.Hex)
			if err != nil {
				t.Fatal(err)
			}
			info, err := ParseConnectedPayload(raw)
			if tc.Error {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if info.TTL != tc.TTL {
				t.Fatalf("ttl got %d want %d", info.TTL, tc.TTL)
			}
			switch tc.Family {
			case "unspec":
				if info.Addr != nil && len(info.Addr) != 0 && !info.Addr.IsUnspecified() {
					// empty is fine
				}
			case "inet":
				if info.Addr.To4() == nil || info.Addr.String() != tc.Addr {
					t.Fatalf("addr got %v want %s", info.Addr, tc.Addr)
				}
			case "inet6":
				if info.Addr.To4() != nil || info.Addr.String() != tc.Addr {
					// IPv6 string form may differ (:: compression)
					if info.Addr == nil || !info.Addr.Equal(net.ParseIP(tc.Addr)) {
						t.Fatalf("addr got %v want %s", info.Addr, tc.Addr)
					}
				}
			}
		})
	}
}

func TestOfficialConnectedFormatRoundTrip(t *testing.T) {
	raw, err := FormatConnectedPayload(net.ParseIP("30.40.50.60"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("1e28323c00000400")
	if hex.EncodeToString(raw) != hex.EncodeToString(want) {
		t.Fatalf("got %x want %x", raw, want)
	}
	raw6, err := FormatConnectedPayload(net.ParseIP("2620:0:6b0:b:1a1a:0:26e5:480e"), 3600)
	if err != nil {
		t.Fatal(err)
	}
	want6, _ := hex.DecodeString("00000000062620000006b0000b1a1a000026e5480e00000e10")
	if hex.EncodeToString(raw6) != hex.EncodeToString(want6) {
		t.Fatalf("ipv6 got %x want %x", raw6, want6)
	}
}

func TestOfficialCreate2NtorHeader(t *testing.T) {
	vf := loadConnectedVectors(t)
	raw, err := hex.DecodeString(vf.Create2.Hex)
	if err != nil || len(raw) != 4 {
		t.Fatal(err, len(raw))
	}
	ht := int(raw[0])<<8 | int(raw[1])
	ln := int(raw[2])<<8 | int(raw[3])
	if ht != vf.Create2.HandshakeType || ln != vf.Create2.OnionSkinLen {
		t.Fatalf("ht=%d ln=%d", ht, ln)
	}
}
