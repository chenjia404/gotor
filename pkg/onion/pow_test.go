package onion

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/opd-ai/go-tor/pkg/crypto/equix"
	"github.com/opd-ai/go-tor/pkg/logger"
)

func TestParsePoWParams(t *testing.T) {
	seed := bytes.Repeat([]byte{0xab}, 32)
	b64 := base64.RawStdEncoding.EncodeToString(seed)
	line := "v1 " + b64 + " 21 2099-01-02T03:04:05"
	p := parsePoWParamsLine(line)
	if p == nil {
		t.Fatal("应解析 v1 pow-params")
	}
	if !bytes.Equal(p.Seed, seed) {
		t.Fatal("seed")
	}
	if p.SuggestedEffort != 21 {
		t.Fatalf("effort=%d", p.SuggestedEffort)
	}
	if p.Expiration.Year() != 2099 {
		t.Fatalf("exp=%v", p.Expiration)
	}
	if parsePoWParamsLine("v2 "+b64+" 1 2099-01-01T00:00:00") != nil {
		t.Fatal("未知 scheme 应忽略")
	}
}

func TestParseDecryptedLayerPoWParams(t *testing.T) {
	seed := bytes.Repeat([]byte{0x11}, 32)
	b64 := base64.RawStdEncoding.EncodeToString(seed)
	plain := []byte("create2-formats 2\npow-params v1 " + b64 + " 8 2099-06-01T00:00:00\n")
	d, err := parseDecryptedLayer(plain)
	if err != nil {
		t.Fatal(err)
	}
	if d.PoWParams == nil || d.PoWParams.SuggestedEffort != 8 {
		t.Fatalf("未解析 pow-params: %+v", d.PoWParams)
	}
}

func TestSolveOnionPoWEffort1(t *testing.T) {
	params := &PoWParams{
		Seed:            bytes.Repeat([]byte{0x42}, 32),
		SuggestedEffort: 1,
		Expiration:      time.Now().UTC().Add(time.Hour),
	}
	id := bytes.Repeat([]byte{0x07}, 32)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	proof, err := SolveOnionPoW(ctx, params, id)
	if err != nil {
		t.Fatal(err)
	}
	if proof == nil {
		t.Fatal("effort=1 应得到解")
	}
	if proof.Effort != 1 {
		t.Fatalf("effort=%d", proof.Effort)
	}
	if !bytes.Equal(proof.SeedHead[:], params.Seed[:4]) {
		t.Fatal("seed head")
	}
	ch := buildPoWChallenge(id, params.Seed, proof.Nonce[:], proof.Effort)
	eq, err := equix.New(ch)
	if err != nil {
		t.Fatal(err)
	}
	sol, err := equix.SolutionFromBytes(proof.Solution[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := eq.Verify(sol); err != nil {
		t.Fatalf("Equi-X 验证失败: %v", err)
	}
	if !effortSatisfied(ch, proof.Solution[:], proof.Effort) {
		t.Fatal("工作量检查失败")
	}
	ext := encodePoWExtension(proof)
	if len(ext) != 2+powExtFieldLen || ext[0] != introExtPoW || ext[1] != powExtFieldLen || ext[2] != powSchemeV1 {
		t.Fatalf("扩展编码 %x", ext)
	}
}

func TestSolveOnionPoWSkipZeroEffort(t *testing.T) {
	params := &PoWParams{
		Seed:            bytes.Repeat([]byte{1}, 32),
		SuggestedEffort: 0,
		Expiration:      time.Now().UTC().Add(time.Hour),
	}
	proof, err := SolveOnionPoW(context.Background(), params, bytes.Repeat([]byte{2}, 32))
	if err != nil || proof != nil {
		t.Fatalf("effort=0 应跳过: proof=%v err=%v", proof, err)
	}
}

func TestSolveOnionPoWExpired(t *testing.T) {
	params := &PoWParams{
		Seed:            bytes.Repeat([]byte{1}, 32),
		SuggestedEffort: 1,
		Expiration:      time.Now().UTC().Add(-time.Hour),
	}
	_, err := SolveOnionPoW(context.Background(), params, bytes.Repeat([]byte{2}, 32))
	if err == nil {
		t.Fatal("过期种子应失败")
	}
}

func TestBuildIntroduce1CellWithPoW(t *testing.T) {
	log := logger.NewDefault()
	intro := NewIntroductionProtocol(log)
	auth := make([]byte, 32)
	enc := make([]byte, 32)
	_, _ = rand.Read(auth)
	_, _ = rand.Read(enc)
	cookie := make([]byte, 20)
	_, _ = rand.Read(cookie)
	rpKey := make([]byte, 32)
	_, _ = rand.Read(rpKey)
	proof := &PoWProof{Effort: 1}
	_, _ = rand.Read(proof.Nonce[:])
	copy(proof.SeedHead[:], []byte{1, 2, 3, 4})
	_, _ = rand.Read(proof.Solution[:])
	req := &IntroduceRequest{
		IntroPoint: &IntroductionPoint{
			AuthKey: auth,
			EncKey:  enc,
		},
		RendezvousCookie:    cookie,
		RendezvousOnionKey:  rpKey,
		RendezvousLinkSpecs: []LinkSpecifier{{Type: 0, Data: []byte{127, 0, 0, 1, 0, 80}}},
		Subcredential:       make([]byte, 32),
		PoW:                 proof,
	}
	cell, err := intro.BuildIntroduce1Cell(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(cell) < 20+1+2+32+1+32 {
		t.Fatalf("cell 过短 %d", len(cell))
	}
}
