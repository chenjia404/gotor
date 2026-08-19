// Package dnsport 实现 C Tor DNSPort：UDP DNS，经 RELAY_RESOLVE，禁止本机 DNS。
package dnsport

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/opd-ai/go-tor/pkg/logger"
)

// ResolveFunc 经电路解析主机名。禁止调用 net.Resolver / 本机 DNS。
type ResolveFunc func(ctx context.Context, name string) (addrs []net.IP, ttl uint32, err error)

// Server 是 UDP DNS 监听。
type Server struct {
	address string
	resolve ResolveFunc
	logger  *logger.Logger
	pc      net.PacketConn
	mu      sync.Mutex
}

func New(addr string, resolve ResolveFunc, log *logger.Logger) *Server {
	if log == nil {
		log = logger.NewDefault()
	}
	return &Server{
		address: addr,
		resolve: resolve,
		logger:  log.Component("dnsport"),
	}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.resolve == nil {
		return fmt.Errorf("dnsport: resolver required")
	}
	pc, err := net.ListenPacket("udp", s.address)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.pc = pc
	s.mu.Unlock()
	s.logger.Info("DNSPort listening", "addr", pc.LocalAddr())

	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	buf := make([]byte, 2048)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		pkt := append([]byte(nil), buf[:n]...)
		go s.handle(ctx, pc, addr, pkt)
	}
}

func (s *Server) handle(ctx context.Context, pc net.PacketConn, addr net.Addr, pkt []byte) {
	id, name, qtype, ok := parseDNSQuery(pkt)
	if !ok {
		return
	}
	var answers []dnsRR
	if qtype == 1 || qtype == 28 { // A / AAAA
		ips, ttl, err := s.resolve(ctx, name)
		if err == nil {
			for _, ip := range ips {
				if qtype == 1 && ip.To4() != nil {
					answers = append(answers, dnsRR{Name: name, Type: 1, TTL: ttl, Data: ip.To4()})
				}
				if qtype == 28 && ip.To4() == nil && ip.To16() != nil {
					answers = append(answers, dnsRR{Name: name, Type: 28, TTL: ttl, Data: ip.To16()})
				}
			}
		}
	}
	rcode := uint16(0)
	if len(answers) == 0 {
		rcode = 3 // NXDOMAIN
	}
	resp := buildDNSResponse(id, name, qtype, rcode, answers)
	_, _ = pc.WriteTo(resp, addr)
}

func (s *Server) Close() error {
	s.mu.Lock()
	pc := s.pc
	s.pc = nil
	s.mu.Unlock()
	if pc == nil {
		return nil
	}
	return pc.Close()
}

func (s *Server) LocalAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pc == nil {
		return nil
	}
	return s.pc.LocalAddr()
}

type dnsRR struct {
	Name string
	Type uint16
	TTL  uint32
	Data []byte
}

func parseDNSQuery(pkt []byte) (id uint16, name string, qtype uint16, ok bool) {
	if len(pkt) < 12 {
		return 0, "", 0, false
	}
	id = binary.BigEndian.Uint16(pkt[0:2])
	qd := binary.BigEndian.Uint16(pkt[4:6])
	if qd == 0 {
		return 0, "", 0, false
	}
	off := 12
	var labels []string
	for {
		if off >= len(pkt) {
			return 0, "", 0, false
		}
		n := int(pkt[off])
		off++
		if n == 0 {
			break
		}
		if n&0xC0 != 0 || off+n > len(pkt) {
			return 0, "", 0, false
		}
		labels = append(labels, string(pkt[off:off+n]))
		off += n
	}
	if off+4 > len(pkt) {
		return 0, "", 0, false
	}
	qtype = binary.BigEndian.Uint16(pkt[off : off+2])
	return id, strings.Join(labels, "."), qtype, true
}

func encodeName(name string) []byte {
	if name == "" || name == "." {
		return []byte{0}
	}
	name = strings.TrimSuffix(name, ".")
	var out []byte
	for _, lab := range strings.Split(name, ".") {
		if len(lab) > 63 {
			lab = lab[:63]
		}
		out = append(out, byte(len(lab))) // #nosec G115 -- 标签长度已截断到 ≤63
		out = append(out, lab...)
	}
	out = append(out, 0)
	return out
}

func buildDNSResponse(id uint16, name string, qtype uint16, rcode uint16, answers []dnsRR) []byte {
	var b []byte
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	// QR=1, RD=1, RA=1, rcode
	flags := uint16(0x8180) | (rcode & 0xF)
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	ancount := len(answers)
	if ancount > 65535 {
		ancount = 65535
		answers = answers[:65535]
	}
	binary.BigEndian.PutUint16(hdr[6:8], uint16(ancount)) // #nosec G115 -- 已截断到 ≤65535
	b = append(b, hdr...)
	qname := encodeName(name)
	b = append(b, qname...)
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint16(tmp[0:2], qtype)
	binary.BigEndian.PutUint16(tmp[2:4], 1)
	b = append(b, tmp...)
	for _, rr := range answers {
		b = append(b, encodeName(rr.Name)...)
		rrh := make([]byte, 10)
		binary.BigEndian.PutUint16(rrh[0:2], rr.Type)
		binary.BigEndian.PutUint16(rrh[2:4], 1)
		binary.BigEndian.PutUint32(rrh[4:8], rr.TTL)
		dlen := len(rr.Data)
		if dlen > 65535 {
			dlen = 65535
			rr.Data = rr.Data[:65535]
		}
		binary.BigEndian.PutUint16(rrh[8:10], uint16(dlen)) // #nosec G115 -- 已截断到 ≤65535
		b = append(b, rrh...)
		b = append(b, rr.Data...)
	}
	return b
}
