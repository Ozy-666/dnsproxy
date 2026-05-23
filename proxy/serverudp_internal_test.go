package proxy

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestUdpProxy(t *testing.T) {
	dnsProxy := mustStartDefaultProxy(t)

	// Create a DNS-over-UDP client connection
	addr := dnsProxy.Addr(ProtoUDP)
	conn, err := dns.Dial("udp", addr.String())
	require.NoError(t, err)

	sendTestMessages(t, conn)
}

// BenchmarkRespondUDP benchmarks the hot path inside respondUDP: pool.Get →
// PackBuffer → pool.Put.  It intentionally skips UDPWrite (syscall) to isolate
// the allocation profile of the pack step we optimized with udpPackPool.
func BenchmarkRespondUDP(b *testing.B) {
	resp := &dns.Msg{}
	resp.SetReply(&dns.Msg{
		Question: []dns.Question{{
			Name:   "example.com.",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	})
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.IPv4(93, 184, 216, 34),
	}}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pb := udpPackPool.Get().(*[]byte)
		wire, err := resp.PackBuffer(*pb)
		if err != nil {
			b.Fatal(err)
		}
		if cap(wire) > cap(*pb) {
			*pb = wire[:cap(wire)]
		}
		udpPackPool.Put(pb)
	}
}
