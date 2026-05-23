package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func BenchmarkRespondTCP(b *testing.B) {
	resp := &dns.Msg{}
	resp.SetReply(&dns.Msg{})
	resp.Question = []dns.Question{{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("93.184.216.34").To4(),
	}}

	d := &DNSContext{
		Res:   resp,
		Proto: ProtoTCP,
		Addr:  netip.MustParseAddrPort("127.0.0.1:12345"),
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pb := tcpPackPool.Get().(*[]byte)
		wire, err := resp.PackBuffer((*pb)[2:])
		if err != nil {
			b.Fatal(err)
		}
		_ = d
		_ = wire
		tcpPackPool.Put(pb)
	}
}

func TestProxy_tcp(t *testing.T) {
	dnsProxy := mustStartDefaultProxy(t)

	// Create a DNS-over-TCP client connection
	addr := dnsProxy.Addr(ProtoTCP)
	conn, err := dns.Dial("tcp", addr.String())
	require.NoError(t, err)

	sendTestMessages(t, conn)
}

func TestProxy_tls(t *testing.T) {
	serverConfig, caPem := newTLSConfig(t)
	dnsProxy := mustNew(t, &Config{
		Logger:         testLogger,
		TLSListenAddr:  []*net.TCPAddr{net.TCPAddrFromAddrPort(localhostAnyPort)},
		QUICListenAddr: []*net.UDPAddr{net.UDPAddrFromAddrPort(localhostAnyPort)},
		TLSConfig:      serverConfig,
		UpstreamConfig: newTestUpstreamConfig(t, defaultTimeout, testDefaultUpstreamAddr),
		TrustedProxies: defaultTrustedProxies,
	})

	servicetest.RequireRun(t, dnsProxy, testTimeout)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPem)
	tlsConfig := &tls.Config{ServerName: tlsServerName, RootCAs: roots}

	// Create a DNS-over-TLS client connection
	addr := dnsProxy.Addr(ProtoTLS)
	conn, err := dns.DialWithTLS("tcp-tls", addr.String(), tlsConfig)
	require.NoError(t, err)

	sendTestMessages(t, conn)
}
