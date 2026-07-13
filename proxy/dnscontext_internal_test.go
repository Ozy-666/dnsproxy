package proxy

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newBigTXTResponse returns a response to req whose wire size is well over
// maxAdvertisedUDPSize, mimicking the large TXT answers abused by DNS
// amplification floods.
func newBigTXTResponse(req *dns.Msg) (resp *dns.Msg) {
	resp = (&dns.Msg{}).SetReply(req)
	chunk := strings.Repeat("a", 255)
	for range 10 {
		resp.Answer = append(resp.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Txt: []string{chunk},
		})
	}

	return resp
}

func TestDNSSize(t *testing.T) {
	testCases := []struct {
		name    string
		isUDP   bool
		udpSize uint16
		want    int
	}{{
		name:    "udp_no_edns",
		isUDP:   true,
		udpSize: 0,
		want:    dns.MinMsgSize,
	}, {
		name:    "udp_below_clamp_honored",
		isUDP:   true,
		udpSize: 1000,
		want:    1000,
	}, {
		name:    "udp_oversized_clamped",
		isUDP:   true,
		udpSize: 10000,
		want:    maxAdvertisedUDPSize,
	}, {
		name:    "tcp_not_clamped",
		isUDP:   false,
		udpSize: 10000,
		want:    dns.MaxMsgSize,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := (&dns.Msg{}).SetQuestion("example.org.", dns.TypeTXT)
			if tc.udpSize > 0 {
				req.SetEdns0(tc.udpSize, false)
			}

			assert.Equal(t, tc.want, int(dnsSize(tc.isUDP, req)))
		})
	}
}

func TestDNSContext_Scrub_ClampsUDP(t *testing.T) {
	req := (&dns.Msg{}).SetQuestion("example.org.", dns.TypeTXT)
	req.SetEdns0(10000, false)

	dctx := &DNSContext{
		Proto: ProtoUDP,
		Req:   req,
		Res:   newBigTXTResponse(req),
	}

	dctx.scrub()

	// The actual anti-amplification guarantee: no UDP response larger than
	// the clamp, TC bit set so real clients retry over TCP.
	assert.LessOrEqual(t, dctx.Res.Len(), maxAdvertisedUDPSize)
	assert.True(t, dctx.Res.Truncated)

	// The echoed OPT must advertise the size we actually honor, not parrot
	// the client's value.
	o := dctx.Res.IsEdns0()
	require.NotNil(t, o)
	assert.LessOrEqual(t, int(o.UDPSize()), maxAdvertisedUDPSize)
}

func TestDNSContext_Scrub_TCPUnaffected(t *testing.T) {
	req := (&dns.Msg{}).SetQuestion("example.org.", dns.TypeTXT)
	req.SetEdns0(10000, false)

	res := newBigTXTResponse(req)
	wantAnswers := len(res.Answer)

	dctx := &DNSContext{
		Proto: ProtoTCP,
		Req:   req,
		Res:   res,
	}

	dctx.scrub()

	// TCP is connection-verified, not spoofable: the clamp must not apply,
	// and the full answer survives.
	assert.Equal(t, wantAnswers, len(dctx.Res.Answer))
	assert.Greater(t, dctx.Res.Len(), maxAdvertisedUDPSize)
	assert.False(t, dctx.Res.Truncated)
}
