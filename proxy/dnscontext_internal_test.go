package proxy

import (
	"net"
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

// TestDNSContext_Scrub_EmptiesTruncatedUDP checks that a UDP response that has
// to be truncated is reflected as a bare header rather than as a datagram
// packed with the records that happened to fit.
func TestDNSContext_Scrub_EmptiesTruncatedUDP(t *testing.T) {
	req := (&dns.Msg{}).SetQuestion("example.org.", dns.TypeTXT)
	req.SetEdns0(10000, false)

	res := newBigTXTResponse(req)
	res.Ns = append(res.Ns, &dns.NS{
		Hdr: dns.RR_Header{
			Name:   req.Question[0].Name,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Ns: "ns1.example.org.",
	})

	dctx := &DNSContext{
		Proto: ProtoUDP,
		Req:   req,
		Res:   res,
	}

	dctx.scrub()

	require.True(t, dctx.Res.Truncated)

	// The point of the change: no answer bytes are reflected at all.
	assert.Empty(t, dctx.Res.Answer)
	assert.Empty(t, dctx.Res.Ns)

	// The question is what makes the response matchable to the query, so it
	// must survive.
	require.Len(t, dctx.Res.Question, 1)
	assert.Equal(t, req.Question[0], dctx.Res.Question[0])

	// Only the OPT record is left in the additional section.
	require.Len(t, dctx.Res.Extra, 1)
	assert.NotNil(t, dctx.Res.IsEdns0())
}

// TestDNSContext_Scrub_TruncatedKeepsCookie checks that the DNS Cookie survives
// the emptying, since it is how a real client proves return-routability on the
// TCP retry.
func TestDNSContext_Scrub_TruncatedKeepsCookie(t *testing.T) {
	const cookie = "879e584b2498fd92010000006a96dc2c12e7af8abcbe3b7d"

	req := (&dns.Msg{}).SetQuestion("example.org.", dns.TypeTXT)
	req.SetEdns0(10000, false)

	res := newBigTXTResponse(req)
	res.SetEdns0(10000, false)
	opt := res.IsEdns0()
	require.NotNil(t, opt)
	opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: cookie,
	})

	dctx := &DNSContext{
		Proto: ProtoUDP,
		Req:   req,
		Res:   res,
	}

	dctx.scrub()

	require.True(t, dctx.Res.Truncated)

	gotOpt := dctx.Res.IsEdns0()
	require.NotNil(t, gotOpt)

	var got string
	for _, o := range gotOpt.Option {
		if c, ok := o.(*dns.EDNS0_COOKIE); ok {
			got = c.Cookie
		}
	}

	assert.Equal(t, cookie, got)
}

// TestDNSContext_Scrub_UntruncatedUDPKeepsAnswer guards against emptying a
// response that fits: only TC=1 responses lose their records.
func TestDNSContext_Scrub_UntruncatedUDPKeepsAnswer(t *testing.T) {
	req := (&dns.Msg{}).SetQuestion("example.org.", dns.TypeA)
	req.SetEdns0(1232, false)

	res := (&dns.Msg{}).SetReply(req)
	res.Answer = append(res.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   req.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.IP{192, 0, 2, 1},
	})

	dctx := &DNSContext{
		Proto: ProtoUDP,
		Req:   req,
		Res:   res,
	}

	dctx.scrub()

	assert.False(t, dctx.Res.Truncated)
	assert.Len(t, dctx.Res.Answer, 1)
}

// TestDNSContext_Scrub_TruncatedNoEDNS0 checks that a truncated response to a
// request without EDNS(0) keeps no additional section at all, since RFC 6891
// forbids echoing an OPT the request did not carry.
func TestDNSContext_Scrub_TruncatedNoEDNS0(t *testing.T) {
	req := (&dns.Msg{}).SetQuestion("example.org.", dns.TypeTXT)

	dctx := &DNSContext{
		Proto: ProtoUDP,
		Req:   req,
		Res:   newBigTXTResponse(req),
	}

	dctx.scrub()

	require.True(t, dctx.Res.Truncated)
	assert.Empty(t, dctx.Res.Answer)
	assert.Empty(t, dctx.Res.Extra)
}
