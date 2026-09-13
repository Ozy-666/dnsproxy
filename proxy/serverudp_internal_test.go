package proxy

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
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

// timeoutReadErr is a [net.Error] reporting a timeout, as a read deadline does.
type timeoutReadErr struct{}

// Error implements the error interface for timeoutReadErr.
func (timeoutReadErr) Error() string { return "i/o timeout" }

// Timeout implements the [net.Error] interface for timeoutReadErr.
func (timeoutReadErr) Timeout() bool { return true }

// Temporary implements the [net.Error] interface for timeoutReadErr.
func (timeoutReadErr) Temporary() bool { return true }

func TestUDPLoopActionFor(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		err     error
		name    string
		started bool
		want    udpLoopAction
	}{{
		err:     nil,
		name:    "stopped_no_error",
		started: false,
		want:    udpLoopStop,
	}, {
		err:     errors.New("boom"),
		name:    "stopped_with_error",
		started: false,
		want:    udpLoopStop,
	}, {
		err:     nil,
		name:    "no_error",
		started: true,
		want:    udpLoopContinue,
	}, {
		err:     net.ErrClosed,
		name:    "closed",
		started: true,
		want:    udpLoopStop,
	}, {
		err:     fmt.Errorf("reading: %w", net.ErrClosed),
		name:    "wrapped_closed",
		started: true,
		want:    udpLoopStop,
	}, {
		err:     timeoutReadErr{},
		name:    "timeout",
		started: true,
		want:    udpLoopContinue,
	}, {
		err:     &net.OpError{Op: "read", Err: timeoutReadErr{}},
		name:    "wrapped_timeout",
		started: true,
		want:    udpLoopContinue,
	}, {
		err:     errors.New("connection reset by peer"),
		name:    "unknown_error_retires",
		started: true,
		want:    udpLoopRetire,
	}, {
		err:     &net.OpError{Op: "read", Err: errors.New("no buffer space available")},
		name:    "wrapped_unknown_error_retires",
		started: true,
		want:    udpLoopRetire,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, udpLoopActionFor(tc.err, tc.started))
		})
	}
}

func TestProxy_swapUDPListener(t *testing.T) {
	t.Parallel()

	old, next := &net.UDPConn{}, &net.UDPConn{}
	other := &net.UDPConn{}

	t.Run("replaces_in_place", func(t *testing.T) {
		t.Parallel()

		p := &Proxy{udpListen: []*net.UDPConn{other, old}}
		require.True(t, p.swapUDPListener(old, next))

		assert.Equal(t, []*net.UDPConn{other, next}, p.udpListen)
	})

	t.Run("absent_after_shutdown", func(t *testing.T) {
		t.Parallel()

		p := &Proxy{udpListen: nil}
		assert.False(t, p.swapUDPListener(old, next))
		assert.Empty(t, p.udpListen)
	})
}
