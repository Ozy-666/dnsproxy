package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/miekg/dns"
)

// udpPackPool is a pool of reusable wire-buffer pointers for packing DNS
// responses before writing them to a UDP socket.  2048 bytes covers the
// practical DNS-over-UDP ceiling (DNS Flag Day 2020 recommends ≤ 1232 bytes;
// EDNS0 cap is 4096 bytes but real-world responses are almost always < 2048).
// If a response exceeds the pool-buffer length, PackBuffer allocates a new
// slice and the pool slot is updated to the larger allocation so future calls
// of similar size avoid re-allocating.
//
// Safety: UDPWrite is synchronous on all supported platforms (Linux sendmsg,
// BSD sendmsg, Windows WSASendMsg).  The kernel copies the wire bytes before
// returning, so the pool buffer is safe to return immediately after the call.
var udpPackPool = sync.Pool{New: func() any { b := make([]byte, 2048); return &b }}

// udpListenerCount returns the number of UDP sockets to open per listen
// address.  Multiple sockets bound to the same address with SO_REUSEPORT
// (already set by [proxynetutil.ListenConfig]) let the kernel fan inbound
// datagrams across independent file descriptors.  Because each response is
// written back on the socket its query arrived on (see [Proxy.respondUDP]),
// this also splits the per-fd write lock (internal/poll.fdMutex) that
// otherwise serializes every UDP sendmsg through a single mutex under load —
// the dominant block-contention point at high query rates.
//
// The count defaults to GOMAXPROCS (one reader/writer domain per P) and is
// overridable via DNSPROXY_UDP_SHARDS; a value of 1 restores the single-socket
// upstream behavior.  It is clamped to [1, 64].
func udpListenerCount() (n int) {
	n = runtime.GOMAXPROCS(0)
	if s := os.Getenv("DNSPROXY_UDP_SHARDS"); s != "" {
		if v, parseErr := strconv.Atoi(s); parseErr == nil && v > 0 {
			n = v
		}
	}

	return min(max(n, 1), 64)
}

// initUDPListeners initializes UDP listeners with configured addresses.  Each
// address is opened on [udpListenerCount] separate SO_REUSEPORT sockets so the
// per-socket read and write paths shard across cores; server.go starts one
// [Proxy.udpPacketLoop] per socket.
func (p *Proxy) initUDPListeners(ctx context.Context) (err error) {
	shards := udpListenerCount()
	for _, a := range p.UDPListenAddr {
		for i := 0; i < shards; i++ {
			pc, sErr := p.listenUDP(ctx, a)
			if sErr != nil {
				return fmt.Errorf("listening on udp addr %s: %w", a, sErr)
			}

			p.udpListen = append(p.udpListen, pc)
		}
	}

	return nil
}

// listenUDP returns a new UDP connection listening on addr.
func (p *Proxy) listenUDP(ctx context.Context, addr *net.UDPAddr) (conn *net.UDPConn, err error) {
	addrStr := addr.String()
	p.logger.InfoContext(ctx, "creating udp server socket", "addr", addrStr)

	conf := proxynetutil.ListenConfig(p.logger)

	var packetConn net.PacketConn
	err = p.bindWithRetry(ctx, func() (listenErr error) {
		packetConn, listenErr = conf.ListenPacket(ctx, bootstrap.NetworkUDP, addrStr)

		return listenErr
	})
	if err != nil {
		return nil, fmt.Errorf("listening to udp socket: %w", err)
	}

	// TODO(e.burkov):  Use [errors.WithDeferred] for closing errors.

	var ok bool
	conn, ok = packetConn.(*net.UDPConn)
	if !ok {
		// TODO(e.burkov):  Close the connection.

		return nil, fmt.Errorf("bad conn type: %T(%[1]v)", packetConn)
	}

	if p.Config.UDPBufferSize > 0 {
		err = conn.SetReadBuffer(p.Config.UDPBufferSize)
		if err != nil {
			p.logClose(ctx, slog.LevelDebug, conn, "closing after failed read buffer size setting")

			return nil, fmt.Errorf("setting udp buf size: %w", err)
		}
	}

	err = proxynetutil.UDPSetOptions(conn)
	if err != nil {
		p.logClose(ctx, slog.LevelDebug, conn, "closing after failed options setting")

		return nil, fmt.Errorf("setting udp opts: %w", err)
	}

	p.logger.InfoContext(ctx, "listening to udp", "addr", conn.LocalAddr())

	return conn, nil
}

// udpListenersRetired counts UDP listener sockets closed and replaced after an
// unrecoverable read error.  A retirement means a socket stopped serving
// queries, so it must never be silent: the [net.ErrClosed] branch of
// [logUDPConnError] logs at debug level and is invisible under a non-verbose
// log level, which is how a dead listener can go unnoticed for days.
var udpListenersRetired atomic.Uint64

// udpLoopAction is what a UDP listener loop must do after a read attempt.
type udpLoopAction uint8

const (
	// udpLoopContinue means the loop must keep reading from the same socket.
	udpLoopContinue udpLoopAction = iota

	// udpLoopRetire means the socket is unusable and must be closed and
	// replaced.
	udpLoopRetire

	// udpLoopStop means the loop must return.
	udpLoopStop
)

// udpLoopActionFor decides how [Proxy.udpPacketLoop] must react to err from a
// read on a listener socket.  started must be the current value of
// [Proxy.isStarted].
//
// Breaking out of the loop on every error leaves the socket bound but unread.
// With [udpListenerCount] sharding the kernel keeps hashing its SO_REUSEPORT
// share of datagrams into it, so such a socket silently black-holes 1/N of all
// queries once its receive buffer fills.  An error that is fatal for one
// socket must therefore retire it, not abandon it.
func udpLoopActionFor(err error, started bool) (action udpLoopAction) {
	if !started {
		return udpLoopStop
	}

	if err == nil {
		return udpLoopContinue
	}

	if errors.Is(err, net.ErrClosed) {
		return udpLoopStop
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return udpLoopContinue
	}

	return udpLoopRetire
}

// retireUDPListener closes conn after an unrecoverable read error and opens a
// replacement socket on the same address.  Closing is the point: it removes
// the dead socket from the SO_REUSEPORT group so the kernel stops delivering
// datagrams that nobody will ever read.  It returns nil if no replacement
// could be opened, in which case the caller must stop.
func (p *Proxy) retireUDPListener(
	ctx context.Context,
	conn *net.UDPConn,
	readErr error,
) (next *net.UDPConn) {
	addr, _ := conn.LocalAddr().(*net.UDPAddr)

	p.logger.ErrorContext(
		ctx,
		"retiring udp listener after read error",
		"addr", conn.LocalAddr(),
		"retired_total", udpListenersRetired.Add(1),
		slogutil.KeyError, readErr,
	)

	p.logClose(ctx, slog.LevelError, conn, "closing retired udp listener")

	if addr == nil || !p.isStarted() {
		return nil
	}

	var err error
	next, err = p.listenUDP(ctx, addr)
	if err != nil {
		p.logger.ErrorContext(
			ctx,
			"reopening udp listener",
			"addr", addr,
			slogutil.KeyError, err,
		)

		return nil
	}

	if !p.swapUDPListener(conn, next) {
		// Shutdown cleared the listener set while the socket was reopening.
		p.logClose(ctx, slog.LevelDebug, next, "closing replacement udp listener")

		return nil
	}

	return next
}

// swapUDPListener replaces old with next in [Proxy.udpListen] so that shutdown
// closes the socket that is actually in use.  It returns false if old is no
// longer listed, which means shutdown already ran.
func (p *Proxy) swapUDPListener(old, next *net.UDPConn) (ok bool) {
	p.Lock()
	defer p.Unlock()

	for i, l := range p.udpListen {
		if l == old {
			p.udpListen[i] = next

			return true
		}
	}

	return false
}

// udpPacketLoop listens for incoming UDP packets and handles them.
//
// See also the comment on [Proxy.requestsSema].
func (p *Proxy) udpPacketLoop(ctx context.Context, conn *net.UDPConn, reqSema syncutil.Semaphore) {
	p.logger.InfoContext(ctx, "entering udp listener loop", "addr", conn.LocalAddr())

	b := make([]byte, dns.MaxMsgSize)
	for p.isStarted() {
		n, localIP, remoteAddr, err := proxynetutil.UDPRead(conn, b, p.udpOOBSize)
		// The documentation says to handle the packet even if err occurs.
		if n > 0 {
			// Make a copy of all bytes because ReadFrom() will overwrite the
			// contents of b on the next call.  We need that contents to sustain
			// the call because we're handling them in goroutines.
			packet := make([]byte, n)
			copy(packet, b)

			sErr := reqSema.Acquire(ctx)
			if sErr != nil {
				p.logger.ErrorContext(
					ctx,
					"acquiring semaphore",
					"proto", ProtoUDP,
					slogutil.KeyError, sErr,
				)

				break
			}
			go func() {
				defer reqSema.Release()

				p.udpHandlePacket(ctx, packet, localIP, remoteAddr, conn)
			}()
		}

		if err != nil {
			switch udpLoopActionFor(err, p.isStarted()) {
			case udpLoopContinue:
				continue
			case udpLoopRetire:
				conn = p.retireUDPListener(ctx, conn, err)
				if conn == nil {
					return
				}
			default:
				logUDPConnError(err, conn, p.logger)

				return
			}
		}
	}
}

// logUDPConnError writes suitable log message for given err.
func logUDPConnError(err error, conn *net.UDPConn, l *slog.Logger) {
	if errors.Is(err, net.ErrClosed) {
		l.Debug("udp connection closed", "addr", conn.LocalAddr())
	} else {
		l.Error("reading from udp", slogutil.KeyError, err)
	}
}

// udpHandlePacket processes the incoming UDP packet and sends a DNS response.
func (p *Proxy) udpHandlePacket(
	ctx context.Context,
	packet []byte,
	localIP netip.Addr,
	raddr *net.UDPAddr,
	conn *net.UDPConn,
) {
	ctx, cancel := p.reqCtx.New(ctx)
	defer cancel()

	l := p.logger.With("raddr", raddr, "laddr", localIP, logKeyProto, ProtoUDP)
	l.DebugContext(ctx, "handling new packet")

	req := &dns.Msg{}
	err := req.Unpack(packet)
	if err != nil {
		if req.MsgHdr == (dns.MsgHdr{}) {
			l.ErrorContext(ctx, "unpacking", slogutil.KeyError, err)

			return
		}

		l.DebugContext(ctx, "unpacking", slogutil.KeyError, err)

		// Dropping a UDP request with a valid header is considered bad practice
		// since it creates a denial-of-service (DoS) vulnerability for the
		// client.  RFC generally recommends replying with FORMERR in such
		// cases.
		//
		// See https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1.
		resp := p.messages.NewMsgFORMERR(req)
		err = p.respondUDP(resp, conn, raddr, localIP)
	} else {
		d := p.newDNSContext(ProtoUDP, req, netutil.NetAddrToAddrPort(raddr))
		d.Conn = conn
		d.localIP = localIP

		err = p.handleDNSRequest(ctx, d)
	}
	if err != nil {
		l.DebugContext(ctx, "handling request", slogutil.KeyError, err)
	}
}

// respondUDP sends the response message to the client.  It does nothing if resp
// is nil.  It returns an error if writing the response fails, or if the number
// of bytes written is not equal to the length of the packed message.  If resp
// is not nil, conn and raddr must not be nil, and laddr must be valid.
func (p *Proxy) respondUDP(
	resp *dns.Msg,
	conn *net.UDPConn,
	raddr *net.UDPAddr,
	laddr netip.Addr,
) (err error) {
	if resp == nil {
		// Do nothing if no response has been written.
		return nil
	}

	pb := udpPackPool.Get().(*[]byte)
	wire, err := resp.PackBuffer(*pb)
	if err != nil {
		udpPackPool.Put(pb)

		return fmt.Errorf("packing message: %w", err)
	}

	// If PackBuffer had to grow beyond the pool buffer, update the pool slot
	// to the larger allocation so subsequent large responses reuse it.
	if cap(wire) > cap(*pb) {
		*pb = wire[:cap(wire)]
	}

	n, err := proxynetutil.UDPWrite(wire, conn, raddr, laddr)
	// UDPWrite is synchronous: the kernel copies wire bytes before returning,
	// so the buffer is always safe to return to the pool at this point.
	udpPackPool.Put(pb)
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return nil
		}

		return fmt.Errorf("writing message: %w", err)
	}

	return validate.Equal("bytes written", n, len(wire))
}
