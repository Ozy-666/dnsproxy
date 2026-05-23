package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

// tcpPackPool is a pool of 2+dns.MaxMsgSize byte slices for TCP read/write.
// Layout: [len_hi][len_lo][dns_wire_0..dns_wire_N].
var tcpPackPool = sync.Pool{New: func() any { b := make([]byte, 2+dns.MaxMsgSize); return &b }}

// initTCPListeners initializes TCP listeners with configured addresses.
func (p *Proxy) initTCPListeners(ctx context.Context) (err error) {
	for _, addr := range p.TCPListenAddr {
		var ln *net.TCPListener
		ln, err = p.listenTCP(ctx, addr)
		if err != nil {
			return fmt.Errorf("listening on tcp addr %s: %w", addr, err)
		}

		p.tcpListen = append(p.tcpListen, ln)
	}

	return nil
}

// listenTCP returns a new TCP listener listening on addr.
func (p *Proxy) listenTCP(ctx context.Context, addr *net.TCPAddr) (ln *net.TCPListener, err error) {
	addrStr := addr.String()
	p.logger.InfoContext(ctx, "creating tcp server socket", "addr", addrStr)

	conf := proxynetutil.ListenConfig(p.logger)

	var listener net.Listener
	err = p.bindWithRetry(ctx, func() (listenErr error) {
		listener, listenErr = conf.Listen(ctx, bootstrap.NetworkTCP, addrStr)

		return listenErr
	})
	if err != nil {
		return nil, fmt.Errorf("listening to tcp socket: %w", err)
	}

	var ok bool
	ln, ok = listener.(*net.TCPListener)
	if !ok {
		// TODO(e.burkov):  Close the listener.

		return nil, fmt.Errorf("bad listener type: %T", listener)
	}

	p.logger.InfoContext(ctx, "listening to tcp", "addr", ln.Addr())

	return ln, nil
}

// initTLSListeners initializes TLS listeners with configured addresses.
func (p *Proxy) initTLSListeners(ctx context.Context) (err error) {
	for _, addr := range p.TLSListenAddr {
		p.logger.InfoContext(ctx, "creating tls server socket", "addr", addr)

		var tcpListen *net.TCPListener
		err = p.bindWithRetry(ctx, func() (listenErr error) {
			tcpListen, listenErr = net.ListenTCP("tcp", addr)

			return listenErr
		})
		if err != nil {
			return fmt.Errorf("listening on tls addr %s: %w", addr, err)
		}

		l := tls.NewListener(tcpListen, p.TLSConfig)
		p.tlsListen = append(p.tlsListen, l)

		p.logger.InfoContext(ctx, "listening to tls", "addr", l.Addr())
	}

	return nil
}

// tcpPacketLoop listens for incoming TCP packets.  proto must be either
// [ProtoTCP] or [ProtoTLS].
//
// See also the comment on Proxy.requestsSema.
func (p *Proxy) tcpPacketLoop(
	ctx context.Context,
	l net.Listener,
	proto Proto,
	reqSema syncutil.Semaphore,
) {
	p.logger.InfoContext(ctx, "entering listener loop", "proto", proto, "addr", l.Addr())

	for {
		clientConn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				p.logger.DebugContext(ctx, "tcp connection closed", "addr", l.Addr())
			} else {
				p.logger.ErrorContext(ctx, "reading from tcp", slogutil.KeyError, err)
			}

			break
		}

		err = reqSema.Acquire(ctx)
		if err != nil {
			p.logger.ErrorContext(ctx, "acquiring sema", "proto", ProtoTCP, slogutil.KeyError, err)

			break
		}

		go p.handleTCPConnection(ctx, clientConn, proto, reqSema)
	}
}

// handleTCPConnection starts a loop that handles an incoming TCP connection.
// proto must be either [ProtoTCP] or [ProtoTLS].
func (p *Proxy) handleTCPConnection(
	ctx context.Context,
	conn net.Conn,
	proto Proto,
	reqSema syncutil.Semaphore,
) {
	defer slogutil.RecoverAndLog(ctx, p.logger)
	defer reqSema.Release()
	defer func() {
		err := conn.Close()
		if err != nil {
			logWithNonCrit(ctx, err, "closing conn", ProtoTCP, p.logger)
		}
	}()

	p.logger.DebugContext(ctx, "handling new request", "proto", proto, "raddr", conn.RemoteAddr())

	ctx, cancel := p.reqCtx.New(ctx)
	defer cancel()

	for p.isStarted() {
		err := conn.SetDeadline(p.time.Now().Add(defaultTimeout))
		if err != nil {
			// Consider deadline errors non-critical.
			logWithNonCrit(ctx, err, "setting deadline", ProtoTCP, p.logger)
		}

		req := p.readDNSReq(ctx, conn)
		if req == nil {
			return
		}

		d := p.newDNSContext(proto, req, netutil.NetAddrToAddrPort(conn.RemoteAddr()))
		d.Conn = conn

		err = p.handleDNSRequest(ctx, d)
		if err != nil {
			logWithNonCrit(ctx, err, "handling request", ProtoTCP, p.logger)
		}
	}
}

// readDNSReq returns DNS request message from the given connection or nil if
// it failed to read it.  Properly logs the error if it happened.
func (p *Proxy) readDNSReq(ctx context.Context, conn net.Conn) (req *dns.Msg) {
	pb := tcpPackPool.Get().(*[]byte)
	defer tcpPackPool.Put(pb)

	packet, err := readPrefixedBuf(conn, *pb)
	if err != nil {
		logWithNonCrit(ctx, err, "reading msg", ProtoTCP, p.logger)

		return nil
	}

	req = &dns.Msg{}
	err = req.Unpack(packet)
	if err != nil {
		p.logger.ErrorContext(ctx, "handling tcp; unpacking msg", slogutil.KeyError, err)

		return nil
	}

	return req
}

// errTooLarge means that a DNS message is larger than 64KiB.
const errTooLarge errors.Error = "dns message is too large"

// readPrefixedBuf reads a length-prefixed DNS message from conn into buf,
// which must be at least 2+dns.MaxMsgSize bytes.  Returns the message bytes
// (a sub-slice of buf[2:]) without copying.
func readPrefixedBuf(conn net.Conn, buf []byte) (b []byte, err error) {
	_, err = io.ReadFull(conn, buf[:2])
	if err != nil {
		return nil, fmt.Errorf("reading len: %w", err)
	}

	packetLen := int(binary.BigEndian.Uint16(buf[:2]))
	if packetLen > dns.MaxMsgSize {
		return nil, errTooLarge
	}

	_, err = io.ReadFull(conn, buf[2:2+packetLen])
	if err != nil {
		return nil, fmt.Errorf("reading msg: %w", err)
	}

	return buf[2 : 2+packetLen], nil
}

// respondTCP writes a response to the TCP (or TLS) client.
func (p *Proxy) respondTCP(d *DNSContext) error {
	resp := d.Res
	conn := d.Conn

	if resp == nil {
		return conn.Close()
	}

	pb := tcpPackPool.Get().(*[]byte)
	defer tcpPackPool.Put(pb)

	wire, err := resp.PackBuffer((*pb)[2:])
	if err != nil {
		return fmt.Errorf("packing message: %w", err)
	}

	msgLen := len(wire)
	binary.BigEndian.PutUint16((*pb)[:2], uint16(msgLen))
	_, err = conn.Write((*pb)[:2+msgLen])
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("writing message: %w", err)
	}

	return nil
}
