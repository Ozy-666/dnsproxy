package upstream

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
)

// plainPoolEnabled reports whether plain (UDP/TCP) upstream connections are
// pooled and reused across exchanges instead of dialed-and-closed per query.
// It is on by default and disabled by DNSPROXY_PLAIN_POOL=0, restoring the
// original dial-per-query behaviour.  Reused connections eliminate the per-query
// socket/connect/close syscalls — the dominant CPU cost when the resolver
// forwards every query to a local upstream (e.g. an on-box unbound).
var plainPoolEnabled = os.Getenv("DNSPROXY_PLAIN_POOL") != "0"

// maxIdlePlainConns bounds the idle connections retained per network for a
// single plain upstream.  Connections returned when the pool is full are
// closed.  Sized to cover realistic concurrent in-flight query counts so the
// steady state reuses connections rather than dialing.
const maxIdlePlainConns = 1024

// network is the semantic type alias of the network to pass to dialing
// functions.  It's either [networkUDP] or [networkTCP].  It may also be used as
// URL scheme for plain upstreams.
type network = string

const (
	// networkUDP is the UDP network.
	networkUDP network = "udp"

	// networkTCP is the TCP network.
	networkTCP network = "tcp"
)

// plainDNS implements the [Upstream] interface for the regular DNS protocol.
type plainDNS struct {
	// addr is the DNS server URL.  Scheme is always "udp" or "tcp".
	addr *url.URL

	// logger is used for exchange logging.  It is never nil.
	logger *slog.Logger

	// getDialer either returns an initialized dial handler or creates a new
	// one.
	getDialer DialerInitializer

	// net is the network of the connections.
	net network

	// timeout is the timeout for DNS requests.
	timeout time.Duration

	// poolMu guards idleUDP and idleTCP.
	poolMu sync.Mutex

	// idleUDP and idleTCP are LIFO stacks of idle connections available for
	// reuse, kept separate because a single upstream may be exchanged with over
	// either network (TCP fallback on truncation).  A connection is removed
	// from its stack for the exclusive duration of an exchange and returned
	// only after a successful, validated response, so it is never shared
	// concurrently — which would let DNS responses cross-talk between queries.
	idleUDP []net.Conn
	idleTCP []net.Conn
}

// newPlain returns the plain DNS Upstream.  addr.Scheme should be either "udp"
// or "tcp".
func newPlain(addr *url.URL, opts *Options) (u *plainDNS, err error) {
	switch addr.Scheme {
	case networkUDP, networkTCP:
		// Go on.
	default:
		return nil, fmt.Errorf("unsupported url scheme: %s", addr.Scheme)
	}

	addPort(addr, defaultPortPlain)

	return &plainDNS{
		addr:      addr,
		logger:    opts.Logger,
		getDialer: newDialerInitializer(addr, opts),
		net:       addr.Scheme,
		timeout:   opts.Timeout,
	}, nil
}

// type check
var _ Upstream = &plainDNS{}

// Address implements the [Upstream] interface for *plainDNS.
func (p *plainDNS) Address() string {
	switch p.net {
	case networkUDP:
		return p.addr.Host
	case networkTCP:
		return p.addr.String()
	default:
		panic(fmt.Sprintf("unexpected network: %s", p.net))
	}
}

// idleStack returns a pointer to the idle-connection stack for network.
// p.poolMu must be held.
func (p *plainDNS) idleStack(network network) *[]net.Conn {
	if network == networkUDP {
		return &p.idleUDP
	}

	return &p.idleTCP
}

// getIdle returns a pooled idle connection for network, or nil if none is
// available.  The returned connection is owned exclusively by the caller until
// putIdle or Close.
func (p *plainDNS) getIdle(network network) (c net.Conn) {
	if !plainPoolEnabled {
		return nil
	}

	p.poolMu.Lock()
	defer p.poolMu.Unlock()

	st := p.idleStack(network)
	if n := len(*st); n > 0 {
		c = (*st)[n-1]
		(*st)[n-1] = nil
		*st = (*st)[:n-1]
	}

	return c
}

// putIdle returns a healthy connection to the pool for reuse, or closes it when
// pooling is disabled or the pool is full.
func (p *plainDNS) putIdle(network network, c net.Conn) {
	if plainPoolEnabled {
		p.poolMu.Lock()
		st := p.idleStack(network)
		if len(*st) < maxIdlePlainConns {
			*st = append(*st, c)
			p.poolMu.Unlock()

			return
		}
		p.poolMu.Unlock()
	}

	_ = c.Close()
}

// dialExchange performs a DNS exchange with the specified dial handler, reusing
// a pooled connection when one is available and returning it to the pool on a
// clean, validated response.  network must be either [networkUDP] or
// [networkTCP].
func (p *plainDNS) dialExchange(
	network network,
	dial bootstrap.DialHandler,
	req *dns.Msg,
) (resp *dns.Msg, err error) {
	addr := p.Address()
	client := &dns.Client{Timeout: p.timeout}

	conn := &dns.Conn{}
	upstreamReq := setRequestForNetwork(req, conn, network)
	defer func() {
		if resp != nil {
			resp.Id = req.Id
		}
	}()

	logBegin(p.logger, addr, network, upstreamReq)
	defer func() { logFinish(p.logger, addr, network, err) }()

	ctx := context.Background()

	// Try a pooled connection first; fall back to dialing a fresh one.
	conn.Conn = p.getIdle(network)
	fromPool := conn.Conn != nil
	if !fromPool {
		conn.Conn, err = dial(ctx, network, "")
		if err != nil {
			return nil, fmt.Errorf("dialing %s over %s: %w", p.addr.Host, network, err)
		}
	}

	resp, _, err = client.ExchangeWithConn(upstreamReq, conn)
	if err != nil && (fromPool || isExpectedConnErr(err)) {
		// A pooled connection may have gone stale (e.g. the upstream restarted
		// or closed an idle keep-alive), and a freshly-dialed one may hit an
		// expected transient error.  Discard it and retry once with a fresh
		// dial.
		_ = conn.Conn.Close()

		conn.Conn, err = dial(ctx, network, "")
		if err != nil {
			return nil, fmt.Errorf("dialing %s over %s again: %w", p.addr.Host, network, err)
		}

		resp, _, err = client.ExchangeWithConn(upstreamReq, conn)
	}

	if err != nil {
		_ = conn.Conn.Close()

		return resp, fmt.Errorf("exchanging with %s over %s: %w", addr, network, err)
	}

	err = validatePlainResponse(upstreamReq, resp)
	if err != nil {
		// Don't pool a connection that produced an invalid response.
		_ = conn.Conn.Close()

		return resp, err
	}

	p.putIdle(network, conn.Conn)

	return resp, nil
}

// setRequestForNetwork sets connection options in conn and overrides the
// upstream request, if necessary, depending on network.  If network is
// [networkUDP] and orig has a zero ID, req is a copy of orig with a new ID to
// increase entropy.  network must be either [networkUDP] or [networkTCP].  orig
// and conn must not be nil.
func setRequestForNetwork(orig *dns.Msg, conn *dns.Conn, network network) (req *dns.Msg) {
	req = orig
	if network != networkUDP {
		return req
	}

	conn.UDPSize = dns.MinMsgSize

	if orig.Id == 0 {
		req = orig.Copy()
		req.Id = dns.Id()
	}

	return req
}

// isExpectedConnErr returns true if the error is expected.  In this case,
// we will make a second attempt to process the request.
func isExpectedConnErr(err error) (is bool) {
	var netErr net.Error

	return err != nil && (errors.As(err, &netErr) || errors.Is(err, io.EOF))
}

// Exchange implements the [Upstream] interface for *plainDNS.
func (p *plainDNS) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	dial, err := p.getDialer()
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return nil, err
	}

	addr := p.Address()

	resp, err = p.dialExchange(p.net, dial, req)
	if p.net != networkUDP {
		// The network is already TCP.
		return resp, err
	}

	if resp == nil {
		// There is likely an error with the upstream.
		return resp, err
	}

	if errors.Is(err, errQuestion) {
		// The upstream responds with malformed messages, so try TCP.
		p.logger.Debug(
			"plain response is malformed, using tcp",
			"addr", addr,
			slogutil.KeyError, err,
		)

		return p.dialExchange(networkTCP, dial, req)
	} else if resp.Truncated {
		// Fallback to TCP on truncated responses.
		p.logger.Debug(
			"plain response is truncated, using tcp",
			"question", &req.Question[0],
			"addr", addr,
		)

		return p.dialExchange(networkTCP, dial, req)
	}

	// There is either no error or the error isn't related to the received
	// message.
	return resp, err
}

// Close implements the [Upstream] interface for *plainDNS.
func (p *plainDNS) Close() (err error) {
	p.poolMu.Lock()
	defer p.poolMu.Unlock()

	var errs []error
	for _, st := range []*[]net.Conn{&p.idleUDP, &p.idleTCP} {
		for _, c := range *st {
			if cerr := c.Close(); cerr != nil {
				errs = append(errs, cerr)
			}
		}
		*st = nil
	}

	return errors.Join(errs...)
}

// errQuestion is returned when a message has malformed question section.
const errQuestion errors.Error = "bad question section"

// validatePlainResponse validates resp from an upstream DNS server for
// compliance with req.  Any error returned wraps [ErrQuestion], since it
// essentially validates the question section of resp.
func validatePlainResponse(req, resp *dns.Msg) (err error) {
	if qlen := len(resp.Question); qlen != 1 {
		return fmt.Errorf("%w: only 1 question allowed; got %d", errQuestion, qlen)
	}

	reqQ, respQ := req.Question[0], resp.Question[0]

	if reqQ.Qtype != respQ.Qtype {
		return fmt.Errorf("%w: mismatched type %s", errQuestion, dns.Type(respQ.Qtype))
	}

	// Compare the names case-insensitively, just like CoreDNS does.
	if !strings.EqualFold(reqQ.Name, respQ.Name) {
		return fmt.Errorf("%w: mismatched name %q", errQuestion, respQ.Name)
	}

	return nil
}
