# dnsproxy (dnsdoh.art edge fork)

> **Upstream:** Forked from [AdguardTeam/dnsproxy](https://github.com/AdguardTeam/dnsproxy) (Apache-2.0).  
> **Maintained by:** [Ozy-666](https://github.com/Ozy-666) for the [dnsdoh.art](https://dnsdoh.art) production stack.  
> **Base Version:** `v0.81.4-edge.1` + `edge-udp-pool` patchset.

---

## Purpose

Maintained specifically for the [AdGuardHome-edge](https://github.com/Ozy-666/AdGuardHome-edge-spec) project.  All changes target
the hot DNS query path and are benchmarked on the production host before
deployment.

**This fork is public and free for everyone.**  Every patch here runs in
production on a live, internet-facing resolver under real DDoS and
amplification attacks before it lands on this branch.  Use it, study it, or
cherry-pick individual commits — same license as upstream (Apache-2.0).

## Optimization Highlights

### Zero-Alloc UDP Write Path

`proxy/serverudp.go` — `respondUDP()` replaces `resp.Pack()` (1 heap alloc per
response) with `resp.PackBuffer(*pb)` backed by `udpPackPool sync.Pool[*[]byte]`
(2048-byte slots).  The kernel copies bytes synchronously in `UDPWrite`/`sendmsg`
before returning, so the buffer is returned to the pool immediately with no
correctness risk.

| | ns/op | B/op | allocs/op |
|---|---|---|---|
| Before (`resp.Pack()`) | 255 | 160 | **1** |
| After (`udpPackPool`) | ~282 | **0** | **0** |

### Zero-Alloc TCP/DoT Path

`proxy/servertcp.go` — `tcpPackPool sync.Pool[*[]byte]` with 65537-byte slots
(`[len_hi][len_lo][dns_wire_0..N]`).

- **Read**: `readPrefixedBuf` uses two `io.ReadFull` calls (fixes the original
  `conn.Read` short-read bug in `readPrefixed`).  Body bytes are a zero-copy
  sub-slice of the pool buffer returned after `Unpack`.
- **Write**: `resp.PackBuffer((*pb)[2:])` packs into the pool slot; length
  prefix written into `(*pb)[0:2]`; entire frame sent via a single `conn.Write`.
  A `msgLen > dns.MaxMsgSize` guard precedes the prefix write: an oversized
  response cannot fit the pool slot (PackBuffer would allocate `wire` outside
  `*pb`), so the frame is refused with `errTooLarge` rather than truncating the
  uint16 prefix and slicing `(*pb)` out of bounds.

Net result: 4 heap allocs per TCP round-trip → **0**.  Brings TCP/DoT to
performance parity with UDP.

| | ns/op | B/op | allocs/op |
|---|---|---|---|
| Before (4× `make` + `resp.Pack()`) | — | ~512 | **4** |
| After (`tcpPackPool`) | ~251 | **0** | **0** |

### Lock-Free Server State Checks

`proxy/proxy.go` — `Proxy.started bool` converted to `atomic.Bool`.
`isStarted()` previously acquired the global embedded `sync.RWMutex` on every
TCP keepalive iteration.  Under a `Shutdown()` call, the pending write-lock
caused all concurrent `RLock()` callers to queue behind it — a thundering-herd
unblock on restart.  Now a single `p.started.Load()` with no lock.

### Lock-Free Upstream RTT Statistics (Copy-on-Write)

`proxy/proxy.go` + `proxy/exchange.go` — `upstreamRTTStats map[string]upstreamRTTStats`
and its `rttLock sync.Mutex` are replaced with `rttStats atomic.Pointer[map[string]upstreamRTTStats]`
and a narrow `rttMu sync.Mutex` used only by writers.

**Before:** `calcWeights()` (called on every load-balanced query) acquired an
exclusive `sync.Mutex` to *read* the stats map — serializing all concurrent
goroutines at the dispatch point.  `updateRTT()` (called after every upstream
response) acquired the same lock to write a single entry.

**After:**
- `calcWeights()` calls `p.rttStats.Load()` — a single atomic pointer read,
  zero contention, no lock.  The returned snapshot is consistent for the
  duration of the weight calculation.
- `updateRTT()` holds `rttMu` only for the write: loads the current snapshot,
  shallow-copies the map (typically 2–3 entries), updates one entry, and stores
  the new pointer.  Readers see either the old or the new snapshot atomically —
  never a partially-written map.

The shallow copy is proportional to the number of configured upstreams (our
production config: 2–3 entries), making the write path negligible.  All 5
sub-cases of `TestProxy_Exchange_loadBalance` pass with `-race` enabled.

### Configurable QUIC Stream Limit (Finding 9.2)

`proxy/config.go` + `proxy/serverquic.go` — `newServerQUICConfig()` previously
set `MaxIncomingStreams: math.MaxUint16` (65535) for both DoQ and DoH3.  A
single QUIC client could open 65535 concurrent streams per connection, each
spawning a goroutine and consuming a slot from the global `requestsSema`,
starving all other clients and protocols.

**New field:** `QUICMaxIncomingStreams int` in `Config`.

**Validation (`resolvedQUICStreams`):**

| Input | Behaviour |
|---|---|
| `0` (unset) | Default 64, no log |
| `[1, 1024]` | Used as-is |
| Outside range, non-zero | Warn log + default 64 |

Both the DoQ listener (`listenQUIC`) and the DoH3 listener (`listenH3`) use
the validated value.  QUIC flow control (`MAX_STREAMS` frame) now rejects
excess streams at the transport layer — no goroutine is ever spawned for
a stream beyond the limit.

**AdGuardHome-Edge wiring:** `QUICMaxIncomingStreams` is exposed in
`AdGuardHome.yaml` under `dns.quic_max_incoming_streams` (schema v35,
`internal/dnsforward/config.go`).  Default is 64.  Leave unset or set to 0
to get the default silently; set to a value in `[1, 1024]` to override.

### Bounded DoH POST Body

`proxy/serverhttps.go` — the `newDoHReq` handler previously called
`io.ReadAll(r.Body)` with no upper bound, acknowledged by an in-tree
`TODO(d.kolyshev): Limit reader.` that was never resolved upstream.

Under a POST flood, each goroutine would allocate memory proportional to the
POST body length until the HTTP `ReadTimeout` fired, causing GC pressure spikes.

Fix: `io.LimitReader(r.Body, dns.MaxMsgSize+1)` caps the read at 65536 bytes.
If the body exceeds `dns.MaxMsgSize` (65535 bytes — the DNS wire-format maximum
per RFC 8484 §4.1), the handler returns `413 Request Entity Too Large` before
calling `Unpack`.  Any legitimate DoH request fits in 64 KB.

### Plain Upstream Connection Pooling

`upstream/plain.go` — `plainDNS.dialExchange` dialed a fresh connection and
closed it on **every** exchange.  When the host resolver forwards every query to
a local upstream (the AdGuardHome-Edge deployment runs with AGH's own cache
disabled and delegates caching to an on-box unbound at `127.0.0.1:5353`), a CPU
profile under a DoT flood — taken *after* the AGH-layer lock contention was
removed, leaving the resolver network-IO bound — showed `net.Dialer.DialContext`
at **~19% of all CPU**: pure per-query `socket`/`connect`/`close` syscall
overhead, the single largest avoidable cost remaining.

**Fix.** A per-upstream, per-network LIFO connection pool (`idleUDP`/`idleTCP`).
A connection is removed from the pool for the **exclusive** duration of one
exchange (write + read) and returned only after a clean, validated response —
never shared concurrently, which would let DNS responses cross-talk between
in-flight queries (a pooled UDP socket read could return another goroutine's
reply).  A pooled connection that errors (stale: upstream restart or idle
keep-alive close) is discarded and the exchange retried once with a fresh dial,
folding in the existing `isExpectedConnErr` retry.  The pool is bounded
(`maxIdlePlainConns = 1024` per network; overflow connections are closed on
return) and drained on `Close`.

Feature-flagged: `DNSPROXY_PLAIN_POOL=0` restores the original dial-per-query
behaviour.

**Result (A/B, identical DoT loopback ramp, deployed AGH-Edge host):**

| concurrency | answers/s before | answers/s after | Δ |
|---|---|---|---|
| c=100 | 10,672 | 14,975 | **+40%** |
| c=200 | 7,319 | 11,110 | **+52%** |
| c=400 | 4,775 | 9,605 | **+101%** |
| c=600 | 3,196 | 6,126 | **+92%** |

Re-profiled, `DialContext` is gone and total CPU *fell* (245% → 216%) while
throughput roughly doubled — the per-query dial was a blocking `connect()`
serialization, not merely CPU.  Connection-count sampling confirmed the upstream
sockets plateau at a bounded count per concurrency level and are reused, instead
of churning thousands of dials per second.  The remaining CPU is genuine work:
the downstream TLS response write and the upstream exchange.

### Clamped EDNS0 UDP Payload Size (Anti-Amplification)

`proxy/dnscontext.go` — the EDNS0 UDP buffer size a client advertises is now
honored only up to **1232 bytes** (`maxAdvertisedUDPSize`, the
[DNS Flag Day 2020](https://dnsflagday.net/2020/) recommendation) for
plain-UDP responses.  Both the truncation limit (`dnsSize`) and the OPT size
echoed back to the client (`calcFlagsAndSize` → `scrub`) are clamped; the
resolver never advertises more than it honors.

Motivation: a live reflection campaign against the production host sent
spoofed-source queries advertising **bufsize 10000** to reflect 2,257-byte TXT
answers at victims (31.8× amplification).  With the clamp, the same query
yields a ≤1232-byte `TC=1` answer: real clients transparently retry over TCP
and get the full response; spoofed sources cannot complete a TCP handshake, so
the reflection dies.  TCP, DoT, DoQ and DoH are connection-verified and
unaffected — full-size answers still flow there.

This complements the response-rate-limiting (RRL) layer in AdGuardHome-Edge
(spec §7.18): RRL kills the bulk of a flood; the clamp caps the blast radius
of whatever budget RRL still answers.

### DoT ALPN ("dot")

`proxy/servertcp.go` — `initTLSListeners` now offers the
[RFC 7858](https://www.rfc-editor.org/rfc/rfc7858#section-6) ALPN token `dot`
on DNS-over-TLS listeners.  Upstream hands `p.TLSConfig` to `tls.NewListener`
unchanged, so the DoT listener negotiates no ALPN at all, while the HTTPS and
QUIC listeners clone the same config and set their own `NextProtos`.

Motivation: a resolver publishing DDR/SVCB designations
([RFC 9461](https://www.rfc-editor.org/rfc/rfc9461),
[RFC 9462](https://www.rfc-editor.org/rfc/rfc9462)) advertises `alpn="dot"` for
its port-853 TCP endpoint, and the handshake never confirmed the token it had
just promised.  Verified on the production host before and after:

```
# before
$ openssl s_client -connect <resolver>:853 -alpn dot </dev/null | grep ALPN
No ALPN negotiated

# after
$ openssl s_client -connect <resolver>:853 -alpn dot </dev/null | grep ALPN
ALPN protocol: dot
```

ALPN remains optional for DoT: RFC 7858 Section 3.1 forbids rejecting a
connection that does not use it, and Go honors that — a client sending no ALPN
extension still connects, verified against three client stacks.  The one
behavior change is RFC 7301 conformance: a client that offers an ALPN list with
no token in common is now refused rather than silently accepted.

### AA Bit Cleared on Relayed Responses

`proxy/proxy.go` — `handleExchangeResult` clears the `AA` (Authoritative
Answer) flag on responses received from an upstream.  A forwarding resolver is
not authoritative for anything it relays, and passing the bit through lets a
downstream client believe the answer came from the zone's authoritative server.
Upstream fix for AdGuardHome issue #7955, taken as `35baa86`.

### FORMERR Instead of a Silent Drop (JIGGLE Mitigation)

`proxy/serverudp.go`, `proxy/proxy.go` — a UDP packet whose DNS header parses
but whose body does not is answered **FORMERR** rather than dropped, and a
request whose question count is not exactly 1 gets FORMERR rather than
SERVFAIL, per [RFC 1035 §4.1.1](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1).
This is the GHSA-p5f5-3p5g-rfjw (JIGGLE) mitigation, hand-merged here against
the fork's `respondUDP`, which carries the pooled pack buffer and a different
signature.

Note for anyone tracking the advisory: the upstream commit *named* for JIGGLE
contains only the regression test and a Go bump; the mitigation itself is a
separate commit.

Answering a malformed packet deserves scrutiny on a host that has been used for
reflection.  It cannot amplify: a question that fails to parse is not echoed
back, so the reply is smaller than the packet that triggered it.  Measured on
the production host, a 33-byte malformed query drew a 12-byte response —
**0.36×**, a deamplifier:

```
reply 12 B  (request was 33 B)   rcode=1 (FORMERR)  qr=1 aa=0
qd=0 an=0 ns=0 ar=0
```

The reply is emitted inside dnsproxy, before the host's rate-limiting layer
sees it; a packet-filter layer covers that gap independently.

### DoQ Refuses Unidirectional QUIC Streams

`proxy/serverquic.go`, `proxy/serverhttps.go` — `newServerQUICConfig` is now
DoQ-only and sets `MaxIncomingUniStreams: -1`; DoH3 moves to its own
`newServerDoH3Config`, which keeps the unidirectional allowance it genuinely
needs for the HTTP/3 control stream and the QPACK encoder/decoder streams
(≥3 per [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114)), plus this fork's
configurable bidirectional limit.

This is the fix for **GHSA-w6v6-f44j-3rj2** ("DoQ unidirectional stream state
exhaustion", patched upstream in v0.83.1).  A client can open only the
highest-numbered unidirectional stream; under QUIC stream-ID semantics every
lower-numbered stream of the same type is then considered open, so quic-go
materialises receive-stream state for all 65,535 of them, and dnsproxy — which
never accepts or cancels them — holds that state until the connection closes.

This fork was already partly shielded: `f9ab1de` had bounded the limit at 64
against upstream's `math.MaxUint16`, capping the vector before the advisory
published.  Refusing the streams outright is strictly better for DoQ, which
reads none of them.  Landed here as `df16938` on 2026-07-31, before the
advisory was published on 2026-08-18.

## Versioning

The fork is based on upstream stable releases and extended with edge commits on
the `edge-udp-pool` branch.

| Tag | Upstream base | Notes |
|---|---|---|
| `v0.81.4-edge.1` | `v0.81.4` | DNSSEC DO-bit cache key fix, QUIC idle timeout hardening |

**Branch `edge-udp-pool` commits on top of `v0.81.4-edge.1`** (in order):

| Commit | Description |
|---|---|
| `bbd79ad` | `atomic.Bool` for `Proxy.started`; `tcpPackPool` zero-alloc TCP/DoT path |
| `0b14b22` | `rttLock` mutex → `atomic.Pointer` CoW map (lock-free RTT reads) |
| `00fc061` | DoH POST body bounded to `dns.MaxMsgSize` via `io.LimitReader` |
| `716e780` | `QUICMaxIncomingStreams` configurable field, default 64, range [1,1024] |
| `f9ab1de` | `MaxIncomingUniStreams` decoupled from the bidi cap (fixed 64) so a low DoQ limit can't break DoH3 control/QPACK streams |
| `4728330` | `respondTCP` oversized-response guard (`msgLen > dns.MaxMsgSize` → `errTooLarge`); closes uint16 prefix truncation + out-of-bounds reslice panic (audit H2) |
| `7363632` | Plain UDP/TCP upstream **connection pool** (reuse instead of dial-per-query); eliminates ~19% per-query `connect()` CPU; goodput ≈ doubled at high concurrency. `DNSPROXY_PLAIN_POOL=0` to disable |
| `e1cef22` | **EDNS0 UDP payload clamp to 1232** (DNS Flag Day 2020, anti-amplification): honored truncation size and echoed OPT size both capped for plain UDP; TCP/DoT/DoQ/DoH untouched |
| `14c4d5b` | **RFC 7858 `dot` ALPN on DoT listeners**: upstream negotiated no ALPN on port 853 while advertising `alpn="dot"` in its DDR/SVCB designation; ALPN stays optional per RFC 7858 §3.1 |
| `1e17078` | `logDNSMessage` skips `Msg.String()` unless debug logging is enabled — the formatting cost was paid on every query regardless of level |
| `3927e02` | UDP listener sharded into **SO_REUSEPORT** sockets, one per core; the kernel spreads incoming datagrams instead of funnelling them through a single socket queue |
| `6645070` | Requests cache **sharded** to split the global cache lock |
| `7363632` | (see above) plain upstream connection pooling |
| `71dc552` | Diagnostic watchdog for malformed question names |
| `b74b7bb` | Client connection resets logged at Debug rather than Error — a reset peer is not a server error, and at flood volume the log itself became the load |
| `25d8f46` | **DoH upstream response body bounded** (`io.LimitReader`) before parsing — upstream AGDNS-4074 |
| `ad5e739` | `golang.org/x/net` bumped to v0.55.0 (GO-2026-5026) |
| `2c1f097` | **DoH upstream validation** hardened: message ID zeroed in the wire bytes, ID-0 echo required, question-section validation unified with plain DNS (upstream AGDNS-4080, GHSA-4qjf-2hgm-92q6) |
| `35baa86` | **AA bit cleared** on relayed upstream responses (AdGuardHome #7955) |
| `c9d9863` | **FORMERR** for malformed UDP and for a question count ≠ 1, instead of a silent drop / SERVFAIL — GHSA-p5f5-3p5g-rfjw (JIGGLE) |
| `df16938` | **DoQ refuses unidirectional QUIC streams** (`-1`); DoH3 split into `newServerDoH3Config` — GHSA-w6v6-f44j-3rj2, landed here 18 days before the advisory published |

The fork module path remains `github.com/AdguardTeam/dnsproxy` (unchanged from
upstream) so it integrates via a `go.mod replace` directive in the host repo:

```
replace github.com/AdguardTeam/dnsproxy => ../dnsproxy
```

Builds must be run from the AdGuardHome-Edge repo root with this fork checked
out at `../dnsproxy`.  A remote versioned replace does not work because the
fork's `go.mod` declares the original module path, not the fork's.

## Upstream Tracking

This fork tracks upstream by **review**, not by merge.  Upstream releases are
read commit by commit; what applies is ported by hand onto the patched code and
what does not is recorded with a reason.  The base version therefore stays where
the code is, and is not bumped to advertise currency.

| Reviewed | Upstream | Outcome |
|---|---|---|
| 2026-07-31 | releases up to `v0.83.0` | Three patches taken: `35baa86`, `c9d9863`, `df16938`.  The DNSCrypt-upstream validation work was skipped — the consuming deployment speaks plain DNS to a local DNSCrypt process, so this code never runs there. |
| 2026-08-21 | `v0.83.1` … `v0.84.1` | **Nothing taken.**  The range is four commits: a DNS64 CNAME/DNAME chain fix (#438), a `dnsproxytest` helper package, a Go bump, and `AGDNS-4357`, which unexports every field of `proxy.Proxy`.  That last one is a breaking API change through the exact surface this fork patches — the pooled UDP write path, the QUIC server config, the rate-limit and cookie hooks — with no security content behind it.  The DNS64 fix is unreachable in the consuming deployment (`use_dns64: false`).  GHSA-w6v6-f44j-3rj2, patched upstream in `v0.83.1`, was already answered here by `df16938`. |

### Constants mirrored downstream

`maxAdvertisedUDPSize` (1232, `proxy/dnscontext.go`) is **mirrored** in the
consuming AdGuardHome fork's `internal/dnsforward/msg.go`, which clamps the
EDNS(0) buffer size it echoes on responses it generates itself (blocked answers,
NXDOMAIN, REFUSED, SERVFAIL, NODATA, FORMERR).  Upstream AdGuard Home echoes the
client's raw advertised size there; that would advertise a buffer this fork
never honours, on exactly the responses cheapest for a reflector to trigger.

If this constant changes, change it in both places.

---

## License & Attribution

* **Original Work:** Copyright (c) 2017-2026 AdGuard Team, licensed under the [Apache License 2.0](LICENSE).
* **Edge-Fork Modifications & Optimization Patches:** Copyright (c) 2026 **Ozy-666** [https://dnsdoh.art](https://dnsdoh.art), licensed under the [Apache License 2.0](LICENSE).
