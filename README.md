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

The fork module path remains `github.com/AdguardTeam/dnsproxy` (unchanged from
upstream) so it integrates via a `go.mod replace` directive in the host repo:

```
replace github.com/AdguardTeam/dnsproxy => ../dnsproxy
```

Builds must be run from the AdGuardHome-Edge repo root with this fork checked
out at `../dnsproxy`.  A remote versioned replace does not work because the
fork's `go.mod` declares the original module path, not the fork's.

---

## License & Attribution

* **Original Work:** Copyright (c) 2017-2026 AdGuard Team, licensed under the [Apache License 2.0](LICENSE).
* **Edge-Fork Modifications & Optimization Patches:** Copyright (c) 2026 **Ozy-666** [https://dnsdoh.art](https://dnsdoh.art), licensed under the [Apache License 2.0](LICENSE).
