# dnsproxy (Edge Fork for AdGuardHome)

This is a custom, performance-optimized fork of the original [AdguardTeam/dnsproxy](https://github.com/AdguardTeam/dnsproxy).

## Purpose

Maintained specifically for the `AdGuardHome-edge` project.  All changes target
the hot DNS query path and are benchmarked on the production host before
deployment.

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

## Versioning

We maintain specific `-edge` tags based on upstream stable releases.

| Tag | Upstream base | Key upstream changes |
|---|---|---|
| `v0.81.4-edge.1` | `v0.81.4` | DNSSEC DO-bit cache key fix, QUIC idle timeout hardening |

The fork module path remains `github.com/AdguardTeam/dnsproxy` (unchanged from
upstream) so it integrates via a `go.mod replace` directive in the host repo:

```
replace github.com/AdguardTeam/dnsproxy => ../dnsproxy
```

Builds must be run from the AdGuardHome-Edge repo root with this fork checked
out at `../dnsproxy`.  A remote versioned replace does not work because the
fork's `go.mod` declares the original module path, not the fork's.
