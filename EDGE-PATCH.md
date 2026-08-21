# EDGE-PATCH.md — historical marker

This file records only the **first** patch of the fork (`v0.81.4-edge.1`, the
zero-alloc UDP write path).  It is kept for provenance and is not maintained.

**The current list of what this fork carries — every patch, its motivation, its
measured effect, and which upstream releases were reviewed and skipped — lives
in [`README.md`](README.md).**

---

Fork based on v0.81.4 with Zero-Alloc UDP pool.

Patch: `proxy/serverudp.go` — `respondUDP()` replaces `resp.Pack()` (1 alloc)
with `resp.PackBuffer(*pb)` backed by `udpPackPool sync.Pool[*[]byte]` (2048-byte slots).
Buffer returned to pool immediately after synchronous `proxynetutil.UDPWrite`.
Result: 0 B/op, 0 allocs/op on the hot UDP response path.

Benchmark (AMD EPYC 7542, count=5): ~280 ns/op, 0 B/op, 0 allocs/op.
Tag: v0.81.4-edge.1
