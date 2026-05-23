Fork based on v0.81.4 with Zero-Alloc UDP pool.

Patch: `proxy/serverudp.go` — `respondUDP()` replaces `resp.Pack()` (1 alloc)
with `resp.PackBuffer(*pb)` backed by `udpPackPool sync.Pool[*[]byte]` (2048-byte slots).
Buffer returned to pool immediately after synchronous `proxynetutil.UDPWrite`.
Result: 0 B/op, 0 allocs/op on the hot UDP response path.

Benchmark (AMD EPYC 7542, count=5): ~280 ns/op, 0 B/op, 0 allocs/op.
Tag: v0.81.4-edge.1
