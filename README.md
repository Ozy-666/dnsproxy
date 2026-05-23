# dnsproxy (Edge Fork for AdGuardHome)

This is a custom, performance-optimized fork of the original [AdguardTeam/dnsproxy](https://github.com/AdguardTeam/dnsproxy).

## Purpose
Maintained specifically for the `AdGuardHome-edge` project. 

## Custom Modifications
- **Zero-Alloc UDP Write Path**: Implemented `udpPackPool` (`sync.Pool`) in `proxy/serverudp.go` to eliminate heap allocations on the hot UDP path. This provides a measurable performance gain and reduces GC pressure in high-load scenarios.

## Versioning
We maintain specific `-edge` tags based on upstream stable releases. Currently based on **`v0.81.4`** (tag `v0.81.4-edge.1`). The `v0.81.4` upstream base includes a DNSSEC DO-bit cache key fix and QUIC timeout hardening over `v0.81.3`.
