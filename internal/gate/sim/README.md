# Gate attack simulation

`Env` creates a signed real witness store, three operator keys, a signed
bounded ten-asset policy, the real event-feed bridge, and the real gate daemon
served over its Unix socket. All keys are public test fixtures. The gate feed
exists before the bridge starts; the bridge's witnessed open record establishes
readiness. Tests call `Daemon.Poll` manually and observe committed request
records before releasing commit-waiters. There are no synchronization sleeps.
The injected atomic clock controls freshness without waiting for wall time.

Each numbered test corresponds to the requested reachable acceptance case.
Case 9 uses a signed policy with downtime tick weight zero to isolate evidence
health from the default immediate class trip. Case 22 keeps two requests pending
at commit-wait, fills the caller's inflight cap, trips its principal and host,
and verifies a different principal on a different host still receives a token.

Run without network or dependency downloads:

```
GOPROXY=off go test ./internal/gate/sim -count=10 -timeout=10m
GOPROXY=off go test -race ./internal/gate/sim -count=10 -timeout=15m
GOPROXY=off go test ./internal/gate/sim -run '^$' -bench BenchmarkDecide -benchtime=100x -count=1
```

The benchmark reports nearest-rank `p50-ms` and `p99-ms` for the full
`/v1/decide` socket round trip, including feed fsync and signing, with and
without commit-wait. Commit-wait uses the real bridge and the daemon's default
one-second polling interval. Setup and teardown are excluded. Small sample
counts are smoke tests, not reliable p99 measurements.

Execution requires permission to listen on Unix sockets. A sandbox that blocks
`setsockopt` cannot run these acceptance tests or measure these latencies.
