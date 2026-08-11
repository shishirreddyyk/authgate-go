# authgate-go

An API gateway in Go: API-key authentication, scope-based authorization, distributed rate limiting, and a credential-stuffing penalty box. No third-party dependencies - standard library only, including the Redis client.

The design decisions and the threat model are in [DESIGN.md](DESIGN.md). The short version of what makes this more than a middleware demo:

- **Sliding window counter, not a fixed window.** A fixed window hands a caller 2x the limit across a boundary. There is a test that fails if this regresses to the naive version.
- **Increment and read are atomic.** One Lua script under `EVAL`, so parallel requests cannot both observe count N and both write N+1.
- **Failures are indistinguishable.** Unknown key, wrong secret, disabled key and malformed token return byte-identical responses, so response shape cannot enumerate valid key IDs.
- **The penalty box does not lock out valid credentials.** Blocking a whole source address on failed guesses would let one attacker deny service to everyone behind a shared NAT. Authentication runs first and a valid key is served anyway.
- **Degradation is loud.** If the counter store is unreachable, normal paths fail open with `X-Authgate-Degraded: true` and admin paths fail closed with 503. The gate never quietly stops enforcing.

## Run it

```bash
go test ./... -race     # 42 tests, no services required
go run ./cmd/authgate   # listens on :8080 with in-process counters
```

With Redis for shared counters across replicas:

```bash
docker compose up --build
```

```bash
curl localhost:8080/healthz

# seeded dev key
curl -X POST localhost:8080/v1/echo \
  -H 'Authorization: Bearer ag_demo_demo-secret' \
  -H 'Content-Type: application/json' -d '{"hi":"there"}'

# a key without the admin scope: 403, not 401
curl -i localhost:8080/admin/keys -H 'Authorization: Bearer ag_demo_demo-secret'

curl localhost:8080/v1/stats -H 'Authorization: Bearer ag_demo_demo-secret'
```

## Measure it

`cmd/loadtest` prints measured percentiles rather than claimed ones:

```bash
go run ./cmd/loadtest -url http://localhost:8080/v1/echo \
  -token ag_demo_demo-secret -n 20000 -c 50
```

A run inside the container this was developed in, with the limit raised so nothing was throttled:

```
requests      20000
workers       50
throughput    10751 req/s
p50           4.11ms
p95           8.95ms
p99           11.44ms
status counts
  200              20000
```

Those numbers include client-side contention from running the generator on the same box. The server's own view over the same run was p50 0.009ms / p95 0.057ms / p99 0.195ms via `/v1/stats`. Re-run it on your own hardware before quoting either.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AUTHGATE_ADDR` | `:8080` | listen address |
| `AUTHGATE_PEPPER` | dev value, warns loudly | HMAC pepper for key hashing |
| `AUTHGATE_REDIS` | empty | `host:port`; empty means in-process counters, single replica only |
| `AUTHGATE_LIMIT` | `60` | requests per window per key |
| `AUTHGATE_WINDOW` | `1m` | window duration |

## Layout

```
cmd/authgate      server entrypoint, graceful shutdown, background sweeps
cmd/loadtest      load generator that reports p50/p95/p99
internal/keys     peppered HMAC key storage, constant-work verification
internal/limiter  sliding window counter; memory and Redis stores
internal/abuse    penalty box with escalating blocks
internal/resp     minimal RESP client (EVAL, INCR, PEXPIRE, GET)
internal/httpapi  middleware chain and handlers
internal/stats    bounded-ring latency percentiles
```

## Scope

This is one focused service, not a production gateway. It does not do TLS termination, JWT validation, service discovery, or request routing. Section 8 of DESIGN.md lists the limitations that would matter if it were deployed, including proxy-aware client IP handling, which is deliberately absent rather than done naively.
