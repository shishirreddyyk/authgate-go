# RFC-001: authgate

**Status:** implemented
**Author:** Sai Shishir Koppula
**Scope:** authentication, authorization, rate limiting and abuse mitigation for an HTTP API

---

## 1. Problem

An API needs four things in front of every request: know who is calling, know what they may do, keep any single caller from consuming the service, and make guessing credentials expensive. These are usually four separate pieces of middleware written at four different times, which is how you end up with a rate limiter that resets at window boundaries and a penalty box that locks out legitimate users.

This document records the decisions, including the ones that cost something.

## 2. Threat model

What this defends against:

| Threat | Control |
|---|---|
| Credential guessing / stuffing | Per-source penalty box with escalating block duration |
| Account enumeration | Identical response for unknown key, wrong secret, disabled key, malformed token |
| Offline attack on a leaked key table | Keys stored as HMAC-SHA256 with a pepper held outside the datastore |
| Single caller exhausting the service | Per-key sliding-window rate limit, shared across replicas |
| Boundary abuse of the rate limiter | Sliding window counter, not a fixed window |
| Parallel-request races on the counter | Increment and read in one Lua script under `EVAL` |
| Silent loss of enforcement | Degradation is explicit: `X-Authgate-Degraded`, fail closed on admin paths |

What it does not defend against, stated so nobody assumes otherwise:

- **Distributed low-and-slow guessing.** Five failures per source per minute is below the threshold; an attacker with 10,000 addresses gets 50,000 attempts an hour. Mitigating that needs per-account failure tracking and reputation data this service does not have.
- **A stolen valid key.** Authentication cannot tell a thief from an owner. Key rotation and anomaly detection live above this layer.
- **Compromise of the process.** The pepper is in memory. Anyone reading process memory has already won.
- **Layer 3/4 floods.** This is application-layer control. It assumes something upstream absorbs volumetric attacks.

## 3. Rate limiting: why sliding window counter

**Rejected: fixed window.** Cheapest to implement, and wrong at the boundary. A caller spends the full budget at 0:59 and the full budget again at 1:00, giving 2x the limit inside two seconds. This is the classic failure and there is a test for it (`TestSlidingWindowSurvivesBoundary`).

**Rejected: sliding window log.** Exact, and stores a timestamp per request. Memory scales with traffic, which is the wrong shape for a control whose job is surviving traffic spikes.

**Chosen: sliding window counter.** Two counters per key, weighted by how much of the previous window is still in view:

```
estimate = previous_count * (1 - elapsed/window) + current_count
```

Two integers per key regardless of rate. The estimate assumes the previous window's traffic was evenly spread, so it can be slightly wrong for very bursty callers. That error is bounded by the previous window's count and never grants more than a full extra window of budget, which is the property that matters.

**Rejected requests still count.** A caller that hits the limit does not earn a free retry budget by being rejected, and an attacker cannot probe the boundary for free.

## 4. Order of operations

`authenticate -> penalty box -> authorize -> rate limit -> handler`

The obvious order puts the penalty box first: it is the cheapest check, so reject blocked sources before doing any cryptographic work. This service does not do that, deliberately.

If the block is applied before authentication, then one attacker guessing passwords from a shared egress address locks out every legitimate user behind it. A control meant to raise the cost of guessing would have handed the attacker a denial-of-service primitive against their neighbours. So a request that authenticates successfully is served even when its source is in the penalty box; only failed attempts are refused.

The cost is one HMAC-SHA256 per request from a blocked source. That is nanoseconds over a 32-byte input. **If credentials were verified with bcrypt or Argon2, this trade would go the other way** and the block would have to come first, because then an attacker could make the service burn milliseconds of CPU per garbage request. The decision follows from the cost of the primitive, not from taste. Covered by `TestPenaltyDoesNotLockOutValidCredentials`.

## 5. Credential storage

Keys are `ag_<id>_<secret>`. The store keeps `HMAC-SHA256(secret, pepper)`, never the secret. The pepper comes from the environment, not the datastore, so a dumped key table is not enough to forge a token.

Verification does the same work whether the key ID exists or not: an unknown ID is compared against a decoy hash rather than short-circuiting. A short-circuit makes response latency an oracle for "is this key ID real", which is free reconnaissance for an attacker deciding where to aim. Every failure path returns one identical error (`TestFailuresAreIndistinguishable`, `TestRejectionsAreShapedIdentically`).

The admin listing returns key IDs, scopes and a 12-character hash prefix. Enough to tell two credentials apart in an audit, useless for forgery (`TestAdminListingNeverReturnsKeyMaterial`).

## 6. Degradation

The counter store is a dependency, and dependencies fail. Two ways to handle that, both defensible:

- **Fail open.** Losing Redis should not take down an API that is otherwise healthy.
- **Fail closed.** Losing Redis means the limit is not enforced, and an unenforced limit on a sensitive path is worse than an outage.

Neither is right everywhere, so it is a per-path policy. Default: fail open, with `X-Authgate-Degraded: true` on the response so the behaviour is visible in logs and dashboards rather than inferred later. Paths matching `FailClosedPrefixes` (default `/admin/`) return 503 instead. The rule is that the gate never quietly stops enforcing (`TestDegradedStoreFailsOpenOnReadsAndClosedOnAdmin`).

## 7. Redis client

The service speaks RESP directly rather than importing a client library. Four commands are needed: `EVAL`, and inside the script `INCR`, `PEXPIRE`, `GET`. The client is roughly 200 lines, has no dependency tree, and CI runs with nothing to fetch.

The trade: no pipelining, no cluster support, no pub/sub, one connection guarded by a mutex. At one round trip per request that is adequate, and if this needed Redis Cluster the honest move would be to import a real client rather than grow this one. Tests run against a stub server asserting the exact bytes on the wire (`TestRedisStoreSendsAtomicEvalAndParsesReply`).

## 8. Known limitations

1. **The penalty-box block is cached per replica.** Failure *counts* are shared through the store, so they accumulate correctly across replicas, but the resulting block lives in process memory. A cold replica can be up to one window behind on an in-flight attacker. Moving the block itself into Redis is the fix; it was not done because it adds a round trip to the hot path for a control that is already probabilistic.
2. **Sliding-window estimate assumes even distribution** of the previous window's traffic (section 3).
3. **In-memory counters are single-replica only.** Running two replicas without `AUTHGATE_REDIS` gives each its own budget. The startup log says so.
4. **Client IP comes from `RemoteAddr`.** Behind a proxy this needs a trusted `X-Forwarded-For` parser with a configured hop count. Reading that header without validating the hop count lets a caller spoof its source and evade the penalty box entirely, so the naive version is worse than none.

## 9. Open questions

- Should the rate limit vary by scope, so an admin key gets a different budget than a read key?
- Is per-account failure tracking (in addition to per-source) worth the write amplification? It would close the distributed-guessing gap in section 2.
- Should `Retry-After` on a penalty-box block report the true unblock time? It currently does, which tells an attacker exactly how long their block is. Rounding or flattening the value leaks less but is less useful to legitimate clients recovering from a misconfiguration.
