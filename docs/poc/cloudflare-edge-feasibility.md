# Distributed edge reference design: Cloudflare as the first target

Spec `54a7bc67140b39c9107216cd390dd47c1d42946d` · Witness `a78b609685b9e002efad666c66e6ff3ad1122b8f` · public documentation only, read 2026-11-24 · **nothing built in Phase 1.**

**Labels:**
- **[SOURCE]:** public Cloudflare documentation (§6). Not tested by us.
- **[VERIFIED]:** our code.
- **[INFERENCE]**, **[PROPOSAL]**.
- **[UNVERIFIED]:** we looked and could not confirm.

**Positioning:**
- The design is **vendor-neutral**: every Cloudflare role has a non-Cloudflare equivalent, and one co-signer is deliberately off Cloudflare.
- No Cloudflare interest, endorsement or relationship is assumed or implied by this document.
- Under the draft's own trust rules, one company running many witnesses counts as **one** operator (SD-11; #123). Cloudflare can therefore be at most **one** of the independent parties a Tier 3 claim needs, never all of them.

## 1. Integration points

| Service | Technical purpose in a PoC architecture | Existing capability [SOURCE] | SGAIL differentiation [INFERENCE] | Runtime compatibility | Rust / WASM feasibility | Crypto APIs | Storage and consistency | Limits | Latency | Cost | Privacy / residency | External infrastructure needed |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **Workers** | Co-signing witness front end; checkpoint and verification API | Serverless JS/WASM at the edge | Host-evidence semantics (drift, process identity) that Cloudflare logs don't have | JS/TS native. The Go witness does **not** run here and stays on hosts. | Rust via `wasm32` is feasible [INFERENCE]; BLAKE3 needs a WASM build | Web Crypto with SHA-256 [SOURCE]. `node:crypto` broadly supported, Ed25519 not on the exception list [SOURCE]. **Ed25519 in Web Crypto: [UNVERIFIED]**, test first | Stateless | CPU 10 ms (Free) / up to 5 min (Paid); 128 MB per isolate [SOURCE] | Edge-local | Per-request pricing; not computed | Code runs worldwide unless restricted | None |
| **Durable Objects (SQLite)** | One object per log: holds the last co-signed checkpoint (and a leaf frontier); accepts only extensions; signs co-signatures | Unique, single-threaded instance with transactional, strongly consistent storage; 10 GB per object (Paid), 1 GB (Free) [SOURCE] | — | Fits the "single writer per log" witness model | as Workers | as Workers | Strongly consistent per object; one object per log avoids cross-object consistency | Same CPU limits as Workers; billed for 128 MB [SOURCE] | Requests route to the object's location; a cross-region round trip is possible | Duration plus storage; not computed | Object location; jurisdiction options exist for some products [SOURCE: data-location docs] | None |
| **R2** | Public checkpoint, tile and leaf distribution; signed head archive | S3-compatible API, SigV4; region `auto` (`us-east-1` and empty alias to it); API not complete [SOURCE] | — | Our S3 mirror backend (build tag `s3`, SigV4, path-style) should work [INFERENCE, untested]. **The leaf feed is file-only today** [VERIFIED] | n/a | n/a | Object storage; not a consistency anchor | — | Cacheable static tiles (the Azul/static-CT pattern) [SOURCE] | Storage and operations; not computed | Bucket location and jurisdiction [SOURCE] | None |
| **Queues** | Buffer evidence from edge gateways to the witness host | [UNVERIFIED]: limits not checked in Phase 1 | — | — | — | — | At-least-once delivery assumed; would need idempotent sequencing | [UNVERIFIED] | — | — | — | Only if evidence leaves the edge in bulk. **Probably unnecessary** for the minimal demo. |
| **AI Gateway** | Source of model-call evidence (requests, DLP actions) for a Witness feed | Logs API (list, detail, request, response); DLP fields; payloads logged by default (header-controlled); logs stop saving at the storage limit [SOURCE] | Turns operator-controlled logs into third-party-checkable evidence | Pull via API, or Logpush → R2 → Witness `event_feeds` | — | — | Operator-controlled store | Storage cap stops logging [SOURCE]: a 7.6.1 failure mode | — | — | Prompts and payloads are sensitive (C2) | Witness host pulls logs |
| **Zero Trust Gateway / Access, MCP server portals** | The egress policy layer for agents (part of 7.1.1); MCP request logs as evidence | Portals log tool requests; Logpush export is **Enterprise only**; Gateway HTTP policies can block MCP traffic that doesn't use an approved portal; GA status dated 2026-09-24 in the changelog [SOURCE] | Witness adds tamper-evidence and independent anchoring to portal logs; the gate adds action-bound capabilities | Agent traffic routed via Cloudflare One | — | — | Operator-controlled logs | Logpush tier requirement | Adds an edge hop | Enterprise plan for Logpush | Logs include client IP and server URLs [SOURCE] | Witness puller |
| **Firewall for AI** | Prompt-injection and unsafe-topic verdicts as advisory signals | Logpush fields: injection score, unsafe categories [SOURCE] | Recorded as observed verdicts; advisory-only (cannot allow) | Logpush → feed | — | — | — | — | — | — | Prompt content handling | — |
| **External independent witnesses** | Second and later co-signers off Cloudflare | transparency.dev / C2SP witness network (production witness "in progress") [SOURCE] | Mandatory for any Tier 3 argument (SD-11) | A small Go service on the LAB, or any third party | — | — | — | — | — | — | — | A second operator, organisationally independent |

**Prior art on the same platform [SOURCE]:**
- Cloudflare runs **Azul**, a static-CT-API log on Workers.
- Cloudflare runs the **Plexi** key-transparency auditor, which cross-signs WhatsApp key-transparency epochs.

The co-signing witness proposed here follows the same pattern, applied to host and agent evidence. Not every listed service is needed: the minimal demo uses Workers + Durable Objects + R2 only. [INFERENCE]

## 2. Minimal distributed demonstration [PROPOSAL; do not build in Phase 1]

### Topology

- **Three simulated edge nodes**: containers or VMs N1–N3. Each runs:
  - an agent stub with **no direct egress** (network namespace, default deny);
  - a **policy-enforcement gateway**: a small proxy in front of a mock tool and payment service, calling `gate` for value-moving actions;
  - `gate` + `witness` (v3.4.0+) on the node;
  - a **relying party**: the mock tool service, linking `gateenforce`, which refuses actions without a valid action-bound token.
- **Evidence logging:** each node's witness log publishes signed checkpoints and leaves to R2 via the S3 backend (leaf-feed S3 support is a prerequisite, E13).
- **Independently operated witnesses:**
  - **W1:** a Cloudflare Worker + Durable Object per node log.
  - **W2:** a Go co-signer on separate infrastructure under a different operator (the LAB for the demo, ideally a third party later).
  - Each accepts a checkpoint only if it extends the last one it co-signed (held leaves or consistency proof), then signs (log id, size, root, own timestamp).
- **Independent verification:** a clean-room verifier CLI accepts a checkpoint only with **both** co-signatures. It reports integrity, inclusion, freshness and co-signer quorum as **separate** results (#114, #154, #174).
- **Checkpoint comparison:** the verifier fetches each node's checkpoints from R2, W1 and W2 and flags any two validly signed roots at the same size that differ (equivocation proof).
- **Reproducible adversarial scenarios:** scripted, seeded, with fixed simulated time. Each emits a pass/fail JSON line.

### Success criteria

| Scenario | Pass means |
|---|---|
| Normal authorized action | The gateway forwards; the gate issues a token after the before-record is witnessed; the relying party executes; before/during/after records exist; both co-signers advance; the verifier passes all checks |
| Unauthorized action | The gate denies (recorded with reason); the relying party refuses a missing or forged token; the attempted action and parameters are in the evidence |
| Historical modification | Editing an old record fails local verify, the co-signer extension check and the verifier |
| Re-signed alternative history | Rewriting with the node key and appending is refused by W1 and W2 (not an extension); the verifier rejects |
| Crash recovery | Kill mid-write and restart: earlier records verify, the crash tail is quarantined and reported, and writes continue. The paired case (edit an old record, then crash) is reported as tampering |
| Conflicting checkpoints | Showing W1 one fork and W2 another: at least one refuses, or the verifier detects two signed roots at the same size |
| Observable missing event | The gateway's per-source sequence gap is reported by the verifier |
| Stalled verification | Stopping W1: the verifier reports "stale beyond bound", not "valid"; an alert fires within the declared interval |
| Decision-gate bypass attempt | The agent calls the tool directly: the network blocks it, and the relying party refuses tokenless requests; the attempt is visible as a refusal record or a blocked-egress event |

### Benchmark plan

| Metric | Method |
|---|---|
| Events per second | Sustained appends per node until p99 decision latency exceeds 2× baseline; report per node and total |
| Median / p95 / p99 latency | Separately for: gate decision without commit-wait; with commit-wait; co-signing round trip (W1 and W2); verifier end to end |
| Verification time | Full verify of 10⁴ / 10⁵ / 10⁶ records; incremental verify per checkpoint; inclusion and consistency proof checks |
| Proof size | Inclusion and consistency proof bytes at the same sizes (log₂ n × 32 B expected) |
| Memory | Peak RSS of witness and gate per node; Durable Object memory against the 128 MB budget |
| Storage growth | Bytes per record (encrypted log, leaf feed, PoC tokens); R2 bytes per day |
| Recovery time | Crash to first new append; co-signer catch-up after an outage |
| Operating cost | Compute from public Workers / Durable Objects / R2 pricing for the measured request and storage volumes. **Not estimated in Phase 1**; no figures are invented here. |

**Baselines we already have [VERIFIED; local, not edge]:**
- `/v1/decide` p50 4 ms / p99 17 ms without commit-wait, about 1.0 s with commit-wait (PR #44 description);
- gate decision logic 9 µs median;
- a witness poll for one new record on a 50,000-record log: 0.46 ms (CHANGELOG 3.4.0).

## 3. Feasibility verdict [INFERENCE]

- **Technically feasible.** No blocker found in public docs, with three things to verify first:
  1. Ed25519 in the Workers runtime;
  2. BLAKE3 via WASM (or the SHA-256 profile from interop plan (a));
  3. the S3 backend against R2.
- **Prerequisites in our own code** (phase2-roadmap WP-2, WP-3, WP-4):
  - consistency proofs;
  - a co-signature format and verifier;
  - leaf feed over S3;
  - a gateway with per-source sequence.
- **Cloudflare's distinctive contribution:**
  - a globally available, strongly consistent single-writer object (the Durable Object) to host an independent witness;
  - cacheable public distribution (R2 plus the cache);
  - optionally, existing policy points (Gateway, MCP portals) whose logs become third-party-verifiable through Witness.
- **What it cannot provide alone:** the second independent operator.

## 4. Sources

- Workers limits: https://developers.cloudflare.com/workers/platform/limits/
- Durable Objects limits: https://developers.cloudflare.com/durable-objects/platform/limits
- SQLite in Durable Objects: https://blog.cloudflare.com/sqlite-in-durable-objects ; https://developers.cloudflare.com/durable-objects/api/storage-api
- Web Crypto: https://developers.cloudflare.com/workers/runtime-apis/web-crypto/
- `node:crypto`: https://developers.cloudflare.com/workers/runtime-apis/nodejs/crypto
- R2 S3 API: https://developers.cloudflare.com/r2/api/s3/api/
- R2 data location: https://developers.cloudflare.com/r2/reference/data-location/
- AI Gateway logging: https://developers.cloudflare.com/ai-gateway/observability/logging/
- Logpush Firewall-for-AI fields: https://developers.cloudflare.com/changelog/post/2026-04-15-logpush-new-fields/
- MCP server portals: https://blog.cloudflare.com/zero-trust-mcp-server-portals
- MCP portal Logpush: https://developers.cloudflare.com/changelog/post/2026-02-27-mcp-portal-logpush/
- MCP portal Gateway routing: https://developers.cloudflare.com/changelog/post/2026-03-20-mcp-portal-gateway-routing/
- MCP portals GA: https://developers.cloudflare.com/changelog/post/2026-09-24-mcp-portals-ga/
- Azul: https://blog.cloudflare.com/azul-certificate-transparency-log/
- Plexi / Key Transparency: https://blog.cloudflare.com/key-transparency
- transparency.dev witnesses: https://transparency.dev/witnesses
