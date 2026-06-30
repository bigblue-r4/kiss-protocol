# Prior Art — Sentinel / Witness / Bigblue

> Curated open-source architectural cousins to Harborlight. Each entry documents what it does,
> how it relates to this codebase, and whether it is a slot-in candidate, a diff target, or a
> citation baseline.

---

## 1. microsoft/agent-governance-toolkit

**Repo:** https://github.com/microsoft/agent-governance-toolkit

Closest architectural cousin to Bigblue overall. Every tool call, message send, and delegation
is intercepted in deterministic application code before the model's intent reaches the wire —
actions the kernel denies are structurally impossible, not just discouraged. The policy decision
runtime is a stateless, fail-closed Rust core.

**Relevance to Harborlight:**
The ephemeral-tool forge (create / register / destroy, no persistent pool) needs a policy
enforcement gate. This toolkit's policy layer is a candidate for that gate rather than building
enforcement from scratch. The stateless fail-closed design matches Harborlight's own posture:
the witness log is append-only and the core process has no network listeners precisely so that
a compromised downstream component cannot silence the record.

**How to apply:** Evaluate as the policy enforcement layer in front of the forge pool before
rolling a custom gate. The Rust core is extractable independently of the broader toolkit.

---

## 2. RightNow-AI/OpenFang (Rust agent OS)

**Repo:** https://github.com/RightNow-AI/OpenFang

Implements a Merkle hash-chain audit trail where each entry chains to the previous via SHA-256,
making it impossible to modify or delete historical actions without breaking the chain. Rust-native
and action-level in granularity (not conversation-level), which matches what `internal/store` and
`internal/merkle` already do.

**Relevance to Harborlight:**
Use as a structural diff target against the Harborlight hash-chain implementation
(`internal/store` — uint32 len + AES-GCM wire format; `internal/merkle` — Merkle tree with
`PrevRoot` head chain). The comparison may surface gaps in the chain-continuity proof or the
adversarial-append path before the SGAIL server build.

**How to apply:** Diff OpenFang's chain verification logic against `internal/merkle/fuzz_test.go`
(ProveVerify, VerifyAdversarial harnesses). Where OpenFang's model is stronger, adopt it; where
Harborlight's AES-GCM envelope adds properties OpenFang lacks, document them for the SBIR writeup.

---

## 3. AgentSeal (MCP server)

**Repo:** https://github.com/AgentSeal/AgentSeal

Purpose-built for cryptographic audit trails for AI agents, exposed as an MCP server. Provides
a reference implementation for surfacing audit data over MCP to downstream consumers (dashboards,
compliance tools) without the integrator building the MCP protocol layer.

**Relevance to Harborlight:**
The Witness JSONL store and Sentinel telemetry bus already produce the audit data. AgentSeal
is a candidate MCP adapter layer — expose the same signed Merkle leaves over MCP to downstream
consumers without building the protocol from scratch.

**How to apply:** If the Sentinel server build adds a dashboard or external-consumer API, use
AgentSeal as the MCP layer rather than implementing MCP transport manually. The cryptographic
audit trail is already Harborlight's — AgentSeal adds the protocol adapter only.

---

## 4. Meta LlamaFirewall

**Repo:** https://github.com/meta-llama/LlamaFirewall

Academically documented layered guardrail pipeline integrating prompt injection mitigation
directly into a security-focused stack (not general content-safety). Builds on NeMo Guardrails
and Llama Guard. Described in a published paper with reproducible benchmark numbers.

**Relevance to Harborlight:**
Not a code import. Useful as a named baseline against which to position Harborlight's
zero-false-positive claim on the CyberEC dataset in the DHS SBIR writeup. LlamaFirewall is
the most credible academic prior for layered injection defense; citing it and then showing
Harborlight's Stage 0–2 precision numbers on the same attack taxonomy gives the comparison
a peer-reviewed anchor.

**How to apply:** Cite in the SBIR narrative when positioning Bigblue's layering decisions.
Use the LlamaFirewall attack taxonomy table as the classification framework for Harborlight's
threat model section — it provides a shared vocabulary reviewers will recognise.

---

## Architectural synthesis

| Tool | Relationship to Harborlight | Action |
|---|---|---|
| agent-governance-toolkit | Policy enforcement gate pattern — stateless, fail-closed Rust | Evaluate as forge gate before rolling custom |
| OpenFang | Merkle chain diff target — same granularity, same language | Diff against `internal/merkle` fuzz harnesses |
| AgentSeal | MCP protocol adapter for Witness JSONL | Use for Sentinel server MCP exposure |
| LlamaFirewall | SBIR citation baseline — precision comparison anchor | Cite in narrative; borrow attack taxonomy |
