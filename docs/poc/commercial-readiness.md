# Commercial and strategic readiness

Spec `54a7bc67140b39c9107216cd390dd47c1d42946d` · Witness `a78b609685b9e002efad666c66e6ff3ad1122b8f` · 2026-11-24

**Every statement in this file is a HYPOTHESIS unless marked [VERIFIED].**
- No market sizes, prices or revenue figures are given, because none have been researched.
- No organization has been contacted.
- Nothing here assumes interest from Cloudflare or any other company.

## 1. Where we stand [VERIFIED]

- **Open source:** `kiss-protocol` is public, MIT-licensed (`LICENSE`: "MIT License, Copyright (c) 2026 Chris Howard"). GitHub's license detector reports `none`, probably because of the file's form.
- **Releases:** signed releases (cosign keyless), CycloneDX SBOMs and build provenance from v3.4.0.
- **Public standards record:** SGAIL issues #148–#155 on the Proof-of-Control standard. Two of them rest on defects found, fixed and disclosed in our own verifier.
- **Conformance:**
  - no conformance statement; no complete tier (tier-assessment.md);
  - matrix: 2 PASS, 49 PARTIAL, 64 FAIL, 10 N/A, 2 UNCLEAR of 127.
- **Gate:** source-only and untested outside simulation.
- **Users:** one internal deployment (the OptiPlex test host). No external users or customers are known from the repository.

## 2. Opportunities

| Opportunity | Potential customer | Customer problem | Existing alternatives | Proposed differentiation | Technical prerequisites | Commercial prerequisites | Operational obligations | Security and liability risks | Evidence required before approaching customers |
|---|---|---|---|---|---|---|---|---|---|
| **Open-source adoption** | Teams deploying AI agents on their own hosts; standards participants | Need evidence of what agents did that others can check | Agent receipt logs (SHACKLE, The Membrane, halo-record, AI Identity, per the PoC threads); Sigstore/Rekor for supply chain; SIEM logs | Host-level evidence (drift, process identity) plus a decision gate in one small, signed, static binary | Tier 2 conformance statement; published schema; clean-room verifier (interop (b)) | Clear licensing (§3); contribution policy | Issue triage; security advisories (SECURITY.md exists) | Over-claiming tier status (8.1.4) | Published conformance statement; at least one outside user's verification run |
| **Paid enterprise integration** | Operators with regulated agent workloads (finance, healthcare, public sector) | Auditable control evidence for agent actions | SIEM plus audit logging; vendor attestation services (Tier 2 by the draft's own rules) | Third-party-verifiable evidence (once Tier 3 work lands); fail-closed gate for value-moving actions | Gateway (T3-5); co-signing; key custody (PIV/HSM) | Contracts, SOWs, pricing model | Integration support; incident response | Integration errors presented as "proof"; evidentiary reliance | A working demo (cloudflare-edge-feasibility §2) plus an outside verification run |
| **Commercial support** | Adopters of the open-source witness | Upgrade, hardening, key handling | In-house teams | Authors of the implementation and of standards issues | Stable releases and LTS policy | Support terms, SLA | On-call | SLA breach | Real adopters |
| **Independent witness service** (co-signing checkpoints) | Log operators needing Tier 3 independence | A log they run themselves is Tier 2 (C8:71; 8.1.3) | transparency.dev / C2SP witness network (Google's production witness "in progress"); Cloudflare's Plexi model (WhatsApp KT) | A witness that understands host-evidence logs and PoC tokens; operationally independent of the log operator | Co-signature protocol; consistency proofs; key ceremony; monitoring | **Independence is the product:** governance that makes SGAIL demonstrably independent of its customers | 24/7 availability; key custody; public transparency of our own witness | A compromised or colluding witness undermines customers' claims; liability for a wrong co-signature | Our own witness operating publicly for months with a published key and uptime record; a third-party audit of the witness |
| **Hosted verification infrastructure** | Relying parties and auditors | Checking evidence without running tooling | Self-run verifiers | Clean-room verifier, multi-format (PoC tokens + Witness) | Interop (b); hardened public service | Terms of service | Availability | A hosted verifier is itself a trusted party (scenario 6) and adds no Tier 3 value unless the verifier is reproducible locally | Open-source verifier first; hosted is a convenience only |
| **Security testing and conformance assessment** | Implementers preparing PoC claims | Need assessment against 127 rows and the attack set | Other self-assessors in the thread (Aqua SDK, VERITON); future third-party assessors | This Phase 1 method (clean-room, black-box vectors and attacks, probe tests) | A published methodology; the C07 probe suite on main | Assessor independence; possibly accreditation if the WG defines it | Reports, re-assessment cycles (10.3.5) | Conflict of interest if we also sell the implementation; assessing competitors | An assessment of our own system that an outside party reproduces |
| **Technology licensing** | Vendors embedding evidence or gating | Build-versus-buy | MIT code is already free to embed | Mostly none while MIT; licensing value would lie in non-public components | A decision on which components (if any) stay non-open | Legal review (§3) | — | Community trust if licensing changes | Not recommended before adoption |
| **Infrastructure partnerships** (e.g. edge platforms such as Cloudflare) | Platform providers | Making their own logs third-party-verifiable | Platform-native logging; their own transparency work (Azul, Plexi) | A reference integration; standards participation | The §2 demo in cloudflare-edge-feasibility.md, built and benchmarked | Partnership terms; an NDA only if needed (verification tooling must stay NDA-free per 8.1.8) | Joint support boundaries | Dependence on one platform contradicts the multi-operator requirement (SD-11) | A working, measured demo, plus a second non-platform co-signer |

## 3. Is independent witness operation a meaningful service? [HYPOTHESIS]

**For:**
- The draft caps any operator-run log at Tier 2 (C8:71; 8.1.3).
- Tier 3 needs evidence "anyone can verify" with residual parties named, and the thread converges on independent co-signers or monitors as the accepted route (#114, #123, Leva's #87 self-assessment).
- Every implementer who wants Tier 3 needs at least one party they don't control. That is a structural need, not a feature preference.

**Against, and open questions:**
- Witnessing is cheap to run, so the value is in **demonstrated independence and longevity**, which takes time to build.
- Public, free witness networks exist (transparency.dev / C2SP).
- The WG has not defined how many independent operators are required (SD-11).
- A business witness must avoid becoming a single trusted party itself.

**Evidence needed before treating it as a business:**
1. Our own public witness running with a published key and uptime history.
2. At least one outside log co-signed.
3. A WG resolution, or a clear consensus, on the independence test.

## 4. Interoperability with other independent implementations [HYPOTHESIS]

- **SHACKLE** (Dante Bullock, #145):
  - an 82-case decision-gate certification battery, reproduced by an outside reviewer (per his thread).
  - Running our `gate` against a published battery, if its license allows, would give our gate the independent reproduction it lacks (SD-16).
  - License: not checked.
- **VERITON** (Bjørn Vidar Hauge): proposed assessor cases (#148, #151, #152, #154) and reproduced Sergeev's 13-case package (#182). Its cases are natural Phase 2 regression tests for us, credited in commits (issues-and-provenance.md).
- **Aqua SDK** (Tim Bansemer, inblock.io): a full 127-row self-assessment published. Comparing method and results would be useful.
- **Second-verifier authors** (Sankalp Gilda, #170): a clean-room spec-only verifier. Cross-running each other's verifiers on each other's evidence is a cheap, credible interop demonstration.

Any outreach is an external communication and needs SGAIL leadership approval. None has been made.

## 5. Matters for professional legal review

1. **Copyright holder versus operating entity.** `LICENSE` names "Chris Howard". SGAIL's operating entity is SGAIL LLC. Confirm an IP assignment or license from the individual to the LLC before commercial terms.
2. **Contributor ownership.**
   - Commit authors include Chris Howard (several identities), "Codex" (AI tool, 9 commits) and "KISS Bot" (3 commits). Many commits are co-authored by Claude (AI).
   - Ask counsel about copyrightability and ownership of AI-assisted contributions and their effect on licensing.
   - No external human code contributions have been merged (issues-and-provenance.md).
3. **Third-party components:**
   - Pipelock is installed and launched by our installer; check its license and redistribution terms if we ever bundle it.
   - Go module licenses: an SBOM per release lists them.
4. **Names.**
   - "Harborlight" is used by unrelated GitHub projects (e.g. `nextatlas20/harborlight`, observed in search), so check for trademark conflicts.
   - "Proof-of-Control" is the standard's term, restricted by 8.1.4 to Tier 3/4 registered claims. Check whether the stewarding body (Advanced AI Society / LF Decentralized Trust) controls its use.
5. **Liability** for evidence used in disputes or insurance (witness service, assessments): limitation of liability, and disclaimers matching the "execution facts only" rule (7.5.1/7.5.2).
6. **Export controls** on cryptographic software (open source is generally treated differently; confirm for any commercial distribution).
7. **Standards IPR policy:** our filings on the standard repository may be subject to its contribution terms. Confirm before reusing others' proposed text in our products.

## 6. Public open source versus possible future services

| Public today (MIT) | Possible future service (not built) |
|---|---|
| Witness, enforcer, gate source, `gateenforce`, installers, docs | Hosted independent witness (co-signing) |
| Verifiers (`verify`, `verify-export`, `verify-leaves`) | Hosted verification convenience |
| C07 probe tests (on a tag) | Conformance assessment engagements |
| Phase 1 documents (this branch) | Enterprise integration and support |
