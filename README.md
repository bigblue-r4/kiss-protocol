# SpaProtocol

A lightweight, model-agnostic session-hygiene pattern for long-running AI agent workflows.

---

## The problem

Long agent sessions drift. Instructions lose weight, focus softens, and context fills with noise. By the time the session is far enough in, the agent is technically present but functionally somewhere else.

Most teams treat this as a bug or a failure. SpaProtocol treats it as **routine maintenance**.

---

## The idea

Before a session gets stale:

1. **Save state** — write down the task, position, next step, and open questions
2. **Reset context** — start a fresh session
3. **Resume from the handoff** — reload only what matters and continue

That's it. The agent returns focused instead of drifting.

---

## Contents

| File | What it is |
|------|-----------|
| `SPA_PROTOCOL.md` | The full protocol — triggers, stages, and guidance |
| `STATE_HANDOFF.json` | Minimal schema for the state handoff between sessions |
| `examples/manual-reset.md` | Worked example: manual reset with handoff |
| `examples/auto-spa.md` | Worked example: scheduled reset after turn threshold |
| `LICENSE` | MIT |

---

## Quick start

1. Read `SPA_PROTOCOL.md`
2. Copy `STATE_HANDOFF.json` into your agent setup
3. Before any long-session reset, fill out the handoff fields
4. Start a new session, load only the handoff, and continue

---

## Works with

Any agent framework that supports custom context or session restarts — commercial models, local models, open-source stacks, or custom RAG setups.

No code required. SpaProtocol is a pattern, not a library.

---

## Related projects

SpaProtocol also appears inside the Anne Flint / Sentinel project family as one approach to session hygiene for long-running agent work.

If you want a persona-oriented companion pack built on top of these ideas, see the Anne Flint Essence Pack.

---

## License

MIT
