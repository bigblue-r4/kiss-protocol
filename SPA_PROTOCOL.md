# SpaProtocol

_Version: 1.0_

---

## What it is

SpaProtocol is a session-hygiene pattern for long-running AI agent workflows.

It defines when and how to reset an agent session to prevent drift — and how to preserve enough state that the agent can resume immediately without losing work.

---

## Core principle

**Drift is maintenance, not failure.**

Long sessions accumulate noise. The agent's context fills, instructions lose salience, and responses gradually become blurrier and less focused. This is expected, not exceptional. SpaProtocol handles it the same way a good system handles memory: intentionally, on schedule, and without drama.

---

## When to trigger a Spa

### Auto-Spa (scheduled)
Trigger after a set number of turns or elapsed time. Recommended:
- Every ~20–40 turns for complex multi-step tasks
- Every ~60–80 turns for simpler or repetitive workflows
- Adjust based on how quickly your agent's context fills

### Manual Spa (operator-triggered)
Trigger when you observe drift symptoms:
- Responses feel slower or blurrier than earlier in the session
- The agent repeats itself or revisits resolved decisions
- Tone, style, or constraints have shifted noticeably
- The agent missed something obvious that was in the original instructions
- You sense the session has gone stale even if you can't point to one thing

Both types follow the same stages.

---

## Protocol stages

### Stage 1 — Save state

Before ending the current session, record a state handoff using `STATE_HANDOFF.json`:

```
task         — the current top-level goal
position     — what has been completed
next_step    — the immediate next action to take on resume
open_questions — anything unresolved that needs attention
confidence   — high / medium / low
notes        — anything the returning agent should know
```

Keep it brief. One sentence per field is enough. The goal is to capture just enough to resume cleanly — not to document everything.

### Stage 2 — Reset context

End or archive the current session. The method depends on your framework:
- Start a new conversation thread
- Clear the context window
- Load a fresh agent instance
- Use your framework's session-reset mechanism

Do not carry over the full prior context. That is the point.

### Stage 3 — Resume from handoff

Start the new session by loading:
1. Your agent's core identity and operating rules (system prompt, persona, etc.)
2. The state handoff from Stage 1

Then continue from `next_step`. Do not re-read the full prior session. Trust the handoff.

---

## What to preserve vs. discard

| Preserve | Discard |
|----------|---------|
| Task and position | Full conversation history |
| Next step | Accumulated working notes |
| Open questions | Prior reasoning chains |
| Core operating rules | Noise and tangents |

The handoff is a distillation, not a transcript.

---

## Adaptive pacing

Optionally, the agent can adjust its pace to operator state:

- **Active engagement** — fast execution mode: direct answers, minimal hedging
- **Quiet or low response rate** — deliberative mode: slower, more considered

This is not required for SpaProtocol to work. It is a useful complement for long-running collaborative sessions.

---

## Important cautions

- **Do not skip the handoff.** A reset without a handoff loses continuity. The agent will restart but not resume.
- **Keep the handoff minimal.** A long handoff defeats the purpose. Five short fields is almost always enough.
- **Resume from next_step, not from re-reading history.** If the handoff is well-written, re-reading the session is rarely necessary.

---

## See also

- `STATE_HANDOFF.json` — the minimal handoff schema
- `examples/manual-reset.md` — worked example of a manual reset
- `examples/auto-spa.md` — worked example of a scheduled auto-reset
