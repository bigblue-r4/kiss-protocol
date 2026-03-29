# Example: Manual Spa Reset

This is a worked example of a manual Spa reset triggered by operator observation.

---

## Scenario

You are 45 turns into a session helping refactor a Python codebase. The agent was sharp early on but has started giving longer, blurrier answers. It also repeated a suggestion you had already rejected two turns ago.

You decide to trigger a manual Spa.

---

## Step 1 — Save state

Before ending the session, you fill out `STATE_HANDOFF.json`:

```json
{
  "task": "Refactor the authentication module to replace session tokens with JWT",
  "position": "auth/session.py and auth/middleware.py are complete. Tests pass. auth/refresh.py not started.",
  "next_step": "Refactor auth/refresh.py — replace session.renew() calls with JWT refresh flow",
  "open_questions": [
    "Should refresh tokens be single-use? Currently undefined — needs decision before auth/refresh.py is done."
  ],
  "confidence": "high",
  "notes": "Do not touch auth/legacy.py — it is intentionally kept for a deprecated API endpoint still in use."
}
```

---

## Step 2 — Reset context

End the current session. Start a new one with a clean context window.

---

## Step 3 — Resume from handoff

Load your agent's system prompt or persona, then add the handoff as the first message:

> "Resuming a session. Here is the current state:
>
> Task: Refactor the authentication module to replace session tokens with JWT
> Position: auth/session.py and auth/middleware.py are complete. Tests pass.
> Next step: Refactor auth/refresh.py — replace session.renew() calls with JWT refresh flow
> Open question: Should refresh tokens be single-use? Needs decision before proceeding.
> Notes: Do not touch auth/legacy.py.
>
> Continue from the next step."

---

## Result

The agent resumes on `auth/refresh.py` immediately, with no drift, no repetition of prior reasoning, and the single open question surfaced at the top where it belongs.
