# Example: Auto-Spa (Scheduled Reset)

This is a worked example of a scheduled Spa reset triggered automatically after a turn threshold.

---

## Scenario

You are running a long research session. Your agent assists with document review, summarisation, and drafting. You set a rule: reset every 30 turns.

At turn 30, the auto-Spa triggers.

---

## Step 1 — The agent saves state

The agent writes a handoff before context is cleared:

```json
{
  "task": "Review and summarise the Q1 supplier contracts for renewal risk",
  "position": "17 of 23 contracts reviewed. Summaries saved to contracts/summaries/. Contracts 18-23 not started.",
  "next_step": "Begin review of contract 18 — Meridian Logistics (file: contracts/meridian-q1.pdf)",
  "open_questions": [
    "Hargrove contract (contract 12) has an ambiguous auto-renewal clause — flag for legal review before decision."
  ],
  "confidence": "high",
  "notes": "Renewal risk threshold defined as: any contract expiring within 90 days with no renewal clause = HIGH RISK."
}
```

---

## Step 2 — Context resets

The session clears. Prior conversation history, accumulated working notes, and intermediate reasoning are discarded.

---

## Step 3 — Resume

New session loads with:
1. Core instructions: the task brief, the risk-threshold definition, output format
2. The handoff above

The agent picks up at contract 18 without any re-reading of prior work.

---

## Why this works

The handoff contains everything needed to continue and nothing that creates noise. The agent does not need to re-read 30 turns of prior context — it knows exactly where it is, what is next, and what to watch out for.

The Hargrove flag survives the reset because it was written into `open_questions`. Nothing important was lost.

---

## Tip

If you use a tool that supports automated session management, you can make the handoff-save step part of the reset trigger itself — so the agent always writes its handoff before the context is cleared.
