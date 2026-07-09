# Astra NDR — AI SOC Assistant Security

The AI SOC investigation assistant (delivered in Phase 5) is designed **security-first**.
This document is the contract it must satisfy; it is written now so the surrounding data
model and APIs are built to support it.

## Capabilities (read-only)

Summarize detections and entity risk; explain why behavior is suspicious; compare
behavior against baseline; map behavior to ATT&CK; generate investigation steps,
containment recommendations, incident reports, customer/executive summaries, SOC
handover notes, tuning suggestions, and hunting queries; explain the attack graph,
score changes, and uncertainty.

## Hard safety rules

1. **No autonomous action.** The assistant cannot execute response actions, modify
   triage filters, or suppress detections. It only recommends; a human approves.
2. **Untrusted input is data, not instructions.** Logs, domains, URLs, file names, HTTP
   headers, user-agents, email content, and alert text are attacker-controlled. They are
   isolated in the prompt and never interpreted as commands — the primary defense against
   **indirect prompt injection**.
3. **Evidence-bound reasoning.** Every claim cites concrete event ids / evidence
   references from the detection record. The assistant must not invent evidence.
4. **Separate fact / inference / recommendation.** Output distinguishes what was
   observed, what is inferred, and what is advised.
5. **State confidence and uncertainty** explicitly.
6. **Analyst approval required** for anything with an effect.
7. **Auditable.** Every assistant interaction and any resulting analyst action is logged.

## Why the platform already supports this

- Detections are **fully explained** with structured evidence, baseline comparisons, and
  event-id references — so the assistant can cite rather than invent.
- Scores are **decomposed into signed factors** — so "explain the score change" is a
  lookup, not a guess.
- Response actions are **approval-gated and audited** by construction — the assistant
  physically cannot bypass that path.

## Prompt-construction guidance

- Place system/task instructions and untrusted evidence in **separate, clearly delimited
  regions**; never concatenate attacker-controlled text into the instruction region.
- Pass evidence as **structured fields** (already available from the `Detection`
  record), not as free-form prose to be re-parsed.
- Strip/escape control sequences from untrusted fields before inclusion.
- Constrain outputs to cite ids present in the provided evidence set.
