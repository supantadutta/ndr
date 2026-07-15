# Astra NDR — Tuning Guide

Tuning reduces noise without hiding attacker behavior. Astra makes every knob explicit
and every suppression auditable.

## Where the knobs live

- **Rule thresholds** — `DetectionRuleDef.Thresholds` (e.g. `distinct_ports`,
  `min_queries`, `max_interval_cv`, `min_bytes_out`). Overridable per deployment; changes
  are versioned (`detection_rule_versions`) and logged (`detection_tuning`).
- **Coverage** — internal/external/excluded/dropped CIDRs, DNS allowlist, domain
  controllers, critical assets, zones. Dropped CIDRs are discarded at ingest; excluded
  CIDRs bypass detection.
- **Asset criticality & group importance** — raise/lower urgency for the right assets.
- **Triage filters & allowlists** — suppress a detection type / entity group / IP range /
  domain / port / protocol / sensor / account / RPC UUID / named pipe / threat-intel
  actor, for a time range, with a reason and an owner.

## Triage actions

Close benign · close remediated · mark expected behavior · create triage filter from a
detection · create allowlist from a detection · suppress score contribution (keep
visibility, remove scoring impact) · assign owner · add note · escalate · reopen · bulk
triage. **All triage changes are audited.**

## Safe-tuning principles

1. **Suppress the smallest thing that removes the noise** — prefer a specific tuning
   field (from the detection's `TuningFields`) over disabling a whole rule.
2. **Keep visibility by default** — "suppress score contribution" retains the record for
   hunting while removing prioritization pressure.
3. **Never silently hide attacker behavior** — the (Phase 5) AI assistant warns when a
   proposed filter would mask activity that looks malicious, and never suppresses
   anything without analyst approval.
4. **Everything is reversible and logged** — filters/allowlists can expire and are
   attributed to an owner.

## Reading a detection for tuning

Each detection ships **false-positive considerations** and **tuning fields** — the exact
fields a filter should match. Start there: they tell you both *why it might be benign*
and *what to scope a filter to*.
