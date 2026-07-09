# Astra NDR — Detection Engine

Source: [`src/Astra.Server/DetectionEngine.fs`](../src/Astra.Server/DetectionEngine.fs).

## Model

A **rule** implements `IDetectionRule`:

```fsharp
type RuleInput = { Window: NormalizedEvent list; Now: DateTimeOffset; Store: AstraStore }

type IDetectionRule =
    abstract Definition: DetectionRuleDef        // tunable, versionable metadata
    abstract Evaluate: RuleInput -> Detection list
```

The engine runs every enabled rule over a sliding window of recent normalized events
(default 30 min) on the ingestion worker's interval (default 15 s). Rules are:

- **Pure** given their input → unit-testable.
- **Isolated** — a throwing rule is caught; it never stops the pipeline.
- **Deduplicated** — a rule skips entities that already have an open detection for it.
- **Individually tunable** — thresholds live in `DetectionRuleDef.Thresholds` and can be
  overridden per deployment without code changes.

## Every detection is fully explained

`materialize` turns a `DetectionDraft` into a `Detection` carrying:

- identity + MITRE mapping (tactic, technique id/name, kill-chain stage)
- severity / confidence / certainty / threat score / urgency contribution
- affected / source / target / related entities
- **evidence** items (label, value, backing event ids) and evidence references
- **baseline comparisons** (metric, baseline, observed, deviation)
- **why suspicious**, **false-positive considerations**
- **recommended investigation steps** and **recommended response actions**
- **tuning fields** — the exact fields a triage filter could match on
- triage state, status, timestamps

This is what the Detection Center renders, and what the (future) AI assistant cites.

## Starter rules (Phase 1)

| Rule id | Family | MITRE | Signal |
|---------|--------|-------|--------|
| `recon.internal_port_scan` | Reconnaissance | T1046 | distinct ports/hosts fanout from one internal host |
| `c2.dns_tunnel_indicators` | Command & Control | T1071.004 | long / TXT-heavy queries to one domain |
| `c2.beaconing` | Command & Control | T1071.001 | low-variance periodic external connections |
| `cred.bruteforce_then_success` | Credential Access | T1110 | failure burst → success, same account/source |
| `lateral.admin_share_access` | Lateral Movement | T1021.002 | C$/ADMIN$ writes across internal hosts |
| `exfil.large_upload_rare_destination` | Exfiltration | T1048 | upload-dominated volume to a rarely-contacted destination |

Each demonstrates a different engine kind (behavioral, statistical, rule) and a
different combination of evidence, baseline comparison, and rarity/velocity/breadth
signals.

## Detection families (full catalog, delivered across phases)

The architecture defines families A–H from the product spec — Reconnaissance, Command
& Control, Lateral Movement, Credential/Identity, Exfiltration, Malware/Ransomware,
Policy/Exposure/Compliance, and Cloud/SaaS. Phase 1 ships representative rules from
A–E; Phase 3 fills out the catalog and adds the baseline engine that several behavioral
rules depend on.

## Adding a rule

1. Implement `IDetectionRule` with a `mkRuleDef` descriptor and an `Evaluate` that
   returns `DetectionDraft`s built through `materialize`.
2. Register it in `DetectionEngine`'s `rules` list.
3. Add a unit test asserting it fires on a crafted window and stays silent on benign
   traffic (see `docs/` test guidance / `tests/` in Phase 3).

## Signature/IDS layer

Suricata-compatible signature matching (upload rulesets, per-sensor assignment,
enable/disable, thresholds, suppression, rate limiting, CEF/JSON/syslog export, and
IDS-to-behavioral correlation) is modeled in the schema (`detection_rules`,
`ids_alerts`) and delivered in Phase 3.
