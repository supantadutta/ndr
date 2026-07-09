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

## Rules (12, Phases 1–3)

| Rule id | Family | MITRE | Signal |
|---------|--------|-------|--------|
| `recon.internal_port_scan` | Reconnaissance | T1046 | distinct ports/hosts fanout from one internal host |
| `c2.dns_tunnel_indicators` | Command & Control | T1071.004 | long / TXT-heavy queries to one domain |
| `c2.beaconing` | Command & Control | T1071.001 | low-variance periodic external connections |
| `c2.rare_external_destination` | Command & Control | T1071 | repeated connections to a near-unique external destination |
| `cred.bruteforce_then_success` | Credential Access | T1110 | failure burst → success, same account/source |
| `cred.password_spray` | Credential Access | T1110.003 | failures across many distinct accounts from one source |
| `lateral.admin_share_access` | Lateral Movement | T1021.002 | C$/ADMIN$ writes across internal hosts |
| `lateral.internal_fanout` | Lateral Movement | T1021 | one host → many internal hosts over 445/3389/22 |
| `lateral.remote_access_spread` | Lateral Movement | T1021 | RDP/SSH from one host to several internal hosts |
| `exfil.large_upload_rare_destination` | Exfiltration | T1048 | upload-dominated volume to a rarely-contacted destination |
| `policy.cleartext_external` | Policy / Exposure | T1048.003 | FTP/Telnet/plain-HTTP to an external destination |
| `signature.high_severity_ids_alert` | Signature (IDS) | T1071 | high-severity Suricata match, correlated with behavior |

Rules span behavioral, statistical, rule, and signature engine kinds. Each is
individually **enable/disable**-able and its thresholds are **tunable at runtime**
through the Detection Engineering API/UI (`store.RuleThreshold` reads live config, so a
change takes effect on the next analysis cycle without a rebuild).

## Behavioral baselines

`Baselines.fs` provides the statistical foundation rules build on: `mean`/`stddev`,
`median`/`mad`, classic and **robust z-score**, `percentile`, **frequency rarity**, a
streaming **EWMA** accumulator (mean + variance + decay), and **time-of-day
histograms** for off-hours detection. `judgeNumeric` returns an `AnomalyVerdict`
(is-anomalous + score + baseline/observed descriptions) that a rule can drop straight
into its evidence and baseline-comparison fields.

## Triage suppression & re-fire prevention

A detection an analyst closes (benign/remediated) or that a **triage filter** matches is
marked suppressed: the scoring engine excludes it, and dedup treats it as
already-handled so the next analysis cycle does **not** re-raise it. Every triage and
tuning action is written to the audit log.

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
