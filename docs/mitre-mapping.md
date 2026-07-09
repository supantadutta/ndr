# Astra NDR — MITRE ATT&CK® Mapping

Astra maps every detection to the public **MITRE ATT&CK** taxonomy. Types are in
[`src/Astra.Shared/Mitre.fs`](../src/Astra.Shared/Mitre.fs).

> ATT&CK tactic and technique identifiers are public references. Astra's mapping,
> explanations, evidence and response guidance are original.

## What each detection carries

- **Tactic** (`MitreTactic` DU — all 14 tactics)
- **Technique id** (e.g. `T1046`) and **technique name**
- **Kill-chain stage** (`KillChainStage`) with an ordinal used by scoring for
  progression modifiers
- Technique explanation, evidence fields, investigation steps, response steps
  (carried on the `Detection`)

## Phase-1 coverage

| Technique | Name | Tactic | Rule |
|-----------|------|--------|------|
| T1046 | Network Service Discovery | Discovery | internal port scan |
| T1071.004 | Application Layer Protocol: DNS | Command & Control | DNS tunnel indicators |
| T1071.001 | Application Layer Protocol: Web Protocols | Command & Control | beaconing |
| T1110 | Brute Force | Credential Access | brute force + success |
| T1021.002 | Remote Services: SMB/Admin Shares | Lateral Movement | admin-share access |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | large upload to rare dest |

## Dashboards

The executive dashboard renders **tactic distribution** across open detections today.
Phase 3–5 add: technique coverage, top active techniques, techniques by
entity/incident/time, coverage gaps, an ATT&CK Navigator-layer export, and optional
**D3FEND** countermeasure mapping per technique.
