# Astra NDR — Scoring Engine

Source: [`src/Astra.Server/ScoringEngine.fs`](../src/Astra.Server/ScoringEngine.fs).

Astra scores **entities**, not just alerts, and every score is **explainable**: it is
the clamped sum of named, signed factors, so the console can show precisely why an
entity ranks where it does.

## The four scores (0–100)

- **Risk** — overall combined risk from the entity's open detections and context.
- **Urgency** — Risk folded with asset criticality and group importance; this is the
  single number that orders the analyst queue.
- **Threat** — the strength of the strongest individual detection.
- **Certainty** — average confidence across contributing detections.

Severity and Confidence per detection feed these; asset-criticality, group-importance,
rarity, velocity, breadth, kill-chain progression, repetition, threat-intel, triage and
time-decay act as modifiers.

## Explainable factors (`ScoreFactor`)

Each factor carries a `Kind`, a human `Label`, a signed `Contribution` (score points,
negative = reduction), an `Explanation`, and the detections it relates to. Phase-1
factors include:

| Factor | Effect |
|--------|--------|
| Detection severity & confidence | base, with diminishing returns per detection |
| Attack category breadth | + when activity spans ≥2 categories |
| Kill-chain progression | + when reaching installation or later stages |
| Detection velocity | + for many detections in a short span |
| Asset criticality | scales the base by the entity's criticality weight |
| Threat-intel match | + weighted by indicator confidence |
| Triage suppression | − when analyst marked benign/expected |
| Time decay | − as the most recent activity ages |

## How urgency prioritizes

```
risk    = clamp(Σ factor.Contribution)
urgency = clamp(risk × criticalityWeight)      # critical assets float to the top
threat  = max(detection.ThreatScore)
certainty = avg(detection.Certainty)
```

`recomputeAll` runs after every detection pass; `ScoreBreakdown` (with the full factor
list and a score-history snapshot) is stored per entity and served to the Entity Detail
page's "Why this score" panel.

## Two views

- **Unified urgency** for triage prioritization (the Entity Queue).
- **Detailed threat / certainty / risk breakdown** for technical investigation (the
  Entity Detail page), showing contributing detections, evidence, and the signed factor
  ledger.

## Design intent

Analysts must be able to trust — and tune — the score. Because every point is
attributable to a labeled factor with an explanation and backing detections, triage
decisions (suppress, allowlist, mark expected) have a visible, auditable effect on the
number, and nothing about the score is a black box.
