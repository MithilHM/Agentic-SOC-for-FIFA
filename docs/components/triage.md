# Triage

`pipeline/triage.py` classifies each alert's attack type, filters false
positives, and computes a risk score and severity. It's the first pipeline stage.

## Model loading (lazy)

The XGBoost model (`ml/model/xgboost_model.json`) and its feature list are
loaded on the **first** `triage()` call, not at import — so importing the module
(e.g. in tests) has no side effects. If the model file is missing, triage
degrades to a rule-based heuristic (`_heuristic_triage`) instead of failing.

The model is trained by `ml/train_model.py` (run at Docker build time, or via
`make train`). Training uses a seeded RNG (`random.Random(42)`) for reproducible
synthetic data.

## Feature engineering

`_featurize(alert)` produces the model's input vector:

| Feature | Source |
|---|---|
| `confidence_score` | alert field |
| `whois_age_days` | alert field (999 if unknown) |
| `visual_similarity_score` | alert field |
| `threat_intel_score` | alert field |
| `src_is_known_bad` | source IP ∈ curated known-bad set |
| `failed_attempts` | alert field |
| `off_hours` | timestamp outside 06:00–22:00 UTC |
| `is_external` | has a source IP that isn't `10.*` |
| `url_entropy` | Shannon entropy of the URL string |

`off_hours` treats 06:00–22:00 UTC as business hours for a global platform.
`url_entropy` catches high-randomness phishing/C2 URLs.

## Classification & the false-positive gate

`triage()` runs `predict_proba`, takes the arg-max as `event_type` (one of
`schema.ocsf.ATTACK_TYPES`), and sets `confidence_score` from the winning
probability if not already present.

The **FP gate**: an alert with `confidence_score < 40` whose source IP is **not**
known-bad is treated as a false positive — its `risk_score` is cut and its
`event_type` is reset to `"Other"`, so analysts see less noise. Known-bad IPs are
never gated out.

## Risk & severity

```
risk = business_impact(asset) + 0.4·threat_intel + 0.3·confidence + known_bad_bonus   (clamped 0–100)
```

- `business_impact`: Payment Gateway 30, Official Ticket Portal / Admin Console
  25, everything else 10.
- `known_bad_bonus`: +20 if the source IP is in the curated known-bad set.
- FP-gated alerts instead get `risk = confidence // 3`.

Severity thresholds:

| Risk | Severity |
|---|---|
| ≥ 90 | Critical |
| ≥ 70 | High |
| ≥ 40 | Medium |
| ≥ 15 | Low |
| < 15 | Info |

The `risk_score` feeds directly into incident **priority** — see
[Correlation → Priority](correlation.md#priority-scoring).

## Heuristic fallback

When no model is available, `_heuristic_triage` maps `event_source → event_type`
(e.g. `WAF → WebAttack`, `Auth → BruteForce`, `Email → Phishing`), applies a
threat-intel-based FP check, and runs the same risk/severity formulas. This keeps
the pipeline functional with no ML artifact present.

Feature extraction and scoring are covered by `tests/test_triage_features.py`.
