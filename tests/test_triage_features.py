"""ML triage feature-extraction tests.

These target the pure feature-engineering helpers (no XGBoost model required),
which is what the classifier actually consumes: off_hours, failed_attempts,
is_external, known-bad flagging, URL entropy, plus the risk/severity mapping.
"""
import json
import os

from pipeline.triage import (
    KNOWN_BAD, _entropy, _featurize, _off_hours, _risk, _severity,
)
from schema.ocsf import OCSFAlert

_FEAT_PATH = os.path.join(os.path.dirname(__file__), "..", "ml", "model", "feature_list.json")


def _alert(**kw):
    kw.setdefault("alert_id", "ALT-000001")
    kw.setdefault("event_source", "WAF")
    return OCSFAlert(**kw)


# ── off_hours ──────────────────────────────────────────────────────────────

def test_off_hours_before_business_start():
    assert _off_hours("2026-07-15T03:00:00Z") == 1   # 03:00 UTC


def test_off_hours_during_business():
    assert _off_hours("2026-07-15T12:00:00Z") == 0


def test_off_hours_boundaries():
    assert _off_hours("2026-07-15T06:00:00Z") == 0   # 06:00 is in-hours
    assert _off_hours("2026-07-15T05:59:00Z") == 1
    assert _off_hours("2026-07-15T22:00:00Z") == 1   # 22:00 is off-hours
    assert _off_hours("2026-07-15T21:59:00Z") == 0


def test_off_hours_bad_input_is_safe():
    assert _off_hours("") == 0
    assert _off_hours("not-a-timestamp") == 0


# ── failed_attempts / feature vector shape ──────────────────────────────────

def test_featurize_failed_attempts_passthrough():
    assert _featurize(_alert(failed_attempts=9))["failed_attempts"] == 9
    # Missing -> 0, never None (the model can't consume None).
    assert _featurize(_alert())["failed_attempts"] == 0


def test_featurize_keys_match_model_feature_list():
    # The featurizer must emit exactly the features the trained model expects.
    with open(os.path.abspath(_FEAT_PATH)) as f:
        expected = json.load(f)
    feats = _featurize(_alert())
    assert set(feats) == set(expected)


def test_featurize_known_bad_and_external_flags():
    bad_ip = next(iter(KNOWN_BAD))
    f = _featurize(_alert(source_ip=bad_ip))
    assert f["src_is_known_bad"] == 1
    assert f["is_external"] == 1

    internal = _featurize(_alert(source_ip="10.0.0.4"))
    assert internal["src_is_known_bad"] == 0
    assert internal["is_external"] == 0


def test_featurize_whois_default_when_missing():
    # No whois age -> sentinel 999 (treated as "old/benign" by the model).
    assert _featurize(_alert())["whois_age_days"] == 999
    assert _featurize(_alert(whois_age_days=2))["whois_age_days"] == 2


# ── entropy ─────────────────────────────────────────────────────────────────

def test_entropy():
    assert _entropy("") == 0.0
    assert _entropy("aaaa") == 0.0        # single symbol -> zero entropy
    assert _entropy("ab") == 1.0          # two equally-likely symbols -> 1 bit


# ── risk / severity ─────────────────────────────────────────────────────────

def test_risk_false_positive_is_downgraded():
    a = _alert(confidence_score=60)
    assert _risk(a, is_fp=True) == 20     # 60 // 3


def test_risk_composition_is_clamped_and_weighted():
    a = _alert(source_ip="185.174.21.14", asset="Payment Gateway",
               threat_intel_score=50, confidence_score=80)
    # 30 (asset) + 0.4*50 + 0.3*80 + 20 (known-bad) = 94
    assert _risk(a, is_fp=False) == 94


def test_severity_thresholds():
    assert _severity(95) == "Critical"
    assert _severity(70) == "High"
    assert _severity(40) == "Medium"
    assert _severity(15) == "Low"
    assert _severity(5) == "Info"
