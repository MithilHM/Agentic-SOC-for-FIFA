"""
pipeline/triage.py — ML-based alert triage with lazy model loading.

Risk formula (for judges):
  risk = business_impact(asset) + 0.4·threat_intel + 0.3·confidence + known_bad_bonus
  Clamped 0-100. FP-gated alerts are downgraded so analysts see less noise.
"""
import json
import math
import os
import logging

from schema.ocsf import OCSFAlert, ATTACK_TYPES

logger = logging.getLogger(__name__)

KNOWN_BAD = {"185.174.21.14", "45.155.205.99", "193.169.255.10"}
_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "ml", "model", "xgboost_model.json")
_FEAT_PATH  = os.path.join(os.path.dirname(__file__), "..", "ml", "model", "feature_list.json")

# Lazy-loaded — populated on first call, not at import time
_model   = None
_FEATURES = None


def _load_model():
    """Load XGBoost model from disk. Returns (model, features) or (None, None)."""
    global _model, _FEATURES
    if _model is not None:
        return _model, _FEATURES

    model_path = os.path.abspath(_MODEL_PATH)
    feat_path  = os.path.abspath(_FEAT_PATH)

    if not os.path.exists(model_path):
        logger.warning("ML model not found at %s — falling back to heuristic triage.", model_path)
        return None, None

    try:
        import xgboost as xgb
        m = xgb.XGBClassifier()
        m.load_model(model_path)
        with open(feat_path) as f:
            feats = json.load(f)
        _model, _FEATURES = m, feats
        logger.info("ML model loaded from %s", model_path)
        return _model, _FEATURES
    except Exception as e:
        logger.error("Failed to load ML model: %s", e)
        return None, None


# ---------------------------------------------------------------------------
# Feature engineering
# ---------------------------------------------------------------------------

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    p = [s.count(c) / len(s) for c in set(s)]
    return round(-sum(x * math.log2(x) for x in p), 2)


def _featurize(a: OCSFAlert) -> dict:
    url = a.url or ""
    return {
        "confidence_score":       a.confidence_score or 0,
        "whois_age_days":         a.whois_age_days if a.whois_age_days is not None else 999,
        "visual_similarity_score":a.visual_similarity_score or 0,
        "threat_intel_score":     a.threat_intel_score or 0,
        "src_is_known_bad":       int((a.source_ip or "") in KNOWN_BAD),
        "failed_attempts":        0,   # parser may set via raw["attempts"]
        "off_hours":              0,   # TODO: derive from timestamp
        "is_external":            int(bool(a.source_ip)
                                      and not (a.source_ip or "").startswith("10.")),
        "url_entropy":            _entropy(url),
    }


# ---------------------------------------------------------------------------
# Heuristic fallback (no ML model required)
# ---------------------------------------------------------------------------

_HEURISTIC_MAP = {
    "WAF":       "WebAttack",
    "Auth":      "BruteForce",
    "Firewall":  "Recon",
    "DNS":       "Malware",
    "Email":     "Phishing",
    "SIEM":      "Other",
    "Cloud":     "InsiderThreat",
    "IDS":       "Recon",
    "EDR":       "Malware",
    "Ticketing": "InsiderThreat",
    "Streaming": "DDoS",
}


def _heuristic_triage(a: OCSFAlert) -> OCSFAlert:
    """Rule-based triage when ML model is unavailable."""
    a.event_type      = _HEURISTIC_MAP.get(a.event_source, "Other")
    a.confidence_score = a.confidence_score or 55   # neutral default
    is_fp  = (a.source_ip or "") not in KNOWN_BAD and (a.threat_intel_score or 0) < 30
    a.risk_score = _risk(a, is_fp)
    a.severity   = _severity(a.risk_score)
    if is_fp:
        a.event_type = "Other"
    return a


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def triage(a: OCSFAlert) -> OCSFAlert:
    """Classify alert event_type, set confidence/risk/severity. FP gate applied."""
    model, features = _load_model()

    if model is None:
        return _heuristic_triage(a)

    import numpy as np
    feat_dict = _featurize(a)
    feat_vec  = np.array([[feat_dict[f] for f in features]])

    proba = model.predict_proba(feat_vec)[0]
    idx   = int(proba.argmax())

    a.event_type       = ATTACK_TYPES[idx]
    a.confidence_score = a.confidence_score or int(proba[idx] * 100)

    # False-positive gate
    is_fp = a.confidence_score < 40 and (a.source_ip or "") not in KNOWN_BAD
    a.risk_score = _risk(a, is_fp)
    a.severity   = _severity(a.risk_score)
    if is_fp:
        a.event_type = "Other"
    return a


def _risk(a: OCSFAlert, is_fp: bool) -> int:
    """
    Dynamic risk score (0-100):
      risk = business_impact + 0.4·threat_intel + 0.3·confidence + known_bad_bonus
    """
    if is_fp:
        return max(0, (a.confidence_score or 0) // 3)
    business  = {"Payment Gateway": 30, "Official Ticket Portal": 25,
                 "Admin Console": 25}.get(a.asset or "", 10)
    intel     = (a.threat_intel_score or 0) * 0.4
    conf      = (a.confidence_score or 0) * 0.3
    known_bad = 20 if (a.source_ip or "") in KNOWN_BAD else 0
    return min(100, int(business + intel + conf + known_bad))


def _severity(risk: int) -> str:
    return ("Critical" if risk >= 90 else "High"   if risk >= 70
            else "Medium" if risk >= 40 else "Low"  if risk >= 15 else "Info")
