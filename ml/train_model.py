"""
ml/train_model.py — Trains the XGBoost multi-class alert classifier.

Synthetic training data is generated with realistic feature-to-label correlations
per attack type so the model learns meaningful patterns, not random noise.

Feature engineering mirrors pipeline/triage.py's _featurize().
"""
import json
import logging
import math
import os
import random

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from schema.ocsf import ATTACK_TYPES

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

FEATURES = [
    "confidence_score",
    "whois_age_days",
    "visual_similarity_score",
    "threat_intel_score",
    "src_is_known_bad",
    "failed_attempts",
    "off_hours",
    "is_external",
    "url_entropy",
]

# ---------------------------------------------------------------------------
# Per-label feature distributions (mu, sigma for each feature)
# ---------------------------------------------------------------------------

_rng = random.Random(42)

# Shape: {label: {feature: (mean, std)}}
_DIST: dict[str, dict[str, tuple[float, float]]] = {
    "Phishing": {
        "confidence_score":        (82, 10),
        "whois_age_days":          (5,  10),    # newly registered domain
        "visual_similarity_score": (88, 8),     # high brand similarity
        "threat_intel_score":      (75, 15),
        "src_is_known_bad":        (0.7, 0.45),
        "failed_attempts":         (1,  2),
        "off_hours":               (0.5, 0.5),
        "is_external":             (0.9, 0.3),
        "url_entropy":             (3.5, 0.5),
    },
    "BruteForce": {
        "confidence_score":        (78, 12),
        "whois_age_days":          (400, 200),
        "visual_similarity_score": (10, 10),
        "threat_intel_score":      (60, 20),
        "src_is_known_bad":        (0.6, 0.49),
        "failed_attempts":         (45, 15),    # many failures
        "off_hours":               (0.7, 0.45),
        "is_external":             (0.95, 0.2),
        "url_entropy":             (2.0, 0.5),
    },
    "Malware": {
        "confidence_score":        (75, 15),
        "whois_age_days":          (30, 60),
        "visual_similarity_score": (15, 15),
        "threat_intel_score":      (80, 10),
        "src_is_known_bad":        (0.8, 0.4),
        "failed_attempts":         (0,  2),
        "off_hours":               (0.4, 0.49),
        "is_external":             (0.85, 0.35),
        "url_entropy":             (4.0, 0.6),
    },
    "WebAttack": {
        "confidence_score":        (70, 15),
        "whois_age_days":          (500, 300),
        "visual_similarity_score": (5,  8),
        "threat_intel_score":      (55, 20),
        "src_is_known_bad":        (0.5, 0.5),
        "failed_attempts":         (3,  5),
        "off_hours":               (0.3, 0.46),
        "is_external":             (0.9, 0.3),
        "url_entropy":             (4.5, 0.5),  # high entropy URLs (SQLi, XSS payloads)
    },
    "InsiderThreat": {
        "confidence_score":        (60, 20),
        "whois_age_days":          (700, 300),
        "visual_similarity_score": (5,  8),
        "threat_intel_score":      (30, 20),
        "src_is_known_bad":        (0.1, 0.3),  # internal user — IP not flagged
        "failed_attempts":         (0,  2),
        "off_hours":               (0.8, 0.4),  # after-hours access
        "is_external":             (0.05, 0.2),
        "url_entropy":             (2.5, 0.5),
    },
    "DDoS": {
        "confidence_score":        (85, 8),
        "whois_age_days":          (200, 150),
        "visual_similarity_score": (5,  5),
        "threat_intel_score":      (70, 15),
        "src_is_known_bad":        (0.75, 0.43),
        "failed_attempts":         (0,  1),
        "off_hours":               (0.5, 0.5),
        "is_external":             (1.0, 0.0),
        "url_entropy":             (1.5, 0.5),
    },
    "CredentialTheft": {
        "confidence_score":        (72, 12),
        "whois_age_days":          (100, 100),
        "visual_similarity_score": (50, 30),
        "threat_intel_score":      (65, 15),
        "src_is_known_bad":        (0.55, 0.5),
        "failed_attempts":         (20, 10),
        "off_hours":               (0.5, 0.5),
        "is_external":             (0.8, 0.4),
        "url_entropy":             (3.0, 0.5),
    },
    "Recon": {
        "confidence_score":        (65, 20),
        "whois_age_days":          (600, 400),
        "visual_similarity_score": (3,  5),
        "threat_intel_score":      (50, 20),
        "src_is_known_bad":        (0.4, 0.49),
        "failed_attempts":         (0,  1),
        "off_hours":               (0.6, 0.49),
        "is_external":             (0.95, 0.2),
        "url_entropy":             (2.0, 0.5),
    },
    "DataExfil": {
        "confidence_score":        (68, 18),
        "whois_age_days":          (50, 80),
        "visual_similarity_score": (10, 10),
        "threat_intel_score":      (72, 12),
        "src_is_known_bad":        (0.6, 0.49),
        "failed_attempts":         (2,  4),
        "off_hours":               (0.7, 0.45),
        "is_external":             (0.85, 0.35),
        "url_entropy":             (4.2, 0.6),
    },
    "Other": {
        "confidence_score":        (40, 20),
        "whois_age_days":          (500, 300),
        "visual_similarity_score": (10, 15),
        "threat_intel_score":      (25, 20),
        "src_is_known_bad":        (0.2, 0.4),
        "failed_attempts":         (2,  5),
        "off_hours":               (0.3, 0.46),
        "is_external":             (0.5, 0.5),
        "url_entropy":             (2.5, 1.0),
    },
}


def _sample(label: str, n: int = 100) -> list[dict]:
    dist = _DIST[label]
    rows = []
    for _ in range(n):
        row = {"label": label}
        for feat, (mu, sigma) in dist.items():
            if feat in ("src_is_known_bad", "off_hours", "is_external"):
                # Bernoulli feature: mu is probability of being 1
                row[feat] = float(random.random() < mu)
            else:
                row[feat] = max(0.0, random.gauss(mu, sigma))
        # Clamp integer-range features
        row["confidence_score"]        = min(100, max(0, round(row["confidence_score"])))
        row["visual_similarity_score"] = min(100, max(0, round(row["visual_similarity_score"])))
        row["threat_intel_score"]      = min(100, max(0, round(row["threat_intel_score"])))
        row["failed_attempts"]         = max(0, round(row["failed_attempts"]))
        rows.append(row)
    return rows


def generate_dataset(n_per_class: int = 300) -> pd.DataFrame:
    rows = []
    for label in ATTACK_TYPES:
        rows.extend(_sample(label, n_per_class))
    random.shuffle(rows)
    return pd.DataFrame(rows)


def train(csv_path: str = "data/labeled_alerts.csv",
          out_dir: str = "ml/model",
          n_per_class: int = 300):
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(os.path.dirname(csv_path) if os.path.dirname(csv_path) else ".", exist_ok=True)

    if os.path.exists(csv_path):
        logger.info("Loading existing dataset from %s", csv_path)
        df = pd.read_csv(csv_path).fillna(0)
    else:
        logger.info("Generating synthetic training dataset (%d samples/class)…", n_per_class)
        df = generate_dataset(n_per_class)
        df.to_csv(csv_path, index=False)
        logger.info("Saved dataset → %s", csv_path)

    label_map = {t: i for i, t in enumerate(ATTACK_TYPES)}
    X = df[FEATURES].astype(float)
    y = df["label"].map(label_map).fillna(0).astype(int)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    clf = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        objective="multi:softprob",
        num_class=len(ATTACK_TYPES),
        eval_metric="mlogloss",
        random_state=42,
    )
    clf.fit(X_tr, y_tr, eval_set=[(X_te, y_te)], verbose=False)

    preds = clf.predict(X_te)
    logger.info("Validation accuracy: %.4f", (preds == y_te.values).mean())
    logger.info("\n%s", classification_report(
        y_te, preds, target_names=ATTACK_TYPES, zero_division=0))

    model_path = os.path.join(out_dir, "xgboost_model.json")
    feat_path  = os.path.join(out_dir, "feature_list.json")
    clf.save_model(model_path)
    with open(feat_path, "w") as f:
        json.dump(FEATURES, f)
    logger.info("Model saved → %s", model_path)
    logger.info("Feature list → %s", feat_path)


if __name__ == "__main__":
    train()
