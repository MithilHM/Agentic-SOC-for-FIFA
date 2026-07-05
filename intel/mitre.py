"""
intel/mitre.py — MITRE ATT&CK mapping + technique catalogue.

map_to_attack() maps our internal event_type enum to a representative
(tactic, technique) pair — used by the enrichment layer.

lookup_technique() looks up a specific technique ID (e.g. "T1566.002") against
the full ATT&CK Enterprise catalogue (697 techniques, pre-extracted from the
official MITRE STIX bundle into intel/data/mitre_catalogue.json so no network
call or the 50MB+ raw bundle is needed at runtime).
"""
import json
import logging
import os

logger = logging.getLogger(__name__)

_STATIC = {
    "Phishing": ("Initial Access", "T1566"),
    "BruteForce": ("Credential Access", "T1110"),
    "CredentialTheft": ("Credential Access", "T1555"),
    "Malware": ("Execution", "T1204"),
    "WebAttack": ("Initial Access", "T1190"),
    "InsiderThreat": ("Exfiltration", "T1052"),
    "DataExfil": ("Exfiltration", "T1041"),
    "DDoS": ("Impact", "T1498"),
    "Recon": ("Reconnaissance", "T1595"),
    "Other": (None, None),
}

_CATALOGUE_PATH = os.path.join(os.path.dirname(__file__), "data", "mitre_catalogue.json")
_catalogue: dict | None = None


def map_to_attack(event_type: str):
    return _STATIC.get(event_type, (None, None))


def load_catalogue(path: str = _CATALOGUE_PATH) -> dict:
    """Load (and cache) the full MITRE ATT&CK technique catalogue."""
    global _catalogue
    if _catalogue is not None:
        return _catalogue

    if not os.path.exists(path):
        logger.warning("MITRE catalogue not found at %s — technique lookups will use static fallback only", path)
        _catalogue = {}
        return _catalogue

    try:
        with open(path, encoding="utf-8") as f:
            _catalogue = json.load(f)
        logger.info("Loaded MITRE ATT&CK catalogue: %d techniques", len(_catalogue))
    except Exception as e:
        logger.error("Failed to load MITRE catalogue: %s", e)
        _catalogue = {}
    return _catalogue


def lookup_technique(technique_id: str) -> dict:
    """
    Look up a technique ID against the full ATT&CK catalogue.
    Returns {"technique": id, "name": ..., "description": ..., "tactics": [...], "source": ...}.
    """
    catalogue = load_catalogue()
    entry = catalogue.get(technique_id)
    if entry:
        return {
            "technique": technique_id,
            "name": entry.get("name"),
            "description": entry.get("description"),
            "tactics": entry.get("tactics", []),
            "source": "mitre-attack-catalogue",
        }
    return {
        "technique": technique_id,
        "name": None,
        "description": "No description available for this technique.",
        "tactics": [],
        "source": "unknown",
    }
