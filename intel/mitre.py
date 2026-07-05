import json, os

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

def map_to_attack(event_type: str):
    return _STATIC.get(event_type, (None, None))

def load_catalogue(path="../cspm-ebpf/enterprise-attack.json"):
    """Optional: index the full MITRE STIX bundle for richer lookups / RAG."""
    if not os.path.exists(path):
        return {}
    bundle = json.load(open(path, encoding="utf-8"))
    out = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    out[ref["external_id"]] = obj.get("name")
    return out
