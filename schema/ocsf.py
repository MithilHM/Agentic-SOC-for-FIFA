from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field

ATTACK_TYPES = ["Phishing", "Malware", "BruteForce", "WebAttack", "InsiderThreat",
                "DDoS", "CredentialTheft", "Recon", "DataExfil", "Other"]
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SOURCES = ["Firewall", "WAF", "EDR", "Auth", "DNS", "Email", "SIEM",
           "Cloud", "IDS", "Ticketing", "Streaming"]

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

class OCSFAlert(BaseModel):
    timestamp: str = Field(default_factory=_now)
    alert_id: str
    incident_id: Optional[str] = None
    event_source: str
    event_type: str = "Other"
    severity: str = "Info"
    confidence_score: int = 0
    risk_score: int = 0
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    user: Optional[str] = None
    device: Optional[str] = None
    country: Optional[str] = None
    whois_age_days: Optional[int] = None
    ssl_valid: Optional[bool] = None
    visual_similarity_score: Optional[int] = None
    threat_intel_score: Optional[int] = None
    failed_attempts: Optional[int] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    ioc_type: Optional[str] = None
    ioc_value: Optional[str] = None
    campaign_name: Optional[str] = None
    asset: Optional[str] = None
    description: Optional[str] = None
    recommended_action: Optional[str] = None
