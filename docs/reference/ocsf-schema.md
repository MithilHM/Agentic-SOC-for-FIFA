# OCSF Alert Schema

Every ingested event is normalized into a single canonical alert model —
`OCSFAlert` in `schema/ocsf.py` (a pydantic `BaseModel`). This is the contract the
entire pipeline operates on.

## Fields

Only `alert_id` and `event_source` are required; everything else has a default.

| Field | Type | Default | Notes |
|---|---|---|---|
| `timestamp` | str | now (UTC, ISO-ish `…Z`) | Event time. Used by triage's off-hours feature. |
| `alert_id` | str | **required** | `ALT-%06d` from the Redis sequence (or UUID fallback). |
| `incident_id` | str? | `None` | Set by the correlation engine once grouped. |
| `event_source` | str | **required** | One of the 11 sources (`Firewall`, `WAF`, `EDR`, `Auth`, `DNS`, `Email`, `SIEM`, `Cloud`, `IDS`, `Ticketing`, `Streaming`). |
| `event_type` | str | `"Other"` | Attack type — set by triage (one of `ATTACK_TYPES`). |
| `severity` | str | `"Info"` | Set by triage from risk (`Critical`/`High`/`Medium`/`Low`/`Info`). |
| `confidence_score` | int | `0` | Classifier confidence (0–100). |
| `risk_score` | int | `0` | Computed risk (0–100). Drives incident priority. |
| `source_ip` | str? | `None` | Correlation dimension + reputation/geo lookup. |
| `destination_ip` | str? | `None` | |
| `domain` | str? | `None` | WHOIS + brand-impersonation input; primary IOC candidate. |
| `url` | str? | `None` | Entropy feature; IOC candidate. |
| `user` | str? | `None` | Correlation dimension; IOC candidate. |
| `device` | str? | `None` | |
| `country` | str? | `None` | Filled by GeoIP enrichment. |
| `whois_age_days` | int? | `None` | Filled by WHOIS enrichment; triage feature. |
| `ssl_valid` | bool? | `None` | Set during brand-impersonation scoring. |
| `visual_similarity_score` | int? | `None` | Brand-impersonation score (0–100). |
| `threat_intel_score` | int? | `None` | Reputation score; triage feature. |
| `failed_attempts` | int? | `None` | e.g. brute-force auth attempts; triage feature. |
| `mitre_tactic` | str? | `None` | Set by MITRE mapping in enrichment. |
| `mitre_technique` | str? | `None` | ATT&CK technique ID (e.g. `T1566.002`). |
| `ioc_type` | str? | `None` | `Domain` / `URL` / `IP` / `User`. |
| `ioc_value` | str? | `None` | The primary IOC — key correlation dimension. |
| `campaign_name` | str? | `None` | Threat-campaign label; carried onto the incident. |
| `asset` | str? | `None` | Targeted FIFA asset; correlation dimension + business-impact input. |
| `description` | str? | `None` | Human-readable summary. |
| `recommended_action` | str? | `None` | Suggested remediation. |

## Enumerations (`schema/ocsf.py`)

- **`ATTACK_TYPES`** — `Phishing`, `Malware`, `BruteForce`, `WebAttack`,
  `InsiderThreat`, `DDoS`, `CredentialTheft`, `Recon`, `DataExfil`, `Other`.
  The XGBoost classifier's output classes (arg-max index → this list).
- **`SEVERITIES`** — `Critical`, `High`, `Medium`, `Low`, `Info`.
- **`SOURCES`** — the 11 `event_source` values above.

## Example

```json
{
  "timestamp": "2026-07-15T19:45:33Z",
  "alert_id": "ALT-004582",
  "incident_id": "INC-000871",
  "event_source": "WAF",
  "event_type": "Phishing",
  "severity": "High",
  "confidence_score": 96,
  "risk_score": 93,
  "source_ip": "185.174.21.14",
  "domain": "fifa-ticket-secure2026.com",
  "url": "https://fifa-ticket-secure2026.com/login",
  "country": "Russia",
  "whois_age_days": 2,
  "visual_similarity_score": 98,
  "threat_intel_score": 91,
  "mitre_tactic": "Initial Access",
  "mitre_technique": "T1566.002",
  "ioc_type": "Domain",
  "ioc_value": "fifa-ticket-secure2026.com",
  "campaign_name": "Fake FIFA Ticket Campaign",
  "asset": "Official Ticket Portal"
}
```

## Which stage populates what

| Stage | Fields it sets |
|---|---|
| Parser | Structural fields from the source record (`source_ip`, `domain`, `user`, `failed_attempts`, `timestamp`, …). |
| Triage | `event_type`, `confidence_score`, `risk_score`, `severity`. |
| Enrichment | `country`, `whois_age_days`, `visual_similarity_score`, `ssl_valid`, `threat_intel_score`, `ioc_type`, `ioc_value`, `mitre_tactic`, `mitre_technique`. |
| Correlation | `incident_id`. |
