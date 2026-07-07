import json
import os
import time
from datetime import datetime, timezone
import redis

# Connect to Redis
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
r = redis.from_url(REDIS_URL)

# Redis keys
_OPEN_SET_KEY = "soc:open_incidents"
_METRICS_KEY = "soc:metrics"
_SEQ_KEY = "soc:sequence:incident"

def seed_all_six_incidents():
    """Seeds exactly 6 structured incidents of high variety and clean details
    representing 3 simple attacks and 3 complex attacks.
    """
    print("[SEED] Resetting Redis state to start clean...")
    # Clear index keys, incidents, alerts, metrics, and streams
    r.delete(_OPEN_SET_KEY, _METRICS_KEY, _SEQ_KEY)
    
    # Clean keys space
    for key in r.scan_iter("incident:*"):
        r.delete(key)
    for key in r.scan_iter("alert:*"):
        r.delete(key)
    for key in r.scan_iter("soc:idx:*"):
        r.delete(key)
    r.delete("alerts.raw")
    
    # Standard threat geos coordinate codes
    country_codes = {
        "Russia": "RU", "China": "CN", "United States": "US", "North Korea": "KP",
        "Brazil": "BR", "Germany": "DE", "Iran": "IR", "Netherlands": "NL", "Unknown": "XX"
    }

    # Generate current mock timestamps
    base_ts = time.time()
    
    # ── 1. Brute Force (Simple Attack) ──
    inc_1_id = "INC-000001"
    alert_ids_1 = ["ALT-100001", "ALT-100002"]
    inc_1 = {
        "incident_id": inc_1_id,
        "created": base_ts - 7200,
        "last_seen": base_ts - 7000,
        "asset": "Authentication Server",
        "users": ["admin"],
        "ioc_values": ["185.174.21.14"],
        "source_ips": ["185.174.21.14"],
        "alert_ids": alert_ids_1,
        "event_types": ["CredentialTheft", "BruteForce"],
        "max_risk": 75,
        "tactics": ["Credential Access"],
        "techniques": ["T1110"],
        "campaign_name": "Admin Console Brute Force",
        "priority": "P2",
        "summary": "Brute-force credential spray campaign detected targeting the main admin panel.",
        "narrative": "An external actor initiated a brute-force authentication campaign using 80 sequential login attempts. The system blocked the source after authentication logs registered continuous credential failures.",
        "root_cause": "Weak password policy allowing rapid credential spray attacks on public administration endpoints.",
        "recommended_action": "Enforce multi-factor authentication (MFA) for administrative roles and implement IP-based rate limiting."
    }
    
    alerts_1 = [
        {
            "alert_id": "ALT-100001",
            "timestamp": datetime.fromtimestamp(base_ts - 7200, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_source": "Auth",
            "severity": "High",
            "confidence_score": 92,
            "event_type": "BruteForce",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110",
            "description": "80 failed authentication attempts within 60s for user admin.",
            "source_ip": "185.174.21.14",
            "country": "Russia"
        },
        {
            "alert_id": "ALT-100002",
            "timestamp": datetime.fromtimestamp(base_ts - 7000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_source": "Auth",
            "severity": "Medium",
            "confidence_score": 85,
            "event_type": "CredentialTheft",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110",
            "description": "Subsequent login success from blacklisted IP 185.174.21.14 on admin account.",
            "source_ip": "185.174.21.14",
            "country": "Russia"
        }
    ]

    # ── 2. SQL Injection (Simple Attack) ──
    inc_2_id = "INC-000002"
    alert_ids_2 = ["ALT-200001"]
    inc_2 = {
        "incident_id": inc_2_id,
        "created": base_ts - 6000,
        "last_seen": base_ts - 5900,
        "asset": "Payment Gateway",
        "users": ["anonymous"],
        "ioc_values": ["45.155.205.99"],
        "source_ips": ["45.155.205.99"],
        "alert_ids": alert_ids_2,
        "event_types": ["WebAttack"],
        "max_risk": 90,
        "tactics": ["Initial Access"],
        "techniques": ["T1190"],
        "campaign_name": "Payment SQLi Attempt",
        "priority": "P1",
        "summary": "WAF blocked SQL Injection attempts targeting checkout backend database endpoints.",
        "narrative": "An attacker targeted the checkout endpoint of the Payment Gateway, trying traversal and SQL payloads to dump backend tables.",
        "root_cause": "Unsanitized inputs inside checkout endpoint queries.",
        "recommended_action": "Enable parameterized SQL queries and update WAF rules to instantly block database-dump command strings."
    }
    
    alerts_2 = [
        {
            "alert_id": "ALT-200001",
            "timestamp": datetime.fromtimestamp(base_ts - 6000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_source": "WAF",
            "severity": "Critical",
            "confidence_score": 96,
            "event_type": "WebAttack",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1190",
            "description": "SQL Injection attempt intercepted on URI /payment/checkout with query payload: 1' OR '1'='1.",
            "source_ip": "45.155.205.99",
            "country": "China"
        }
    ]

    # ── 3. Stadium WiFi Scan (Simple Attack) ──
    inc_3_id = "INC-000003"
    alert_ids_3 = ["ALT-300001"]
    inc_3 = {
        "incident_id": inc_3_id,
        "created": base_ts - 5000,
        "last_seen": base_ts - 4800,
        "asset": "Stadium WiFi",
        "users": ["anonymous"],
        "ioc_values": ["193.169.255.10"],
        "source_ips": ["193.169.255.10"],
        "alert_ids": alert_ids_3,
        "event_types": ["Recon"],
        "max_risk": 45,
        "tactics": ["Reconnaissance"],
        "techniques": ["T1595"],
        "campaign_name": "Stadium Perimeter Scan",
        "priority": "P3",
        "summary": "External port scan targeting stadium public infrastructure interfaces.",
        "narrative": "Firewall and IDS logs registered a systematic external scan looking for open host ports across stadium WiFi routers.",
        "root_cause": "Publicly accessible wireless infrastructure interfaces scanning exposure.",
        "recommended_action": "Configure perimeter firewall to drop ICMP/port scanner probes automatically."
    }
    
    alerts_3 = [
        {
            "alert_id": "ALT-300001",
            "timestamp": datetime.fromtimestamp(base_ts - 5000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_source": "Firewall",
            "severity": "Medium",
            "confidence_score": 88,
            "event_type": "Recon",
            "mitre_tactic": "Reconnaissance",
            "mitre_technique": "T1595",
            "description": "Systematic TCP port scanning from external IP 193.169.255.10 against stadium gateway nodes.",
            "source_ip": "193.169.255.10",
            "country": "Germany"
        }
    ]

    # ── 4. Phishing & Account Takeover (Complex Attack) ──
    inc_4_id = "INC-000004"
    alert_ids_4 = ["ALT-400001", "ALT-400002", "ALT-400003"]
    inc_4 = {
        "incident_id": inc_4_id,
        "created": base_ts - 4000,
        "last_seen": base_ts - 3500,
        "asset": "Official Ticket Portal",
        "users": ["ticket_ops"],
        "ioc_values": ["fifa-ticket-secure2026.com", "198.54.117.200"],
        "source_ips": ["198.54.117.200"],
        "alert_ids": alert_ids_4,
        "event_types": ["Phishing", "CredentialTheft", "Exfiltration"],
        "max_risk": 95,
        "tactics": ["Initial Access", "Credential Access", "Exfiltration"],
        "techniques": ["T1566", "T1110", "T1041"],
        "campaign_name": "Ticket Portal Takeover",
        "priority": "P1",
        "summary": "Multi-stage spear-phishing campaign led to successful compromise of customer support accounts and exfiltration.",
        "narrative": "The attack started with a DNS lookup to a spoofed ticket domain, followed by phishing emails sent to ticket administrators. A support user clicked the credential harvesting URL, leading to account takeover and lateral movement to extract customer purchase orders.",
        "root_cause": "Lack of email SPF validation and missing MFA requirements for remote support accounts.",
        "recommended_action": "Reset compromised account credentials, implement strict email SPF/DKIM validation rules, and revoke unauthorized active user sessions."
    }
    
    alerts_4 = [
        {
            "alert_id": "ALT-400001",
            "timestamp": datetime.fromtimestamp(base_ts - 4000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_source": "Email",
            "severity": "Low",
            "confidence_score": 90,
            "event_type": "Phishing",
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1566",
            "description": "Spoofed domain email ticket-alert@fifa-ticket-secure2026.com delivered with subject 'Your FIFA ticket order confirmation'.",
            "source_ip": "198.54.117.200",
            "country": "Iran"
        },
        {
            "alert_id": "ALT-400002",
            "timestamp": datetime.fromtimestamp(base_ts - 3800, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_source": "WAF",
            "severity": "High",
            "confidence_score": 85,
            "event_type": "CredentialTheft",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110",
            "description": "Credential harvesting form submitted by user ticket_ops on external malicious domain fifa-ticket-secure2026.com.",
            "source_ip": "198.54.117.200",
            "country": "Iran"
        },
        {
            "alert_id": "ALT-400003",
            "timestamp": datetime.fromtimestamp(base_ts - 3500, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_source": "Ticketing",
            "severity": "Critical",
            "confidence_score": 95,
            "event_type": "Exfiltration",
            "mitre_tactic": "Exfiltration",
            "mitre_technique": "T1041",
            "description": "Bulk ticket resale exfiltration trigger. 15,000 reservation items dumped to IP 198.54.117.200.",
            "source_ip": "198.54.117.200",
            "country": "Iran"
        }
    ]

    # ── 5. Cloud Insider Exfiltration (Complex Attack) ──
    inc_5_id = "INC-000005"
    alert_ids_5 = ["ALT-500001", "ALT-500002"]
    inc_5 = {
        "incident_id": inc_5_id,
        "created": base_ts - 3000,
        "last_seen": base_ts - 2600,
        "asset": "Cloud Infrastructure",
        "users": ["svc_payment"],
        "ioc_values": ["secure-fifa.xyz"],
        "source_ips": ["91.108.4.0"],
        "alert_ids": alert_ids_5,
        "event_types": ["InsiderThreat", "Exfiltration"],
        "max_risk": 92,
        "tactics": ["Execution", "Defense Evasion", "Exfiltration"],
        "techniques": ["T1204", "T1027", "T1048"],
        "campaign_name": "Insider Secret Theft",
        "priority": "P1",
        "summary": "Suspicious database dump and credential download cradle from key-vault bucket.",
        "narrative": "An internal service principal modified security group settings and pulled cloud secrets. EDR flagged suspicious script execution parented by mshta.exe transferring substantial media backup databases to external targets.",
        "root_cause": "Misconfigured IAM policies allowing broad administrative access to sensitive credentials.",
        "recommended_action": "Revoke wildcard permission grants, restrict bucket modification API access, and enable data loss prevention (DLP) alerts."
    }
    
    alerts_5 = [
        {
            "alert_id": "ALT-500001",
            "timestamp": datetime.fromtimestamp(base_ts - 3000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_source": "Cloud",
            "severity": "High",
            "confidence_score": 90,
            "event_type": "InsiderThreat",
            "mitre_tactic": "Execution",
            "mitre_technique": "T1204",
            "description": "IAM role svc_payment assumed. Security policy bucket policy modified to allow public download.",
            "source_ip": "91.108.4.0",
            "country": "Netherlands"
        },
        {
            "alert_id": "ALT-500002",
            "timestamp": datetime.fromtimestamp(base_ts - 2600, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_source": "EDR",
            "severity": "Critical",
            "confidence_score": 93,
            "event_type": "Exfiltration",
            "mitre_tactic": "Exfiltration",
            "mitre_technique": "T1048",
            "description": "mshta.exe spawned powershell to exfiltrate secret payload to secure-fifa.xyz.",
            "source_ip": "91.108.4.0",
            "country": "Netherlands"
        }
    ]

    # ── 6. C2 Ransomware Preparation (Complex Attack) ──
    inc_6_id = "INC-000006"
    alert_ids_6 = ["ALT-600001", "ALT-600002"]
    inc_6 = {
        "incident_id": inc_6_id,
        "created": base_ts - 2000,
        "last_seen": base_ts - 1500,
        "asset": "Media Portal",
        "users": ["anonymous"],
        "ioc_values": ["ticket-fifa2026.ru"],
        "source_ips": ["198.54.117.200"],
        "alert_ids": alert_ids_6,
        "event_types": ["Malware", "WebAttack"],
        "max_risk": 88,
        "tactics": ["Execution", "Command and Control", "Impact"],
        "techniques": ["T1204", "T1071", "T1486"],
        "campaign_name": "Media Portal C2 Beaconing",
        "priority": "P2",
        "summary": "Suspicious registry updates and high-entropy folder encryption preparations detected.",
        "narrative": "The attacker exploited a WAF bypass to execute commands on the Media CMS server, establishing persistent registry keys. System telemetry detected beaconing to a command-and-control server accompanied by high CPU encryption actions.",
        "root_cause": "Outdated CMS patch allowing remote command execution on the host OS.",
        "recommended_action": "Quarantine the affected Media server node, upgrade CMS dependencies, and deploy latest endpoint protection indicators."
    }
    
    alerts_6 = [
        {
            "alert_id": "ALT-600001",
            "timestamp": datetime.fromtimestamp(base_ts - 2000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_source": "WAF",
            "severity": "High",
            "confidence_score": 90,
            "event_type": "WebAttack",
            "mitre_tactic": "Execution",
            "mitre_technique": "T1204",
            "description": "WAF bypass attempt: Command execution trigger on /cms/upload.",
            "source_ip": "198.54.117.200",
            "country": "North Korea"
        },
        {
            "alert_id": "ALT-600002",
            "timestamp": datetime.fromtimestamp(base_ts - 1500, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_source": "DNS",
            "severity": "High",
            "confidence_score": 86,
            "event_type": "Malware",
            "mitre_tactic": "Command and Control",
            "mitre_technique": "T1071",
            "description": "Continuous DNS requests targeting C2 beacon domain ticket-fifa2026.ru.",
            "source_ip": "198.54.117.200",
            "country": "North Korea"
        }
    ]

    all_incs = [inc_1, inc_2, inc_3, inc_4, inc_5, inc_6]
    all_alerts = alerts_1 + alerts_2 + alerts_3 + alerts_4 + alerts_5 + alerts_6

    # ── Push alerts to Redis ──
    for a in all_alerts:
        r.set(f"alert:{a['alert_id']}", json.dumps(a))
        print(f"[SEED] Stored alert:{a['alert_id']}")

    # ── Push incidents to Redis and build indices ──
    p1_count = 0
    sev_counts = {}
    type_counts = {}

    for inc in all_incs:
        inc_id = inc["incident_id"]
        # Save incident payload
        r.set(f"incident:{inc_id}", json.dumps(inc))
        
        # Add to open_incidents sorted set (score=last_seen)
        r.zadd(_OPEN_SET_KEY, {inc_id: inc["last_seen"]})
        
        if inc["priority"] == "P1":
            p1_count += 1
            
        # Write O(1) correlation indexes
        for ioc in inc["ioc_values"]:
            r.setex(f"soc:idx:ioc:{ioc.lower()}", 900, inc_id)
        r.setex(f"soc:idx:asset:{inc['asset'].lower()}", 900, inc_id)
        for user in inc["users"]:
            r.setex(f"soc:idx:user:{user.lower()}", 900, inc_id)
        for ip in inc["source_ips"]:
            r.setex(f"soc:idx:ip:{ip.lower()}", 900, inc_id)

        print(f"[SEED] Correlated & Stored incident:{inc_id} ({inc['priority']})")

    # Tally alert aggregates for metrics
    for a in all_alerts:
        severity = a["severity"]
        event_type = a["event_type"]
        sev_counts[severity] = sev_counts.get(severity, 0) + 1
        type_counts[event_type] = type_counts.get(event_type, 0) + 1

    # Save metrics hash
    metrics = {
        "open_incidents": len(all_incs),
        "p1": p1_count
    }
    for sev, cnt in sev_counts.items():
        metrics[f"sev:{sev}"] = cnt
    for t, cnt in type_counts.items():
        metrics[f"type:{t}"] = cnt

    r.hmset(_METRICS_KEY, metrics)
    
    # Seed the sequence counter
    r.set(_SEQ_KEY, len(all_incs))
    
    # Publish updates to live web sockets channel
    for inc in all_incs:
        r.publish("incidents.live", inc["incident_id"])

    print(f"[SEED] Success! 6 Incidents seeded (P1: {p1_count}, P2: 2, P3: 1). Emitters offline.")

if __name__ == "__main__":
    seed_all_six_incidents()
