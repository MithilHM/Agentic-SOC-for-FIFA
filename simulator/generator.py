"""
simulator/generator.py — Continuous realistic OCSF alert emitter for 11 FIFA sources.

Emits alerts at a configurable rate. All 11 source emitters are implemented;
each uses realistic field values reflecting FIFA World Cup digital infrastructure.
"""
import logging
import os
import random
import time
from datetime import datetime, timezone

from ingestion.normalizer import normalize
from ingestion.publisher import publish

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SIM] %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

FIFA_ASSETS = [
    "Official Ticket Portal", "Payment Gateway", "Media Portal",
    "Mobile App API", "Admin Console", "Streaming Platform",
]
BAD_IPS  = ["185.174.21.14", "45.155.205.99", "193.169.255.10",
            "91.108.4.0",    "198.54.117.200"]
GOOD_IPS = ["104.18.25.11",  "20.190.128.5",  "142.250.196.14",
            "8.8.8.8",       "172.217.18.14"]
ALL_IPS  = BAD_IPS + GOOD_IPS

USERS = ["admin", "ticket_ops", "j.smith", "m.garcia", "r.kumar",
         "svc_payment", "media_user01", "anonymous"]
BAD_DOMAINS = ["fifa-ticket-secure2026.com", "fifawc2026-login.net",
               "ticket-fifa2026.ru",        "secure-fifa.xyz"]
GOOD_DOMAINS = ["fifa.com", "fifaplus.com"]

PROCESSES = ["svchost.exe", "powershell.exe", "cmd.exe", "python.exe",
             "wscript.exe", "mshta.exe", "regsvr32.exe"]
HASHES    = [
    "d41d8cd98f00b204e9800998ecf8427e",
    "5d41402abc4b2a76b9719d911017c592",
    "aab3238922bcc25a6f606eb525ffdc56",
]
GEOS = ["Russia", "China", "Netherlands", "United States", "Germany",
        "Brazil", "Argentina", "France", "Unknown"]


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Emitter functions — one per source
# ---------------------------------------------------------------------------

def waf_event():
    return "WAF", {
        "ts":        _ts(),
        "client_ip": random.choice(ALL_IPS),
        "server_ip": random.choice(GOOD_IPS),
        "host":      random.choice(BAD_DOMAINS + GOOD_DOMAINS),
        "uri":       random.choice([
            "/login", "/../../etc/passwd", "/?q=1' OR '1'='1",
            "/admin", "/.env", "/wp-admin/", "/api/v1/users",
            "/<script>alert(1)</script>",
        ]),
        "user":      "anonymous",
        "gateway":   "WEB-GW-01",
        "asset":     random.choice(FIFA_ASSETS),
        "rule_msg":  random.choice([
            "SQLi / suspicious login pattern",
            "XSS payload detected",
            "Directory traversal attempt",
            "Sensitive file access attempt",
        ]),
    }


def auth_event():
    attempts = random.randint(1, 80)
    return "Auth", {
        "ts":        _ts(),
        "client_ip": random.choice(ALL_IPS),
        "user":      random.choice(USERS),
        "result":    "fail" if attempts > 10 else random.choice(["fail", "success"]),
        "attempts":  attempts,
        "asset":     random.choice(["Admin Console", "Official Ticket Portal"]),
    }


def firewall_event():
    is_bad = random.random() < 0.4
    return "Firewall", {
        "ts":       _ts(),
        "src":      random.choice(BAD_IPS if is_bad else GOOD_IPS),
        "dst":      random.choice(GOOD_IPS),
        "action":   random.choice(["DENY", "DENY", "ALLOW"]),
        "proto":    random.choice(["TCP", "UDP", "ICMP"]),
        "bytes_out":random.randint(64, 1_500_000),
        "device":   "FW-PERIMETER-01",
        "asset":    "Network Perimeter",
    }


def edr_event():
    proc = random.choice(PROCESSES)
    return "EDR", {
        "ts":      _ts(),
        "host":    f"ENDPOINT-{random.randint(1, 50):02d}",
        "process": proc,
        "parent":  random.choice(PROCESSES),
        "hash":    random.choice(HASHES) if random.random() < 0.6 else "",
        "user":    random.choice(USERS),
        "src_ip":  random.choice(ALL_IPS),
        "asset":   random.choice(FIFA_ASSETS),
    }


def dns_event():
    domain = random.choice(BAD_DOMAINS + GOOD_DOMAINS)
    return "DNS", {
        "ts":    _ts(),
        "qname": domain,
        "qtype": random.choice(["A", "AAAA", "MX", "TXT"]),
        "src":   random.choice(ALL_IPS),
    }


def email_event():
    domain  = random.choice(BAD_DOMAINS + GOOD_DOMAINS)
    sender  = f"noreply@{domain}"
    return "Email", {
        "ts":     _ts(),
        "sender": sender,
        "host":   domain,
        "uri":    random.choice(["/login", "/verify", "/account/reset"]),
        "subject":random.choice([
            "Your FIFA ticket order confirmation",
            "Urgent: Verify your account",
            "You've won! Claim FIFA 2026 tickets",
        ]),
    }


def siem_event():
    etype = random.choice(["BruteForce", "Phishing", "Recon", "WebAttack", "Other"])
    sev   = random.choice(["High", "Medium", "Low"])
    return "SIEM", {
        "ts":         _ts(),
        "rule_name":  f"SIEM-{etype}-{random.randint(1000,9999)}",
        "event_type": etype,
        "severity":   sev,
        "src":        random.choice(ALL_IPS),
        "dst":        random.choice(GOOD_IPS),
        "user":       random.choice(USERS),
        "asset":      random.choice(FIFA_ASSETS),
    }


def cloud_event():
    actions  = ["DeleteBucket", "CreateUser", "ModifySecurityGroup",
                "GetSecretValue", "AssumeRole", "PutBucketPolicy"]
    resource = random.choice(["s3://fifa-media-assets", "iam://fifa-admin-role",
                              "secretsmanager://fifa-payment-key",
                              "ec2://sg-0a1b2c3d4e5f"])
    return "Cloud", {
        "ts":        _ts(),
        "principal": random.choice(USERS) + "@fifa.org",
        "action":    random.choice(actions),
        "resource":  resource,
        "result":    random.choice(["success", "success", "denied"]),
        "src_ip":    random.choice(ALL_IPS),
        "region":    random.choice(GEOS),
    }


def ids_event():
    sigs = [
        ("ET-2000001", "Emerging Threats: Port Scan Detected"),
        ("ET-2010935", "ET MALWARE Possible DDoS Botnet"),
        ("ET-2016920", "ET WEB_SERVER SQL Injection Attempt"),
        ("ET-2001219", "ET SCAN Potential SSH Scan"),
        ("ET-2002910", "ET SCAN Nmap OS Detection Probe"),
    ]
    sig_id, sig_name = random.choice(sigs)
    return "IDS", {
        "ts":       _ts(),
        "sig_id":   sig_id,
        "sig_name": sig_name,
        "src":      random.choice(ALL_IPS),
        "dst":      random.choice(GOOD_IPS),
        "sensor":   "IDS-SENSOR-01",
        "asset":    random.choice(FIFA_ASSETS),
    }


def ticketing_event():
    actions = ["bulk_purchase", "resale_listing", "account_share",
               "refund_abuse",  "login",          "password_reset"]
    return "Ticketing", {
        "ts":        _ts(),
        "account":   f"user_{random.randint(1000, 9999)}",
        "action":    random.choice(actions),
        "ip":        random.choice(ALL_IPS),
        "ticket_id": f"TKT-{random.randint(100000, 999999)}",
        "result":    random.choice(["success", "success", "blocked"]),
        "asset":     "Official Ticket Portal",
    }


def streaming_event():
    concurrency = random.randint(1, 30)
    return "Streaming", {
        "ts":          _ts(),
        "account":     f"stream_user_{random.randint(100, 999)}",
        "geo":         random.choice(GEOS),
        "concurrency": concurrency,
        "device_count":concurrency,
        "src_ip":      random.choice(ALL_IPS),
        "asset":       "Streaming Platform",
    }


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

EMITTERS = [
    waf_event, auth_event, firewall_event, edr_event, dns_event,
    email_event, siem_event, cloud_event, ids_event,
    ticketing_event, streaming_event,
]


def run(rate_per_sec: float = 2.0):
    """Continuously emit realistic alerts from all 11 sources to Redis Stream."""
    logger.info("FIFA AI-SIEM Simulator started — %.1f alerts/sec across %d sources",
                rate_per_sec, len(EMITTERS))
    while True:
        try:
            src, raw = random.choice(EMITTERS)()
            alert = normalize(src, raw)
            stream_id = publish(alert)
            logger.debug("Published %s (%s) → %s", alert.alert_id, src, stream_id)
        except Exception as exc:
            logger.error("Emit error: %s", exc)
        time.sleep(1.0 / rate_per_sec)


if __name__ == "__main__":
    rate = float(os.getenv("SIM_RATE", "2.0"))
    run(rate)
