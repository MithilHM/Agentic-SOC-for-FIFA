import time
from datetime import datetime, timezone
from ingestion.normalizer import normalize
from ingestion.publisher import publish

def fake_ticket_campaign():
    """Multi-stage 'Fake FIFA Ticket Campaign' — correlates into 1 incident."""
    steps = [
        ("DNS", {"ts": None, "qname": "fifa-ticket-secure2026.com", "src": "10.0.0.5"}),
        ("Email", {"ts": None, "sender": "tickets@fifa-ticket-secure2026.com",
                   "host": "fifa-ticket-secure2026.com", "uri": "/login"}),
        ("WAF", {"ts": None, "client_ip": "185.174.21.14",
                 "host": "fifa-ticket-secure2026.com", "uri": "/login"}),
        ("Auth", {"ts": None, "client_ip": "185.174.21.14", "user": "ticket_ops",
                  "result": "success", "attempts": 41}),
    ]
    for src, raw in steps:
        if raw.get("ts") is None:
            raw["ts"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        publish(normalize(src, raw))
        time.sleep(1.5)

if __name__ == "__main__":
    fake_ticket_campaign()

