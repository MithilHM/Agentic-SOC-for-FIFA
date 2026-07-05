"""OCSF parser normalization tests.

Verifies that source-native records are mapped into the canonical OCSFAlert
schema with the right field mapping and defaults.
"""
import re

import pytest

from ingestion.normalizer import normalize
from schema.ocsf import OCSFAlert

_TS = "2026-07-15T19:45:33Z"


def test_waf_parser_field_mapping():
    raw = {
        "ts": _TS,
        "client_ip": "185.174.21.14",
        "server_ip": "104.18.25.11",
        "uri": "https://fifa-ticket-secure2026.com/login",
        "host": "fifa-ticket-secure2026.com",
        "rule_msg": "SQLi attempt blocked",
    }
    a = normalize("WAF", raw)

    assert isinstance(a, OCSFAlert)
    assert a.event_source == "WAF"
    assert a.source_ip == "185.174.21.14"
    assert a.destination_ip == "104.18.25.11"
    assert a.url == "https://fifa-ticket-secure2026.com/login"
    assert a.domain == "fifa-ticket-secure2026.com"
    assert a.description == "SQLi attempt blocked"
    # Defaults applied by the WAF parser
    assert a.user == "anonymous"
    assert a.device == "WEB-GW-01"
    assert a.asset == "Official Ticket Portal"


def test_auth_parser_failed_attempts_on_failure():
    a = normalize("Auth", {"ts": _TS, "client_ip": "10.0.0.5",
                            "user": "ticket_ops", "attempts": 7, "result": "fail"})
    assert a.event_source == "Auth"
    assert a.user == "ticket_ops"
    assert a.failed_attempts == 7


def test_auth_parser_zero_attempts_on_success():
    # A successful auth must NOT report failed attempts (feeds the ML triage).
    a = normalize("Auth", {"ts": _TS, "client_ip": "10.0.0.5",
                            "user": "ticket_ops", "attempts": 7, "result": "success"})
    assert a.failed_attempts == 0


def test_dns_parser_maps_qname_to_domain():
    a = normalize("DNS", {"ts": _TS, "qname": "evil.example.com", "src": "10.1.2.3"})
    assert a.domain == "evil.example.com"
    assert a.source_ip == "10.1.2.3"


def test_normalize_applies_schema_defaults():
    # Fields not provided by the source should get canonical defaults.
    a = normalize("DNS", {"ts": _TS, "qname": "x.com", "src": "1.2.3.4"})
    assert a.event_type == "Other"
    assert a.severity == "Info"
    assert a.confidence_score == 0
    assert a.risk_score == 0
    assert a.incident_id is None


def test_alert_id_format_and_uniqueness():
    a1 = normalize("DNS", {"ts": _TS, "qname": "a.com", "src": "1.1.1.1"})
    a2 = normalize("DNS", {"ts": _TS, "qname": "b.com", "src": "1.1.1.2"})
    assert re.fullmatch(r"ALT-\d{6}", a1.alert_id)
    assert a1.alert_id != a2.alert_id


def test_unknown_source_rejected():
    with pytest.raises(KeyError):
        normalize("NotARealSource", {"ts": _TS})
