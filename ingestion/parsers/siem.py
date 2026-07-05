"""
SIEM parser — passthrough for already-normalized SIEM rule hits.

Native fields: rule_name, src, dst, user, asset, event_type, severity
Typical event_types: Any (already classified by upstream SIEM)
"""
from ingestion.parsers.base import BaseParser, next_alert_id
from schema.ocsf import OCSFAlert


class SIEMParser(BaseParser):
    source = "SIEM"

    def to_ocsf(self, raw: dict) -> OCSFAlert:
        return OCSFAlert(
            alert_id=next_alert_id(),
            timestamp=raw.get("ts"),
            event_source=self.source,
            event_type=raw.get("event_type", "Other"),
            severity=raw.get("severity", "Info"),
            source_ip=raw.get("src"),
            destination_ip=raw.get("dst"),
            user=raw.get("user"),
            asset=raw.get("asset", "SIEM-Monitored Asset"),
            device=raw.get("device"),
            description=raw.get("rule_name", "SIEM rule triggered"),
        )
