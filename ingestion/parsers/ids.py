"""
IDS/IPS parser — maps Intrusion Detection System fields to OCSF.

Native fields: sig_id, sig_name, src, dst, proto, severity
Typical event_types: Recon, WebAttack
"""
from ingestion.parsers.base import BaseParser, next_alert_id
from schema.ocsf import OCSFAlert


class IDSParser(BaseParser):
    source = "IDS"

    def to_ocsf(self, raw: dict) -> OCSFAlert:
        sig_id   = raw.get("sig_id", "SID-0000")
        sig_name = raw.get("sig_name", "Unknown IDS Rule")
        desc = f"IDS Alert: [{sig_id}] {sig_name}"
        return OCSFAlert(
            alert_id=next_alert_id(),
            timestamp=raw.get("ts"),
            event_source=self.source,
            source_ip=raw.get("src"),
            destination_ip=raw.get("dst"),
            device=raw.get("sensor", "IDS-SENSOR-01"),
            asset=raw.get("asset", "Network Segment"),
            description=desc,
        )
