"""
Firewall parser — maps Firewall-native log fields to OCSF.

Native fields: src, dst, action, proto, bytes_out
Typical event_types: DDoS, Recon
"""
from ingestion.parsers.base import BaseParser, next_alert_id
from schema.ocsf import OCSFAlert


class FirewallParser(BaseParser):
    source = "Firewall"

    def to_ocsf(self, raw: dict) -> OCSFAlert:
        action = raw.get("action", "DENY")
        proto  = raw.get("proto", "TCP")
        bytes_ = raw.get("bytes_out", 0)
        desc   = (f"Firewall {action} {proto} traffic"
                  f" — {bytes_} bytes" if bytes_ else f"Firewall {action} {proto}")
        return OCSFAlert(
            alert_id=next_alert_id(),
            timestamp=raw.get("ts"),
            event_source=self.source,
            source_ip=raw.get("src"),
            destination_ip=raw.get("dst"),
            device=raw.get("device", "FW-01"),
            asset=raw.get("asset", "Network Perimeter"),
            description=desc,
        )
