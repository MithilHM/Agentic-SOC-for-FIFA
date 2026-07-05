from ingestion.parsers.base import BaseParser, next_alert_id
from schema.ocsf import OCSFAlert

class WAFParser(BaseParser):
    source = "WAF"

    def to_ocsf(self, raw: dict) -> OCSFAlert:
        return OCSFAlert(
            alert_id=next_alert_id(),
            timestamp=raw.get("ts"),
            event_source=self.source,
            source_ip=raw.get("client_ip"),
            destination_ip=raw.get("server_ip"),
            url=raw.get("uri"),
            domain=raw.get("host"),
            user=raw.get("user", "anonymous"),
            device=raw.get("gateway", "WEB-GW-01"),
            asset=raw.get("asset", "Official Ticket Portal"),
            description=raw.get("rule_msg"),
        )
