from ingestion.parsers.base import BaseParser, next_alert_id
from schema.ocsf import OCSFAlert

class DNSParser(BaseParser):
    source = "DNS"

    def to_ocsf(self, raw: dict) -> OCSFAlert:
        return OCSFAlert(
            alert_id=next_alert_id(),
            timestamp=raw.get("ts"),
            event_source=self.source,
            domain=raw.get("qname"),
            source_ip=raw.get("src"),
            description=f"DNS Lookup for {raw.get('qname')}",
        )
