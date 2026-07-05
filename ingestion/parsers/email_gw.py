from ingestion.parsers.base import BaseParser, next_alert_id
from schema.ocsf import OCSFAlert

class EmailParser(BaseParser):
    source = "Email"

    def to_ocsf(self, raw: dict) -> OCSFAlert:
        return OCSFAlert(
            alert_id=next_alert_id(),
            timestamp=raw.get("ts"),
            event_source=self.source,
            domain=raw.get("host"),
            url=raw.get("uri"),
            description=f"Suspicious email from {raw.get('sender')}",
        )
