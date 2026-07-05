from ingestion.parsers.base import BaseParser, next_alert_id
from schema.ocsf import OCSFAlert

class AuthParser(BaseParser):
    source = "Auth"

    def to_ocsf(self, raw: dict) -> OCSFAlert:
        attempts = raw.get("attempts") or 0
        result = raw.get("result")
        return OCSFAlert(
            alert_id=next_alert_id(),
            timestamp=raw.get("ts"),
            event_source=self.source,
            source_ip=raw.get("client_ip"),
            user=raw.get("user"),
            asset=raw.get("asset", "Admin Console"),
            failed_attempts=attempts if result == "fail" else 0,
            description=f"Auth attempt result: {result} with {attempts} attempts",
        )
