"""
Streaming parser — maps FIFA streaming platform access fields to OCSF.

Native fields: account, geo, concurrency, device_count, action
Typical event_types: DDoS (credential stuffing / account sharing)
"""
from ingestion.parsers.base import BaseParser, next_alert_id
from schema.ocsf import OCSFAlert


class StreamingParser(BaseParser):
    source = "Streaming"

    def to_ocsf(self, raw: dict) -> OCSFAlert:
        account     = raw.get("account", "unknown")
        concurrency = raw.get("concurrency", 1)
        geo         = raw.get("geo", "Unknown")
        desc = (f"Streaming: Account '{account}' active on {concurrency} "
                f"concurrent sessions from {geo}")
        return OCSFAlert(
            alert_id=next_alert_id(),
            timestamp=raw.get("ts"),
            event_source=self.source,
            user=account,
            country=geo,
            source_ip=raw.get("src_ip"),
            asset=raw.get("asset", "Streaming Platform"),
            description=desc,
        )
