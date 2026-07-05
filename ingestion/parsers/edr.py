"""
EDR parser — maps Endpoint Detection & Response fields to OCSF.

Native fields: host, process, hash, parent, action
Typical event_types: Malware, InsiderThreat
"""
from ingestion.parsers.base import BaseParser, next_alert_id
from schema.ocsf import OCSFAlert


class EDRParser(BaseParser):
    source = "EDR"

    def to_ocsf(self, raw: dict) -> OCSFAlert:
        proc   = raw.get("process", "unknown.exe")
        parent = raw.get("parent", "explorer.exe")
        hash_  = raw.get("hash", "")
        desc   = (f"EDR: Process '{proc}' spawned by '{parent}'"
                  + (f" | hash={hash_}" if hash_ else ""))
        return OCSFAlert(
            alert_id=next_alert_id(),
            timestamp=raw.get("ts"),
            event_source=self.source,
            device=raw.get("host", "ENDPOINT-01"),
            asset=raw.get("asset", "Endpoint"),
            user=raw.get("user"),
            source_ip=raw.get("src_ip"),
            ioc_type="Hash" if hash_ else None,
            ioc_value=hash_ or None,
            description=desc,
        )
