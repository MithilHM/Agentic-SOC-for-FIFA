"""
Cloud Security parser — maps cloud provider audit log fields to OCSF.

Native fields: principal, action, resource, region, result
Typical event_types: InsiderThreat, CredentialTheft
"""
from ingestion.parsers.base import BaseParser, next_alert_id
from schema.ocsf import OCSFAlert


class CloudParser(BaseParser):
    source = "Cloud"

    def to_ocsf(self, raw: dict) -> OCSFAlert:
        principal = raw.get("principal", "unknown@fifa.org")
        action    = raw.get("action", "unknown_action")
        resource  = raw.get("resource", "unknown_resource")
        result    = raw.get("result", "success")
        desc = (f"Cloud: '{principal}' performed '{action}' on '{resource}'"
                f" [{result.upper()}]")
        return OCSFAlert(
            alert_id=next_alert_id(),
            timestamp=raw.get("ts"),
            event_source=self.source,
            user=principal,
            asset=resource,
            source_ip=raw.get("src_ip"),
            country=raw.get("region"),
            description=desc,
        )
