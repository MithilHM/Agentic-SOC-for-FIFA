"""
Ticketing parser — maps FIFA ticketing platform audit fields to OCSF.

Native fields: account, action, ip, ticket_id, result
Typical event_types: InsiderThreat (bulk-buy, resale fraud)
"""
from ingestion.parsers.base import BaseParser, next_alert_id
from schema.ocsf import OCSFAlert


class TicketingParser(BaseParser):
    source = "Ticketing"

    def to_ocsf(self, raw: dict) -> OCSFAlert:
        account   = raw.get("account", "unknown")
        action    = raw.get("action", "purchase")
        ticket_id = raw.get("ticket_id", "")
        result    = raw.get("result", "success")
        desc = (f"Ticketing: Account '{account}' performed '{action}'"
                + (f" on ticket {ticket_id}" if ticket_id else "")
                + f" [{result.upper()}]")
        return OCSFAlert(
            alert_id=next_alert_id(),
            timestamp=raw.get("ts"),
            event_source=self.source,
            user=account,
            source_ip=raw.get("ip"),
            asset=raw.get("asset", "Official Ticket Portal"),
            description=desc,
        )
