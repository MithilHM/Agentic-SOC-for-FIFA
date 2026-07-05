from ingestion.parsers import (firewall, waf, edr, auth, dns, email_gw,
                               siem, cloud, ids, ticketing, streaming)

_REGISTRY = {
    "Firewall": firewall.FirewallParser(), "WAF": waf.WAFParser(),
    "EDR": edr.EDRParser(), "Auth": auth.AuthParser(), "DNS": dns.DNSParser(),
    "Email": email_gw.EmailParser(), "SIEM": siem.SIEMParser(),
    "Cloud": cloud.CloudParser(), "IDS": ids.IDSParser(),
    "Ticketing": ticketing.TicketingParser(), "Streaming": streaming.StreamingParser(),
}

def normalize(source: str, raw: dict):
    parser = _REGISTRY[source]
    return parser.to_ocsf(raw)
