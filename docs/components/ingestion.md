# Ingestion

Turns source-native records into canonical OCSF alerts on the `alerts.raw`
stream. Three pieces: **parsers**, the **normalizer**, and the **publisher**.

## Parsers

Each of the 11 supported sources has a parser under `ingestion/parsers/`, all
subclassing `BaseParser` (`ingestion/parsers/base.py`):

```python
class BaseParser(ABC):
    source: str
    @abstractmethod
    def to_ocsf(self, raw: dict) -> OCSFAlert: ...
```

Registered sources (`ingestion/parsers/__init__.py`... via `normalizer.py`):

| Source | Parser | Source | Parser |
|---|---|---|---|
| Firewall | `firewall.FirewallParser` | SIEM | `siem.SIEMParser` |
| WAF | `waf.WAFParser` | Cloud | `cloud.CloudParser` |
| EDR | `edr.EDRParser` | IDS | `ids.IDSParser` |
| Auth | `auth.AuthParser` | Ticketing | `ticketing.TicketingParser` |
| DNS | `dns.DNSParser` | Streaming | `streaming.StreamingParser` |
| Email | `email_gw.EmailParser` | | |

A parser's job is purely structural mapping — take the vendor-shaped dict and
populate the [OCSF fields](../reference/ocsf-schema.md). Threat scoring, GeoIP,
and MITRE mapping happen **later** in the pipeline (triage/enrichment), not here.

### Alert ID assignment

Parsers assign `alert_id` via `next_alert_id()` (also in `base.py`), which is
backed by a Redis `INCR` counter (`soc:sequence:alert`) so IDs are globally
unique across concurrent ingestor processes, with a UUID fallback if Redis is
unreachable. See [Correlation → Distributed ID generation](correlation.md#distributed-id-generation).

## Normalizer

`ingestion/normalizer.py` is a thin dispatcher:

```python
def normalize(source: str, raw: dict):
    parser = _REGISTRY[source]      # KeyError on an unknown source (intentional)
    return parser.to_ocsf(raw)
```

An unknown `source` raises `KeyError` — the system rejects sources it has no
parser for rather than silently dropping them. (`tests/test_ocsf_parsers.py`
covers this.)

## Publisher

`ingestion/publisher.py` serializes the OCSF alert and appends it to the stream:

```python
STREAM = "alerts.raw"
def publish(alert) -> str:
    return r.xadd(STREAM, {"data": alert.model_dump_json()}).decode()
```

The entire alert travels as a single `data` field. The worker's consumer group
(`soc`) reads from here — see [Alert lifecycle](../architecture/alert-lifecycle.md).

## Adding a new source

1. Create `ingestion/parsers/<source>.py` with a `class <Name>Parser(BaseParser)`
   implementing `to_ocsf(raw) -> OCSFAlert`.
2. Import and register it in `ingestion/normalizer.py`'s `_REGISTRY`.
3. Add a field-mapping test in `tests/test_ocsf_parsers.py`.
4. (If you want it in the simulated feed) emit records for it from
   `simulator/generator.py`.
