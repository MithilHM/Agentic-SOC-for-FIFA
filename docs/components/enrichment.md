# Enrichment

`pipeline/enrichment.py` decorates a triaged alert with threat intelligence. It's
the second pipeline stage and the one with potentially slow outbound calls — so
the worker runs it in a **thread pool** (see
[Scaling & concurrency](../operations/scaling-and-concurrency.md#4-non-blocking-enrichment)).

`enrich(alert)` fills in, in order:

## 1. GeoIP + IP reputation

`_geo_and_rep(ip)`:
- Curated offline list first (`_KNOWN_BAD_IPS`) → `(country, reputation)`.
- When `ENABLE_LIVE_INTEL=1`: live `geolocate(ip)` for country, plus
  `ip_reputation(ip)` checked against public blocklists.

Sets `alert.country` and raises `alert.threat_intel_score` to the reputation.

### GeoIP resilience (`intel/geoip.py`)

- Primary provider **ipapi.co**, with retry + exponential backoff on HTTP 429
  (both status-code and in-body rate-limit signals are handled).
- Automatic fallback to **ipwho.is** (free, no key) when the primary is exhausted.
- **Two-level cache**: L1 in-process dict + L2 Redis (`soc:cache:geoip:{ip}`,
  24h TTL for hits / 5min for misses) shared across all worker instances.
- Never raises — returns an `Unknown` result if every provider fails.

Tunables: `GEO_MAX_RETRIES`, `GEO_BACKOFF_BASE_SEC`, `GEO_TIMEOUT_SEC`.

### IP reputation (`intel/reputation.py`)

Checks the IP against free public blocklists (Spamhaus DROP, Tor exit list,
FireHOL), which are downloaded and cached (refreshed per `BLOCKLIST_REFRESH_HOURS`).
`warm_blocklists()` is called at worker startup so a total feed outage is logged
loudly rather than silently degrading scoring. Returns a score, listed-flag, and
the matching sources.

## 2. WHOIS domain age (`intel/whois_lookup.py`)

For alerts with a `domain` and no known age: `lookup_domain_age(domain)`.
- With `ENABLE_LIVE_INTEL=1`: a real WHOIS query, run in an **isolated daemon
  thread** with a `join(timeout)` so it can't hang the caller and — importantly —
  never mutates the process-global socket timeout (a prior bug).
- Otherwise: a keyword heuristic (suspicious FIFA-lookalike tokens →
  newly-registered), keeping the demo deterministic for the simulator's fake
  domains.

## 3. Brand-impersonation / visual similarity

`_domain_similarity_score(domain)` scores 0–100 how much a domain impersonates a
legitimate FIFA brand domain (`fifa.com`, `fifaplus.com`, `fifa.org`) using
`difflib` string similarity plus typosquat heuristics (contains the `fifa`
token, suspicious TLDs like `.xyz`/`.top`/`.ru`). Populates
`visual_similarity_score`.

## 4. Primary IOC selection

If the alert has no `ioc_value` yet, one is chosen by priority
**Domain > URL > IP > User** and `ioc_type`/`ioc_value` are set. This IOC becomes
the primary correlation key — see [Correlation](correlation.md).

## 5. MITRE ATT&CK mapping

`map_to_attack(event_type)` (from `intel/mitre.py`) maps the classified attack
type to a `(tactic, technique)`. When triage produced `"Other"`, a
**source-based fallback** applies (e.g. `WAF → Initial Access / T1190`,
`Auth → Credential Access / T1110`). The technique can later be looked up in full
against the **697-technique** catalogue by the LLM agent's `lookup_mitre` tool.

## Safety

`enrich()` is safe to call even when every optional field is `None`, and all
outbound calls are gated behind `ENABLE_LIVE_INTEL=1`, so the default demo runs
fully offline and deterministically.
