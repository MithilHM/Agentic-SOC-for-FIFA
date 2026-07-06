# Correlation Engine

`pipeline/correlation.py` groups related alerts into **incidents**. It's the
third pipeline stage and the heart of the scaling refactor: lookups are O(1) via
reverse indexes, IDs are globally coordinated, and it maintains the pre-aggregated
structures the API reads.

`correlate(alert) -> (incident_id, is_new)` is the entry point. `is_new=True`
triggers the LLM investigation downstream.

## Grouping rules

An incoming alert joins an existing **open** incident if it shares **any** of:

- an **IOC value** (domain, IP, URL, hash),
- an **asset**,
- a **user**,
- a **source IP** (captures kill-chain progression across event types).

"Open" means seen within `CORRELATION_WINDOW_SEC` (default 900s) — enforced by
the TTL on the reverse indexes.

## Reverse-index lookups (the O(1) design)

The old engine scanned every `incident:*` key per alert — O(N). The current
engine maintains four reverse indexes, each mapping a correlation dimension to
its active incident ID:

```
soc:idx:ioc:{value}    → incident_id      (TTL = CORRELATION_WINDOW_SEC)
soc:idx:asset:{value}  → incident_id
soc:idx:user:{value}   → incident_id
soc:idx:ip:{value}     → incident_id
```

- `_write_indexes()` writes/refreshes these on every incident create/update via a
  pipelined `SETEX`. The window-length TTL means stale incidents drop out of
  matching automatically.
- `_find_open_incident()` collects the alert's non-empty dimensions, does a
  **single pipeline** of `GET`s, and returns the first hit whose `incident:{id}`
  still exists (guarding the TTL race). Values are normalized (lower-cased,
  trimmed) via `_idx_key()` for consistent matching.

Result: correlation cost is independent of how many incidents exist.

## Distributed ID generation

`_next_incident_id()` returns `INC-%06d` backed by an atomic Redis `INCR` on
`soc:sequence:incident`; alert IDs work identically via
`ingestion/parsers/base.py::next_alert_id` on `soc:sequence:alert`.

Why it matters: the previous in-memory counters (`itertools.count`, `count(1)`)
restarted at 1 in every process, so two workers/ingestors would mint the **same**
ID and clobber each other's Redis keys. `INCR` is atomic and process-global, so
every process gets a unique number. If Redis is unreachable, both fall back to a
UUID-suffixed ID (`INC-<hex>` / `ALT-<hex>`) so offline/local runs still work.

> **Trade-off (by design):** IDs are now globally coordinated rather than
> per-process. In a multi-worker deployment the numbers are still unique and
> sequential, but a single process no longer necessarily starts at `000001`.

Covered by `tests/test_id_generation.py` (sequential formatting + uniqueness
under concurrency).

## Incident record & field merging

On a new incident, a record is created with empty collections; on an existing
one, it's loaded from `incident:{id}`. Either way the alert's attributes are
merged with `_append_unique()` (deduped): `users`, `ioc_values`, `source_ips`,
`tactics`, `techniques`, `event_types`; `max_risk` takes the running max;
`last_seen` advances; `alert_ids` appends. The record is persisted back to
`incident:{id}`.

## Priority scoring

```
score = max_risk + n_distinct_tactics × 8
```

| Score | Priority |
|---|---|
| ≥ 90 | P1 |
| ≥ 70 | P2 |
| ≥ 40 | P3 |
| < 40 | P4 |

Multi-stage kill-chains (many distinct MITRE tactics) escalate faster — each
distinct tactic adds 8. Because both `max_risk` and the distinct-tactic count
only ever grow as alerts join, **priority is monotonic**: an incident never
de-escalates.

## Serving structures maintained here

After merging, `correlate()` also updates the structures the API reads so it
never scans the keyspace:

- **`soc:open_incidents`** (sorted set, score = `last_seen`) via `ZADD` — powers
  `GET /api/incidents`.
- **`soc:metrics`** (hash) via `_update_metrics()`:
  - `open_incidents` `+1` on each new incident,
  - `sev:{severity}` and `type:{event_type}` `+1` per alert,
  - **`p1` `+1` only when an incident crosses into P1.** Because priority is
    monotonic, this "became-P1" transition happens at most once per incident, so
    a single `HINCRBY` keeps the counter exact with no re-tally.

> The `p1` counter previously reset to `0` and was never re-populated, so
> `/api/metrics` always reported `p1: 0`. It now increments on the P4/P3/P2 → P1
> crossing (captured by comparing the pre- and post-recalculation priority).
> Covered by `tests/test_correlation_index.py`.

## Tests

`tests/test_correlation_index.py` verifies: shared-IOC and shared-source-IP
grouping, fully-disjoint alerts creating separate incidents, index TTL bounded by
the window, the `open_incidents` sorted set + `soc:metrics` hash maintenance, and
the `p1` counter (increments once, no double-count on re-correlation, counts
escalation into P1). Requires a reachable Redis; skips otherwise.
