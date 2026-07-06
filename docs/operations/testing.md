# Testing

## Running the suite

The suite lives in `tests/`. Many tests require a reachable Redis and **skip**
themselves (not fail) when it's absent, using `pytest.importorskip` +
`skipif(not _redis_reachable())`.

### Via Make (recommended)

```bash
make up            # ensure redis (+ worker/api) are running
make test          # runs pytest in a throwaway container with dev deps
```

`make test` = `docker compose run --rm api sh -c "pip install -q -r
requirements-dev.txt && python -m pytest tests/ -v"`.

### Directly

```bash
# With a local Redis running and REDIS_URL pointing at it:
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

> **Python version:** the application code uses `X | None` annotations and needs
> **Python 3.10+**. Python 3.9 can't import the pipeline modules, so run tests
> under 3.10+ (the Docker image uses 3.12).

### Ad-hoc container run against a standalone Redis

```bash
docker run -d --name t-redis --network <net> --network-alias redis redis:7-alpine
docker run --rm --network <net> -e REDIS_URL=redis://redis:6379 -v "$PWD":/app \
  <image> sh -c "pip install -q 'pytest>=8' && python -m pytest tests/ -v"
```

## What's covered

| Test file | Covers |
|---|---|
| `test_ocsf_parsers.py` | Parser field mapping, normalizer defaults, unknown-source rejection, alert-ID format. |
| `test_triage_features.py` | Feature extraction, off-hours logic, risk composition/clamping, FP downgrade, severity thresholds. |
| `test_geoip.py` | Retry-on-429, provider fallback, caching, body/HTTP rate-limit detection. |
| `test_reputation.py` | Blocklist matching (CIDR + flat), cache TTL/refresh, warm-up behavior. |
| `test_mitre.py` | Catalogue load (full enterprise set), caching, technique lookup + fallback, missing-file degradation. |
| `test_rag_seed.py` | Seed checkpoint roundtrip, resume-from-checkpoint, completion marking. |
| `test_auth.py` | API-key auth enable/disable, header + bearer + token paths. |
| `test_health.py` | `/api/health` ok / degraded (stale + missing heartbeat). |
| `test_id_generation.py` | Sequential `ALT-/INC-%06d` formatting **and** uniqueness under concurrency (Redis `INCR`). |
| `test_correlation_index.py` | Reverse-index grouping (IOC, source-IP), disjoint→separate incidents, index TTL, `open_incidents` set + `soc:metrics` hash, `p1` counter correctness. |

## Regression pins

Two tests exist specifically to fail if a prior fix is reverted:

- **`test_regression_rlock.py`** — the RAG-seeding `RLock` deadlock (reentrancy,
  no deadlock, concurrent seed + index access).
- **`test_regression_ws_leak.py`** — the WebSocket connection-pool leak; drives
  `server._close_pubsub` across N subscribe→cleanup cycles and asserts the pool
  doesn't grow (verified to leak N without the `aclose()`).

## Adding tests

Follow the existing skip pattern for anything needing Redis:

```python
redis_sync = pytest.importorskip("redis")

def _redis_reachable() -> bool: ...
pytestmark = pytest.mark.skipif(not _redis_reachable(),
                                reason="Redis not reachable at REDIS_URL")
```

Clean up only the keys your test touches (scan the relevant prefixes) so a shared
Redis isn't clobbered — see `test_correlation_index.py`'s `_flush` fixture.
