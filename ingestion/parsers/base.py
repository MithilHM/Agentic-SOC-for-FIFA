"""
ingestion/parsers/base.py — Abstract base parser + distributed alert ID generation.

Alert IDs used to be generated with itertools.count(1), which re-starts at 1
in every process.  Running two ingestor containers simultaneously would create
duplicate alert IDs (e.g. ALT-000001 from process A overwriting the alert
already stored under that key by process B).

Fix: delegate ID generation to a Redis INCR counter (soc:sequence:alert).
INCR is atomic, so every process gets a unique number even under concurrent
writes.  Falls back to a UUID hex if Redis is unreachable so offline/test
runs are unaffected.
"""
import os
import uuid
import logging
from abc import ABC, abstractmethod

from schema.ocsf import OCSFAlert

logger = logging.getLogger(__name__)

_SEQ_KEY  = "soc:sequence:alert"
_redis    = None   # lazily initialised


def _get_redis():
    """Return a synchronous Redis client, creating it once per process."""
    global _redis
    if _redis is None:
        import redis
        try:
            _redis = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"),
                                    socket_connect_timeout=1)
        except Exception as e:
            logger.warning("Could not initialise Redis for ID generation: %s", e)
    return _redis


def next_alert_id() -> str:
    """Return a globally unique, sequentially formatted alert ID.

    Uses Redis INCR to coordinate across processes.  Falls back to a UUID
    hex string (ALT-<hex>) if Redis is unavailable.
    """
    r = _get_redis()
    if r is not None:
        try:
            seq = r.incr(_SEQ_KEY)
            return f"ALT-{seq:06d}"
        except Exception as e:
            logger.warning("Redis ID generation failed, falling back to UUID: %s", e)
    return f"ALT-{uuid.uuid4().hex[:8].upper()}"


class BaseParser(ABC):
    source: str  # set by subclass

    @abstractmethod
    def to_ocsf(self, raw: dict) -> OCSFAlert:
        """Map a source-native record to the canonical OCSF alert."""
