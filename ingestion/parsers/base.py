from abc import ABC, abstractmethod
from itertools import count
from schema.ocsf import OCSFAlert

_seq = count(1)

def next_alert_id() -> str:
    return f"ALT-{next(_seq):06d}"

class BaseParser(ABC):
    source: str  # set by subclass

    @abstractmethod
    def to_ocsf(self, raw: dict) -> OCSFAlert:
        """Map a source-native record to the canonical OCSF alert."""
