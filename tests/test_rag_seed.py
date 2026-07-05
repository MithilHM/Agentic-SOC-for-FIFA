"""MITRE RAG seeding checkpoint / resume tests (intel/rag.py, item #3).

Verifies that seeding persists a checkpoint and resumes past it across runs
instead of restarting at 0 or skipping the remainder of the 697-technique set.
"""
import pytest

from intel import rag


class _FakeEmbedder:
    def embed_documents(self, texts):
        return [[0.0] * rag._EMBED_DIM for _ in texts]


class _RecordingIndex:
    def __init__(self):
        self.upserted_ids = []

    def upsert(self, vectors):
        self.upserted_ids.extend(v["id"] for v in vectors)

    def describe_index_stats(self):
        return {"total_vector_count": 0}


def test_checkpoint_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(rag, "_CHECKPOINT_FILE", str(tmp_path / "cp.json"))
    assert rag._load_seed_checkpoint() == 0            # missing file -> 0
    rag._save_seed_checkpoint(120, 697)
    assert rag._load_seed_checkpoint() == 120


@pytest.fixture
def seedable(monkeypatch):
    monkeypatch.setattr(rag, "_seeded", False)
    monkeypatch.setattr(rag, "_ready", lambda: True)
    monkeypatch.setattr(rag, "_get_embedder", lambda: _FakeEmbedder())
    idx = _RecordingIndex()
    monkeypatch.setattr(rag, "_get_index", lambda: idx)
    return idx


def test_seed_resumes_from_checkpoint(seedable, monkeypatch):
    # Pretend 100 techniques are already seeded; one run should do the next 50.
    state = {"n": 100}
    monkeypatch.setattr(rag, "_load_seed_checkpoint", lambda: state["n"])
    monkeypatch.setattr(rag, "_save_seed_checkpoint",
                        lambda seeded, total: state.__setitem__("n", seeded))

    rag.seed_mitre_techniques(max_items=50)

    assert len(seedable.upserted_ids) == 50      # only the next 50, not 0-50
    assert state["n"] == 150                      # checkpoint advanced
    assert rag._seeded is False                   # not complete yet -> resumable


def test_seed_stops_when_complete(seedable, monkeypatch):
    from intel.mitre import load_catalogue
    total = len(load_catalogue())
    monkeypatch.setattr(rag, "_load_seed_checkpoint", lambda: total)
    monkeypatch.setattr(rag, "_save_seed_checkpoint", lambda seeded, tot: None)

    rag.seed_mitre_techniques(max_items=50)

    assert seedable.upserted_ids == []            # nothing left to seed
    assert rag._seeded is True                    # marked complete


def test_seed_marks_complete_on_final_run(seedable, monkeypatch):
    from intel.mitre import load_catalogue
    total = len(load_catalogue())
    # Start near the end so a single run finishes the catalogue.
    state = {"n": total - 10}
    monkeypatch.setattr(rag, "_load_seed_checkpoint", lambda: state["n"])
    monkeypatch.setattr(rag, "_save_seed_checkpoint",
                        lambda seeded, tot: state.__setitem__("n", seeded))

    rag.seed_mitre_techniques(max_items=100)

    assert len(seedable.upserted_ids) == 10
    assert state["n"] == total
    assert rag._seeded is True
