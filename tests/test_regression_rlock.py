"""Regression test for the RAG seeding deadlock.

Bug (fixed): ``seed_mitre_techniques()`` acquires ``rag._lock`` and, while
holding it, calls ``_get_index()`` which acquires the same lock. With a plain
``threading.Lock`` that nested acquisition deadlocks the worker's background
seed thread forever (the original hang). The fix made ``rag._lock`` a
re-entrant ``RLock``.

This test pins both the reentrancy and the concurrent-caller behaviour, with
Pinecone/Gemini fully stubbed so no network or API key is needed.
"""
import sys
import threading
import types

import pytest

from intel import rag


class _FakeIndex:
    def describe_index_stats(self):
        return {"total_vector_count": 0}

    def upsert(self, vectors):
        return None

    def query(self, **kwargs):
        return {"matches": []}


class _FakePinecone:
    def __init__(self, api_key=None):
        pass

    def list_indexes(self):
        class _L:
            def names(self):
                return []
        return _L()

    def create_index(self, **kwargs):
        return None

    def Index(self, name):
        return _FakeIndex()


class _FakeEmbedder:
    def embed_documents(self, texts):
        return [[0.0] * rag._EMBED_DIM for _ in texts]

    def embed_query(self, text):
        return [0.0] * rag._EMBED_DIM


@pytest.fixture
def stub_rag(monkeypatch):
    # Reset module-global state so the seed actually runs.
    monkeypatch.setattr(rag, "_index", None)
    monkeypatch.setattr(rag, "_embedder", None)
    monkeypatch.setattr(rag, "_seeded", False)
    monkeypatch.setattr(rag, "_ready", lambda: True)
    monkeypatch.setattr(rag, "_get_embedder", lambda: _FakeEmbedder())
    # Always seed from 0 and don't touch the real checkpoint file, so this test
    # deterministically exercises the seed -> _get_index nested-lock path.
    monkeypatch.setattr(rag, "_load_seed_checkpoint", lambda: 0)
    monkeypatch.setattr(rag, "_save_seed_checkpoint", lambda seeded, total: None)

    fake_pc = types.ModuleType("pinecone")
    fake_pc.Pinecone = _FakePinecone
    fake_pc.ServerlessSpec = lambda **kwargs: None
    monkeypatch.setitem(sys.modules, "pinecone", fake_pc)
    yield


def test_lock_is_reentrant():
    # A plain Lock re-acquired by the same thread would block; RLock returns
    # immediately. acquire(timeout=1) makes the failure a fast False, not a hang.
    assert rag._lock.acquire(timeout=1) is True
    try:
        assert rag._lock.acquire(timeout=1) is True, "rag._lock is not re-entrant"
        rag._lock.release()
    finally:
        rag._lock.release()


def test_seed_does_not_deadlock(stub_rag):
    # seed_mitre_techniques() holds _lock and calls _get_index() (which also
    # takes _lock). If _lock regresses to a plain Lock this thread never
    # finishes and the join times out.
    done = threading.Event()

    def _run():
        rag.seed_mitre_techniques(max_items=20)
        done.set()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=15)
    assert done.is_set(), "seed_mitre_techniques deadlocked (RLock regression?)"
    assert rag._index is not None   # _get_index ran under the held lock


def test_concurrent_seed_and_get_index(stub_rag):
    # Hammer _get_index() from several threads while seeding runs — no thread
    # should hang.
    errors = []

    def _seed():
        try:
            rag.seed_mitre_techniques(max_items=20)
        except Exception as e:  # pragma: no cover - defensive
            errors.append(e)

    def _get():
        try:
            for _ in range(50):
                rag._get_index()
        except Exception as e:  # pragma: no cover - defensive
            errors.append(e)

    threads = [threading.Thread(target=_seed, daemon=True)]
    threads += [threading.Thread(target=_get, daemon=True) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    assert not any(t.is_alive() for t in threads), "a thread deadlocked"
    assert not errors, f"unexpected errors: {errors}"
