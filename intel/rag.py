"""
intel/rag.py — Pinecone-backed RAG for the LLM security analyst.

One Pinecone index holds two corpora, distinguished by metadata "kind":
  - "technique" : MITRE ATT&CK technique descriptions (seeded once from
                  intel/data/mitre_catalogue.json) — grounds remediation advice.
  - "incident"  : past incident summaries — lets the analyst say "this matches
                  a campaign we've seen before" and reuse prior recommended actions.

Embeddings use Gemini's text-embedding-004 (via langchain-google-genai), so no
separate embedding-provider key is needed beyond GEMINI_API_KEY.

Fully gated: every public function no-ops if PINECONE_API_KEY or GEMINI_API_KEY
is missing/placeholder, so the pipeline keeps degrading gracefully offline.
"""
from __future__ import annotations

import logging
import os
import threading

logger = logging.getLogger(__name__)

_INDEX_NAME  = os.getenv("PINECONE_INDEX", "fifa-soc-incidents")
_CLOUD       = os.getenv("PINECONE_CLOUD", "aws")
_REGION      = os.getenv("PINECONE_REGION", "us-east-1")
# text-embedding-004 was retired; gemini-embedding-001 is the current model.
# It natively outputs 3072-dim vectors but supports Matryoshka truncation via
# output_dimensionality, so we request 768 to keep the Pinecone index small.
_EMBED_MODEL = "models/gemini-embedding-001"
_EMBED_DIM   = 768

_lock     = threading.RLock()  # reentrant: seed_mitre_techniques() holds it while calling _get_index()
_index    = None
_embedder = None
_seeded   = False


def _attr(obj, key, default=None):
    """Read `key` from obj whether it's dict-like or an SDK response object."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _ready() -> bool:
    pine_key = os.getenv("PINECONE_API_KEY", "")
    gem_key  = os.getenv("GEMINI_API_KEY", "")
    return (bool(pine_key) and not pine_key.startswith("your_")
            and bool(gem_key) and not gem_key.startswith("your_"))


def _get_embedder():
    global _embedder
    if _embedder is None:
        from langchain_google_genai import GoogleGenerativeAIEmbeddings
        _embedder = GoogleGenerativeAIEmbeddings(
            model=_EMBED_MODEL, google_api_key=os.getenv("GEMINI_API_KEY"),
            output_dimensionality=_EMBED_DIM)
    return _embedder


def _get_index():
    global _index
    if _index is not None:
        return _index
    with _lock:
        if _index is not None:
            return _index
        from pinecone import Pinecone, ServerlessSpec
        pc = Pinecone(api_key=os.getenv("PINECONE_API_KEY"))
        try:
            existing = set(pc.list_indexes().names())
        except AttributeError:
            existing = {_attr(i, "name") for i in pc.list_indexes()}

        if _INDEX_NAME not in existing:
            logger.info("Creating Pinecone serverless index '%s' (%s/%s)",
                        _INDEX_NAME, _CLOUD, _REGION)
            pc.create_index(
                name=_INDEX_NAME, dimension=_EMBED_DIM, metric="cosine",
                spec=ServerlessSpec(cloud=_CLOUD, region=_REGION),
            )
        _index = pc.Index(_INDEX_NAME)
        return _index


def embed(text: str) -> list[float] | None:
    if not _ready() or not text:
        return None
    try:
        return _get_embedder().embed_query(text[:8000])
    except Exception as e:
        logger.warning("Gemini embedding failed: %s", e)
        return None


def seed_mitre_techniques(max_items: int = 100) -> None:
    """One-time seed of MITRE technique descriptions, so the analyst can ground
    remediation advice in real ATT&CK guidance instead of just its own memory."""
    global _seeded
    if _seeded or not _ready():
        return
    with _lock:
        if _seeded:
            return
        try:
            from intel.mitre import load_catalogue
            index = _get_index()
            stats = index.describe_index_stats()
            if (_attr(stats, "total_vector_count", 0) or 0) > 0:
                _seeded = True
                return

            items     = list(load_catalogue().items())[:max_items]
            embedder  = _get_embedder()
            chunk_size = 50   # batched via embed_documents -> few API calls, not one per technique
            seeded_count = 0

            for i in range(0, len(items), chunk_size):
                chunk = items[i:i + chunk_size]
                texts = [f"{tid} {info.get('name', '')}: {info.get('description', '')}"
                         for tid, info in chunk]
                try:
                    vectors = embedder.embed_documents(texts)
                except Exception as e:
                    logger.warning("Batch embedding failed for techniques %d-%d: %s",
                                   i, i + len(chunk), e)
                    continue

                index.upsert(vectors=[
                    {"id": f"mitre:{tid}", "values": vec,
                     "metadata": {"kind": "technique", "technique": tid,
                                  "name": info.get("name", ""),
                                  "tactics": ",".join(info.get("tactics", []))}}
                    for (tid, info), vec in zip(chunk, vectors)
                ])
                seeded_count += len(chunk)
                logger.info("RAG seed progress: %d/%d MITRE techniques", seeded_count, len(items))

            _seeded = True
            logger.info("Seeded Pinecone with %d MITRE technique vectors", seeded_count)
        except Exception as e:
            logger.warning("Failed to seed MITRE technique corpus: %s", e)


def upsert_incident(inc_id: str, text: str, metadata: dict) -> None:
    """Store an incident's summary in Pinecone for future similar-campaign retrieval."""
    if not _ready():
        return
    vec = embed(text)
    if vec is None:
        return
    try:
        meta = {"kind": "incident", **{k: v for k, v in metadata.items() if v is not None}}
        _get_index().upsert(vectors=[{"id": f"incident:{inc_id}", "values": vec, "metadata": meta}])
    except Exception as e:
        logger.warning("Failed to upsert incident %s into Pinecone: %s", inc_id, e)


def query_similar(text: str, top_k: int = 3, kind: str | None = None,
                   exclude_id: str | None = None) -> list[dict]:
    """Return top-k semantically similar entries (technique docs and/or past incidents)."""
    if not _ready():
        return []
    vec = embed(text)
    if vec is None:
        return []
    try:
        flt = {"kind": kind} if kind else None
        res = _get_index().query(vector=vec, top_k=top_k + 1, include_metadata=True, filter=flt)
        out = []
        for m in _attr(res, "matches", []):
            mid = _attr(m, "id")
            if exclude_id and mid == f"incident:{exclude_id}":
                continue
            out.append({"id": mid, "score": _attr(m, "score"), **(_attr(m, "metadata") or {})})
        return out[:top_k]
    except Exception as e:
        logger.warning("Pinecone query failed: %s", e)
        return []
