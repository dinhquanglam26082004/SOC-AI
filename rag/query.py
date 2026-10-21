"""
Truy van ChromaDB de lay tai lieu lien quan (RAG retrieval).
Ho tro Smart Retrieval:
- Exact match metadata khi co CVE ID hoac MITRE Tech ID trong cau hoi.
- Loc giam noise tu kho CVE khi cau hoi khong lien quan CVE.
"""
import re
import logging
import chromadb

from common.config import CHROMA_PATH, EMBEDDING_MODEL, CHROMA_COLLECTION_NAME

COLLECTION_NAME = CHROMA_COLLECTION_NAME

_client = None
_collection = None
_embedder = None
_embedder_error = None

logger = logging.getLogger(__name__)

# Tu khoa cho thay cau hoi co the lien quan den CVE/lo hong
CVE_KEYWORDS = ["cve", "vulnerability", "lỗ hổng", "lo hong", "exploit", "patch", "cvss", "clamav"]


def _get_collection():
    global _client, _collection
    if _collection is None:
        _client = chromadb.PersistentClient(path=CHROMA_PATH)
        _collection = _client.get_or_create_collection(name=COLLECTION_NAME)
    return _collection


class _EmbedderWrapper:
    def __init__(self):
        try:
            from sentence_transformers import SentenceTransformer
            self._st = SentenceTransformer(EMBEDDING_MODEL)
        except Exception as exc:
            raise RuntimeError(f"Could not load configured embedding model {EMBEDDING_MODEL}: {exc}") from exc

    def encode(self, texts):
        encoded = self._st.encode(texts)
        return encoded.tolist() if hasattr(encoded, "tolist") else encoded


def _get_embedder():
    global _embedder, _embedder_error
    if _embedder is None:
        try:
            _embedder = _EmbedderWrapper()
            _embedder_error = None
        except Exception as exc:
            _embedder_error = str(exc)
            raise
    return _embedder


def embedding_status() -> dict:
    return {
        "initialized": _embedder is not None or _embedder_error is not None,
        "available": _embedder is not None if _embedder_error is not None or _embedder is not None else None,
        "model": EMBEDDING_MODEL,
        "error": _embedder_error,
    }


def smart_retrieve(query: str, top_k: int = 5, doc_type: str = None) -> dict:
    """
    Truy van thong minh da tang (Hybrid Exact + Semantic):
    1. Kiem tra CVE ID (CVE-YYYY-NNNNN): neu co -> tim exact theo cve_id metadata.
    2. Kiem tra MITRE Tech ID (T1xxx hoặc T1xxx.xxx): neu co -> uu tien loc mitre.
    3. Neu khong co tu khoa CVE: loai bo type='cve' khoi pool tim kiem de chong pollution.
    4. Semantic search cho phan con lai.
    
    Tra ve dict: {
        "documents": [...],
        "metadatas": [...],
        "distances": [...],
        "ids": [...]
    }
    """
    try:
        collection = _get_collection()
        embedder = _get_embedder()

        count = collection.count()
        if count == 0:
            logger.warning("[RAG] Collection '%s' is empty. Run 'python -m rag.ingest' first.", COLLECTION_NAME)
            return {"documents": [], "metadatas": [], "distances": [], "ids": []}

        effective_top_k = min(top_k, count)

        retrieved_docs = []
        retrieved_metas = []
        retrieved_dists = []
        retrieved_ids = []
        seen_ids = set()

        query_lower = query.lower()

        # 1. Kiem tra CVE ID
        cve_match = re.search(r"\b(CVE-\d{4}-\d{4,7})\b", query, re.IGNORECASE)
        if cve_match:
            cve_id = cve_match.group(1).upper()
            try:
                exact_cve = collection.get(
                    where={"cve_id": cve_id},
                    include=["documents", "metadatas"]
                )
                if exact_cve and exact_cve["ids"]:
                    for cid, doc, meta in zip(exact_cve["ids"], exact_cve["documents"], exact_cve["metadatas"]):
                        if cid not in seen_ids:
                            seen_ids.add(cid)
                            retrieved_ids.append(cid)
                            retrieved_docs.append(doc)
                            retrieved_metas.append(meta)
                            retrieved_dists.append(0.0)  # exact match distance = 0.0
            except Exception as e:
                logger.debug("Exact CVE lookup error: %s", e)

        # 2. Kiem tra MITRE Tech ID
        tech_match = re.search(r"\b(T\d{4}(?:\.\d{3})?)\b", query, re.IGNORECASE)
        if tech_match and len(retrieved_ids) < effective_top_k:
            tech_id = tech_match.group(1).upper()
            try:
                exact_tech = collection.get(
                    where={"tech_id": tech_id},
                    include=["documents", "metadatas"]
                )
                if exact_tech and exact_tech["ids"]:
                    for cid, doc, meta in zip(exact_tech["ids"], exact_tech["documents"], exact_tech["metadatas"]):
                        if cid not in seen_ids and len(retrieved_ids) < effective_top_k:
                            seen_ids.add(cid)
                            retrieved_ids.append(cid)
                            retrieved_docs.append(doc)
                            retrieved_metas.append(meta)
                            retrieved_dists.append(0.0)
            except Exception as e:
                logger.debug("Exact Tech ID lookup error: %s", e)

        # 3. Neu da du top_k ket qua tu exact lookup -> return ngay
        if len(retrieved_ids) >= effective_top_k:
            return {
                "documents": retrieved_docs[:effective_top_k],
                "metadatas": retrieved_metas[:effective_top_k],
                "distances": retrieved_dists[:effective_top_k],
                "ids": retrieved_ids[:effective_top_k]
            }

        # 4. Semantic Search bo sung
        needed = effective_top_k - len(retrieved_ids)
        query_embedding = embedder.encode(query)

        where_filter = None
        if doc_type:
            where_filter = {"type": doc_type}
        elif cve_match or any(kw in query_lower for kw in ["cve", "lỗ hổng", "lo hong", "vulnerability", "cvss"]):
            where_filter = {"type": "cve"}
        elif not any(kw in query_lower for kw in CVE_KEYWORDS):
            # Khong co tu khoa CVE -> loai bo CVE khoi search pool de tranh lam loang
            where_filter = {"type": {"$ne": "cve"}}

        try:
            sem_results = collection.query(
                query_embeddings=[query_embedding],
                n_results=min(effective_top_k * 2, count),
                where=where_filter,
                include=["documents", "metadatas", "distances"]
            )
            s_docs = sem_results.get("documents", [[]])[0]
            s_metas = sem_results.get("metadatas", [[]])[0]
            s_dists = sem_results.get("distances", [[]])[0]
            s_ids = sem_results.get("ids", [[]])[0]

            for cid, doc, meta, dist in zip(s_ids, s_docs, s_metas, s_dists):
                if cid not in seen_ids:
                    seen_ids.add(cid)
                    retrieved_ids.append(cid)
                    retrieved_docs.append(doc)
                    retrieved_metas.append(meta)
                    retrieved_dists.append(dist)
                if len(retrieved_ids) >= effective_top_k:
                    break
        except Exception as e:
            raise RuntimeError(f"Semantic query failed: {e}") from e

        return {
            "documents": retrieved_docs[:effective_top_k],
            "metadatas": retrieved_metas[:effective_top_k],
            "distances": retrieved_dists[:effective_top_k],
            "ids": retrieved_ids[:effective_top_k]
        }

    except Exception as exc:
        logger.error("[RAG] retrieval failed (%s); inspect service health", type(exc).__name__)
        return {"documents": [], "metadatas": [], "distances": [], "ids": [], "error": str(exc)}


def retrieve(query: str, top_k: int = 3, doc_type: str = None):
    """
    Tim top_k tai lieu lien quan nhat toi `query`.
    doc_type: loc theo metadata "type" (vd: "policies", "playbooks", "mitre", "cve").
    """
    res = smart_retrieve(query, top_k=top_k, doc_type=doc_type)
    if res.get("error"):
        raise RuntimeError(f"Knowledge retrieval failed: {res['error']}")
    docs = res.get("documents", [])
    metas = res.get("metadatas", [])
    return [{"text": d, "metadata": m} for d, m in zip(docs, metas)]


def format_context(docs) -> str:
    """Dinh dang danh sach tai lieu thanh khoi text de dua vao prompt."""
    blocks = []
    for i, d in enumerate(docs, start=1):
        source = d["metadata"].get("source", f"doc_{i}")
        blocks.append(f"[DOCUMENT {i} - {source}]\n{d['text']}")
    return "\n\n".join(blocks) if blocks else "(No relevant documents found in knowledge base.)"


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_query = "CVE-2023-20198 là lỗ hổng gì?"
    result_docs = retrieve(test_query, top_k=3)
    print("Test CVE query:")
    print(format_context(result_docs))
