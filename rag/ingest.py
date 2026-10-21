"""
Nap toan bo tai lieu trong rag/documents/<type>/*.txt|*.md vao ChromaDB.
Su dung chunking theo loai tai lieu:
  - CVE      : 1 file = 1 chunk (ngan, ~100 tu, giu nguyen)
  - MITRE    : chunk theo section (Tactic/Description/Detection/Mitigation)
  - Playbooks: chunk theo section (TRIGGER/INVESTIGATION/RESPONSE/ESCALATION)
  - Policies : chunk theo section (phan tach bang dong trong)
  - Other    : chunk theo doan van (500 tu, overlap 50 tu)

Chay: python -m rag.ingest
"""
import os
import re
import glob
import chromadb
from pathlib import Path
from sentence_transformers import SentenceTransformer

from common.config import CHROMA_PATH, EMBEDDING_MODEL, CHROMA_COLLECTION_NAME

DOCS_ROOT = os.path.join(os.path.dirname(__file__), "documents")
COLLECTION_NAME = CHROMA_COLLECTION_NAME

# ─── Chunking config per doc type ─────────────────────────────────────────────
# CVE files are short (~100-120 words) — keep as single chunk
CVE_MAX_WORDS = 400   # if under this, don't split

# Section headers that trigger a new chunk
MITRE_SECTION_PATTERNS = re.compile(
    r"^(Description:|Sub-techniques:|Detection:|Mitigation:|Tactic:|Platform:)",
    re.MULTILINE
)
PLAYBOOK_SECTION_PATTERNS = re.compile(
    r"^(TRIGGER:|INVESTIGATION:|RESPONSE:|ESCALATION:|NAME:|PLAYBOOK ID:)",
    re.MULTILINE
)
POLICY_SECTION_PATTERNS = re.compile(
    r"^([A-Z][A-Z ]{2,}:$|#{1,3} )",   # ALL-CAPS label lines or markdown headers
    re.MULTILINE
)

# Fallback chunk config for misc docs
FALLBACK_CHUNK_WORDS   = 300
FALLBACK_OVERLAP_WORDS = 40


# ─── Chunking functions ────────────────────────────────────────────────────────

def _word_count(text: str) -> int:
    return len(text.split())


def chunk_by_section(text: str, pattern: re.Pattern,
                     min_words: int = 30) -> list[str]:
    """
    Split text at every match of `pattern`. Each resulting section is
    kept as its own chunk. Sections below min_words are merged with
    the previous section to avoid tiny embeddings.
    """
    parts = pattern.split(text)
    # pattern.split() returns [before, sep1, body1, sep2, body2, ...]
    # Reassemble: prepend separator to its body
    chunks = []
    i = 0
    # First part may be empty header before any section marker
    preamble = parts[0].strip()
    if preamble:
        chunks.append(preamble)
    i = 1
    while i + 1 < len(parts):
        header = parts[i].strip()
        body   = parts[i + 1].strip()
        chunk  = f"{header}\n{body}" if body else header
        if chunks and _word_count(chunk) < min_words:
            # Merge tiny chunks into previous
            chunks[-1] = chunks[-1] + "\n\n" + chunk
        else:
            chunks.append(chunk)
        i += 2

    # If the split produced only 1 chunk (no sections found), return as-is
    return [c for c in chunks if c.strip()]


def chunk_fallback(text: str,
                   chunk_words: int = FALLBACK_CHUNK_WORDS,
                   overlap_words: int = FALLBACK_OVERLAP_WORDS) -> list[str]:
    """Split text into overlapping word-count chunks."""
    words = text.split()
    if len(words) <= chunk_words:
        return [text]
    chunks = []
    start = 0
    while start < len(words):
        end = start + chunk_words
        chunks.append(" ".join(words[start:end]))
        start += chunk_words - overlap_words
    return chunks


def chunk_document(text: str, doc_type: str) -> list[str]:
    """
    Return list of chunks for a document, based on its doc_type.
    Each chunk will become one embedding in ChromaDB.
    """
    text = text.strip()
    if not text:
        return []

    if doc_type == "cve":
        # CVE files are short — always 1 chunk
        return [text]

    elif doc_type == "mitre":
        chunks = chunk_by_section(text, MITRE_SECTION_PATTERNS, min_words=25)
        first_line = text.split("\n")[0].strip()
        prefix = f"[{first_line}]" if not first_line.startswith("[") else first_line
        enriched = []
        for i, chunk in enumerate(chunks):
            if chunk.startswith(prefix) or chunk.startswith(first_line):
                enriched.append(chunk)
            else:
                enriched.append(f"{prefix}\n\n{chunk}")
        return enriched if enriched else [text]

    elif doc_type == "playbooks":
        chunks = chunk_by_section(text, PLAYBOOK_SECTION_PATTERNS, min_words=30)
        first_line = text.split("\n")[0].strip()
        prefix = f"[{first_line}]" if not first_line.startswith("[") else first_line
        enriched = []
        for i, chunk in enumerate(chunks):
            if chunk.startswith(prefix) or chunk.startswith(first_line):
                enriched.append(chunk)
            else:
                enriched.append(f"{prefix}\n\n{chunk}")
        return enriched if enriched else [text]

    elif doc_type == "policies":
        # Chunk at blank-line-separated major sections (double newline)
        sections = re.split(r"\n{2,}", text)
        # Merge small sections
        chunks = []
        buf = ""
        for sec in sections:
            sec = sec.strip()
            if not sec:
                continue
            candidate = (buf + "\n\n" + sec).strip() if buf else sec
            if _word_count(candidate) < FALLBACK_CHUNK_WORDS:
                buf = candidate
            else:
                if buf:
                    chunks.append(buf)
                buf = sec
        if buf:
            chunks.append(buf)
        return chunks if chunks else [text]

    else:
        # Generic fallback: word-count based sliding window
        return chunk_fallback(text)


# ─── Document loading ─────────────────────────────────────────────────────────

def load_documents() -> list[dict]:
    """
    Read every .txt/.md file in rag/documents/<type>/, apply chunking,
    return list of dicts: {id, text, metadata}.
    """
    docs = []
    for type_dir in sorted(glob.glob(os.path.join(DOCS_ROOT, "*"))):
        if not os.path.isdir(type_dir):
            continue
        doc_type = os.path.basename(type_dir)
        file_count = 0
        chunk_count = 0

        for filepath in sorted(glob.glob(os.path.join(type_dir, "*"))):
            if not filepath.lower().endswith((".txt", ".md")):
                continue
            # Exclude README files — they are index docs, not knowledge docs
            if os.path.basename(filepath).lower() in ("readme.md", "readme.txt"):
                continue
            try:
                with open(filepath, encoding="utf-8") as f:
                    content = f.read().strip()
            except UnicodeDecodeError:
                print(f"  [SKIP] encoding error: {filepath}")
                continue
            if not content:
                continue

            chunks = chunk_document(content, doc_type)
            base_id = f"{doc_type}_{os.path.splitext(os.path.basename(filepath))[0]}"

            # Extract doc-type specific metadata
            extra_meta = {}
            if doc_type == "cve":
                cve_match = re.search(r"^CVE ID:\s*(CVE-\d{4}-\d{4,7})", content, re.MULTILINE)
                if not cve_match:
                    cve_match = re.search(r"^\[(CVE-\d{4}-\d{4,7})", content)
                if cve_match:
                    extra_meta["cve_id"] = cve_match.group(1).upper()
                
                sev_match = re.search(r"^Severity:\s*(\w+)(?:\s*\(CVSS:\s*([\d\.]+)\))?", content, re.MULTILINE)
                if sev_match:
                    extra_meta["severity"] = sev_match.group(1).upper()
                    if sev_match.group(2):
                        try:
                            extra_meta["cvss_score"] = float(sev_match.group(2))
                        except ValueError:
                            pass
                            
            elif doc_type == "mitre":
                tech_match = re.search(r"^(T\d{4}(?:\.\d{3})?)", os.path.splitext(os.path.basename(filepath))[0].replace("_", "."))
                if not tech_match:
                    tech_match = re.search(r"^(T\d{4}(?:\.\d{3})?)", content)
                if tech_match:
                    extra_meta["tech_id"] = tech_match.group(1)

            for i, chunk in enumerate(chunks):
                chunk_id = f"{base_id}__c{i}" if len(chunks) > 1 else base_id
                meta = {
                    "type":       doc_type,
                    "source":     os.path.basename(filepath),
                    "chunk_idx":  i,
                    "chunk_total": len(chunks),
                }
                meta.update(extra_meta)
                docs.append({
                    "id":   chunk_id,
                    "text": chunk,
                    "metadata": meta,
                })
            file_count += 1
            chunk_count += len(chunks)

        if file_count:
            avg = chunk_count / file_count
            print(f"  {doc_type:12s}: {file_count} files -> {chunk_count} chunks "
                  f"(avg {avg:.1f}/file)")
    return docs


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("Loading and chunking documents...")
    docs = load_documents()
    if not docs:
        print(f"No documents found in {DOCS_ROOT}.")
        return

    total_chunks = len(docs)
    print(f"\nTotal chunks to embed: {total_chunks}")
    print("Creating embeddings (this may take a few minutes)...")

    embedder   = SentenceTransformer(EMBEDDING_MODEL)
    embeddings = embedder.encode(
        [d["text"] for d in docs],
        batch_size=64,
        show_progress_bar=True,
    ).tolist()

    client     = chromadb.PersistentClient(path=CHROMA_PATH)
    collection = client.get_or_create_collection(name=COLLECTION_NAME)

    # Clear existing collection and re-populate (full rebuild)
    existing_ids = collection.get(include=[])["ids"]
    if existing_ids:
        collection.delete(ids=existing_ids)
        print(f"Cleared {len(existing_ids)} old documents from collection.")

    # Upsert in batches of 500 to avoid memory issues
    batch_size = 500
    for start in range(0, total_chunks, batch_size):
        batch = docs[start:start + batch_size]
        collection.upsert(
            ids=[d["id"] for d in batch],
            documents=[d["text"] for d in batch],
            embeddings=embeddings[start:start + batch_size],
            metadatas=[d["metadata"] for d in batch],
        )
    final_count = collection.count()
    print(f"\nDone. ChromaDB collection '{COLLECTION_NAME}' now has {final_count} chunks.")
    print(f"Path: {CHROMA_PATH}")


if __name__ == "__main__":
    main()
