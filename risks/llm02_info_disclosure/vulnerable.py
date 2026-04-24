"""LLM02 — Sensitive Information Disclosure: VULNERABLE implementation.

A naive RAG pipeline that:
  * Ingests every file under data/kb_with_secrets/ without classification or redaction.
  * Retrieves top-k chunks by TF-IDF similarity regardless of caller identity.
  * Concatenates retrieved chunks verbatim into the LLM prompt.
  * Returns the model output to the user with no post-filter.

The flaws are intentional and mirrored 1:1 by the mitigations in `mitigated.py`,
so a diff of the two files is the lesson.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from shared.llm_client import call

KB_DIR = Path(__file__).resolve().parents[2] / "data" / "kb_with_secrets"

VULNERABLE_SYSTEM_PROMPT = (
    "You are a helpful internal assistant. Answer the user's question using the "
    "context below. Be thorough and quote directly from the context when useful."
)


@dataclass
class Chunk:
    doc: str
    text: str


def _load_chunks() -> list[Chunk]:
    # FLAW #1: every document is ingested regardless of sensitivity label.
    # FLAW #2: no PII / secret redaction is applied at ingest time.
    chunks: list[Chunk] = []
    for md in sorted(KB_DIR.glob("*.md")):
        for para in md.read_text(encoding="utf-8").split("\n\n"):
            p = para.strip()
            if p:
                chunks.append(Chunk(doc=md.name, text=p))
    return chunks


def _retrieve(query: str, chunks: list[Chunk], k: int = 3) -> list[Chunk]:
    # FLAW #3: retrieval has no ACL — it matches on similarity only.
    corpus = [c.text for c in chunks]
    vec = TfidfVectorizer(stop_words="english").fit(corpus + [query])
    sims = cosine_similarity(vec.transform([query]), vec.transform(corpus))[0]
    ranked = sorted(zip(sims, chunks), key=lambda x: x[0], reverse=True)
    return [c for _, c in ranked[:k]]


def answer(query: str) -> tuple[str, list[Chunk]]:
    chunks = _load_chunks()
    retrieved = _retrieve(query, chunks)

    # FLAW #4: retrieved content is concatenated into the prompt verbatim, including
    # whatever credentials / PII the chunks contain.
    context = "\n\n---\n\n".join(f"[{c.doc}]\n{c.text}" for c in retrieved)
    user_msg = f"Context:\n{context}\n\nQuestion: {query}"

    resp = call(
        system=VULNERABLE_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    )
    # FLAW #5: no output-side filter — model output is returned as-is.
    return resp.text, retrieved
