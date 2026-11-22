"""Hybrid Lexical + Cosine Vector Knowledge-Base MCP Server."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from mcp_suite.security.governance import GovernanceController
from mcp_suite.security.pii_redactor import redact_payload

TOKEN_RE = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class KnowledgeDocument:
    doc_id: str
    category: str
    title: str
    content: str
    owner_contact: str


SEED_KNOWLEDGE_BASE: list[KnowledgeDocument] = [
    KnowledgeDocument(
        doc_id="KB-SEC-01",
        category="security",
        title="Read-Only SQL & PII Governance Standard for AI Agents",
        content=(
            "AI agents accessing PostgreSQL or Amazon Aurora must use read-only credentials, "
            "block DDL and DML statements, clamp query results to 200 rows, and mask customer "
            "email and phone PII unless the caller holds pii:read scope."
        ),
        owner_contact="security-team@enterprise.example",
    ),
    KnowledgeDocument(
        doc_id="KB-RAG-02",
        category="architecture",
        title="Production Hybrid RAG Retrieval Tuning on AWS Bedrock & OpenSearch",
        content=(
            "Combine BM25 lexical matching with dense vector embeddings on Amazon OpenSearch "
            "and rerank top candidates to boost context recall and RAGAS faithfulness."
        ),
        owner_contact="ai-platform@enterprise.example",
    ),
    KnowledgeDocument(
        doc_id="KB-HITL-03",
        category="governance",
        title="Human-in-the-Loop (HITL) Approval Pattern on GCP Cloud Run",
        content=(
            "Persist multi-agent checkpoints in Cloud SQL before triggering external customer "
            "actions. Use Cloud Tasks for resilient retries and log reviewer sign-off."
        ),
        owner_contact="fde-lead@enterprise.example",
    ),
    KnowledgeDocument(
        doc_id="KB-OBS-04",
        category="observability",
        title="Chatbot Telemetry Pipeline with ECS FireLens, Glue, Athena & QuickSight",
        content=(
            "Stream structured JSON LLM logs via FireLens to S3 Parquet, catalog with AWS Glue "
            "Crawlers, query token cost and latency in Athena, and schedule QuickSight reports."
        ),
        owner_contact="data-ops@enterprise.example",
    ),
]


def _tokenize(text: str) -> list[str]:
    return TOKEN_RE.findall(text.lower())


class VectorKnowledgeBaseMCPServer:
    """Hybrid BM25-style keyword overlap + TF-IDF cosine similarity search over enterprise docs."""

    def __init__(
        self,
        governance: GovernanceController,
        documents: list[KnowledgeDocument] | None = None,
    ) -> None:
        self.governance = governance
        self.documents = documents or list(SEED_KNOWLEDGE_BASE)
        self._doc_tokens = {d.doc_id: _tokenize(f"{d.title} {d.content}") for d in self.documents}
        self._idf = self._compute_idf()

    def _compute_idf(self) -> dict[str, float]:
        n_docs = max(1, len(self.documents))
        df: Counter[str] = Counter()
        for tokens in self._doc_tokens.values():
            for tok in set(tokens):
                df[tok] += 1
        return {tok: math.log((n_docs + 1) / (count + 1)) + 1.0 for tok, count in df.items()}

    def _tfidf_vector(self, tokens: list[str]) -> dict[str, float]:
        tf = Counter(tokens)
        return {tok: float(cnt) * self._idf.get(tok, 1.0) for tok, cnt in tf.items()}

    @staticmethod
    def _cosine(v1: dict[str, float], v2: dict[str, float]) -> float:
        dot = sum(val * v2.get(k, 0.0) for k, val in v1.items())
        n1 = math.sqrt(sum(v * v for v in v1.values()))
        n2 = math.sqrt(sum(v * v for v in v2.values()))
        if n1 == 0.0 or n2 == 0.0:
            return 0.0
        return dot / (n1 * n2)

    def search_knowledge_base(
        self,
        query: str,
        caller_id: str,
        role: str,
        top_k: int = 3,
        category: str | None = None,
    ) -> dict[str, Any]:
        should_redact = self.governance.authorize(
            caller_id, role, "kb.search_knowledge_base", "kb:search"
        )
        q_tokens = _tokenize(query)
        q_vec = self._tfidf_vector(q_tokens)
        q_set = set(q_tokens)

        scored: list[tuple[float, KnowledgeDocument]] = []
        for doc in self.documents:
            if category and doc.category.lower() != category.lower():
                continue
            d_tokens = self._doc_tokens[doc.doc_id]
            d_vec = self._tfidf_vector(d_tokens)
            cosine_score = self._cosine(q_vec, d_vec)
            lexical_overlap = len(q_set & set(d_tokens)) / max(1, len(q_set))
            hybrid_score = round(0.65 * cosine_score + 0.35 * lexical_overlap, 4)
            if hybrid_score > 0.0:
                scored.append((hybrid_score, doc))

        scored.sort(key=lambda item: item[0], reverse=True)
        hits = [
            {
                "doc_id": doc.doc_id,
                "category": doc.category,
                "title": doc.title,
                "score": score,
                "excerpt": doc.content,
                "owner_contact": doc.owner_contact,
            }
            for score, doc in scored[: max(1, min(top_k, 10))]
        ]
        if should_redact:
            hits = redact_payload(hits)

        return {
            "query": query,
            "pii_redacted": should_redact,
            "hit_count": len(hits),
            "results": hits,
        }

    def get_document_by_id(self, doc_id: str, caller_id: str, role: str) -> dict[str, Any]:
        should_redact = self.governance.authorize(
            caller_id, role, "kb.get_document_by_id", "kb:search"
        )
        for doc in self.documents:
            if doc.doc_id == doc_id:
                payload = {
                    "doc_id": doc.doc_id,
                    "category": doc.category,
                    "title": doc.title,
                    "content": doc.content,
                    "owner_contact": doc.owner_contact,
                }
                return redact_payload(payload) if should_redact else payload
        raise KeyError(f"Knowledge document '{doc_id}' not found.")
