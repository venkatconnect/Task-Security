"""Streamlit page for LLM02 — 5-tab layout."""
from __future__ import annotations

from pathlib import Path

import streamlit as st

from shared.callouts import note
from shared.risk_matrix import Assessment, Level, RiskScore
from shared.ui import AttackResult, render_assessment, render_attack_runner, render_diff

from risks.llm02_info_disclosure import mitigated, vulnerable
from risks.llm02_info_disclosure.attacks import ATTACKS

HERE = Path(__file__).resolve().parent


ASSESSMENT = Assessment(
    title="LLM02 — Sensitive Information Disclosure",
    threat=(
        "A RAG pipeline indexes a mixed corpus containing public FAQs, internal HR "
        "PII, and restricted SRE credentials. With no classification, no ACL, and "
        "no redaction, any caller can cause the assistant to retrieve and quote "
        "regulated data or production secrets verbatim."
    ),
    pre=RiskScore(likelihood=Level.HIGH, impact=Level.CRITICAL),
    post=RiskScore(likelihood=Level.LOW, impact=Level.HIGH),
    residual_scenarios=[
        "Novel PII / credential formats escape regex-based redaction.",
        "Semantic paraphrase leaks structural hints about redacted values.",
        "Indirect prompt injection via an attacker-controlled document.",
        "Role spoofing when upstream auth is missing or weak.",
        "Model memorization echoes training-data secrets.",
    ],
    mitigations=[
        "Document classification + role-based ACL filtering pre-retrieval.",
        "Ingest-time PII/secret redaction; the vector store never holds raw secrets.",
        "Extraction-shape query classifier refuses 'list / dump / regex' queries.",
        "Output-side redaction as a second layer.",
        "Hardened, cached system prompt with explicit refusal rules.",
    ],
    monitoring=[
        "Alert on query-classifier refusals (recon signal).",
        "Alert on output-side redactor hits (ingest regex drift).",
        "Periodic re-scan of the vector store with updated regex list.",
        "Audit log retrievals by role, doc, acl — watch for anomalies.",
    ],
)


def render() -> None:
    st.title("LLM02 · Sensitive Information Disclosure")
    st.caption("OWASP Top 10 for LLM Applications (2025)")

    tabs = st.tabs(
        [
            "Overview",
            "Vulnerable",
            "Risk · pre",
            "Mitigation",
            "Risk · post",
        ]
    )

    with tabs[0]:
        st.markdown(
            """
### Threat model

A RAG assistant indexes three documents with significantly different
sensitivity levels:

| Document              | Contents                                   | Classification |
|-----------------------|--------------------------------------------|----------------|
| `public_faq.md`       | Product information, contact email         | `public`       |
| `hr_roster.md`        | Names, emails, SSNs, salaries              | `internal`     |
| `infra_runbook.md`    | AWS keys, database passwords, Stripe keys  | `restricted`   |

The unmitigated pipeline ingests all three without classification, access
control, or redaction. The mitigated pipeline adds role-based ACL
filtering, ingest-time and output-side redaction, an extraction-shape query
classifier, and a hardened system prompt.
            """
        )

    with tabs[1]:
        note(
            "This tab exercises the <strong>unmitigated</strong> pipeline. "
            "Payloads are expected to succeed.",
            tone="caution",
        )
        render_attack_runner(
            ATTACKS,
            lambda payload: _run_vulnerable(payload),
            key_prefix="llm02_vuln",
            expected_success=True,
        )

    with tabs[2]:
        render_assessment(ASSESSMENT, post=False)
        with st.expander("Pre-mitigation assessment (full)"):
            st.markdown((HERE / "assessment.md").read_text(encoding="utf-8"))

    with tabs[3]:
        note(
            "This tab exercises the <strong>mitigated</strong> pipeline. "
            "The same payloads should now be refused or redacted.",
            tone="ok",
        )
        role = st.selectbox(
            "Caller role", ["anonymous", "employee", "sre"], index=0,
            help="Demonstrates role-based ACL. Anonymous sees only public documents.",
        )
        render_attack_runner(
            ATTACKS,
            lambda payload, r=role: _run_mitigated(payload, r),
            key_prefix=f"llm02_mit_{role}",
            expected_success=False,
        )
        st.markdown("")
        st.subheader("Source diff · vulnerable vs. mitigated")
        render_diff(HERE / "vulnerable.py", HERE / "mitigated.py")

    with tabs[4]:
        render_assessment(ASSESSMENT, post=True)
        with st.expander("Post-mitigation assessment (full)"):
            st.markdown((HERE / "assessment_post.md").read_text(encoding="utf-8"))


def _run_vulnerable(payload: str) -> AttackResult:
    out, retrieved = vulnerable.answer(payload)
    docs = ", ".join(sorted({c.doc for c in retrieved})) or "(none)"
    leaked = _looks_leaked(out)
    return AttackResult(
        name="",
        succeeded=leaked,
        user_input=payload,
        output=out,
        notes=f"Retrieved docs: {docs}",
    )


def _run_mitigated(payload: str, role: str) -> AttackResult:
    out, retrieved, note = mitigated.answer(payload, role=role)
    docs = ", ".join(sorted({c.doc for c in retrieved})) or "(none)"
    leaked = _looks_leaked(out)
    return AttackResult(
        name="",
        succeeded=leaked,
        user_input=payload,
        output=out,
        notes=f"Retrieved docs: {docs}" + (f" · {note}" if note else ""),
    )


def _looks_leaked(text: str) -> bool:
    """Heuristic: did a real secret slip through? Used only to color the UI badge."""
    import re
    patterns = [
        r"\b\d{3}-\d{2}-\d{4}\b",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"\bsk_live_[A-Za-z0-9]{10,}\b",
        r"(?i)password\s*[:=]\s*\S+",
    ]
    return any(re.search(p, text) for p in patterns)
