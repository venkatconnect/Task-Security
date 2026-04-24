"""Streamlit page for LLM06 — 5-tab layout."""
from __future__ import annotations

from pathlib import Path

import streamlit as st

from shared.callouts import note
from shared.risk_matrix import Assessment, Level, RiskScore
from shared.ui import AttackResult, render_assessment, render_attack_runner, render_diff

from risks.llm06_excessive_agency import mitigated, vulnerable
from risks.llm06_excessive_agency.attacks import ATTACKS, ensure_poisoned_file

HERE = Path(__file__).resolve().parent


ASSESSMENT = Assessment(
    title="LLM06 — Excessive Agency",
    threat=(
        "A tool-using agent is wired with an over-broad toolset (file I/O, shell, "
        "email, HTTP) and instructed to 'take initiative'. Ambiguous requests, "
        "indirect prompt injection via tool output, and tool chaining can turn "
        "benign tasks into data loss, exfiltration, or unwanted outbound traffic."
    ),
    pre=RiskScore(likelihood=Level.HIGH, impact=Level.CRITICAL),
    post=RiskScore(likelihood=Level.LOW, impact=Level.HIGH),
    residual_scenarios=[
        "Approval fatigue — operator rubber-stamps queued actions.",
        "Allowed-tool misuse — data leakage through allowlisted endpoints.",
        "Human approves a malicious queued write or email.",
        "Persuasive injection still reaches the pending-queue review stage.",
        "Deliberate budget exhaustion as a DoS on the agent.",
    ],
    mitigations=[
        "Least-privilege tools: no delete, no shell, HTTP allowlist only.",
        "Sandbox path canonicalization rejects '..' and out-of-sandbox paths.",
        "Human-in-the-loop confirmation queue for writes and emails.",
        "Per-session tool-call, write, and HTTP budgets.",
        "Argument validation (email body URL scan, URL host check).",
        "Hardened cached system prompt: tool output is data, not instructions.",
    ],
    monitoring=[
        "Alert on spikes of blocked tool calls (recon signal).",
        "Alert on queued actions referencing external hosts or emails.",
        "Require two-click approval for out-of-sandbox-adjacent actions.",
        "Track per-user approval rate to detect approval fatigue.",
    ],
)


def render() -> None:
    ensure_poisoned_file()  # idempotent — makes attack #2 reproducible

    st.title("LLM06 · Excessive Agency")
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

The agent is provisioned with six unrestricted tools — `read_file`,
`write_file`, `delete_file`, `run_shell`, `send_email`, `http_request` —
and a system prompt directing it to act autonomously. This combination is
the canonical Excessive Agency anti-pattern.

| Attack family            | Mechanism                                                   |
|--------------------------|-------------------------------------------------------------|
| Scope creep              | Ambiguous requests permit destructive follow-up actions.    |
| Indirect prompt injection| Instructions embedded in retrieved files steer the agent.   |
| Data exfiltration        | Unrestricted `http_request` allows outbound transmission.   |
| Privilege chaining       | `run_shell` combined with `http_request` yields RCE + exfil.|

The mitigated agent removes destructive tools, sandboxes file I/O,
allowlists outbound HTTP, queues writes and emails for human approval,
applies per-session budgets, and instructs the model to treat tool output
as data rather than instructions.
            """
        )

    with tabs[1]:
        note(
            "This tab exercises the <strong>unmitigated</strong> agent. "
            "Side-effecting tools (delete, shell, email, HTTP) are mocked — "
            "the audit records the intent that would have executed.",
            tone="caution",
        )
        render_attack_runner(
            ATTACKS,
            lambda payload: _run_vulnerable(payload),
            key_prefix="llm06_vuln",
            expected_success=True,
        )

    with tabs[2]:
        render_assessment(ASSESSMENT, post=False)
        with st.expander("Pre-mitigation assessment (full)"):
            st.markdown((HERE / "assessment.md").read_text(encoding="utf-8"))

    with tabs[3]:
        note(
            "This tab exercises the <strong>mitigated</strong> agent. "
            "Observe the sandbox, allowlist, budget, and approval-queue "
            "controls engaging as payloads are replayed.",
            tone="ok",
        )
        render_attack_runner(
            ATTACKS,
            lambda payload: _run_mitigated(payload),
            key_prefix="llm06_mit",
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
    state = vulnerable.run(payload)
    bad = (
        bool(state.files_deleted)
        or bool(state.shell_commands)
        or bool(state.emails_sent)
        or bool(state.http_calls)
    )
    summary = _summarize_vulnerable(state)
    return AttackResult(
        name="",
        succeeded=bad,
        user_input=payload,
        output=summary,
        notes=f"{len(state.audit)} tool call(s) executed",
    )


def _run_mitigated(payload: str) -> AttackResult:
    state = mitigated.run(payload)
    # 'Succeeded' from an attacker's POV means an unapproved side effect landed.
    # Queued actions do not count as success until approved.
    executed_side_effect = any(
        a.tool not in {"list_sandbox_files", "read_sandbox_file"} and not a.blocked
        and not a.result.startswith("QUEUED")
        for a in state.audit
    )
    summary = _summarize_mitigated(state)
    return AttackResult(
        name="",
        succeeded=executed_side_effect,
        user_input=payload,
        output=summary,
        notes=(
            f"{len(state.audit)} tool call(s), "
            f"{sum(1 for a in state.audit if a.blocked)} blocked, "
            f"{len(state.pending)} queued for approval"
        ),
    )


def _summarize_vulnerable(state) -> str:
    lines = ["Agent side-effects recorded (mocked but would have executed):"]
    if state.files_deleted:
        lines.append(f"  • files deleted: {state.files_deleted}")
    if state.files_written:
        lines.append(f"  • files written: {state.files_written}")
    if state.shell_commands:
        lines.append(f"  • shell commands: {state.shell_commands}")
    if state.emails_sent:
        lines.append(f"  • emails sent: {[e['to'] for e in state.emails_sent]}")
    if state.http_calls:
        lines.append(f"  • http calls: {[h['url'] for h in state.http_calls]}")
    if len(lines) == 1:
        lines.append("  • (none — agent chose not to act this run)")
    lines.append("")
    lines.append("Tool-call audit:")
    for a in state.audit:
        lines.append(f"  - {a.tool}({a.args}) -> {a.result[:120]}")
    return "\n".join(lines)


def _summarize_mitigated(state) -> str:
    lines = ["Mitigated agent audit:"]
    for a in state.audit:
        tag = "BLOCKED" if a.blocked else "ok"
        lines.append(f"  - [{tag}] {a.tool}({a.args}) -> {a.result[:120]}")
    if state.pending:
        lines.append("")
        lines.append("Pending actions (require human approval):")
        for p in state.pending:
            lines.append(f"  - id={p.id} {p.tool}({p.args}) — {p.reason}")
    lines.append("")
    lines.append(
        f"Budgets — tool calls: {state.tool_calls}/{mitigated.MAX_TOOL_CALLS}, "
        f"http: {state.http_calls}/{mitigated.MAX_HTTP_CALLS}, "
        f"writes: {state.write_calls}/{mitigated.MAX_WRITE_CALLS}"
    )
    return "\n".join(lines)
