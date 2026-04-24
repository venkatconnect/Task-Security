"""Reusable Streamlit UI helpers: risk-score card, diff viewer, attack runner."""
from __future__ import annotations

import difflib
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import streamlit as st

from shared.risk_matrix import Assessment, RiskScore


def render_score_card(title: str, score: RiskScore) -> None:
    st.markdown(
        f"""
        <div style="border-left:5px solid {score.color};
                    padding:1.1rem 1.3rem;
                    background:var(--surface-2, #141A24);
                    border:1px solid var(--border, #232B3A);
                    border-left-width:5px;
                    border-radius:10px;
                    margin:0.6rem 0 1rem;">
          <div style="font-size:0.82rem;
                      text-transform:uppercase;
                      letter-spacing:0.1em;
                      color:var(--text-2, #9AA6B2);
                      font-weight:600;">
            {title}
          </div>
          <div style="font-size:2.1rem;
                      font-weight:700;
                      letter-spacing:-0.02em;
                      color:{score.color};
                      margin-top:0.3rem;
                      line-height:1.1;">
            {score.label} <span style="opacity:0.65;font-weight:500;font-size:1.5rem;">({score.score})</span>
          </div>
          <div style="font-size:0.95rem;
                      color:var(--text-2, #9AA6B2);
                      margin-top:0.5rem;">
            Likelihood: <strong style="color:var(--text-1, #E6EDF3);font-weight:600;">{score.likelihood.name.title()}</strong>
            &nbsp;·&nbsp;
            Impact: <strong style="color:var(--text-1, #E6EDF3);font-weight:600;">{score.impact.name.title()}</strong>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_assessment(a: Assessment, *, post: bool = False) -> None:
    score = a.post if post else a.pre
    render_score_card("Post-mitigation (residual)" if post else "Pre-mitigation", score)

    st.markdown(f"**Threat:** {a.threat}")

    if post:
        st.markdown("**Mitigations applied**")
        for m in a.mitigations:
            st.markdown(f"- {m}")
        st.markdown("**Residual-risk scenarios** *(why this is not fully mitigated)*")
        for r in a.residual_scenarios:
            st.markdown(f"- {r}")
        st.markdown("**Monitoring / detective controls**")
        for m in a.monitoring:
            st.markdown(f"- {m}")


def render_diff(before_path: str | Path, after_path: str | Path) -> None:
    before = Path(before_path).read_text(encoding="utf-8").splitlines(keepends=False)
    after = Path(after_path).read_text(encoding="utf-8").splitlines(keepends=False)
    diff = difflib.unified_diff(
        before, after, fromfile=str(before_path), tofile=str(after_path), lineterm=""
    )
    st.code("\n".join(diff) or "(files identical)", language="diff")


@dataclass
class AttackResult:
    name: str
    succeeded: bool
    user_input: str
    output: str
    notes: str = ""


def render_attack_runner(
    attacks: list[dict],
    runner: Callable[[str], AttackResult],
    *,
    key_prefix: str,
    expected_success: bool,
) -> None:
    """Render an attack panel. `expected_success` True = vulnerable demo."""
    for i, atk in enumerate(attacks):
        label = f"A{i + 1:02d}  ·  {atk['name']}"
        with st.expander(label, expanded=False):
            st.caption(atk.get("description", ""))
            st.code(atk["payload"], language="text")
            if st.button("Execute payload", key=f"{key_prefix}_atk_{i}"):
                try:
                    result = runner(atk["payload"])
                except Exception as e:
                    st.error(f"Runner error: {e}")
                    st.code(traceback.format_exc(), language="python")
                    continue

                _render_verdict(result.succeeded, expected_success)

                st.markdown("**Response**")
                st.code(result.output or "(empty)", language="text")
                if result.notes:
                    st.caption(result.notes)


def _render_verdict(succeeded: bool, expected_success: bool) -> None:
    """Render a muted status pill instead of a loud coloured alert."""
    if succeeded:
        label = "Payload succeeded"
        detail = "Sensitive output produced or unintended action executed."
        color = "#E05C5C" if expected_success else "#E0A95C"
    else:
        label = "Payload blocked"
        detail = "Control refused the request or returned a safe response."
        color = "#6ECB8E" if not expected_success else "#E0A95C"

    st.markdown(
        f"""
        <div style="display:flex;align-items:center;gap:0.75rem;
                    padding:0.65rem 0.9rem;
                    border:1px solid {color}55;
                    border-left:3px solid {color};
                    background:{color}12;
                    border-radius:8px;
                    margin:0.5rem 0;">
          <span style="width:8px;height:8px;border-radius:50%;background:{color};
                       box-shadow:0 0 0 3px {color}33;"></span>
          <div style="display:flex;flex-direction:column;">
            <span style="font-weight:600;color:{color};font-size:0.98rem;
                         letter-spacing:0.01em;">{label}</span>
            <span style="font-size:0.88rem;color:var(--text-2, #9AA6B2);">
              {detail}
            </span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
