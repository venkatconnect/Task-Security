"""Lightweight inline status notes — replacement for loud st.warning / st.success."""
from __future__ import annotations

import streamlit as st


def note(text: str, *, tone: str = "info") -> None:
    """Render a subtle status note.

    tone: 'info' (neutral), 'caution' (amber), 'ok' (green).
    """
    colors = {
        "info":    "#7C5CFF",
        "caution": "#E0A95C",
        "ok":      "#6ECB8E",
    }
    color = colors.get(tone, colors["info"])
    st.markdown(
        f"""
        <div style="display:flex;gap:0.75rem;align-items:flex-start;
                    padding:0.7rem 1rem;
                    border:1px solid {color}40;
                    border-left:3px solid {color};
                    background:{color}10;
                    border-radius:8px;
                    margin:0.3rem 0 0.9rem;
                    font-size:0.98rem;">
          <span style="width:6px;height:6px;border-radius:50%;background:{color};
                       margin-top:0.55rem;flex-shrink:0;"></span>
          <div style="color:var(--text-1, #E6EDF3);line-height:1.55;">{text}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
