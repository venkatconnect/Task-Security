"""OWASP LLM Top 10 — Security Demo (Task 4).

Two risks, one app:
  * LLM02 — Sensitive Information Disclosure (RAG-based)
  * LLM06 — Excessive Agency (tool-using agent)

Each risk has its own 5-tab page: Overview, Vulnerable demo, Risk (pre),
Mitigation (+ code diff), Risk (post).

Run with:  streamlit run app.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, str(Path(__file__).resolve().parent))

st.set_page_config(
    page_title="OWASP LLM Top 10 · Security Demo",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
  --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --font-mono: 'JetBrains Mono', 'Fira Code', ui-monospace, SFMono-Regular, Menlo, monospace;
  --surface-2: #141A24;
  --border:    #232B3A;
  --text-1:    #E6EDF3;
  --text-2:    #9AA6B2;
  --accent:    #7C5CFF;
}

html { font-size: 18px; }

html, body, .stApp, [class*="css"] {
  font-family: var(--font-sans) !important;
  font-feature-settings: "cv02","cv03","cv04","cv11","ss01";
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  line-height: 1.65;
}

.stApp, .stMarkdown p, .stMarkdown li, .stMarkdown {
  font-size: 1.12rem;
  color: var(--text-1);
}

code, pre, kbd, samp, [data-testid="stCodeBlock"] code {
  font-family: var(--font-mono) !important;
  font-size: 1rem;
  line-height: 1.6;
}

.main .block-container { max-width: 1200px; padding-top: 2.25rem; }

h1, h2, h3, h4 {
  letter-spacing: -0.02em;
  font-weight: 700;
  line-height: 1.2;
}
h1 { font-size: 2.55rem; margin-bottom: 0.5rem; }
h2 { font-size: 1.9rem; }
h3 { font-size: 1.45rem; font-weight: 600; }
h4 { font-size: 1.2rem; font-weight: 600; }

.stMarkdown strong { color: var(--text-1); font-weight: 600; }
.stMarkdown em { color: var(--text-2); }

[data-testid="stCaptionContainer"], .caption, small {
  font-size: 0.95rem !important;
  color: var(--text-2) !important;
  letter-spacing: 0.01em;
}

/* In-page tabs (the 5-tab stepper on each risk page) */
.stTabs [data-baseweb="tab-list"] {
  gap: 0.5rem;
  border-bottom: 1px solid var(--border);
}
.stTabs [data-baseweb="tab"] {
  font-weight: 500;
  font-size: 1.25rem;
  padding: 0.9rem 1.4rem;
  border-radius: 8px 8px 0 0;
  letter-spacing: 0.005em;
}
.stTabs [data-baseweb="tab"] p,
.stTabs [data-baseweb="tab"] div,
.stTabs [data-baseweb="tab"] span {
  font-size: 1.25rem !important;
}
.stTabs [aria-selected="true"] {
  background: var(--surface-2);
  color: var(--text-1);
  font-weight: 600;
}

/* --- Top-level risk selector: render radio as a tabbed segmented switch --- */
div[role="radiogroup"] {
  display: inline-flex !important;
  gap: 0;
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 5px;
  box-shadow: 0 1px 0 rgba(255,255,255,0.02) inset;
}
div[role="radiogroup"] > label {
  background: transparent !important;
  border: 1px solid transparent !important;
  border-radius: 8px;
  padding: 0.6rem 1.3rem !important;
  margin: 0 !important;
  font-size: 1.05rem !important;
  font-weight: 500 !important;
  color: var(--text-2);
  cursor: pointer;
  transition: color 120ms ease, background 120ms ease, border-color 120ms ease;
}
div[role="radiogroup"] > label > div:first-child { display: none !important; }  /* hide the radio dot */
div[role="radiogroup"] > label:hover { color: var(--text-1); }
div[role="radiogroup"] > label:has(input:checked) {
  background: var(--accent) !important;
  border-color: var(--accent) !important;
  color: #fff !important;
  font-weight: 600 !important;
  box-shadow: 0 2px 8px rgba(124, 92, 255, 0.35);
}

.stButton > button {
  font-family: var(--font-sans) !important;
  font-weight: 500;
  font-size: 1rem;
  padding: 0.55rem 1.2rem;
  border-radius: 8px;
}

[data-testid="stCodeBlock"] {
  border: 1px solid var(--border);
  border-radius: 10px;
}

[data-testid="stExpander"] {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: 10px;
}
[data-testid="stExpander"] summary {
  font-size: 1.08rem;
  font-weight: 500;
}

.stAlert, div[data-testid="stAlert"] {
  border-radius: 10px;
  border: 1px solid var(--border);
  font-size: 1.05rem;
}

table { font-size: 1.02rem; }
th { font-weight: 600; color: var(--text-1); }

hr, [data-testid="stDivider"] {
  border: 0;
  border-top: 1px solid var(--border) !important;
  opacity: 1;
  margin: 1.25rem 0 1.75rem;
}

/* Muted scrollbar for a more polished feel */
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb {
  background: var(--border);
  border-radius: 6px;
  border: 2px solid var(--surface-2);
}
::-webkit-scrollbar-thumb:hover { background: #2F3A4C; }

/* Selection colour */
::selection { background: rgba(124, 92, 255, 0.35); color: var(--text-1); }

/* Keep the Streamlit header visible but visually lighter */
header[data-testid="stHeader"] {
  background: transparent;
  border-bottom: 1px solid var(--border);
}
</style>""",
    unsafe_allow_html=True,
)

from risks.llm02_info_disclosure import page as llm02_page
from risks.llm06_excessive_agency import page as llm06_page

PAGES = {
    "LLM02  ·  Sensitive Information Disclosure": llm02_page.render,
    "LLM06  ·  Excessive Agency": llm06_page.render,
}

LOGO_SVG = """
<svg xmlns="http://www.w3.org/2000/svg" width="30" height="30"
     viewBox="0 0 24 24" fill="none" stroke="currentColor"
     stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
  <path d="M12 3 4 6v6c0 4.5 3.2 8.3 8 9 4.8-.7 8-4.5 8-9V6l-8-3Z"/>
  <path d="M9 12l2 2 4-4"/>
</svg>
"""


def main() -> None:
    header_left, header_right = st.columns([3, 5])
    with header_left:
        st.markdown(
            f"""
            <div style="display:flex;align-items:center;gap:0.75rem;">
              <span style="color:var(--accent);">{LOGO_SVG}</span>
              <div style="display:flex;flex-direction:column;line-height:1.15;">
                <span style="font-size:1.15rem;font-weight:600;letter-spacing:-0.01em;">
                  OWASP LLM Top 10
                </span>
                <span style="font-size:0.85rem;color:var(--text-2);letter-spacing:0.02em;">
                  Security assessment · Task 4
                </span>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with header_right:
        choice = st.radio(
            "Select risk",
            list(PAGES.keys()),
            horizontal=True,
            label_visibility="collapsed",
        )

    with st.expander("Usage", expanded=False):
        st.markdown(
            "1. Review the threat model on the **Overview** tab.\n"
            "2. Execute attack payloads against the unmitigated implementation.\n"
            "3. Review the pre-mitigation risk score and rationale.\n"
            "4. Inspect the mitigation diff, then re-execute the same payloads.\n"
            "5. Review the residual-risk assessment and monitoring controls.\n\n"
            "Inference is served locally by Ollama. Ensure `ollama serve` is "
            "running and `OLLAMA_BASE_URL` / `OLLAMA_MODEL` are configured in "
            "`.env`."
        )

    st.divider()
    PAGES[choice]()


if __name__ == "__main__":
    main()
