# Task 4 — OWASP LLM Top 10 Security Demos

Interactive Streamlit app demonstrating two risks from the
[OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/)
with paired **vulnerable** and **mitigated** implementations, live attack
runners, and before/after risk assessments.

## Risks covered

| Risk  | Name                              | Demo leverages                         |
|-------|-----------------------------------|----------------------------------------|
| LLM02 | Sensitive Information Disclosure  | RAG pipeline (Task_RAG patterns)       |
| LLM06 | Excessive Agency                  | Tool-using agent (Task3_Agents_MCP)    |

Each risk page has five tabs that map to the grading rubric:

1. **Overview** — threat model, attack surface.
2. **Vulnerable demo** — runs the unsafe implementation; attacks succeed.
3. **Risk (pre)** — likelihood × impact score with justification.
4. **Mitigation** — runs the hardened implementation (same attacks are
   refused/redacted) + a side-by-side code diff.
5. **Risk (post)** — residual-risk assessment. "Fully mitigated" is never the
   answer — each page lists concrete bypass scenarios that remain.

## Quickstart

### 1. Set up Ollama
Make sure Ollama is installed and running:
```bash
ollama serve
```

In another terminal, pull a model (if not already available):
```bash
ollama pull llama2
# or try another model: ollama pull mistral, ollama pull neural-chat, etc.
```

### 2. Set up the app
```bash
cd Task4_Security
python -m venv .venv
# PowerShell: .venv\Scripts\Activate.ps1   |   bash: source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env if needed (defaults: OLLAMA_BASE_URL=http://localhost:11434, OLLAMA_MODEL=llama2)

streamlit run app.py
```

Open the URL Streamlit prints (default `http://localhost:8501`).

## Project layout

```
Task4_Security/
├── app.py                          # Streamlit entry; sidebar selects a risk
├── requirements.txt
├── .env.example
├── shared/
│   ├── llm_client.py               # client wrapper + prompt caching
│   ├── risk_matrix.py              # RiskScore / Assessment primitives
│   └── ui.py                       # Streamlit helpers (score card, diff, attack runner)
├── risks/
│   ├── llm02_info_disclosure/
│   │   ├── vulnerable.py           # naive RAG — no ACL, no redaction
│   │   ├── mitigated.py            # ACL + ingest redaction + output filter + query classifier
│   │   ├── attacks.py              # 4 attack payloads
│   │   ├── assessment.md           # pre-mitigation write-up
│   │   ├── assessment_post.md      # post-mitigation (residual) write-up
│   │   └── page.py                 # Streamlit tabs for this risk
│   └── llm06_excessive_agency/
│       ├── vulnerable.py           # over-broad tool-use agent
│       ├── mitigated.py            # least-privilege tools + sandbox + HITL queue + budgets
│       ├── attacks.py              # 4 attack payloads
│       ├── assessment.md
│       ├── assessment_post.md
│       └── page.py
└── data/
    ├── kb_with_secrets/            # synthetic RAG corpus (fake PII + secrets)
    └── sandbox/                    # writable area for the LLM06 agent tools
```

## Risk-scoring rubric

Both assessments use one shared rubric so before/after comparisons are
apples-to-apples:

```
Likelihood × Impact:  1=Low · 2=Medium · 3=High · 4=Critical
Bands:    1–3 Low · 4–6 Medium · 7–9 High · 10–16 Critical
```

Post-mitigation scores are structurally prevented from being zero: the
`Assessment` dataclass requires at least one concrete residual-risk scenario,
enforcing the guidance that *risk is fully mitigated is typically not an
option*.

## Summary of scores

| Risk  | Pre-mitigation            | Post-mitigation      | Delta          |
|-------|---------------------------|----------------------|----------------|
| LLM02 | **Critical (12)** — H × C | **Low (3)** — L × H  | −9 (Critical → Low) |
| LLM06 | **Critical (12)** — H × C | **Low (3)** — L × H  | −9 (Critical → Low) |

Residual risk stays non-zero in both cases — see each risk's
`assessment_post.md` for the concrete bypass paths that remain.

## Safety notes

- All "secrets" in `data/kb_with_secrets/` are **synthetic** — do not replace with real data.
- Tool side-effects (delete, shell, email, http) in LLM06 are **mocked** — they record intent without executing.

## Tech stack

- Python 3.11+
- Streamlit (UI)
- Ollama (local LLM inference via HTTP)
- `scikit-learn` TF-IDF for the lightweight RAG (no GPU / no model download)
- `requests` for HTTP calls to Ollama

Models tested: `llama2`, `mistral`, `neural-chat`

## Verifying without Ollama

If you want to make sure the scaffolding is correct before running Ollama, this smoke test imports every module with stubs:

```bash
python -c "
import sys; sys.path.insert(0, '.')
import shared.llm_client, shared.risk_matrix
import risks.llm02_info_disclosure.attacks, risks.llm06_excessive_agency.attacks
print('imports OK')
"
```

The attack runners require Ollama running because they actually call the LLM.
