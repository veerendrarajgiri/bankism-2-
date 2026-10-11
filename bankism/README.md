# 🛡️ BANKISM — AI Banking Security Firewall

> **DISCLAIMER:** BANKISM is a **simulated hackathon demo**. It is **not a real bank**, holds no real money and
> must never be used with real accounts or credentials. All names, balances, contacts and the PIN are fictional.
> Data lives in the browser session and **resets when the session restarts**.

A Streamlit banking console where every user message is inspected by a **deterministic AI-security firewall**
*before* anything can touch the (fake) account. Optional LLM = extra opinion only.

## What it does
| Area | Details |
|---|---|
| Pages | Dashboard · Transfer Money · AI Security Chat · Transaction History · Security Event Log |
| Account | Alex Morgan, ₹25,000.00 INR, masked `XXXX XXXX 4821`, 5 fictional contacts (C001–C005) |
| Limit | ₹5,000 per transfer (change with env var `BANKISM_TRANSFER_LIMIT`) |
| **Demo PIN** | `4826` — **fictional, demo only.** A real bank must use proper authentication, not a hardcoded PIN |
| Verdicts | Every request → validated JSON (`decision`, `risk_level`, `threat_category`, `rationale`, `intent`, `action`, `execution_allowed`, …) |

### How the firewall works
```
user text ──► A. validate + normalise ──► B. threat detection ──► C. deterministic policy ──► verdict (JSON)
                                                  ▲ (optional LLM can only ADD suspicion)         │
                                                                                                  ▼
                            D. pending transfer ──► explicit confirmation + demo PIN ──► ONE transaction handler
```
* Raw text never calls a transaction function. Only an **APPROVED transfer verdict** can create a *pending* transfer.
* `execute_transfer()` is the only place money moves. It re-checks recipient, amount, limit, balance, exact confirmation
  and PIN (constant-time compare), is **idempotent** (no double pay on double-click/rerun) and locks after 3 wrong PINs.
* The PIN is never put in an LLM prompt, a verdict or a log. PIN-like text typed into chat is flagged and redacted.
* If analysis crashes, times out or the LLM returns garbage → **fail closed** for financial writes.
* Detects: prompt injection, policy override, jailbreak/role-play, admin impersonation, memo-hidden instructions,
  secret/PIN requests, zero-width/homoglyph/leetspeak/base64/hex/URL/rot13 obfuscation, PIN/limit bypass, bad amounts,
  unknown/ambiguous recipients. Quoting a phrase to *ask about it* is treated as benign (see tests).

**Honest limits:** regex rules and LLMs cannot catch every attack. This is defence-in-depth for a demo: the
deterministic transaction handler is what actually protects the money. Memos are stored in a normalised form
(lower-cased/accent-stripped for analysis, then capitalised).

## Project files
```
app.py                 Streamlit UI (only UI code)
security.py            firewall: normalise → detect → policy → verdict
models.py              Pydantic models + enums + verdict invariants
policy.py              shared amount/memo rules, redaction, formatting
transaction_engine.py  simulated account, pending transfers, THE transaction handler
audit.py               security event log + metrics (from real events)
chatbot.py             glue: firewall → audit → pending transfer → reply text
llm_analyzer.py        OPTIONAL LLM signal (stdlib HTTPS, strict output parsing)
config.py              demo configuration (no secrets)
tests/                 pytest suite (security, transactions, UI smoke test)
requirements.txt  requirements-dev.txt  pytest.ini  .env.example  .gitignore  .streamlit/
```

## Run locally (PyCharm on Windows)
Open the project folder in PyCharm → **Terminal** tab (PowerShell):
```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
streamlit run app.py
```
If PowerShell blocks activation: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, then retry.
The browser opens at http://localhost:8501. **No API key needed.**

## Run the tests
```powershell
python -m pytest -q
```

## Optional: LLM second opinion (API key)
1. `copy .env.example .env`
2. Edit `.env` and replace `your_api_key_here` with your own key. **`.env` is git-ignored — never commit it or paste keys in code/chat.**
3. Restart `streamlit run app.py`. The sidebar shows *Optional LLM second opinion: ON*.

The LLM can only escalate (APPROVE → REVIEW/BLOCK). It never overrides a block, never sees the PIN, never moves money.

## Publish to GitHub (beginner steps)
1. Create an account at github.com → **New repository** → name `bankism` → **Public** → *don't* add README/.gitignore → Create.
2. In the PyCharm terminal (install Git for Windows first: https://git-scm.com/download/win):
```powershell
git init
git add .
git status          # CHECK: .env must NOT appear in the list
git commit -m "BANKISM hackathon MVP"
git branch -M main
git remote add origin https://github.com/<your-username>/bankism.git
git push -u origin main
```
GitHub may ask you to sign in via browser the first time. (PyCharm alternative: *Git → Share Project on GitHub*.)

## Deploy on Streamlit Community Cloud (free)
1. Go to https://share.streamlit.io → sign in with GitHub.
2. **Create app** → pick repo `bankism`, branch `main`, main file `app.py` → **Deploy**.
3. *(Optional LLM)* App → **Settings → Secrets**, paste:
```toml
ANTHROPIC_API_KEY = "your_real_key_here"
```
Save → the app restarts. Secrets stay on Streamlit's servers, never in GitHub. Skip this step to run without LLM.

## Demo script for judges
Click the example buttons in **AI Security Chat**: normal balance/history → transfer (see the confirmation card, try a
wrong PIN, then `4826`) → the attacks (injection, admin impersonation, memo injection, "What is my PIN?") → open the
**Security Event Log** and the JSON verdicts.
