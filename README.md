# MINEARENA 2.0 — Context-Aware Privacy Gateway for Enterprise LLMs

A local-first privacy firewall positioned between enterprise applications and external Large Language Models (LLMs). Built for **Code Commit, BIET Davangere (PS-02: DPDP-Ready Privacy Gateway)**.

MINEARENA intercepts text and documents locally, detects Indian personal data and enterprise secrets, applies deterministic policy rules, replaces sensitive spans with request-scoped placeholders, validates the exact outbound payload via an independent firewall, and restores authorized values locally after the LLM responds.

---

## Core Architecture & Security Guarantees
* **Local-First Detection Ensemble:** Combines Microsoft Presidio, custom Indian regex/checksum validators, local NER models, and context/abbreviation dictionaries.
* **Mandatory Indian Identifiers:** Detects and validates **Aadhaar, PAN, GSTIN, Voter ID, and Passport** candidates alongside **PERSON** and **ADDRESS** entities in Indian English and tested Indic/code-mixed inputs.
* **Fail-Closed Outbound Firewall:** External LLM adapters only accept an immutable `ValidatedSanitizedPayload` object. If a scanner crashes, times out, or detects residual PII/high-risk ambiguity, the gateway fails closed and blocks the external API call.
* **Request-Scoped Token Vault:** Generates non-deterministic, typed placeholders (e.g., `<PERSON_1>`, `<AADHAAR_1>`, `<PAN_1>`) stored in isolated, short-lived memory/storage separate from ordinary audit logs.
* **Safe Local Reinsertion:** Restores valid current-request tokens locally while blocking cross-person substitutions and ignoring fabricated or dropped tokens.

---

## Tech Stack
* **Backend & API:** Python 3.11+, FastAPI, Pydantic, Uvicorn
* **PII Detection & NLP:** Microsoft Presidio, Custom Indian Recognizers, Local NER
* **Storage & Audit:** SQLite, SQLAlchemy (separate audit and protected mapping stores)
* **Frontend UI:** Three-panel interactive dashboard (Streamlit / React)
* **Testing & Evaluation:** Pytest, HTTPX, 50+ labeled synthetic Indian enterprise documents

---

## Project Structure

```text
minearena/
├── backend/app/
│   ├── api/            # Gateway, review, audit, and metrics endpoints
│   ├── pipeline/       # Normalization, sanitizer, outbound firewall, reinsertion
│   ├── detection/      # Presidio, regex, NER, context, and unknown-risk engines
│   ├── recognizers/    # India-specific (Aadhaar, PAN, GSTIN, Voter ID, Passport) & domain packs
│   ├── policies/       # Deterministic DPDP & enterprise-confidentiality policy engine
│   ├── token_vault/    # Request-scoped token mapping and encryption
│   └── providers/      # Pluggable external LLM adapter & offline mock provider
├── frontend/           # Three-panel UI (Original Input | Sanitized Outbound | Restored Response)
├── data/               # 50+ synthetic Indian documents & ground-truth labels
├── tests/              # Unit, integration, security (fail-closed), and adversarial tests
├── PRD.txt             # Product Requirements Document
└── TRD.txt             # Technical Requirements Document
```
*(Adapted from the TRD repository specification.)*

---

## Prerequisites
* **Python 3.11** or higher
* **Node.js 18+** (if running the React/Vite frontend)
* *(Optional)* An external LLM API key (e.g., Gemini API key) — **Note:** Includes a built-in **Mock Provider** mode so the full pipeline and evaluation suite can run completely offline without API credentials.

---

## Local Setup & Installation

### 1. Clone the repository
```bash
git clone https://github.com[your-username]/minearena.git
cd minearena
```

### 2. Set up the Python environment
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
pip install -e .
```

### 3. Configure environment variables
Copy `.env.example` to `.env` and configure your settings:
```bash
cp .env.example .env
```

Example `.env` configuration:
```env
APP_ENV=development
DATABASE_URL=sqlite:///./minearena.db
LLM_PROVIDER=mock          # Set to 'mock' for offline demo, or your configured provider name
LLM_API_KEY=               # Leave blank in mock mode; never commit real keys
LLM_MODEL=
TOKEN_TTL_SECONDS=1800
OUTBOUND_FAIL_CLOSED=true
MAX_REQUEST_BYTES=1000000
```

### 4. Start the Backend Gateway
```bash
uvicorn app.main:app --reload
```
The FastAPI server and health check (`GET /health`) will run at `http://localhost:8000`.

### 5. Start the Three-Panel UI
* **If using Streamlit:**
  ```bash
  streamlit run frontend/streamlit_app.py
  ```
* **If using React/Vite:**
  ```bash
  cd frontend
  npm install
  npm run dev
  ```

---

## Running Tests & Synthetic Evaluation

Run the full unit, security, and fail-closed test suite:
```bash
pytest -q
```

Run the benchmark evaluation across the synthetic Indian dataset (KYC, Loan Applications, Insurance Claims, Support Tickets):
```bash
python scripts/run_evaluation.py
```
Metrics reported include **per-entity Precision/Recall/F1, Outbound Leakage Count (target: 0), Reinsertion Accuracy, and p50/p95 Latency**.

---

## Important Limitations & Disclaimers
* **Hackathon Prototype Scope:** Built as a modular monolith prototype for demonstration and evaluation. Not intended as a drop-in, multi-tenant production deployment without enterprise KMS, RBAC, and TLS hardening.
* **Legal Compliance:** Technical safeguards (data minimization, local masking, audit logs) support privacy engineering, but using this tool does not automatically certify legal compliance under the Digital Personal Data Protection (DPDP) Act.
* **Synthetic Data Only:** All test fixtures and evaluation benchmarks use synthetic Indian identifiers. Never upload real customer, patient, or personal identity data during testing.
*
