# Threat-Protection-HIDS
##

## TOOL
AI powered Threat Detection System providing a segmented honeypot and a rotating(dynamic) firewall, to provide businesses with a method to detect and to a lesser degree prevent attacks.

### Usuage and Application of tool:
Threat Detection and prevention system that focuses and targets business and their employees, the tool is a focused on providing host intrusion detection, that will be using API calls to: 
1. Provide a lightweight tool
2. Automated checks and dashboard logging and, 
3. Comprehensive knowlegde base using AI tools (Ollama,etc) to gain a better understanding of the environnment and common and emerging threats through OSSEC and MITRE ATT&CK.

## Inspiration

- South Africa is ranked in the __top 10__ for most targeted region for attakcs globally and ranked as one of the lowest in the top 10 for **cybersecurity education** and **prepardness**.
- It is also noted that **60%** pf breaches occured in 2024, had "_a nonmalicious human error_", basically a simple human error.

# Threat Protection HIDS (prototype)

Lightweight Host Intrusion Detection & Prevention (HIDS) prototype focused on small-footprint agents, automated checks, dashboard logging, and an AI-backed knowledge base. This repo contains a minimal FastAPI server, a tiny host agent, and a small AI KB adapter (for Ollama or other LLMs).

Goals

- Provide a lightweight agent to collect host telemetry and forward to a server.
- Provide automated checks and centralized logging/search for events.
- Use an AI knowledge base (local LLM like Ollama) and MITRE ATT&CK mappings to enrich and triage alerts.

Quickstart (development)

1. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Run the API server (development):

```bash
# set required env variables (example)
export $(cat .env.example | xargs)
uvicorn server.main:app --reload --host 0.0.0.0 --port 8000
```

3. Run the agent once to send a telemetry event (in another shell):

```bash
python -m agent.agent --server http://localhost:8000 --agent-id myhost1 --once
```

4. Open the simple dashboard: http://localhost:8000/dashboard (or serve `dashboard/index.html` via a static host). The server exposes `/events/log` for recent events.

Notes and next steps

- OSSEC integration: forward OSSEC alerts (syslog or alert files) to `/events` to centralize them.
- MITRE ATT&CK: expand `ai/kb.py` mapping and automate tagging of alerts.
- Ollama/local LLM: set `OLLAMA_URL` env var to point to a running Ollama instance to enable richer KB queries.
 - Security: this prototype enforces an API key for protected endpoints. Set `API_KEY` (see `.env.example`) and give agents the key via `AGENT_API_KEY` env var or `--api-key` CLI flag.
 - TLS / Reverse proxy: run behind an HTTPS reverse-proxy (nginx/Caddy) in production; the uvicorn example above is for local development only.

Files of interest

- `server/main.py` — FastAPI app handling registration, events, and KB queries. Protected endpoints require `x-api-key` header or `api_key` query param.
- `agent/agent.py` — lightweight agent that collects host telemetry and posts it. Use `--api-key` or set `AGENT_API_KEY` env to authenticate.

Running tests

```bash
pytest -q
```

Files of interest

- `server/main.py` — FastAPI app handling registration, events, and KB queries.
- `agent/agent.py` — lightweight agent that collects host telemetry and posts it.
- `ai/kb.py` — AI knowledge-base adapter and simple MITRE mapping placeholder.
- `dashboard/index.html` — very small static dashboard.
- `docs/architecture.md` — architecture notes and integration points.

CI and secrets
---------------

CI should never hardcode sensitive values. For integration tests that require
`MASTER_KEY` or `API_KEY`, store them in GitHub Secrets and reference them in
workflow files. Example (protected job snippet) — do NOT place secrets directly
in the repo; instead add them with repository Settings -> Secrets and variables:

```yaml
jobs:
	integration:
		runs-on: ubuntu-latest
		permissions: write-all
		secrets: inherit
		steps:
			- uses: actions/checkout@v4
			- name: Set up Python
				uses: actions/setup-python@v4
				with:
					python-version: '3.11'
			- name: Export secrets
				env:
					MASTER_KEY: ${{ secrets.MASTER_KEY }}
					API_KEY: ${{ secrets.API_KEY }}
					REDIS_URL: redis://redis:6379
				run: |
					echo "Secrets are available to the environment for this job"
			- name: Run integration tests
				run: pytest tests -q
```

Notes:
- Mark such jobs as requiring approval for forks or run only on protected branches
	to avoid secret leakage.
- Prefer a dedicated CI-only KMS (or GitHub Encrypted Secrets) and avoid printing
	secrets in logs.

Security recommendations (short)
- Terminate TLS at a reverse-proxy (nginx/Caddy) in production and enable
	mTLS for agent provisioning if possible.
- Use a KMS or Vault for `MASTER_KEY` and rotate it periodically; plan a
	re-encryption strategy for DB secrets.
- Store transient tokens in Redis with TTL for multi-instance deployments.

Contributing

This is an early prototype. If you'd like help expanding it (OSSEC parsers, production TLS, auth, richer KB integrations), open an issue or a PR.

Notice the trend of employees not knowing/adhering to company policy, on the company workstations. This opens organizations to threats/ransomware/etc, be it from phishing emails, unauthorised installation of applications that are not company regulated/approved.
