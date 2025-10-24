# Threat Protection HIDS - Architecture

This document outlines the minimal architecture for the lightweight Host Intrusion Detection and Prevention prototype.

Components

- Server (FastAPI): receives agent registrations and events, exposes a small KB query endpoint and a simple events log used by the dashboard.
- Agent (Python script): lightweight host-side script that collects basic telemetry and posts events to the server. Designed to be minimal and easy to extend (add file integrity checks, OSSEC log forwarding, etc.).
- AI Knowledge Base (ai/kb.py): small adapter to an LLM (e.g., Ollama) to provide context, triage help, and map alerts to MITRE ATT&CK.
- Dashboard: static frontend or integrated app that reads the server event log endpoint and displays recent events.

Integration Points

- OSSEC: The project can ingest OSSEC alerts by forwarding OSSEC syslog/alerts into the server `/events` endpoint. A connector or small forwarder can be added later.
- MITRE ATT&CK: ai/kb provides a mapping helper to attach ATT&CK technique IDs to alerts; this will be expanded with richer rules and heuristics.
- Ollama / Local LLMs: The `OLLAMA_URL` environment variable can point to a local Ollama instance to enrich alerts with contextual explanations and suggested mitigations.

Security and Ops

- Keep the agent lightweight (no persistent remote shells). Use TLS for server when in production.
- Put the server behind authentication and rate-limiting in real deployments.
