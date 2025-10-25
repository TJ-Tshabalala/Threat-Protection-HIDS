"""AI Knowledge Base helpers.
This module provides a small wrapper to query a local LLM service (e.g., Ollama) or a remote API.
It's intentionally lightweight and returns a simple string response.
"""
import os
import requests
from typing import Optional


OLLAMA_URL = os.getenv("OLLAMA_URL")  # e.g. http://localhost:11434


def query_kb(prompt: str) -> Optional[str]:
    """Query the configured LLM/KB. Returns string or None on failure.

    This is a placeholder - adapt to your LLM provider's API.
    """
    if not OLLAMA_URL:
        # No LLM configured: do a simple heuristic reply
        return f"[KB disabled] got query: {prompt[:200]}"

    try:
        # Example Ollama-style request (adjust per your server)
        url = OLLAMA_URL.rstrip("/") + "/api/generate"
        payload = {"prompt": prompt, "max_tokens": 512}
        r = requests.post(url, json=payload, timeout=20)
        r.raise_for_status()
        data = r.json()
        # The response shape depends on your LLM server; try a few keys
        if isinstance(data, dict):
            for k in ("text", "response", "result", "output"):
                if k in data:
                    return data[k]
        return str(data)
    except Exception:
        return None


# Placeholder: map simple observable to MITRE ATT&CK tags
MITRE_MAPPING = {
    "suspicious_binary": ["T1059", "T1204"],
    "privilege_escalation": ["T1068"],
}


def map_to_mitre(alert_type: str):
    return MITRE_MAPPING.get(alert_type, [])
