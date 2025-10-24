"""Lightweight host agent to collect basic telemetry and post to server.
Usage:
  python -m agent.agent --server http://localhost:8000 --agent-id myhost1 --once
"""
import argparse
import json
import os
import platform
import subprocess
import time
from typing import Dict

import requests
import hmac
import hashlib
import time as _time
import os as _os


def collect_basic_info() -> Dict[str, object]:
    info = {
        "hostname": platform.node(),
        "os": platform.platform(),
        "python_version": platform.python_version(),
        "timestamp": int(time.time()),
    }

    # get a short process list (pid, comm) using ps for portability without psutil
    try:
        out = subprocess.check_output(["/bin/ps", "-eo", "pid,comm"], text=True)
        lines = out.strip().splitlines()[1:51]  # limit to first 50 processes
        procs = []
        for l in lines:
            parts = l.strip().split(None, 1)
            if len(parts) == 2:
                procs.append({"pid": parts[0], "comm": parts[1]})
        info["processes"] = procs
    except Exception:
        info["processes"] = []

    return info


def post_event(server: str, agent_id: str, event_type: str, payload: Dict):
    url = server.rstrip("/") + "/events"
    body = {"agent_id": agent_id, "event_type": event_type, "payload": payload}
    headers = {}
    api_key = os.getenv("AGENT_API_KEY")
    if api_key:
        headers["x-api-key"] = api_key

    # HMAC signing
    agent_secret = _os.getenv("AGENT_SECRET")
    ts = str(int(_time.time()))
    try:
        body_str = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    except Exception:
        body_str = str(payload)

    if agent_secret:
        msg = (ts + "." + body_str).encode()
        sig = hmac.new(agent_secret.encode(), msg, hashlib.sha256).hexdigest()
        headers.update({"x-agent-id": agent_id, "x-timestamp": ts, "x-signature": sig})

    try:
        r = requests.post(url, json=body, timeout=10, headers=headers)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print("failed to post event:", e)
        return None


def register_agent(server: str, agent_id: str, hostname: str):
    url = server.rstrip("/") + "/agents/register"
    body = {"agent_id": agent_id, "hostname": hostname, "metadata": {}}
    headers = {}
    api_key = os.getenv("AGENT_API_KEY")
    if api_key:
        headers["x-api-key"] = api_key
    try:
        r = requests.post(url, json=body, timeout=10, headers=headers)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print("failed to register agent:", e)
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True, help="Server URL, e.g. http://localhost:8000")
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--api-key", required=False, help="API key to send to server (or set AGENT_API_KEY env)")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    parser.add_argument("--interval", type=int, default=300, help="Seconds between reports when running continuously")
    args = parser.parse_args()

    hostname = platform.node()
    # allow passing API key on CLI for ad-hoc runs
    if args.api_key:
        os.environ["AGENT_API_KEY"] = args.api_key

    reg = register_agent(args.server, args.agent_id, hostname)
    if not reg:
        print("continuing without registration")

    while True:
        info = collect_basic_info()
        resp = post_event(args.server, args.agent_id, "host_telemetry", info)
        if args.once:
            print("posted once, response:", resp)
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
