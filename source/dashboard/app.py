import json
import os
import re
import threading
import urllib.parse
from datetime import datetime
from pathlib import Path

import requests
import urllib3
from flask import Flask, jsonify, request, send_from_directory

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
registry_lock = threading.RLock()

WAZUH_API_URL = os.environ["WAZUH_API_URL"].rstrip("/")
WAZUH_API_USER = os.environ["WAZUH_API_USER"]
WAZUH_API_PASSWORD = os.environ["WAZUH_API_PASSWORD"]
WAZUH_INDEXER_URL = os.environ["WAZUH_INDEXER_URL"].rstrip("/")
WAZUH_INDEXER_USER = os.environ["WAZUH_INDEXER_USER"]
WAZUH_INDEXER_PASSWORD = os.environ["WAZUH_INDEXER_PASSWORD"]

REGISTRY = Path(os.getenv("QUARANTINE_REGISTRY", "./quarantine_registry.json"))

DLP_RULE_IDS = (
    "100010",
    "100011",
    "100012",
    "100015",
    "100016",
    "100017",
    "100018",
    "100019",
    "100020",
)


def load_registry():
    try:
        if not REGISTRY.exists():
            return {}
        return json.loads(REGISTRY.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise RuntimeError("Cannot read quarantine request registry")


def save_registry(data):
    REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    temporary = REGISTRY.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    temporary.replace(REGISTRY)


@app.before_request
def validate_input():
    if not request.path.startswith("/api/") or request.method != "POST":
        return None

    data = request.get_json(silent=True)
    agent_id = str(data.get("agent_id", "")) if isinstance(data, dict) else ""

    if (
        not isinstance(data, dict)
        or not re.fullmatch(r"[0-9]{3,}", agent_id)
        or agent_id == "000"
    ):
        return jsonify(error="Provide the Windows agent_id; 000 is the manager"), 400

    data["agent_id"] = agent_id

    if request.path == "/api/scan" and data.get("scan_type", "quick") not in ("quick", "full"):
        return jsonify(error="scan_type must be quick or full"), 400


@app.errorhandler(requests.RequestException)
def upstream_error(error):
    return jsonify(error="Cannot contact Wazuh; check service logs and credentials"), 502


@app.get("/")
def index():
    return send_from_directory(Path(__file__).parent, "index.html")


def token():
    response = requests.get(
        f"{WAZUH_API_URL}/security/user/authenticate",
        auth=(WAZUH_API_USER, WAZUH_API_PASSWORD),
        verify=False,
        timeout=10,
    )
    if response.status_code != 200:
        return None
    return response.json()["data"]["token"]


def active_response(agent, command, arguments=None, custom=False):
    jwt = token()
    if not jwt:
        return {"error": "Failed to authenticate with Wazuh API"}, 401

    payload = {"command": command}
    if custom:
        payload["custom"] = True
    if arguments is not None:
        payload["arguments"] = arguments

    response = requests.put(
        f"{WAZUH_API_URL}/active-response?agents_list={agent}",
        headers={"Authorization": f"Bearer {jwt}"},
        json=payload,
        verify=False,
        timeout=15,
    )

    try:
        body = response.json()
    except Exception:
        body = {"raw": response.text}

    if not response.ok:
        return {"error": "Wazuh rejected the request"}, 502

    data = body.get("data", {}) if isinstance(body, dict) else {}
    if (
        not isinstance(body, dict)
        or body.get("error", 0)
        or data.get("total_failed_items", 0)
        or not data.get("affected_items")
    ):
        return {"error": "Wazuh did not accept the action for this agent"}, 502

    return {
        "status": "command_sent",
        "message": "Da gui lenh; can kiem tra tep va log tren Windows.",
    }, 202


@app.post("/api/scan")
def scan():
    data = request.get_json(force=True)
    scan_type = data.get("scan_type", "quick")
    command = "win_yara_quick0" if scan_type == "quick" else "win_yara_full0"
    body, status = active_response(data["agent_id"], command)
    return jsonify(body), status


@app.post("/api/quarantine")
def quarantine():
    data = request.get_json(force=True)
    agent = data["agent_id"]
    path = data.get("file_path")

    if not isinstance(path, str) or not re.match(r"^[A-Za-z]:[\\/]", path):
        return jsonify(error="Missing file path for quarantine"), 400

    body, status = active_response(
        agent,
        "win_quarantine0",
        [urllib.parse.quote(path, safe="")],
        False,
    )

    if status == 202:
        with registry_lock:
            registry = load_registry()
            registry.setdefault(agent, []).append(
                {
                    "original_path": path,
                    "original_name": path.replace("/", "\\").split("\\")[-1],
                    "quarantine_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "quarantine_requested",
                }
            )
            save_registry(registry)

    return jsonify(body), status


@app.post("/api/restore")
def restore():
    data = request.get_json(force=True)
    agent = data["agent_id"]
    name = data.get("quarantine_filename")

    if not isinstance(name, str) or not name or "/" in name or "\\" in name:
        return jsonify(error="Missing quarantine_filename"), 400

    body, status = active_response(
        agent,
        "win_restore0",
        [urllib.parse.quote(name, safe="")],
        False,
    )

    if status == 202:
        with registry_lock:
            registry = load_registry()
            registry.setdefault(agent, []).append(
                {
                    "original_name": name,
                    "status": "restore_requested",
                    "quarantine_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
            )
            save_registry(registry)

    return jsonify(body), status


@app.post("/api/list_quarantine")
def list_quarantine():
    data = request.get_json(force=True)
    files = load_registry().get(data["agent_id"], [])
    return jsonify(
        files=files,
        verified=False,
        message="Request history only; inspect the Windows quarantine directory",
    )


@app.post("/api/isolate")
def isolate():
    body, status = active_response(
        request.get_json(force=True)["agent_id"],
        "win_isolate0",
    )
    return jsonify(body), status


@app.post("/api/disable")
def disable():
    body, status = active_response(
        request.get_json(force=True)["agent_id"],
        "win_disable0",
    )
    return jsonify(body), status


@app.get("/api/alerts")
def alerts():
    query = {
        "size": 70,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "should": [{"term": {"rule.id": rule_id}} for rule_id in DLP_RULE_IDS],
                "minimum_should_match": 1,
            }
        },
    }

    response = requests.get(
        f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_search",
        auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
        json=query,
        verify=False,
        timeout=15,
    )

    if response.status_code != 200:
        return (
            jsonify(
                error="Unable to query Indexer",
                details="Inspect Indexer locally",
            ),
            response.status_code,
        )

    output = []
    for hit in response.json().get("hits", {}).get("hits", []):
        source = hit.get("_source", {})
        log = source.get("full_log", "")
        path = source.get("syscheck", {}).get("path") or source.get(
            "data", {}
        ).get("file_path", "Unknown")

        for marker in ("Source Path: [", "Target Path: ["):
            if marker in log:
                path = log.split(marker)[-1].split("]")[0]

        if path == "Unknown" and " in " in log:
            path = log.split(" in ")[-1].strip()

        rule = source.get("rule", {})
        output.append(
            {
                "id": hit.get("_id"),
                "time": source.get("timestamp"),
                "target": path,
                "rule": rule.get("description", "DLP Alert"),
                "level": rule.get("level", 12),
                "agent_id": source.get("agent", {}).get("id"),
                "agent_name": source.get("agent", {}).get("name", "N/A"),
                "full_log": log,
            }
        )

    return jsonify(output)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
