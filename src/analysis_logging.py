import json
import os
from datetime import datetime, timezone


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_DIR = os.path.join(BASE_DIR, "logs")


def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)
    return LOG_DIR


def _log_path(kind: str) -> str:
    ensure_log_dir()
    return os.path.join(LOG_DIR, f"{kind}_analyses.jsonl")


def append_analysis_log(kind: str, payload: dict) -> str:
    path = _log_path(kind)
    record = {
        "logged_at_utc": datetime.now(timezone.utc).isoformat(),
        **payload,
    }

    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    return path


def read_recent_logs(kind: str, limit: int = 10):
    path = _log_path(kind)
    if not os.path.exists(path):
        return []

    records = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return records[-limit:]


def clear_analysis_logs(kind: str) -> str:
    path = _log_path(kind)
    if os.path.exists(path):
        os.remove(path)
    return path
