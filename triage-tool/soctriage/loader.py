"""Load alerts from JSON, JSONL or CSV and normalize them to one schema.

Two input styles are supported:
  * the generic schema used in samples/sample_alerts.json (one flat dict per alert)
  * raw Wazuh alerts (alerts.json / alerts.jsonl from /var/ossec/logs/alerts/)

Normalized alert keys:
  id, timestamp (datetime), rule, rule_id, severity, host, user, src_ip, dst_ip,
  dst_host, process, parent_process, command_line, sha256, mitre (list[str])
"""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path

SEVERITIES = ("low", "medium", "high", "critical")

FIELDS = (
    "id", "timestamp", "rule", "rule_id", "severity", "host", "user", "src_ip",
    "dst_ip", "dst_host", "process", "parent_process", "command_line", "sha256", "mitre",
)


def parse_timestamp(value: str) -> datetime:
    """Parse ISO-8601 timestamps, including Wazuh's '+0000' offset style. Returns UTC."""
    text = value.strip().replace("Z", "+00:00")
    # Convert a basic offset like +0000 / -0530 into +00:00 / -05:30
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def wazuh_level_to_severity(level: int) -> str:
    """Map Wazuh rule levels (0-15) onto four analyst-friendly severities."""
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def _from_generic(raw: dict) -> dict:
    alert = {key: raw.get(key) for key in FIELDS}
    mitre = raw.get("mitre") or []
    if isinstance(mitre, str):  # CSV input: "T1059.001;T1027"
        mitre = [m.strip() for m in re.split(r"[;,|]", mitre) if m.strip()]
    alert["mitre"] = list(mitre)
    severity = str(raw.get("severity") or "medium").lower()
    alert["severity"] = severity if severity in SEVERITIES else "medium"
    if raw.get("event_count"):
        alert["event_count"] = int(raw["event_count"])
    return alert


def _from_wazuh(raw: dict) -> dict:
    rule = raw.get("rule", {})
    agent = raw.get("agent", {})
    data = raw.get("data", {})
    ed = data.get("win", {}).get("eventdata", {})

    sha256 = None
    match = re.search(r"SHA256=([A-Fa-f0-9]{64})", ed.get("hashes", "") or "")
    if match:
        sha256 = match.group(1).lower()

    return {
        "id": raw.get("id"),
        "timestamp": raw.get("timestamp"),
        "rule": rule.get("description"),
        "rule_id": str(rule.get("id", "")),
        "severity": wazuh_level_to_severity(int(rule.get("level", 0))),
        "host": agent.get("name"),
        "user": ed.get("user") or ed.get("targetUserName") or ed.get("subjectUserName"),
        "src_ip": ed.get("ipAddress") or data.get("srcip"),
        "dst_ip": ed.get("destinationIp") or data.get("dstip"),
        "dst_host": ed.get("destinationHostname"),
        "process": ed.get("image"),
        "parent_process": ed.get("parentImage"),
        "command_line": ed.get("commandLine"),
        "sha256": sha256,
        "mitre": list(rule.get("mitre", {}).get("id", [])),
    }


def normalize(raw: dict) -> dict:
    """Detect the input style and return a normalized alert dict."""
    is_wazuh = isinstance(raw.get("rule"), dict) and "level" in raw["rule"]
    alert = _from_wazuh(raw) if is_wazuh else _from_generic(raw)
    if not alert.get("timestamp"):
        raise ValueError(f"Alert {alert.get('id')!r} has no timestamp")
    alert["timestamp"] = parse_timestamp(str(alert["timestamp"]))
    alert["host"] = (alert.get("host") or "UNKNOWN").upper()
    if alert.get("dst_host"):
        alert["dst_host"] = alert["dst_host"].upper()
    if alert.get("sha256"):
        alert["sha256"] = alert["sha256"].lower()
    return alert


def load_alerts(path: str | Path) -> list[dict]:
    """Read an alert file (.json, .jsonl/.ndjson or .csv) and return normalized alerts sorted by time."""
    path = Path(path)
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")

    if suffix in (".jsonl", ".ndjson"):
        raws = [json.loads(line) for line in text.splitlines() if line.strip()]
    elif suffix == ".csv":
        raws = list(csv.DictReader(text.splitlines()))
    else:
        data = json.loads(text)
        raws = data.get("alerts", []) if isinstance(data, dict) else data

    alerts = [normalize(raw) for raw in raws]
    alerts.sort(key=lambda a: a["timestamp"])
    return alerts
