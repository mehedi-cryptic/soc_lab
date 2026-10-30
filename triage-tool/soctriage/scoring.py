"""Risk scoring for alerts and incidents.

Every point added comes with a human-readable reason, so an analyst can see *why*
an alert landed at P1 instead of trusting a black-box number.
"""

from __future__ import annotations

import csv
from pathlib import Path

from .iocs import decode_powershell, suspicious_ps_keywords

BASE_SCORE = {"low": 10, "medium": 25, "high": 45, "critical": 70}
ASSET_BONUS = {"high": 15, "medium": 5, "low": 0}


def priority(score: int) -> str:
    if score >= 80:
        return "P1"
    if score >= 60:
        return "P2"
    if score >= 35:
        return "P3"
    return "P4"


def load_assets(path: str | Path | None) -> dict[str, dict]:
    if not path or not Path(path).exists():
        return {}
    with open(path, newline="", encoding="utf-8") as fh:
        return {row["host"].strip().upper(): row for row in csv.DictReader(fh)}


def load_privileged(path: str | Path | None) -> set[str]:
    if not path or not Path(path).exists():
        return set()
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return {ln.strip().lower() for ln in lines if ln.strip() and not ln.startswith("#")}


def _account_name(user: str | None) -> str:
    """'CORP\\j.rahman' -> 'j.rahman', 'bob@corp.local' -> 'bob'."""
    if not user:
        return ""
    return user.split("\\")[-1].split("@")[0].lower()


def score_alert(alert: dict, enrichment: dict[str, dict], assets: dict, privileged: set[str]) -> tuple[int, list[str]]:
    """Return (score 0-100, reasons). `enrichment` maps IOC value -> enrichment result."""
    score = BASE_SCORE[alert["severity"]]
    reasons = [f"base {alert['severity']} severity (+{score})"]

    malicious = [v for v, r in enrichment.items() if r["verdict"] == "malicious"]
    suspicious = [v for v, r in enrichment.items() if r["verdict"] == "suspicious"]
    if malicious:
        bonus = min(30, 20 * len(malicious))
        score += bonus
        reasons.append(f"{len(malicious)} malicious IOC(s): {', '.join(malicious)} (+{bonus})")
    if suspicious:
        bonus = min(15, 10 * len(suspicious))
        score += bonus
        reasons.append(f"{len(suspicious)} suspicious IOC(s) (+{bonus})")

    known_good = [v for v, r in enrichment.items() if r["verdict"] == "clean" and len(v) in (32, 64)]
    if known_good and not malicious:
        score -= 15
        reasons.append("file hash is on the known-good list (-15)")

    asset = assets.get(alert["host"])
    if asset:
        bonus = ASSET_BONUS.get(asset.get("criticality", "low").lower(), 0)
        if bonus:
            score += bonus
            reasons.append(f"{asset['criticality']}-criticality asset: {asset.get('role', '')} (+{bonus})")

    if _account_name(alert.get("user")) in privileged:
        score += 10
        reasons.append(f"privileged account {alert['user']} (+10)")

    keywords = suspicious_ps_keywords(decode_powershell(alert.get("command_line")))
    if keywords:
        score += 10
        reasons.append(f"decoded PowerShell contains {', '.join(keywords)} (+10)")

    if alert.get("event_count", 0) >= 25:
        score += 5
        reasons.append(f"high volume: {alert['event_count']} events (+5)")

    return max(0, min(score, 100)), reasons
