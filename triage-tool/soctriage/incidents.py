"""Group scored alerts into incidents and link related incidents.

Grouping rule: alerts on the same host belong to one incident unless there is a quiet
gap longer than `gap` between them. An incident's score is its worst alert plus a bonus
for each additional ATT&CK tactic observed, because attack *progression* (execution ->
credential access -> lateral movement) is more alarming than many alerts of one kind.
"""

from __future__ import annotations

from datetime import timedelta

from .scoring import priority

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
]

# Primary tactic for the parent techniques used in this lab
TECHNIQUE_TACTIC = {
    "T1566": "initial-access", "T1190": "initial-access", "T1078": "initial-access",
    "T1204": "execution", "T1059": "execution", "T1047": "execution", "T1569": "execution",
    "T1547": "persistence", "T1053": "persistence", "T1543": "persistence", "T1136": "persistence",
    "T1027": "defense-evasion", "T1218": "defense-evasion", "T1070": "defense-evasion",
    "T1562": "defense-evasion",
    "T1003": "credential-access", "T1110": "credential-access", "T1558": "credential-access",
    "T1033": "discovery", "T1087": "discovery", "T1482": "discovery", "T1069": "discovery",
    "T1018": "discovery",
    "T1021": "lateral-movement", "T1570": "lateral-movement",
    "T1105": "command-and-control", "T1071": "command-and-control",
    "T1041": "exfiltration", "T1567": "exfiltration",
    "T1490": "impact", "T1486": "impact",
}


def tactics_for(techniques: list[str]) -> list[str]:
    found = {TECHNIQUE_TACTIC[t.split(".")[0]] for t in techniques if t.split(".")[0] in TECHNIQUE_TACTIC}
    return [t for t in TACTIC_ORDER if t in found]


def group_incidents(alerts: list[dict], gap: timedelta = timedelta(hours=2)) -> list[dict]:
    """`alerts` must already carry 'score', 'iocs' and 'enrichment' keys."""
    by_host: dict[str, list[dict]] = {}
    for alert in sorted(alerts, key=lambda a: a["timestamp"]):
        by_host.setdefault(alert["host"], []).append(alert)

    clusters: list[list[dict]] = []
    for host_alerts in by_host.values():
        current = [host_alerts[0]]
        for alert in host_alerts[1:]:
            if alert["timestamp"] - current[-1]["timestamp"] > gap:
                clusters.append(current)
                current = []
            current.append(alert)
        clusters.append(current)

    incidents = []
    for cluster in clusters:
        techniques = sorted({t for a in cluster for t in a.get("mitre", [])})
        tactics = tactics_for(techniques)
        top = max(a["score"] for a in cluster)
        bonus = 5 * max(0, len(tactics) - 1)
        score = min(100, top + bonus)
        incidents.append({
            "host": cluster[0]["host"],
            "start": cluster[0]["timestamp"],
            "end": cluster[-1]["timestamp"],
            "alerts": cluster,
            "techniques": techniques,
            "tactics": tactics,
            "score": score,
            "score_reasons": [f"highest alert score {top}"]
            + ([f"{len(tactics)} ATT&CK tactics observed (+{bonus})"] if bonus else []),
            "priority": priority(score),
            "users": sorted({a["user"] for a in cluster if a.get("user")}),
            "related": [],
        })

    incidents.sort(key=lambda i: (-i["score"], i["start"]))
    for n, inc in enumerate(incidents, start=1):
        inc["id"] = f"INC-{n:03d}"
    link_incidents(incidents)
    return incidents


def link_incidents(incidents: list[dict]) -> None:
    """Link incidents that share an external IOC or where one host targeted another."""
    def external_iocs(inc: dict) -> set[str]:
        return {i.value for a in inc["alerts"] for i in a["iocs"] if not i.internal}

    for a in incidents:
        targets = {al.get("dst_host") for al in a["alerts"] if al.get("dst_host")}
        for b in incidents:
            if a is b:
                continue
            reasons = []
            if b["host"] in targets:
                reasons.append(f"{a['host']} executed remotely on {b['host']}")
            shared = external_iocs(a) & external_iocs(b)
            if shared:
                reasons.append("shared IOC " + ", ".join(sorted(shared)))
            if reasons:
                a["related"].append({"incident": b["id"], "host": b["host"], "why": "; ".join(reasons)})
