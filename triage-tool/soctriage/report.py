"""Write triage results as a Markdown report, JSON (for SOAR/automation) and an IOC CSV."""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .iocs import decode_powershell

RECOMMENDATIONS = {
    "initial-access": "Find the delivery vector (email, download, exposed service); block the sender/URL and search for other recipients.",
    "execution": "Collect the full process tree and command lines; acquire suspicious binaries/scripts for analysis.",
    "persistence": "Remove persistence (Run keys, scheduled tasks, services) only after evidence is preserved; hunt for the same artefact fleet-wide.",
    "privilege-escalation": "Review new privileged group memberships and service configurations on the host.",
    "defense-evasion": "Assume logs on this host are incomplete; rely on SIEM/EDR copies and check whether security tooling was tampered with.",
    "credential-access": "Treat every account that logged on to the host as compromised: reset passwords, revoke sessions/tokens, and reset KRBTGT twice if domain admin creds are suspected.",
    "discovery": "Correlate with any later lateral movement; discovery alone is low-confidence.",
    "lateral-movement": "Isolate source and destination hosts; block SMB/WinRM/RDP between workstations; review logons by the account used.",
    "command-and-control": "Block the IPs/domains at the proxy, firewall and DNS; search proxy logs for other hosts contacting them.",
    "exfiltration": "Estimate data volume and destination from proxy/firewall logs; involve legal/privacy if personal data is involved.",
    "impact": "ESCALATE IMMEDIATELY: isolate the host, verify offline backups, and start the ransomware playbook.",
}

TACTIC_LABELS = {t: t.replace("-", " ").title().replace("And", "and") for t in RECOMMENDATIONS}


def _cell(text: object, limit: int | None = None) -> str:
    value = "" if text is None else str(text)
    value = value.replace("|", "\\|").replace("\n", " ")
    if limit and len(value) > limit:
        value = value[: limit - 1] + "…"
    return value


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _incident_iocs(incident: dict) -> list[tuple]:
    seen: dict[tuple[str, str], tuple] = {}
    for alert in incident["alerts"]:
        for ioc in alert["iocs"]:
            res = alert["enrichment"].get(ioc.value, {})
            seen.setdefault((ioc.type, ioc.value), (ioc, res))
    order = {"malicious": 0, "suspicious": 1, "unknown": 2, "clean": 3}
    return sorted(seen.values(), key=lambda x: (x[0].internal, order.get(x[1].get("verdict", "unknown"), 2)))


def render_markdown(incidents: list[dict], meta: dict) -> str:
    lines = [
        "# Alert Triage Report",
        "",
        f"- **Generated:** {meta['generated']} UTC",
        f"- **Input:** `{meta['input']}`",
        f"- **Enrichment mode:** {meta['mode']}",
        f"- **Alerts:** {meta['alert_count']}  |  **Incidents:** {len(incidents)}",
        "",
        "## Summary",
        "",
        "| Incident | Priority | Score | Host | Window (UTC) | Alerts | Tactics | Related |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for inc in incidents:
        related = ", ".join(r["incident"] for r in inc["related"]) or "-"
        lines.append(
            f"| [{inc['id']}](#{inc['id'].lower()}) | **{inc['priority']}** | {inc['score']} | {inc['host']} "
            f"| {inc['start']:%m-%d %H:%M} → {inc['end']:%H:%M} | {len(inc['alerts'])} "
            f"| {len(inc['tactics'])} | {related} |"
        )

    for inc in incidents:
        asset = meta["assets"].get(inc["host"], {})
        lines += [
            "",
            "---",
            "",
            f'<a id="{inc["id"].lower()}"></a>',
            f"## {inc['id']} — {inc['host']} ({inc['priority']}, score {inc['score']})",
            "",
            f"- **Window:** {_fmt(inc['start'])} → {_fmt(inc['end'])} UTC",
            f"- **Asset:** {asset.get('role', 'not in asset inventory')}"
            + (f" (criticality: {asset['criticality']})" if asset.get("criticality") else ""),
            f"- **Accounts:** {', '.join(inc['users']) or '-'}",
        ]
        if inc["tactics"]:
            lines.append("- **ATT&CK progression:** " + " → ".join(TACTIC_LABELS.get(t, t) for t in inc["tactics"]))
            lines.append("- **Techniques:** " + ", ".join(f"`{t}`" for t in inc["techniques"]))
        for rel in inc["related"]:
            lines.append(f"- **Related:** [{rel['incident']}](#{rel['incident'].lower()}) on {rel['host']} — {rel['why']}")

        top = max(inc["alerts"], key=lambda a: a["score"])
        lines += ["", "**Why this score**", ""]
        lines += [f"- {r}" for r in inc["score_reasons"]]
        lines += [f"- top alert `{top['id']}` ({top['rule']}):"] + [f"  - {r}" for r in top["score_reasons"]]

        lines += [
            "",
            "### Timeline",
            "",
            "| Time (UTC) | Score | Alert | Rule | User | Command / Process |",
            "|---|---|---|---|---|---|",
        ]
        for a in inc["alerts"]:
            cmd = a.get("command_line") or a.get("process") or ""
            lines.append(
                f"| {a['timestamp']:%H:%M:%S} | {a['score']} | {a['id']} | {_cell(a['rule'], 60)} "
                f"| {_cell(a.get('user'))} | `{_cell(cmd, 90)}` |" if cmd else
                f"| {a['timestamp']:%H:%M:%S} | {a['score']} | {a['id']} | {_cell(a['rule'], 60)} "
                f"| {_cell(a.get('user'))} | - |"
            )

        decoded = {decode_powershell(a.get("command_line")) for a in inc["alerts"]} - {None}
        if decoded:
            lines += ["", "### Decoded PowerShell", ""]
            for script in sorted(decoded):
                lines += ["```powershell", script, "```"]

        iocs = _incident_iocs(inc)
        if iocs:
            lines += ["", "### Indicators", "", "| Type | Value | Verdict | Sources | Notes |", "|---|---|---|---|---|"]
            for ioc, res in iocs:
                verdict = res.get("verdict", "unknown")
                verdict = f"**{verdict}**" if verdict == "malicious" else verdict
                lines.append(
                    f"| {ioc.type} | `{_cell(ioc.value)}` | {verdict} | {_cell(', '.join(res.get('sources', [])) or '-')} "
                    f"| {_cell('; '.join(res.get('notes', [])) or '-')} |"
                )

        if inc["tactics"]:
            lines += ["", "### Recommended actions", ""]
            for t in reversed(inc["tactics"]):  # most severe stage first
                lines.append(f"- **{TACTIC_LABELS.get(t, t)}:** {RECOMMENDATIONS[t]}")

    lines += ["", "---", "", "_Scores are decision support, not a verdict. Validate every P1/P2 before acting._", ""]
    return "\n".join(lines)


def _jsonable(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    raise TypeError(f"Not JSON serializable: {type(obj)}")


def write_outputs(incidents: list[dict], meta: dict, out_dir: str | Path) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {
        "markdown": out / "triage_report.md",
        "json": out / "incidents.json",
        "csv": out / "iocs.csv",
    }
    paths["markdown"].write_text(render_markdown(incidents, meta), encoding="utf-8")

    public_meta = {k: v for k, v in meta.items() if k != "assets"}
    paths["json"].write_text(
        json.dumps({"meta": public_meta, "incidents": incidents}, default=_jsonable, indent=2),
        encoding="utf-8",
    )

    with open(paths["csv"], "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["incident", "host", "type", "value", "internal", "verdict", "sources", "notes"])
        for inc in incidents:
            for ioc, res in _incident_iocs(inc):
                writer.writerow([
                    inc["id"], inc["host"], ioc.type, ioc.value, ioc.internal,
                    res.get("verdict", "unknown"), ";".join(res.get("sources", [])), "; ".join(res.get("notes", [])),
                ])
    return paths


def generated_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
