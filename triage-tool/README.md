# soctriage: SIEM Alert Triage & Enrichment

A command-line tool that turns a pile of SIEM alerts into a short, prioritized list of incidents,
with the evidence an analyst needs to decide what to do next.

```
alerts.json ─► normalize ─► extract IOCs ─► enrich ─► score ─► group into incidents ─► report
              (generic or   (+ decode       (watchlist,   (explainable   (per host, linked by
               Wazuh)        PowerShell)     VT, AbuseIPDB)  0–100)        lateral movement / shared IOCs)
```

## Features

- **Input:** generic JSON / JSONL / CSV, or raw **Wazuh** `alerts.json` (auto-detected)
- **PowerShell decoding:** extracts and decodes `-EncodedCommand` payloads, then hunts IOCs in the decoded script
- **IOC extraction:** IPs (internal vs external), domains, URLs, SHA-256, MD5
- **Enrichment:** local watchlist (works offline) → 24h cache → **VirusTotal v3** → **AbuseIPDB**;
  respects the VT free-tier rate limit; internal IPs are never sent to external APIs
- **Explainable scoring:** every point has a reason (severity, malicious IOCs, asset criticality,
  privileged account, download-cradle keywords, known-good hash)
- **Incident grouping:** per-host clustering with a configurable quiet gap; bonus for ATT&CK
  tactic progression; links incidents connected by remote execution or shared IOCs
- **Output:** Markdown report, `incidents.json` (for SOAR / automation), `iocs.csv` (for blocklists)

## Usage

```bash
pip install -r requirements.txt

# Offline demo with the bundled sample intrusion
python triage.py samples/sample_alerts.json --offline

# Raw Wazuh alerts, with live enrichment
export VT_API_KEY=...            # https://www.virustotal.com/gui/my-apikey (free)
export ABUSEIPDB_API_KEY=...     # https://www.abuseipdb.com/account/api (free)
python triage.py /var/ossec/logs/alerts/alerts.json --out reports/today

# Only show what needs attention now
python triage.py alerts.jsonl --min-priority P2
```

| Option | Default | Meaning |
|---|---|---|
| `--out` | `reports/` | Output folder |
| `--context` | `context/` | Folder with `assets.csv`, `privileged_accounts.txt`, `watchlist.csv` |
| `--offline` | off | Watchlist only, no API calls |
| `--gap-hours` | `2` | Quiet time that splits a host's alerts into separate incidents |
| `--min-priority` | `P4` | Drop incidents below this priority |

Example output: [`examples/sample_run/triage_report.md`](examples/sample_run/triage_report.md)

## Scoring model

| Factor | Points |
|---|---|
| Base severity | low 10 · medium 25 · high 45 · critical 70 |
| Malicious IOC | +20 each (max +30) |
| Suspicious IOC | +10 each (max +15) |
| Known-good file hash (and nothing malicious) | −15 |
| Asset criticality | high +15 · medium +5 |
| Privileged account | +10 |
| Decoded PowerShell has download / in-memory execution keywords | +10 |
| 25+ events behind the alert | +5 |

**Incident score** = highest alert score + 5 per additional ATT&CK tactic (max 100).
**Priority:** P1 ≥ 80 · P2 ≥ 60 · P3 ≥ 35 · P4 < 35.

The weights are deliberately simple and live in `soctriage/scoring.py`. Tune them to your environment.

## Context files

| File | Purpose |
|---|---|
| `context/assets.csv` | Host criticality, role and owner (your asset inventory / CMDB export) |
| `context/privileged_accounts.txt` | Accounts whose involvement raises the score |
| `context/watchlist.csv` | Local threat intel: known-bad **and** known-good indicators |

## Alert schema (generic input)

```json
{
  "id": "ALR-1004", "timestamp": "2026-10-20T09:12:40Z",
  "rule": "Certutil Used to Download a File", "rule_id": "<sigma id>",
  "severity": "high", "host": "WS-FIN-07", "user": "CORP\\j.rahman",
  "src_ip": "10.10.20.37", "dst_ip": "198.51.100.23", "dst_host": null,
  "process": "C:\\Windows\\System32\\certutil.exe", "parent_process": "...",
  "command_line": "certutil.exe -urlcache -split -f http://...", "sha256": null,
  "mitre": ["T1105", "T1218"]
}
```

## Tests

```bash
python -m pytest -q     # 35 tests: parsing, decoding, enrichment cache, scoring, grouping, end-to-end
```

## Project structure

```
soctriage/
├── loader.py      # read + normalize (generic / Wazuh)
├── iocs.py        # IOC extraction, PowerShell decoding
├── enrich.py      # watchlist, cache, VirusTotal, AbuseIPDB
├── scoring.py     # explainable risk score + priority
├── incidents.py   # grouping, ATT&CK tactic ordering, incident linking
├── report.py      # Markdown / JSON / CSV output
└── cli.py         # argument parsing and orchestration
```

## Ideas to extend it

- Send P1 incidents to Slack/Teams via webhook
- Add a `--since` filter and run it every 15 minutes from cron
- Pull alerts directly from the Wazuh Indexer or Elastic API instead of files
- Add Shodan or GreyNoise enrichment for external IPs
