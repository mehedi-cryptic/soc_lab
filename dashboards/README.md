# Dashboards

Build this SOC overview dashboard in your SIEM, export it, and commit the export plus
screenshots here. Screenshots are what most visitors will actually look at.

## Panels

| # | Panel | Visualization | Splunk SPL (Sysmon/Security) |
|---|---|---|---|
| 1 | Alerts by severity (24h) | Single values | `index=notable \| stats count by severity` |
| 2 | Alerts over time by rule | Stacked column | `index=notable \| timechart span=1h count by rule_name` |
| 3 | Top hosts by alert count | Bar | `index=notable \| top limit=10 dest` |
| 4 | Failed logons by source IP | Table + map | `index=windows EventCode=4625 \| stats count by IpAddress \| iplocation IpAddress \| sort -count` |
| 5 | Process creations from user-writable paths | Table | `index=windows EventCode=1 (Image="C:\\Users\\*" OR Image="C:\\ProgramData\\*") \| stats count by host Image` |
| 6 | Encoded PowerShell executions | Table | contents of `detections/queries/splunk/proc_creation_win_powershell_encoded_command.spl` |
| 7 | ATT&CK tactics observed | Heat map | `index=notable \| stats count by mitre_tactic` |

**Wazuh:** the built-in *Security events*, *MITRE ATT&CK* and *Threat Hunting* modules cover
panels 1–3 and 7. Build panels 4–6 as saved searches in **Discover** and add them to a custom
dashboard.

## Files to add

```
dashboards/
├── soc_overview.json            # exported dashboard (Splunk XML/JSON, Kibana NDJSON, or Wazuh)
└── screenshots/
    ├── 01_overview.png
    ├── 02_attack_heatmap.png
    └── rule_hits/               # one screenshot per rule firing on an Atomic test
```

Blur or remove any real hostnames or IPs before committing screenshots.
