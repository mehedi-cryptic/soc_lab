# Detections

`sigma/` is the source of truth. `queries/` is generated from it; don't edit those files by hand.

## Rule anatomy

Every rule follows the same conventions:

- **File name:** `<category>_<product>_<what>.yml` (same scheme as the [SigmaHQ](https://github.com/SigmaHQ/sigma) repo)
- **`tags`:** ATT&CK tactic + technique, so coverage can be generated automatically
- **`falsepositives`:** real, specific causes, not just "unknown"
- **`level`:** reflects confidence × impact. `low` rules feed correlation/scoring rather than paging anyone

![Sigma rules](https://img.shields.io/badge/Sigma%20rules-19-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-27%20techniques-red)a check detections/sigma
```

## Convert

```bash
| **Detection engineering** | 19 Sigma rules (plus 1 correlation rule) covering all 12 ATT&CK tactics in the lab scope, each with ATT&CK mapping, false-positive notes and tuning guidance | [`detections/sigma/`](detections/sigma) |
sigma convert -t splunk -p splunk_windows detections/sigma/proc_creation_win_shadow_copy_deletion.yml
```

## Field mappings

The Sigma rules use Sysmon field names (`Image`, `CommandLine`, `ParentImage`...). The conversion
pipelines map them for each SIEM:

| Sigma field | Splunk (`splunk_windows`) | Elastic ECS (`ecs_windows`) |
|---|---|---|
| `Image` | `Image` | `process.executable` |
| `CommandLine` | `CommandLine` | `process.command_line` |
| `ParentImage` | `ParentImage` | `process.parent.executable` |
| `TargetImage` | `TargetImage` | `winlog.event_data.TargetImage` |
| `IpAddress` | `IpAddress` | `source.ip` |

If your Splunk uses the CIM data models, convert with `-p splunk_cim` instead.
