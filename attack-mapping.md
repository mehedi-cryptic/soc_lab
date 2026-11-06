# MITRE ATT&CK Coverage Matrix

Each row is one Sigma rule in [`detections/sigma/`](detections/sigma). "Validation" is where you
record how you proved the rule fires: an Atomic Red Team test ID or a dataset name. Fill it in as
you test.

| Rule file | Technique(s) | Tactic | Log source / Event ID | Level | Validation |
|---|---|---|---|---|---|
| `proc_creation_win_office_spawns_shell` | T1566.001, T1204.002 | Initial Access, Execution | Sysmon 1 / Security 4688 | high | Atomic T1204.002 |
| `proc_creation_win_powershell_encoded_command` | T1059.001, T1027 | Execution, Defense Evasion | Sysmon 1 | high | Atomic T1059.001 |
| `proc_creation_win_wmi_remote_shell` | T1047 | Execution, Lateral Movement | Sysmon 1 | high | Atomic T1047 |
| `proc_creation_win_psexec_remote_execution` | T1021.002, T1569.002 | Lateral Movement, Execution | Sysmon 1 | medium | Atomic T1569.002 |
| `proc_creation_win_schtasks_suspicious_create` | T1053.005 | Persistence | Sysmon 1 | medium | Atomic T1053.005 |
| `win_system_service_install_suspicious_path` | T1543.003 | Persistence, Privilege Escalation | System 7045 | high | Atomic T1543.003 |
| `registry_set_win_run_key_persistence` | T1547.001 | Persistence | Sysmon 13 | medium | Atomic T1547.001 |
| `win_security_audit_log_cleared` | T1070.001 | Defense Evasion | Security 1102 | high | Atomic T1070.001 |
| `proc_creation_win_certutil_download` | T1105, T1218 | Command and Control, Defense Evasion | Sysmon 1 | high | Atomic T1105 |
| `win_security_brute_force_failed_logons` (base + correlation) | T1110, T1110.001 | Credential Access | Security 4625 | low / medium | Hydra against lab RDP |
| `proc_access_win_lsass_memory_access` | T1003.001 | Credential Access | Sysmon 10 | high | OTRF: Mimikatz LSASS dataset |
| `proc_creation_win_lsass_dump_comsvcs` | T1003.001, T1218.011 | Credential Access, Defense Evasion | Sysmon 1 | critical | Atomic T1003.001 |
| `proc_creation_win_domain_discovery_commands` | T1087.002, T1482, T1033 | Discovery | Sysmon 1 | low | Atomic T1087.002, T1482 |
| `proc_creation_win_shadow_copy_deletion` | T1490 | Impact | Sysmon 1 | critical | Atomic T1490 |
| `proc_creation_win_defender_tampering` | T1562.001 | Defense Evasion | Sysmon 1 | high | Atomic T1562.001 |
| `win_security_dcsync_replication_request` | T1003.006 | Credential Access | Security 4662 (DC) | high | Mimikatz `lsadump::dcsync` in lab |

| `win_security_kerberoasting_rc4_ticket` | T1558.003 | Credential Access | Security 4769 (DC) | medium | Atomic T1558.003 |

| `proc_creation_win_archive_collection_staging` | T1560.001, T1074.001 | Collection | Sysmon 1 | medium | Atomic T1560.001 |
| `proc_creation_win_rclone_cloud_exfiltration` | T1567.002 | Exfiltration | Sysmon 1 | high | rclone copy to local remote in lab |

> Pick the specific test number for each technique with
> `Invoke-AtomicTest <Technique> -ShowDetailsBrief` and record it here (e.g. `T1059.001 #3`), since numbers change between releases.

## Tactic coverage

Counts include secondary tactic tags (a rule tagged Execution and Defense Evasion counts for both).
21 unique techniques in total.

```
Initial Access        █░░░░  1 rule
Execution             █████  5 rules
Persistence           ███░░  3 rules
Privilege Escalation  █░░░░  1 rule
Defense Evasion       ████░  4 rules
Credential Access     ███░░  3 rules + 1 correlation
Discovery             █░░░░  1 rule
Lateral Movement      ██░░░  2 rules
Command and Control   █░░░░  1 rule
Collection            ░░░░░  0 rules  ← gap
Exfiltration          ░░░░░  0 rules  ← gap
Impact                █░░░░  1 rule
```

## Known gaps and next rules to write

| Gap | Idea | Data source needed |
|---|---|---|
| Exfiltration (T1567, T1048) | Large outbound transfer to cloud storage / rare domain | Proxy or firewall logs, Sysmon 3 |
| Collection (T1560) | Archiving tools (7z, rar, `Compress-Archive`) on file servers | Sysmon 1 |
| Kerberoasting (T1558.003) | 4769 with RC4 encryption (0x17) for service accounts | DC Security log |
| DCSync (T1003.006) | 4662 with replication GUIDs from a non-DC account | DC Security log |
| Defender tampering (T1562.001) | `Set-MpPreference -DisableRealtimeMonitoring` | Sysmon 1, PowerShell 4104 |

## Tuning log

Record every false positive you hit and how you handled it. Interviewers love this section.

| Date | Rule | False positive | Fix | Result |
|---|---|---|---|---|
| 2026-10-20 | `proc_creation_win_schtasks_suspicious_create` | Adobe Acrobat updater creates a daily task from `C:\ProgramData\Adobe\ARM\` | Kept the rule broad; added the signed AdobeARM hash to the triage watchlist as `clean`, which drops the alert to P4 automatically | No analyst time spent on it |
| 2026-10-20 | `proc_access_win_lsass_memory_access` | n/a (false **negative**) | The System32 filter hid `rundll32.exe` dumping LSASS via comsvcs.dll. Wrote the dedicated comsvcs rule instead of loosening the filter | Technique now caught by two complementary rules |
| | `win_security_brute_force_failed_logons` | Vulnerability scanner doing authenticated scans | *e.g. filter scanner IP in the correlation's base rule* | |
