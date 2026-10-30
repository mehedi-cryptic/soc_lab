# Lab Setup

Two ways to get logs into the project. **Path A** needs no lab at all; **Path B** is what makes
the project stand out, because you generate the attacks yourself.

---

## Path A: Public attack datasets (no lab needed)

| Dataset | What it gives you | Use it for |
|---|---|---|
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) | Small JSON files of Windows/Sysmon logs, one per ATT&CK technique | Testing individual Sigma rules |
| [Splunk BOTS v1 / v3](https://github.com/splunk/botsv3) | Full multi-day incident scenarios with questions | Practicing a full investigation (IR report) |
| [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | Raw `.evtx` files grouped by tactic | Replaying in Wazuh/Elastic with Chainsaw or Hayabusa |

Fastest way to test the Sigma rules against `.evtx` files without a SIEM:

```bash
# Chainsaw (https://github.com/WithSecureLabs/chainsaw) runs Sigma rules directly on EVTX
chainsaw hunt EVTX-ATTACK-SAMPLES/ -s detections/sigma/ --mapping mappings/sigma-event-logs-all.yml
```

---

## Path B: Build a home lab

### Hardware / VMs

| VM | OS | RAM | Role |
|---|---|---|---|
| `siem` | Ubuntu Server 22.04/24.04 | 8 GB | Wazuh all-in-one (manager + indexer + dashboard) |
| `ws-01` | Windows 10/11 eval | 4 GB | Victim endpoint with Sysmon + Wazuh agent |
| `attacker` (optional) | Kali Linux | 2 GB | Hydra, Impacket for lateral movement tests |

Use VirtualBox, VMware Workstation Player or Proxmox. Put all VMs on a **host-only / internal
network**, never bridged to your home LAN while running attacks.

### 1. Install Wazuh (on `siem`)

```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
# Note the admin password printed at the end, then browse to https://<siem-ip>
```

Check the [Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html) for the
current version number.

### 2. Install Sysmon (on `ws-01`)

Use a well-maintained config: [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)
for a quiet baseline or [Olaf Hartong's sysmon-modular](https://github.com/olafhartong/sysmon-modular)
for more coverage.

```powershell
# Run as Administrator
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml
.\Sysmon\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

> Several rules in this repo need **Sysmon Event ID 10 (ProcessAccess)** for `lsass.exe`. The
> SwiftOnSecurity config logs it; confirm with
> `Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -FilterXPath "*[System[EventID=10]]" -MaxEvents 5`.

### 3. Turn on the Windows audit policies the rules need

```powershell
auditpol /set /subcategory:"Logon" /failure:enable /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Security System Extension" /success:enable
# Log full command lines in Event 4688 too
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

### 4. Install the Wazuh agent and ship Sysmon logs

Install the agent from the Wazuh dashboard (**Agents → Deploy new agent**). Then add Sysmon to
`C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart the agent: `Restart-Service WazuhSvc`.

### 5. Load the detections

| SIEM | How |
|---|---|
| **Splunk** | Paste queries from `detections/queries/splunk/` into **Settings → Searches, reports, and alerts → New Alert** |
| **Elastic** | Use `detections/queries/elastic/` in **Security → Rules → Create rule → Custom query** (Lucene) or ES\|QL rule |
| **Wazuh** | Wazuh ships many equivalent built-in rules. For a custom one, translate the Sigma logic into a rule in `/var/ossec/etc/rules/local_rules.xml` (example below) |

Example Wazuh custom rule for encoded PowerShell (Sysmon EID 1):

```xml
<group name="sysmon,soc-lab,">
  <rule id="100100" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)\\(powershell|pwsh)\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}</field>
    <description>SOC-LAB: PowerShell encoded command execution</description>
    <mitre><id>T1059.001</id></mitre>
  </rule>
</group>
```

### 6. Simulate attacks with Atomic Red Team (on `ws-01`)

```powershell
# Defender will block some tests - in an isolated lab, add an exclusion for C:\AtomicRedTeam
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

Invoke-AtomicTest T1059.001 -ShowDetailsBrief   # list tests
Invoke-AtomicTest T1059.001 -TestNumbers 17     # run one
Invoke-AtomicTest T1059.001 -TestNumbers 17 -Cleanup
```

Run the tests listed in [`attack-mapping.md`](../attack-mapping.md), confirm each rule fires,
screenshot the alert, and record the result in the "Validation" column.

### 7. Export alerts for the triage tool

```bash
# On the Wazuh manager: alerts from today, one JSON object per line
sudo cp /var/ossec/logs/alerts/alerts.json ~/alerts_today.jsonl
python triage.py ~/alerts_today.jsonl --out reports/today
```

---

## Safety

- Isolate the lab network and take VM snapshots before every test.
- Never run attack tooling against systems you don't own or have written permission to test.
