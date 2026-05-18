# Detection Engineering Portfolio

Microsoft Sentinel is my SIEM of choice, and this repo is where I publish the hunting queries and analytic rules I build against it. Each detection was simulated end-to-end in my home lab — attack run, telemetry observed, KQL written, and false positives tuned out — so the queries reflect what actually fires in production.

## Lab Setup

A Windows 10 VM in Azure serves as the target, with the Azure Monitor Agent shipping Windows Security events, Sysmon, and PowerShell operational logs into a Log Analytics workspace. Entra ID sign-in and audit logs stream in through diagnostic settings. A Parrot Security attack box in UTM drives the offensive traffic, and Sentinel sits on top as the detection and hunting layer.

| Component | Details |
|-----------|---------|
| Attack box | Parrot Security OS (ARM64) on UTM |
| Target | Windows 10 VM in Azure with Sysmon + Security auditing |
| SIEM | Microsoft Sentinel (Log Analytics workspace) |
| Ingestion | Azure Monitor Agent + Entra ID diagnostic settings |
| Log tables | `SecurityEvent`, `Event` (Sysmon), `SigninLogs`, `AuditLogs` |

## The Attack Chain

```
Port scan → Brute force RDP → Encoded PowerShell → LSASS dump → Persistence → Lateral movement
```

## Detections

| Technique | MITRE ID | What it catches |
|-----------|----------|-----------------|
| Port Scan | T1046 | 50+ ports from a single source in 15min (Sysmon EID 3) |
| Password Spray | T1110.003 | 20+ unique accounts failing auth from one source IP (4625 / `SigninLogs`) |
| Brute Force RDP | T1110.001 | 5+ failed RDP logons (LogonType 10) from same source in 10min |
| Encoded PowerShell | T1059.001 | `powershell.exe -enc` with inline base64 decode for review |
| LSASS Dump | T1003.001 | `comsvcs.dll` + `MiniDump` in command line (Sysmon EID 1) |

Each detection lives in `detections/` as a YAML file containing the KQL query plus metadata (technique ID, severity, frequency), with inline comments explaining the logic. Ad-hoc hunting queries live in `hunting/`.

## Example: LSASS Dump via comsvcs.dll

This catches credential theft using a signed Windows binary:

```kql
Event
| where TimeGenerated >= ago(30m)
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| extend CmdLine = tostring(parse_xml(EventData).DataItem.EventData.Data[10]["#text"])
| where CmdLine has_all ("comsvcs.dll", "MiniDump")
| project TimeGenerated, Computer, CmdLine
```

Why this works: attackers reach for `comsvcs.dll` because it’s legitimate — signed by Microsoft, already on the system, no need to drop Mimikatz. The detection catches the behavior pattern, not a specific tool name.

## What I Picked Up

- Threshold tuning is half the battle — started with 5 failed logins, had to adjust based on actual noise
- Behavioral detection beats signature detection every time
- KQL regex for pulling and decoding base64 payloads is more useful than I expected
- The difference between `has` and `contains` actually matters for performance
