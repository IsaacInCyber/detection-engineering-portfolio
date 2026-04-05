# Detection Engineering Portfolio

KQL detections for common attack techniques. Each one was simulated in my home lab, captured in Sentinel/MDE, and tuned until the false positive rate was manageable.

## Lab Setup

| Component | Details |
|-----------|---------|
| Attack box | Parrot Security OS (ARM64) on UTM |
| Target | Windows 10 VM in Azure |
| SIEM | Microsoft Sentinel |
| EDR | Microsoft Defender for Endpoint |
| Log tables | DeviceNetworkEvents, DeviceLogonEvents, DeviceProcessEvents |

## The Attack Chain

These detections follow a realistic attack path:

```
Port scan → Brute force RDP → Encoded PowerShell → LSASS dump → Persistence → Lateral movement
```

## Detections

| Technique | MITRE ID | What it catches |
|-----------|----------|-----------------|
| Port Scan | T1046 | 50+ ports from single source in 15min |
| Password Spray | T1110.003 | 20+ unique IPs failing auth to same host |
| Brute Force RDP | T1110.001 | 5+ failed logins from same source in 10min |
| Encoded PowerShell | T1059.001 | Base64 encoded commands (-enc flag) with decode |
| LSASS Dump | T1003.001 | comsvcs.dll + MiniDump in command line |

Each detection lives in `detections/` with the full KQL and comments explaining the logic.

## Example: LSASS Dump via comsvcs.dll

This catches credential theft using a signed Windows binary:

```kql
DeviceProcessEvents
| where TimeGenerated >= ago(30m)
| where ProcessCommandLine has "comsvcs.dll" and ProcessCommandLine has "MiniDump"
| project TimeGenerated, DeviceName, ProcessCommandLine
```

Why this works: Attackers use comsvcs.dll because it's legit — signed by Microsoft, already on the system. No need to drop Mimikatz. The detection catches the behavior pattern, not a specific tool name.

## What I Picked Up

- Threshold tuning is half the battle — started with 5 failed logins, had to adjust based on actual noise
- - Behavioral detection beats signature detection every time
  - - KQL regex for pulling and decoding base64 payloads
    - - The difference between `has` and `contains` actually matters for performance
