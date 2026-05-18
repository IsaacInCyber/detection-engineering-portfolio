# Detection Engineering Portfolio

Microsoft Sentinel is my SIEM of choice. This repo is where I publish the hunting queries and analytic rules I build for detection work.

The YAML files in `detections/` were originally written against Microsoft Defender for Endpoint’s Advanced Hunting schema (`DeviceProcessEvents`, `DeviceLogonEvents`, `DeviceNetworkEvents`) during a prior lab build that included MDE. I no longer have MDE access, so new work targets Sentinel-native sources. The existing queries are kept here as reference for the M365 Defender XDR schema and the underlying detection logic, which ports over to Sentinel with table substitutions.

## Lab Setup

A Windows 10 VM in Azure as the target with Sysmon and Security event auditing. A Parrot Security attack box in UTM driving the offensive traffic: reconnaissance, brute force, encoded PowerShell, LSASS dump, persistence, and lateral movement. Telemetry was captured into M365 Defender Advanced Hunting tables during the original build. The same activity is observable in Sentinel via `SecurityEvent`, `Event` (Sysmon), `SigninLogs`, and `AuditLogs` through the Azure Monitor Agent and Entra ID diagnostic settings.

## Featured Hunt: Per-User 30-Day Authentication Triage

[`hunting/Triage_User_AuthPattern_30d.yml`](./hunting/Triage_User_AuthPattern_30d.yml)

Pulls 30 days of sign-in attempts for a target UPN and classifies each event into operational outcomes that map to credential and session state: `Success`, `ValidCred_MFABlocked`, `ValidCred_CABlocked`, `FailedAuth`, and `Other_<code>`. Projects the fields needed to distinguish benign activity from credential compromise or token replay (`IsInteractive`, `AuthenticationDetails`, `ISP`, `SessionId`, `RiskLevelDuringSignIn`).

Designed to be the first query an analyst runs when an account is flagged by an alert, user report, or proactive hunt and you need a structured view of recent auth behavior. Covers AiTM and token-replay scenarios mapped to T1078 (Valid Accounts), T1110.003 (Password Spraying), T1539 (Steal Web Session Cookie), and T1556 (Modify Authentication Process).

## Detections

The five YAML files in [`detections/`](./detections) cover the attack chain that was executed end-to-end in the lab:

```
Port scan → Brute force / Password spray → Encoded PowerShell → LSASS dump
```

### How the detections are structured

Every YAML file in `detections/` follows the same shape: a `description` block explaining the technique and why the detection logic works, a `references` section pointing to MITRE ATT&CK and any relevant LOLBAS or vendor write-ups, the `query` itself with inline comments on threshold choices and known false positive sources, and `tags` mapping the file to MITRE techniques and tactics. Open the files directly for the detection logic.

## What I Picked Up

- Threshold tuning is half the battle. Initial thresholds rarely survive contact with real noise.
- Behavioral detection beats signature detection, especially for living-off-the-land techniques.
- The KQL difference between `has`, `contains`, and `==` matters for both correctness and performance.
- Portable detection design pays off. Writing logic that maps cleanly from `DeviceProcessEvents` to `SecurityEvent` 4688 or Sysmon EID 1 is more valuable than coupling tightly to one schema.
