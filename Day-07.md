Day 7 — Final SOC Shift
Date: 06-Oct-2026
Shift: 09:00–17:00
Total Alerts: 5

# Shift focus 

* Primary Focus Areas
* Cloud Security & Identity Monitoring
* Investigate unusual cloud logins and account activity.
* Correlate authentication, device, IP, MFA, and cloud audit logs.
* Account Compromise Detection
* Identify suspicious use of valid credentials.
* Investigate unusual authentication patterns and unauthorized sessions.
* Multi-Source Correlation
* Correlate SIEM, EDR, identity, network, DLP, and cloud telemetry.
* Build an investigation timeline from multiple alerts and log sources.
* Lateral Movement Detection
* Analyze unusual internal authentication and access to multiple systems.
* Distinguish legitimate administrative activity from potential attacker movement.
* Persistence & Endpoint Investigation
* Investigate suspicious processes, scheduled tasks, scripts, and other persistence mechanisms.
* Analyze process trees and endpoint activity.
* Data Exfiltration & Sensitive Data Monitoring
* Identify unusual access and transfer of sensitive information.
* Correlate file-access activity with network and cloud-storage activity.
* Incident Escalation & Documentation
* Determine when evidence supports escalation.
* Document findings, MITRE ATT&CK techniques, affected assets, and recommended response actions.
* Analyst Objective

# Shift Summary

* **Total alerts:** 5
* **True Positive:** 4
* **Suspicious / Needs Monitoring:** 1
* **Benign / Authorized:** 0
* **Escalated:** 4
* **Closed:** 0

## SOC-027 — Suspicious Cloud Account Activity

* **Date:** 06-Oct-2026
* **Time:** 09:24
* **Severity:** High
* **Source:** Cloud Security / Identity Monitoring
* **User:** s.patel
* **Account:** [s.patel@company.example](mailto:s.patel@company.example)
* **Alert Type:** Unusual Cloud Login

### Investigation

* Successful login was detected from unfamiliar IP `185.XX.XX.44`.
* The IP was not associated with the corporate VPN.
* The user stated they were working from home and using the company VPN.
* VPN logs showed no VPN session for the user at the time of the unfamiliar login.
* The unfamiliar session originated from a device ID that did not match the user's registered corporate laptop.
* The registered laptop was simultaneously active from the corporate network.
* MFA was successfully completed, but the user confirmed they did not approve the unfamiliar login.
* The unfamiliar session accessed SharePoint, corporate email, and cloud storage.
* Approximately 185 files were viewed and 12 internal financial documents were downloaded.
* Cloud audit logs confirmed that the downloads originated from the unfamiliar session.
* No malware alert was detected on the user's registered laptop.

### Final Triage

* **Verdict:** True Positive
* **Final Severity:** High
* **Action:** Escalated
* **MITRE ATT&CK:** T1078 — Valid Accounts

### Analyst Reasoning

The activity is consistent with unauthorized use of a valid cloud account. The unfamiliar device authenticated without the user's authorization, did not use the expected corporate VPN, and subsequently accessed and downloaded sensitive corporate files. Successful MFA does not eliminate the possibility of account compromise.

### Escalation Recommendation

* Revoke active cloud sessions and refresh tokens.
* Reset the user's credentials.
* Investigate the MFA authentication event and device registration history.
* Review cloud audit logs for additional file access or downloads.
* Search for the same source IP and device indicators across other accounts.
* Preserve relevant identity and cloud audit logs for incident response.

## SOC-028 — Suspicious PowerShell Persistence

* **Date:** 06-Oct-2026
* **Time:** 10:37
* **Severity:** High
* **Source:** EDR
* **Host:** WIN-HR-12
* **User:** k.sharma
* **Alert Type:** Suspicious Persistence

### Investigation

* Confirmed process chain: `explorer.exe → powershell.exe → powershell.exe`.
* PowerShell executed with `-ExecutionPolicy Bypass -WindowStyle Hidden`.
* An unsigned `update-check.ps1` script was created in the user's AppData directory.
* A new scheduled task named `Microsoft\Windows\SystemUpdateCheck` was created.
* The task executes every 30 minutes, establishing persistence.
* The script contained an encoded PowerShell command.
* The script contacted `198.XX.XX.77:443`.
* The IP was identified as known malicious infrastructure by threat intelligence.
* The script downloaded another PowerShell script, `config.ps1`.
* `config.ps1` attempted process, user, and network configuration discovery.
* No approved software deployment or maintenance activity explained the behavior.
* The user confirmed they did not create the scheduled task or execute the PowerShell commands.

### Final Triage

* **Verdict:** True Positive
* **Final Severity:** High

## SOC-029 — Suspicious Network Scanning Activity

* **Date:** 06-Oct-2026
* **Time:** 12:05
* **Severity:** Medium
* **Source:** Network Security Monitoring / IDS
* **Host:** WIN-DEV-05
* **User:** v.iyer
* **Alert Type:** Internal Network Port Scanning

### Investigation

* Approximately 1,200 connection attempts were recorded against 42 internal hosts.
* Multiple ports were targeted, including SSH, HTTP, RPC, NetBIOS, SMB, and RDP.
* The scanning process was identified as `nmap.exe`.
* Command line: `nmap -sS -sV 10.10.20.0/24`.
* The user confirmed the scan was related to application testing.
* No approved security-testing or change-management ticket existed for the activity.
* The scan included production-adjacent systems outside the user's normal testing scope.
* EDR detected no malicious executable, PowerShell activity, persistence, or credential-access behavior.
* No external connections were observed.
* The user's team lead confirmed that developers sometimes perform Nmap scans during application testing.
* No exploitation attempts were detected after the scan.

### Final Triage

* **Verdict:** Suspicious / Needs Monitoring
* **Final Severity:** Medium
* **Action:** Monitor
* **MITRE ATT&CK:** T1046 — Network Service Scanning

### Analyst Reasoning

The Nmap activity is consistent with legitimate developer testing, but the scan was not pre-approved and exceeded the normal testing scope. Because no exploitation, malware, or external communication was identified, the activity is not confirmed malicious but should be monitored and reviewed with the development team.

### Monitoring Recommendation

* Confirm the approved scope for future development scans.
* Document the activity with the development/security team.
* Monitor `WIN-DEV-05` for subsequent scanning or exploitation activity.
* Investigate any future scans involving production systems or unusual external destinations.

## SOC-030 — Suspicious Privileged Account Activity

* **Date:** 06-Oct-2026
* **Time:** 14:26
* **Severity:** High
* **Source:** SIEM / Windows Security Logs
* **Host:** WIN-DC-02
* **User:** admin-temp
* **Alert Type:** Unexpected Privileged Account Activity

### Investigation

* `admin-temp` successfully logged into `WIN-DC-02` from `WIN-IT-07`.
* The account had Domain Admin privileges but its approved expiration date had already passed.
* The administrator assigned to `WIN-IT-07` was on leave during the activity.
* Commands including `net user`, `net group "Domain Admins"`, and `whoami /groups` were executed.
* Windows Event ID 4720 confirmed creation of the `backup-admin` account.
* Event ID 4728 confirmed that `backup-admin` was added to the Domain Admins group.
* No approved change-management or emergency-access ticket existed.
* `backup-admin` subsequently authenticated to `WIN-DC-02`.
* The account then attempted to access multiple domain systems.
* No malware was detected on `WIN-IT-07`.
* Security team confirmation established that the account creation and privileged-group modification were unauthorized.

### Final Triage

* **Verdict:** True Positive
* **Final Severity:** High
* **Action:** Escalated
* **MITRE ATT&CK:** T1078, T1098, T1136.002, T1069.002, T1087.002

### Analyst Reasoning

The activity represents unauthorized privileged-account abuse. An expired administrative account was used to create a new domain account and grant it Domain Admin privileges without authorization. The subsequent authentication and attempts to access additional domain systems indicate potential persistence and lateral movement.

### Escalation Recommendation

* Disable `admin-temp` and `backup-admin`.
* Remove unauthorized Domain Admin membership.
* Isolate or investigate `WIN-IT-07`.
* Review all authentication activity involving both accounts.
* Search for additional unauthorized account or group modifications.
* Investigate systems accessed by `backup-admin`.
* Preserve relevant Windows Security and domain-controller logs.

## SOC-031 — Suspicious Database Access

* **Date:** 06-Oct-2026
* **Time:** 16:12
* **Severity:** High
* **Source:** Database Activity Monitoring / SIEM
* **Host:** WIN-DB-04
* **User:** svc-reporting
* **Alert Type:** Unusual Database Query Activity

### Investigation

* `svc-reporting` normally performs scheduled reporting queries.
* Approximately 4,800 SELECT queries were executed within 8 minutes.
* The queries accessed customer information, email addresses, payment-related records, and internal transaction data.
* The activity occurred outside the account's normal reporting schedule.
* The connection originated from the legitimate reporting server `WIN-APP-02`.
* The responsible process was the approved and digitally signed `ReportingService.exe`.
* Investigation showed that the reporting task had been modified earlier that afternoon.
* Task Scheduler logs confirmed the schedule was changed from 02:00 to 16:00.
* The modification was performed using an administrator account.
* No approved change ticket existed.
* Database audit logs showed access to sensitive tables outside the normal reporting scope.
* Approximately 2.3 GB of database data was returned to `WIN-APP-02`.
* Shortly afterward, `WIN-APP-02` established an outbound HTTPS connection to `198.XX.XX.105`.
* The destination was not an approved corporate data-processing or storage service.
* Security confirmed that no legitimate report was scheduled for 16:00.
* The administrator account that modified the scheduled task was already under investigation for unrelated suspicious activity.

### Final Triage

* **Verdict:** True Positive
* **Final Severity:** High
* **Action:** Escalated
* **MITRE ATT&CK:** T1053.005, T1078, T1213, T1041

### Analyst Reasoning

The activity represents a confirmed unauthorized data-access and potential exfiltration chain. Although the reporting service and service account were legitimate, the reporting schedule was modified without authorization, sensitive data outside the normal reporting scope was queried, a large volume of data was returned, and the application server subsequently communicated with an unapproved external destination.

### Escalation Recommendation

* Preserve database, Task Scheduler, SIEM, and network logs.
* Investigate the administrator account that modified the scheduled task.
* Review all recent activity involving `svc-reporting`.
* Identify the exact data accessed and transferred.
* Investigate `198.XX.XX.105`.
* Review `WIN-APP-02` for additional unauthorized activity.
* Search for similar scheduled-task modifications across the environment.

* Cloud account investigations should correlate IP address, device identity, VPN activity, MFA events, and cloud audit logs.
* Successful MFA does not automatically prove that a login was legitimate; the authentication context must also be investigated.
* PowerShell combined with scheduled-task persistence, malicious infrastructure, and payload downloads can indicate a confirmed compromise.
* Network scanning should be investigated in the context of the user's role and authorized testing scope.
* Privileged-account activity requires careful investigation of account status, group membership changes, administrative commands, and authentication activity.
* Legitimate service accounts and approved applications can still be abused for unauthorized data access.
* Database activity should be correlated with scheduled jobs, query scope, data volume, administrator actions, and outbound network connections.
* Multi-source correlation is essential for identifying the complete attack chain.
* Initial triage can change as additional evidence becomes available.
* High-confidence malicious activity should be escalated with relevant evidence preserved for incident response.

## End-of-Shift Status

Day 7 completed successfully.

Five alerts were investigated using an advanced L1 SOC triage workflow involving cloud identity monitoring, PowerShell persistence analysis, network scanning detection, privileged-account investigation, database activity monitoring, multi-source correlation, evidence gathering, classification, escalation, and monitoring.




