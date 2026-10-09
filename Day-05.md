# Day 5 — SOC Shift Log

Date: 4 Oct 2026
Shift: 09:00–17:00
Analyst: SOC Analyst L1
Total Alerts: 4

# Shift Focus

* Detecting abnormal authentication patterns.
* Investigating repeated failed logons followed by successful authentication.
* Analyzing unusual source IPs and endpoint identities.
* Investigating RemoteInteractive logons.
* Correlating authentication activity with internal network connections.
* Identifying possible lateral movement through SMB.
* Distinguishing legitimate remote access from unauthorized account activity.
* Escalating confirmed security incidents to L2 / Incident Response.

# Shift Summary

Alerts Investigated: 4
True Positives: 3
Benign / Authorized: 1
Suspicious / Monitoring: 0
Escalated: 3
Closed: 1

## SOC-019 — Suspected Account Compromise

**Date:** 4 Oct 2026
**Time:** 09:24
**Severity:** High
**Source:** SIEM / Windows Security Logs
**Host:** WIN-FIN-15
**User:** m.patil
**Source IP:** 10.10.40.72
**Source Host:** LAPTOP-22

### Alert Details

* 14 failed logon attempts for `m.patil` from `10.10.40.72` within 4 minutes.
* A successful logon occurred 2 minutes later from the same source IP.
* Logon Type: **10 — RemoteInteractive**.
* `10.10.40.72` was identified as `LAPTOP-22`, assigned to another Finance employee, `r.sharma`.
* No approved remote-access ticket connected `r.sharma`'s laptop to `m.patil`'s account.
* Shortly afterward, `WIN-FIN-15` connected to `WIN-FILE-03` using SMB on destination port `445`.
* `m.patil` is a Finance employee and has no documented IT administration responsibilities.

### Investigation

The authentication sequence was reviewed for evidence of possible credential compromise. The combination of multiple failed logons followed by a successful RemoteInteractive logon from another employee's workstation was considered abnormal.

The subsequent SMB connection to `WIN-FILE-03` was investigated as possible lateral movement. Relevant evidence to review includes the SMB share accessed, files/directories accessed, file modifications or copying, data volume, and any additional internal systems contacted by the account.

### Verdict

**True Positive**

### Action

**Escalated to L2 / Incident Response**

Recommended investigation actions include validating the user's credentials, reviewing authentication and endpoint telemetry, investigating activity on `WIN-FILE-03`, and checking for additional lateral-movement activity.

### MITRE ATT&CK

* **T1110 — Brute Force**
* **T1078 — Valid Accounts**
* **T1021.002 — SMB/Windows Admin Shares**

### Analyst Notes

The incident demonstrates a suspicious authentication pattern followed by internal SMB activity. The source workstation belonged to another employee and there was no approved remote-access activity linking the two accounts. Correlation of authentication, endpoint, and network evidence supported escalation as a potential account-compromise and lateral-movement incident.

## SOC-020 — Suspicious PowerShell Activity

**Time:** 10:17
**Severity:** High
**Source:** EDR
**Host:** WIN-HR-08
**User:** s.kulkarni
**Alert Type:** Suspicious PowerShell Execution

### Initial Alert

EDR detected the following process chain:

```text
winword.exe
    └── powershell.exe
          └── powershell.exe
```

PowerShell command line:

```text
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand [BASE64_DATA]
```

Additional telemetry:

* User opened `Employee_Benefits_Update.docm`.
* The document spawned PowerShell shortly afterward.
* PowerShell created:
  `C:\Users\s.kulkarni\AppData\Roaming\Microsoft\Windows\UpdateCheck.ps1`
* The script attempted an outbound HTTPS connection to `185.XX.XX.44:443`.
* The destination had not previously been contacted by this workstation.
* `s.kulkarni` is an HR employee and does not normally run administrative PowerShell scripts.

### Initial Assessment

The combination of Office spawning PowerShell, ExecutionPolicy Bypass, hidden execution, encoded commands, unusual external communication, and abnormal user activity was considered suspicious.

**Initial Verdict:** Suspicious / Needs Monitoring

**Initial Severity:** High

**Initial Action:** Monitor and investigate further.

### Additional Investigation

Further EDR investigation revealed:

* The encoded PowerShell command downloaded another PowerShell script from:
  `hxxps://185.XX.XX.44/update.ps1`
* The script was saved to:
  `C:\ProgramData\Microsoft\Windows\Update\update.ps1`
* The downloaded script created a scheduled task named:
  `WindowsUpdateMaintenance`
* The scheduled task runs every 30 minutes.
* The task launches PowerShell with the downloaded script.
* The destination IP had no approved business association.
* EDR classified `update.ps1` as **malicious**.
* The process subsequently attempted to access:
  `C:\Users\s.kulkarni\Documents\HR_Salary_Review.xlsx`

### Final Verdict

**True Positive**

The evidence confirms malicious PowerShell execution with external payload download, persistence through a scheduled task, and attempted access to a sensitive HR document.

### Action

**Escalated to L2 / Incident Response**

Recommended actions:

* Isolate `WIN-HR-08`.
* Preserve relevant EDR and Windows event logs.
* Investigate the malicious PowerShell scripts.
* Remove the malicious scheduled task and associated files after evidence preservation.
* Investigate access to `HR_Salary_Review.xlsx`.
* Check for additional endpoints communicating with `185.XX.XX.44`.
* Review whether credentials or sensitive HR data were compromised.

### MITRE ATT&CK

* **T1204.002 — User Execution: Malicious File**
* **T1059.001 — PowerShell**
* **T1105 — Ingress Tool Transfer**
* **T1053.005 — Scheduled Task/Job: Scheduled Task**
* **T1071.001 — Web Protocols**
* **T1083 — File and Directory Discovery** *(potentially applicable; requires additional evidence about the file-access behavior)*

### Analyst Notes

The investigation demonstrates why PowerShell alerts should be correlated with the parent process, command line, script contents, network activity, persistence mechanisms, and targeted files. `ExecutionPolicy Bypass` alone does not prove malicious activity, but in this case it appeared together with hidden encoded PowerShell, a malicious downloaded script, scheduled-task persistence, and access to a sensitive HR file.

**Final Classification:** True Positive — High — Escalated

## SOC-021 — Suspicious Privilege Escalation

**Time:** 13:42
**Severity:** High
**Source:** SIEM / Windows Security Logs
**Host:** WIN-DEV-12
**User:** a.joshi
**Alert Type:** Unexpected Privileged Group Membership Change

### Initial Alert

* User `a.joshi` was added to the local **Administrators** group on `WIN-DEV-12`.
* Event ID: **4732 — A member was added to a security-enabled local group**.
* The change was performed by `a.joshi`.
* `a.joshi` is a Software Developer and does not normally have local administrator privileges.
* No corresponding change ticket was initially visible.
* Five minutes later, the endpoint generated:
  `cmd.exe → powershell.exe`
* PowerShell executed:
  `Get-LocalUser; Get-LocalGroupMember Administrators`

### Initial Assessment

The unexpected administrator-group membership change, followed by PowerShell enumeration of local users and administrator-group members, was considered suspicious.

**Initial Verdict:** Suspicious / Needs Monitoring

**Initial Severity:** High

**Initial Action:** Investigate further.

### Additional Investigation

Further investigation revealed:

* `a.joshi` was added to the Administrators group by the same account.
* No approved change ticket was identified.
* At 13:47, PowerShell executed:
  `Get-LocalUser`
* At 13:47, PowerShell executed:
  `Get-LocalGroupMember Administrators`
* At 13:49, the user executed:
  `whoami /groups`
* At 13:51, PowerShell executed:
  `net user administrator /active:yes`
* The built-in local Administrator account had previously been disabled.
* At 13:53, `WIN-DEV-12` established an outbound connection to `185.XX.XX.92:443`.
* The destination was not associated with an approved company service.
* EDR detected creation of:
  `C:\Users\a.joshi\AppData\Local\Temp\svchost.ps1`
* The script had not yet been classified by EDR at the time of investigation.

### Final Verdict

**True Positive**

The sequence of unauthorized privilege escalation, account/group enumeration, enabling the disabled local Administrator account, unexplained external communication, and suspicious PowerShell file creation indicates malicious activity.

### Action

**Escalated to L2 / Incident Response**

Recommended actions:

* Isolate `WIN-DEV-12`.
* Preserve PowerShell, Windows Security, and EDR telemetry.
* Investigate `svchost.ps1` safely.
* Determine how `a.joshi` obtained administrative privileges.
* Investigate the outbound connection to `185.XX.XX.92`.
* Check for additional accounts or hosts affected by the same activity.
* Review whether the local Administrator account was subsequently used.

### MITRE ATT&CK

* **T1098 — Account Manipulation**
* **T1059.001 — PowerShell**
* **T1087 — Account Discovery**
* **T1069.001 — Permission Groups Discovery: Local Groups**
* **T1033 — System Owner/User Discovery**
* **T1071.001 — Web Protocols** *(if the outbound HTTPS communication is confirmed as malicious web/C2 activity)*

### Analyst Notes

The investigation demonstrates that an unexpected administrator-group change should be correlated with subsequent account discovery, privilege-related commands, network activity, and file creation. The individual events may have legitimate explanations, but their sequence and lack of authorization significantly increased the likelihood of compromise.

**Final Classification:** True Positive — High — Escalated

## SOC-022 — Unusual RDP Authentication

**Time:** 15:26
**Severity:** Medium → Low
**Source:** SIEM / Windows Security Logs
**Host:** WIN-FIN-09
**User:** r.desai
**Source IP:** 10.10.30.88
**Source Host:** WIN-ACCT-03
**Alert Type:** Unusual RDP Authentication

### Initial Alert

* Successful Windows Logon Type **10 — RemoteInteractive** was detected for `r.desai`.
* Source IP: `10.10.30.88`
* RDP destination port: **3389**
* Source workstation was different from the user's normal workstation.
* Three failed logon attempts occurred immediately before the successful authentication.
* Five minutes after authentication, `WIN-FIN-09` accessed:
  `\\WIN-FILE-02\Finance`
* No initial malware alert was generated by EDR.

### Initial Assessment

The unusual RDP source, failed authentication attempts, successful RemoteInteractive login, and subsequent Finance share access warranted investigation.

**Initial Verdict:** Suspicious / Needs Monitoring

**Initial Severity:** Medium

**Initial Action:** Investigate further.

### Additional Investigation

Investigation identified `10.10.30.88` as `WIN-ACCT-03`, a workstation assigned to another Finance employee.

Further evidence showed:

* The three failed logons were caused by an incorrect password.
* The successful RDP authentication used valid credentials.
* `r.desai` confirmed they were participating in an approved IT support session.
* IT ticket **IT-2026-1048** confirmed that IT Support temporarily used `WIN-ACCT-03` to assist `r.desai`.
* Access to the Finance share was part of the authorized support activity.
* No suspicious PowerShell, command shell, credential-access activity, or unknown process was detected.
* The RDP session ended normally after approximately 18 minutes.
* No external network connection or suspicious file transfer was observed.

### Final Verdict

**Benign / Authorized Activity**

The initially unusual RDP activity was explained by a documented IT support session and supported by the corresponding IT ticket.

### Action

**Closed**

No further incident-response action was required.

### MITRE ATT&CK

**N/A — Authorized administrative activity**

### Analyst Notes

The alert demonstrates the importance of validating suspicious authentication activity against business context and approved IT activity. The unusual source workstation and failed logons initially justified investigation, but the approved IT ticket, user confirmation, normal endpoint telemetry, and absence of suspicious network activity supported closure.

**Final Classification:** Benign / Authorized Activity — Low — Closed

## End-of-Shift Status

Day 5 completed successfully.

Four alerts were investigated using an L1 SOC triage workflow involving authentication analysis, account-compromise detection, privilege-escalation investigation, PowerShell analysis, lateral-movement detection, evidence correlation, classification, escalation, and closure.


