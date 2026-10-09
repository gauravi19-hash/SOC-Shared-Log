# Day 6 — SOC Shift Log

Date: 5 Oct 2026
Shift: 09:00–17:00
Analyst: SOC Analyst L1
Total Alerts: 4

Shift Focus

* Investigating suspicious executable execution.
* Analyzing process trees and parent-child relationships.
* Investigating PowerShell-based malware execution.
* Detecting persistence mechanisms such as scheduled tasks.
* Correlating endpoint activity with external network connections.
* Identifying potential credential-access activity.
* Using threat-intelligence and file hashes to validate malware.
* Escalating confirmed endpoint compromises to L2 / Incident Response.

# Shift Summary

* **Total alerts:** 4
* **True Positive:** 2
* **Suspicious / Needs Monitoring:** 1
* **Benign / Authorized:** 1
* **Escalated:** 3
* **Closed:** 1

## SOC-023 — Suspected Malware Execution

**Time:** 09:18
**Severity:** High
**Source:** EDR
**Host:** WIN-OPS-07
**User:** n.khan
**Alert Type:** Suspicious Executable Execution

### Initial Alert

EDR detected:

```text
explorer.exe
    └── invoice.exe
          └── cmd.exe
                └── powershell.exe
```

Additional telemetry:

* User opened `Invoice_2026_10_05.exe`.
* File location:
  `C:\Users\n.khan\Downloads\Invoice_2026_10_05.exe`
* `invoice.exe` was unsigned.
* PowerShell executed with `-ExecutionPolicy Bypass` and downloaded `a.ps1`.
* Outbound connection to `198.XX.XX.55:80` was observed.
* `n.khan` is an Operations employee and does not normally execute scripts.
* No approved software deployment or maintenance activity was associated with `WIN-OPS-07`.

### Initial Assessment

The unsigned executable, unusual process chain, hidden PowerShell, external payload download, and abnormal user activity indicated suspicious behavior.

**Initial Verdict:** Suspicious / Needs Monitoring

**Initial Severity:** High

**Initial Action:** Investigate further.

### Additional Investigation

Further investigation revealed:

* `a.ps1` was successfully downloaded from `198.XX.XX.55`.
* EDR classified the script as **malicious**.
* The script created:
  `C:\Users\n.khan\AppData\Roaming\svchost.ps1`
* A scheduled task named `Microsoft\Windows\UpdateCheck` was created.
* The task runs every 15 minutes and launches the malicious PowerShell script.
* The script attempted another outbound connection to `198.XX.XX.55:443`.
* EDR detected an attempt to access browser credential files under the Chrome user profile.
* The hash of `invoice.exe` matched a known malicious sample in the organization's threat-intelligence database.

### Final Verdict

**True Positive**

The evidence confirms malware execution, persistence, external communication, and attempted browser credential access.

### Action

**Escalated to L2 / Incident Response**

Recommended actions:

* Isolate `WIN-OPS-07`.
* Preserve EDR and Windows telemetry.
* Investigate and safely collect the malicious files.
* Remove persistence after evidence preservation.
* Investigate whether browser credentials were accessed or exfiltrated.
* Search the environment for the malicious hash and indicators associated with `198.XX.XX.55`.
* Reset potentially exposed credentials if compromise is confirmed.

### MITRE ATT&CK

* **T1204.002 — User Execution: Malicious File**
* **T1059.001 — PowerShell**
* **T1105 — Ingress Tool Transfer**
* **T1053.005 — Scheduled Task/Job: Scheduled Task**
* **T1071.001 — Web Protocols**
* **T1555.003 — Credentials from Web Browsers**

### Analyst Notes

The investigation demonstrates the importance of correlating file reputation, process trees, PowerShell activity, network connections, persistence mechanisms, and credential-access behavior. A known-malicious hash and EDR-confirmed malicious script provided strong confirmation that the endpoint was compromised.

**Final Classification:** True Positive — High — Escalated

## SOC-024 — Suspicious Data Exfiltration

* **Date:** 05-Oct-2026
* **Time:** 11:06
* **Severity:** High
* **Source:** Network Security Monitoring / DLP
* **Host:** WIN-LEGAL-03
* **User:** p.mehta
* **Alert Type:** Unusual Outbound Data Transfer
* **Destination:** 203.XX.XX.120:443
* **Transfer:** 1.4 GB over HTTPS from 10:52–11:06

### Initial Investigation

* 1.4 GB of data was transferred to an external cloud-storage endpoint.
* The destination was not listed as an approved corporate storage provider.
* The user accessed approximately 320 files from `\\WIN-FILE-04\Legal`.
* Accessed files included sensitive Legal documents such as contracts, settlement agreements, case files, and confidential documents.
* Endpoint telemetry showed no malware, suspicious PowerShell activity, or suspicious process execution.
* The transfer was performed through a legitimate browser process.
* No approved data-transfer ticket existed for the activity.
* The user's manager confirmed that the external upload was not authorized.

### Final Triage

* **Verdict:** Suspicious / Needs Monitoring
* **Final Severity:** High
* **Action:** Escalated
* **MITRE ATT&CK:** T1567.002 — Exfiltration to Cloud Storage

### Analyst Reasoning

The combination of sensitive Legal files, unusually large outbound data transfer, an unapproved external cloud-storage destination, and lack of authorization indicates potentially unauthorized data exfiltration. Although no malware or malicious process was identified, the available evidence is sufficient to escalate the alert for further investigation.

### Escalation Recommendation

* Preserve relevant DLP, network, browser, and file-access logs.
* Identify the exact files transferred and destination account.
* Investigate the user's browser/cloud-storage activity.
* Confirm whether the external destination belongs to a legitimate third party.
* Escalate to the appropriate incident-response/data-loss team for further investigation.

## SOC-025 — Suspicious Credential Access

* **Date:** 05-Oct-2026
* **Time:** 13:42
* **Severity:** High
* **Source:** EDR
* **Host:** WIN-FIN-11
* **User:** a.verma
* **Alert Type:** Suspicious Credential Access

### Investigation

* Confirmed process chain: `explorer.exe → powershell.exe → rundll32.exe → cred.dll`.
* PowerShell executed with `-ExecutionPolicy Bypass`.
* `cred.dll` was created six minutes before the alert.
* The DLL was unsigned and identified by file reputation as malicious.
* The DLL attempted to access the Windows SAM database and credential-related registry locations.
* PowerShell downloaded the DLL from `198.XX.XX.61`.
* The destination IP was associated with known malicious infrastructure in the organization's threat-intelligence feed.
* No approved IT/security ticket existed for the activity.
* Shortly afterward, the same account successfully authenticated to another internal workstation.

### Final Triage

* **Verdict:** True Positive
* **Final Severity:** High
* **Action:** Escalated
* **MITRE ATT&CK:** T1059.001, T1218.011, T1003.002, T1071.001, T1078

### Analyst Reasoning

The activity is confirmed malicious based on the malicious DLL, credential-access attempts against the SAM database, execution through PowerShell and Rundll32, communication with known malicious infrastructure, and subsequent use of the compromised account for internal authentication.

### Escalation Recommendation

* Isolate WIN-FIN-11.
* Disable or reset credentials for `a.verma`.
* Investigate the destination workstation accessed using the account.
* Search for the malicious DLL and related indicators across the environment.
* Review authentication and network logs for additional lateral-movement activity.

## SOC-026 — Unusual Internal Authentication

* **Date:** 05-Oct-2026
* **Time:** 15:18
* **Severity:** Medium → Low
* **Source:** SIEM / Windows Security Logs
* **Host:** WIN-DEV-09
* **User:** r.kapoor
* **Alert Type:** Unusual Internal Authentication

### Investigation

* The account successfully authenticated to three internal servers: `WIN-APP-02`, `WIN-DB-04`, and `WIN-FILE-07`.
* `WIN-DB-04` was initially considered unusual because the user does not normally access it.
* Seven failed authentication attempts occurred before the successful connections.
* Investigation confirmed that the failed attempts resulted from the user entering an old password.
* IT ticket `DEV-2026-1087` authorized r.kapoor to access `WIN-DB-04` for application troubleshooting.
* `WIN-FILE-07` was accessed to retrieve configuration files required for the troubleshooting task.
* The user's manager confirmed the activity.
* No PowerShell, command shell, credential dumping, malware, or suspicious process activity was detected.
* All observed network activity remained within the corporate environment.

### Final Triage

* **Verdict:** Benign / Authorized Activity
* **Final Severity:** Low
* **Action:** Closed
* **MITRE ATT&CK:** N/A

### Analyst Reasoning

Although the authentication pattern initially appeared unusual, investigation confirmed that the activity was authorized by an existing IT ticket and verified by the user's manager. The failed logins were explained by an old password, and no additional indicators of compromise were identified.

### Day 6 End-of-Shift Status


1. Unusual internal authentication should be correlated with user role, normal access patterns, and authentication history.
2. Multiple failed logins do not automatically indicate credential attacks; user error and old passwords can produce similar patterns.
3. Approved IT tickets and manager confirmation are important sources of business context.
4. Lateral movement investigations should examine both authentication activity and endpoint telemetry.
5. Absence of malware or suspicious process activity does not alone prove an event is benign; authorization and business context are also important.
6. A SOC analyst should be willing to change an initial suspicious assessment when investigation produces reliable evidence of legitimate activity.

## End-of-Shift Status

Day 6 completed successfully.

Four alerts were investigated using an L1 SOC triage workflow involving malware execution analysis, endpoint persistence detection, credential-access investigation, data-exfiltration monitoring, network correlation, evidence gathering, classification, escalation, and closure.
