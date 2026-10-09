# Day 4 — Simulated SOC Shift

**Date:** 3 October 2026
**Shift:** 09:00–17:00
**Role:** SOC Analyst L1
**Environment:** Simulated Enterprise SOC

## Shift Focus

* Endpoint Detection and Response (EDR)
* Malware behavior analysis
* Suspicious executables
* Windows service creation
* Process tree analysis
* Persistence mechanisms
* File reputation and hash analysis
* Endpoint containment decisions

## Shift Summary

* **Alerts Investigated:** 5
* **True Positives:** 3
* **Benign / Authorized Activity:** 2
* **Suspicious / Monitoring:** 0
* **Escalated:** 3
* **Closed / Monitored:** 2

---

## SOC-014 — Malicious Executable and Persistence

**Time:** 09:18
**Severity:** High
**Verdict:** True Positive
**Action:** Escalated to L2/IR
**MITRE ATT&CK:** T1204.002 — User Execution: Malicious File; T1059.001 — PowerShell; T1547.001 — Registry Run Keys / Startup Folder; T1071.001 — Web Protocols

### Investigation

EDR detected `svchost.exe` executing from:

`C:\Users\a.mehta\AppData\Roaming\svchost.exe`

The executable was unsigned and its SHA-256 hash was classified as malicious by multiple EDR/AV engines.

The file was created shortly after the user opened the external Excel attachment:

`Invoice_September_2026.xlsm`

The process executed a hidden PowerShell command using `ExecutionPolicy Bypass` and an encoded command:

`powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand <redacted>`

The executable also created persistence through:

`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

with the value:

`WindowsUpdate = C:\Users\a.mehta\AppData\Roaming\svchost.exe`

Immediately after PowerShell execution, the host established an outbound HTTPS connection to:

`185.XX.XX.71:443`

The destination was not associated with an approved corporate service, and repeated connections occurred approximately every 60 seconds.

The email sender's domain was externally registered and was not associated with an approved company vendor.

### Analyst Decision

The evidence confirmed malicious execution and persistence originating from a malicious email attachment.

The combination of a malicious executable, deceptive executable name/location, hidden encoded PowerShell, registry-based persistence, and repeated outbound communication indicated an active endpoint compromise.

**Escalated to L2/IR for containment and further investigation.**

---

## SOC-015 — Authorized Remote Support Service Installation

**Time:** 11:42
**Severity:** Low
**Verdict:** Benign / Authorized Activity
**Action:** Closed
**MITRE ATT&CK:** N/A

### Investigation

A new Windows service named `RemoteSupportUpdater` was created on `WIN-OPS-14` and executed as `LocalSystem`.

The service executable, `rsupdate.exe`, was located under the approved RemoteSupport installation directory.

Investigation identified an approved IT change ticket:

`CHG-2026-1001-042`

The ticket was for deployment of an updated version of the organization's approved RemoteSupport software.

`WIN-OPS-14` was listed as one of the affected endpoints, and the deployment was performed centrally through the organization's software-management platform.

The executable was digitally signed by the RemoteSupport vendor, and its SHA-256 hash matched the vendor's published release hash.

Network activity was limited to the approved vendor endpoint:

`updates.remotesupport.example:443`

No PowerShell, Command Prompt, scripting engine, suspicious child process, or unexpected file creation was observed.

### Analyst Decision

The service creation was consistent with an authorized software deployment by IT Operations.

**Alert closed as benign / authorized activity.**

## SOC-016 — Malicious DLL Execution and Persistence

**Time:** 13:24
**Severity:** High
**Verdict:** True Positive
**Action:** Escalated to L2/IR
**MITRE ATT&CK:** T1204.002 — User Execution: Malicious File; T1218.011 — Rundll32; T1059.001 — PowerShell; T1105 — Ingress Tool Transfer; T1053.005 — Scheduled Task/Job: Scheduled Task; T1071.001 — Web Protocols

### Investigation

EDR detected the following process chain:

`explorer.exe → rundll32.exe → powershell.exe`

The user opened an email attachment named `Invoice_September.xlsm` at 13:21. Shortly afterward, an unsigned DLL named `invoice.dll` appeared in the user's Downloads directory.

The DLL's SHA-256 hash was classified as malicious by multiple security engines. Static analysis showed that its exported `Start` function launched PowerShell.

PowerShell executed with hidden execution and `ExecutionPolicy Bypass` and downloaded a remote PowerShell script from:

`https://198.XX.XX.73/update.ps1`

The destination was not an approved corporate service. The server returned a PowerShell script that was written to:

`C:\Users\s.joshi\AppData\Roaming\Microsoft\Windows\update.ps1`

A scheduled task named `WindowsUpdateCheck` was then created to execute the script using hidden PowerShell.

### Analyst Decision

The evidence confirmed malicious execution originating from the email attachment.

The attack chain demonstrated malicious DLL execution through `rundll32.exe`, hidden PowerShell execution, remote script download, and persistence through a scheduled task.

**Escalated to L2/IR for endpoint containment, malware analysis, and further investigation.**

## SOC-017 — LSASS Memory Dump and Credential Access

**Time:** 14:16
**Severity:** High
**Verdict:** True Positive
**Action:** Escalated to L2/IR
**MITRE ATT&CK:** T1003.001 — OS Credential Dumping: LSASS Memory; T1204.002 — User Execution: Malicious File; T1560.001 — Archive Collected Data: Archive via Utility; T1071.001 — Web Protocols

### Investigation

EDR detected `procdump.exe` attempting to access the Windows `lsass.exe` process.

Although `procdump.exe` was confirmed to be a legitimate, Microsoft-signed Sysinternals utility, the execution context was suspicious.

The command attempted to create a full LSASS memory dump:

`procdump.exe -accepteula -ma lsass.exe C:\Users\v.verma\AppData\Local\Temp\lsass.dmp`

The resulting `lsass.dmp` file was approximately 480 MB and was subsequently compressed into `debug.zip`.

The activity occurred shortly after the user opened an externally sourced `Performance_Debugging_Guide.docm` document. The sender was not associated with an approved company vendor.

The host then attempted an outbound connection to:

`198.XX.XX.91:443`

The destination was not an approved corporate service.

No legitimate debugging ticket or maintenance window existed for the activity.

### Analyst Decision

The evidence indicated credential-access activity involving LSASS memory, followed by collection/compression of the resulting dump and attempted external communication.

The use of a legitimate administrative utility did not make the activity benign; the surrounding execution and network context indicated likely malicious abuse of the tool.

**Escalated to L2/IR for endpoint containment, credential investigation, and further incident response.**

## SOC-018 — Authorized PowerShell System Inventory

**Time:** 16:03
**Severity:** Low
**Verdict:** Benign / Authorized Activity
**Action:** Closed
**MITRE ATT&CK:** N/A

### Investigation

EDR detected PowerShell executing:

`C:\IT\Scripts\Collect-SystemInfo.ps1`

with `ExecutionPolicy Bypass`.

The script was digitally signed by the company's IT Operations certificate, and its SHA-256 hash matched the approved version stored in the organization's internal software repository.

The script had previously been executed across numerous corporate endpoints as part of routine IT inventory operations.

The execution originated from the scheduled task:

`IT-SystemInventory`

The task was configured by `CORP\IT-Automation` to run daily at 16:00.

`WIN-IT-04` belongs to the IT Operations department, and `p.shah` is an authorized IT administrator. The execution occurred at 16:03, within the expected inventory window.

The script only collected system information and wrote the results to the approved local reporting directory. No credential access, persistence, suspicious child processes, external network connections, or additional script execution was observed.

The activity was also associated with approved change ticket:

`CHG-2026-1001-061`

### Analyst Decision

The PowerShell activity was consistent with an authorized IT system-inventory operation.

Although `ExecutionPolicy Bypass` triggered the EDR detection, the surrounding evidence confirmed legitimate administrative activity.

**Alert closed as benign / authorized activity.**

## Day 4 Lessons Learned

1. Investigate suspicious executables using file path, hash, signature, command line, process tree, and network activity.
2. Legitimate Windows process names such as `svchost.exe` can be abused by malware when executed from unusual locations.
3. Hidden and encoded PowerShell combined with persistence and external communication can indicate an active compromise.
4. `rundll32.exe` is a legitimate Windows utility but can be abused to execute malicious DLLs.
5. Legitimate administrative tools such as ProcDump can be abused for credential-access activity.
6. LSASS access should be investigated carefully because legitimate tools can also interact with it.
7. New Windows services running as `LocalSystem` are not automatically malicious; change-management and vendor verification are important.
8. `ExecutionPolicy Bypass` is a detection signal, not proof of malicious activity.
9. Process trees and execution timelines help establish the relationship between user activity, malware execution, persistence, and network communication.
10. EDR alerts should always be correlated with business context, approved changes, file reputation, and endpoint telemetry before closing or escalating.

## End-of-Shift Status

**Day 4 completed successfully.**

Five endpoint-focused alerts were investigated using an L1 SOC workflow involving EDR analysis, process-tree investigation, malware detection, persistence analysis, credential-access investigation, file and hash verification, network analysis, change-management validation, classification, escalation, and closure decisions.



