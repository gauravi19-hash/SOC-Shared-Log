# Day 2 — Simulated SOC Shift

**Date:** 1 October 2026  
**Shift:** 09:00–17:00  
**Role:** SOC Analyst L1  
**Environment:** Simulated Enterprise SOC

## Shift Focus

- Windows and Linux log analysis
- Suspicious process investigation
- Process tree analysis
- Authentication monitoring
- Command-line investigation

## Shift Summary

- **Alerts Investigated:** 4
- **True Positives:** 2
- **Benign / False Positives:** 2
- **Suspicious / Monitoring:** 0
- **Escalated:** 2
- **Closed:** 2

---

## SOC-006 — Suspicious Process Execution

**Time:** 09:37  
**Severity:** High  
**Verdict:** True Positive  
**Action:** Escalated to L2/IR  
**MITRE ATT&CK:** T1218.011 — Rundll32; T1059.001 — PowerShell; T1027 — Obfuscated/Compressed Files or Information; T1204.002 — User Execution: Malicious File

### Initial Investigation

EDR detected `rundll32.exe` executing a DLL from the user's Temp directory.

The process was launched by `WINWORD.EXE`.

Initial process tree:

`WINWORD.EXE → rundll32.exe → update.dll`

The activity was considered suspicious because a DLL was being executed from a user-writable Temp directory by a Microsoft Word process.

### Additional Evidence

The user received an email containing:

`Salary_Adjustment_2026.docm`

The document was opened shortly before the suspicious process execution.

The DLL was:

`C:\Users\a.patel\AppData\Local\Temp\update.dll`

The DLL was unsigned and had an unknown reputation.

Shortly afterward, the DLL spawned:

`powershell.exe`

with:

`-ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand`

An outbound connection to `185.XX.XX.44:443` was then observed.

### Analyst Decision

The combination of malicious document execution, unsigned DLL execution through `rundll32.exe`, hidden and encoded PowerShell activity, and subsequent outbound communication indicated malicious behavior.

**Escalated to L2/IR for containment and further investigation.**

### Analyst Notes

The initial alert was not immediately classified as malicious because additional evidence was required. Process-tree analysis, file location, DLL reputation, PowerShell command-line parameters, and network activity provided sufficient evidence to classify the alert as a True Positive.

Port 443 was treated as HTTPS-related traffic rather than RDP. Further investigation of the destination IP and actual application protocol was recommended.

---

## SOC-007 — Multiple Failed SSH Login Attempts

**Time:** 11:42–11:49  
**Severity:** Low  
**Verdict:** Benign / Authorized Activity  
**Action:** Monitor / Close  
**MITRE ATT&CK:** N/A

### Initial Investigation

27 failed SSH authentication attempts were detected against the `web-admin` account from `10.20.15.77` within approximately five minutes.

The repeated authentication failures initially appeared suspicious and required further investigation.

### Additional Evidence

The source IP `10.20.15.77` was identified as `IT-ADMIN-07`, an approved IT administrator workstation used by the Linux infrastructure team.

A successful SSH login occurred at 11:48:12 using the `web-admin` account.

After authentication, the user executed:

`sudo -u root /usr/bin/systemctl restart nginx`

followed by a status check of the Nginx service.

The session closed shortly afterward.

No suspicious files were created, no unknown processes were launched, and no external network connections were observed.

### Analyst Decision

The authentication activity was consistent with legitimate administrative activity from an approved IT workstation.

**Alert classified as benign authorized activity. Monitoring was recommended.**

### Analyst Notes

The initial failed-login pattern required investigation because repeated SSH authentication failures can indicate brute-force activity. Correlation with the source asset, user account, successful authentication, and post-login activity established legitimate administrative context.

---

## SOC-008 — Suspicious Process Execution

**Time:** 13:18:42  
**Severity:** Medium  
**Verdict:** Benign / Authorized Activity  
**Action:** Monitor activity before and after execution  
**MITRE ATT&CK:** N/A

### Initial Investigation

EDR detected a Python process launched by the Nginx service account:

`www-data`

The process executed:

`python3 /tmp/healthcheck.py`

The script was located in `/tmp`, which is an unusual location for a legitimate application health-check script and required further investigation.

### Additional Evidence

The script was created at 13:18:39 and was owned by `www-data`.

The script contained:

`requests.get("https://monitoring.company.example/health")`

and wrote the response to:

`/var/log/app-health.log`

The process tree was:

`nginx → python3 /tmp/healthcheck.py`

The Python process ran for approximately two seconds and exited normally.

The only network connection was:

`ubuntu-web01 → monitoring.company.example:443`

The destination was confirmed as the company's internal monitoring infrastructure.

Nginx logs showed an internal monitoring request at 13:18:35:

`GET /internal/healthcheck`

The infrastructure team confirmed that a new monitoring health-check deployment had been introduced at 13:15.

### Analyst Decision

The activity was confirmed as part of an authorized monitoring health-check deployment.

Although execution from `/tmp` was unusual and represented a configuration concern, there was no evidence of malicious behavior.

**Alert classified as benign authorized activity. Monitoring of activity before and after execution was recommended, with the unusual `/tmp` placement documented for the infrastructure team.**

### Analyst Notes

The initial alert was suspicious because a service account executed a newly created Python script from `/tmp`.

Correlation with process execution, file contents, network destination, Nginx logs, and confirmation from the infrastructure team established legitimate business context.

This investigation demonstrated that unusual file locations should trigger investigation but should not automatically be classified as malicious.

---

## SOC-009 — Possible Web Shell / Command Injection

**Time:** 15:05–15:06  
**Severity:** High  
**Verdict:** True Positive  
**Action:** Escalated to L2/IR for containment and further investigation  
**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1059.004 — Unix Shell; T1505.003 — Web Shell

### Initial Investigation

Multiple unusual HTTP POST requests were detected against `ubuntu-web01`.

The requests used an undocumented `cmd=` parameter:

`/index.php?cmd=id`

`/index.php?cmd=whoami`

`/index.php?cmd=uname+-a`

`/index.php?cmd=cat+/etc/passwd`

The requests were followed by shell command execution through the PHP application.

### Additional Evidence

The source IP `10.20.15.92` was identified as `DEV-LAPTOP-03`, a developer workstation that was not approved for maintenance activity on the web server.

The process tree showed:

`nginx → php-fpm → /bin/sh`

The shell executed reconnaissance commands including:

`id`

`whoami`

`uname -a`

`cat /etc/passwd`

Shortly afterward, a new file was created:

`/var/www/html/.cache.php`

The file was owned by `www-data`.

An outbound connection was then established:

`ubuntu-web01 → 10.20.15.92:4444`

The connection lasted approximately 18 seconds. Port 4444 was not associated with any approved application activity.

### Analyst Decision

The combination of unauthorized command execution through the web application, system reconnaissance, creation of a new PHP file in the web directory, and an unexpected outbound connection indicated a likely web-server compromise.

**Alert classified as a True Positive and escalated to L2/IR for containment and further investigation.**

### Analyst Notes

The initial alert was treated as suspicious until additional evidence was correlated.

The investigation demonstrated the importance of correlating web-server logs, process execution, file creation, source-host identity, and network activity.

The source IP alone was not sufficient to establish compromise. The complete sequence of application-level command execution, shell activity, web-directory file creation, and unexpected network communication provided the basis for escalation.

## End-of-Shift Status

Day 2 completed successfully.

Four alerts were investigated using an L1 SOC triage workflow involving process analysis, authentication review, network correlation, evidence gathering, classification, escalation, and closure.