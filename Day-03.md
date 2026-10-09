# Day 3 — Simulated SOC Shift

**Date:** 2 October 2026  
**Shift:** 09:00–17:00  
**Role:** SOC Analyst L1  
**Environment:** Simulated Enterprise SOC

## Shift Focus

- DNS log analysis
- Suspicious domains
- Network connection analysis
- Possible Command and Control (C2)
- Beaconing behavior
- Source/destination investigation

## Shift Summary

- **Alerts Investigated:** 4
- **True Positives:** 1
- **Benign / Authorized Activity:** 3
- **Suspicious / Monitoring:** 0
- **Escalated:** 1
- **Closed / Monitored:** 3

---

## SOC-010 — Possible C2 Beaconing

**Time:** 09:21–09:24  
**Severity:** High  
**Verdict:** True Positive  
**Action:** Escalated to L2/IR for containment and further investigation  
**MITRE ATT&CK:** T1059.001 — PowerShell; T1071.001 — Web Protocols

### Initial Investigation

Repeated DNS queries were detected from `WIN-FIN-07` to:

`cdn-update-check.com`

The queries occurred at approximately one-minute intervals.

The domain was newly observed in the environment and was not initially associated with an approved corporate service.

### Additional Evidence

The domain was not an approved corporate domain and had no known legitimate relationship with the organization's software vendors.

The domain was newly registered and resolved to:

`185.XX.XX.91`

EDR showed that a hidden PowerShell process started approximately five seconds before the first DNS query:

`powershell.exe -WindowStyle Hidden -Command ...`

The user `r.shah` confirmed that they had not installed or updated software around the time of the alert.

Each DNS query was followed by an HTTPS connection to the same external IP:

`185.XX.XX.91:443`

The connections occurred at approximately one-minute intervals and lasted 2–3 seconds before closing.

### Analyst Decision

The combination of hidden PowerShell execution, repeated DNS requests at regular intervals, communication with a newly registered and unauthorized external domain, and repeated HTTPS connections to the resolved IP indicated likely command-and-control activity.

**Alert classified as a True Positive and escalated to L2/IR for containment and further investigation.**

### Analyst Notes

The regular timing of the DNS and HTTPS activity was an important indicator of possible beaconing behavior.

The analyst did not classify the activity as malicious based on the newly registered domain alone. Correlation with endpoint process execution, user activity, domain context, and network behavior provided sufficient evidence for escalation.

---

## SOC-011 — Possible DNS Tunneling

**Time:** 11:16–11:21  
**Severity:** Low  
**Verdict:** Benign / Authorized Activity  
**Action:** Closed  
**MITRE ATT&CK:** N/A

### Initial Investigation

Approximately 150 DNS queries were generated from `WIN-ACCT-03` within five minutes.

The queries contained unusually long and structured subdomains, which initially raised the possibility of DNS tunneling or covert data transfer.

### Additional Evidence

The queried domain:

`data-sync-example.com`

was confirmed as a legitimate third-party cloud analytics domain approved by the IT team.

The domain had existed for several years and had no current malicious reputation.

EDR identified the process generating the DNS requests as:

`DataSyncAgent.exe`

The application was installed at:

`C:\Program Files\DataSync\DataSyncAgent.exe`

The executable was digitally signed by the approved vendor.

The application's documentation confirmed that it uses DNS requests to transmit telemetry when direct HTTPS connectivity is unavailable.

No direct connection to an unknown external IP was observed.

All DNS responses came through the organization's approved DNS resolver.

No new executable, script, scheduled task, or suspicious child process was created during the alert period.

### Analyst Decision

The unusual DNS pattern initially appeared suspicious, but the activity was confirmed as legitimate behavior from an approved analytics application.

**Alert classified as benign authorized activity and closed.**

### Analyst Notes

The investigation demonstrated that unusual DNS patterns should not automatically be classified as malicious.

Domain reputation, application identity, process origin, vendor validation, network behavior, and surrounding endpoint activity were correlated before closing the alert.

---

## SOC-012 — Suspicious Outbound Connection

**Time:** 14:31–14:35  
**Severity:** Low  
**Verdict:** Benign / Authorized Activity  
**Action:** Monitor / Document  
**MITRE ATT&CK:** N/A

### Initial Investigation

Repeated outbound HTTPS connections were detected from `WIN-SALES-12` to:

`91.XX.XX.47:443`

The connections occurred approximately every 30 seconds.

The destination was not listed in the organization's approved external-services list, so the activity initially appeared suspicious.

### Additional Evidence

The destination IP belonged to a major cloud hosting provider and had no current malicious reputation.

Reverse DNS resolved the IP to:

`api-sync.cloudservice.example`

The domain had existed for several years.

EDR identified the process responsible for the connections as:

`SalesSync.exe`

The executable was located at:

`C:\Program Files\SalesSync\SalesSync.exe`

and was digitally signed by the organization's approved CRM vendor.

The user `p.kulkarni` confirmed that the company's CRM application had been opened at approximately 14:30.

The outbound connections occurred every 30 seconds while the CRM application was running.

When the CRM application was closed at 14:35, the connections stopped.

No PowerShell, Command Prompt, script execution, suspicious file creation, or unexpected child processes were observed.

### Analyst Decision

The network activity was consistent with legitimate CRM synchronization behavior.

Although the destination was not present on the organization's approved-services list, the endpoint process, vendor signature, destination reputation, user activity, and connection timing supported a benign explanation.

**Alert classified as benign authorized activity. Monitoring was recommended, and the external CRM endpoint should be reviewed for inclusion in the approved-services inventory if appropriate.**

### Analyst Notes

An external destination should not automatically be classified as malicious simply because it is absent from an approved-services list.

Endpoint process attribution and correlation with user and application activity were essential to reaching the final classification.

## SOC-013 — Large Outbound Transfer to External File-Sharing Service

**Time:** 16:12
**Severity:** Medium
**Verdict:** Benign / Authorized Activity
**Action:** Closed
**MITRE ATT&CK:** N/A

### Investigation

A 1.7 GB outbound transfer was detected from `WIN-LEGAL-05` to `104.XX.XX.88:443` associated with `fileshare-example.com`.

The destination was confirmed as a legitimate commercial file-sharing service with an existing corporate account. The service is approved for use by multiple departments, including Legal.

Further investigation showed that `n.desai`, a Legal department employee, regularly works with external counsel. At 15:55, the user received an email from external counsel requesting the September case package to be uploaded to the company's approved external-counsel workspace.

The 1.7 GB archive contained approximately 3,400 Legal case documents, including discovery files, PDF evidence, and attorney correspondence. No executable files or scripts were present.

The archive was created at 16:03 by the approved corporate document-management application. EDR showed the following process chain:

`DocumentManager.exe → Archive creation → fileshare-sync.exe`

Both applications are approved corporate software.

No PowerShell, Command Prompt, suspicious child process, credential-access activity, malware detection, or other suspicious endpoint behavior was observed.

### Analyst Decision

The outbound transfer was consistent with an authorized Legal department workflow requested by external counsel.

Although the transfer volume was large, the destination, user activity, file contents, application/process chain, and business context were all consistent with legitimate activity.

**Alert closed as benign / authorized activity.**

## End-of-Shift Status

Day 3 completed successfully.

Four alerts were investigated using an L1 SOC triage workflow involving DNS and network analysis, data-transfer validation, business-context verification, evidence correlation, classification, escalation, and closure.
