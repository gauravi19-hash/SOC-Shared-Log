# Day 1 — Simulated SOC Shift

**Date:** 30 September 2026
**Shift:** 09:00–17:00
**Role:** SOC Analyst L1
**Environment:** Simulated Enterprise SOC

## Shift Summary

* **Alerts Investigated:** 5
* **True Positives:** 2
* **Benign / False Positives:** 3
* **Escalated:** 2
* **Closed:** 2
* **Monitored:** 1

---

## SOC-001 — Suspected Password Spray

**Time:** 09:42
**Severity:** High
**Verdict:** True Positive
**Action:** Escalated to L2/IR
**MITRE ATT&CK:** T1110.003 — Password Spraying; T1059.001 — PowerShell

### Investigation

18 failed remote login attempts targeted five user accounts from `10.10.20.45` within four minutes. A successful remote login to `j.smith` followed. The source IP was previously unseen for this user.

Shortly afterward, PowerShell executed an encoded command and an outbound connection was observed.

### Analyst Decision

The combination of password-spray behavior, successful remote access, encoded PowerShell execution, and outbound communication indicated likely malicious activity.

**Escalated immediately to L2/IR for containment and further investigation.**

---

## SOC-002 — Suspicious PowerShell Execution

**Time:** 11:17
**Severity:** Low
**Verdict:** Benign / False Positive
**Action:** Closed
**MITRE ATT&CK:** T1059.001 — PowerShell

### Investigation

PowerShell executed with `ExecutionPolicy Bypass` using:

`C:\IT\Scripts\Update-Defender.ps1`

The script was digitally signed by Microsoft, had no malicious reputation, and performed legitimate Microsoft Defender signature updates.

The script was also used across 86 corporate endpoints and was executed through the expected service process.

### Analyst Decision

No evidence of malicious activity was identified.

**Alert closed as benign administrative activity.**

---

## SOC-003 — Phishing Email / Credential Harvesting

**Time:** 13:26
**Severity:** High
**Verdict:** True Positive
**Action:** Immediate escalation and containment
**MITRE ATT&CK:** T1566.002 — Phishing: Spearphishing Link; T1056.002 — Input Capture

### Investigation

The email originated from the lookalike domain `micr0soft-security.com` and used urgent Microsoft 365 account-disabling language.

SPF, DKIM, and DMARC checks failed.

The attached HTML file contained a fake Microsoft 365 login page hosted at a domain identified as malicious/phishing.

Five employees received the email. Two employees clicked the URL, followed by authentication attempts from an external IP.

### Analyst Decision

The evidence confirmed a phishing and credential-harvesting campaign.

**Escalated immediately for account-compromise investigation and containment.**

Recommended actions included reviewing authentication activity, revoking sessions if required, credential reset, MFA review, and blocking the phishing indicators.

---

## SOC-004 — Possible Data Exfiltration

**Time:** 15:04
**Severity:** Low
**Verdict:** Benign / False Positive
**Action:** Closed
**MITRE ATT&CK:** N/A

### Investigation

A 2.8 GB outbound transfer was detected from `HR-LAPTOP-12` to `drive.company-cloud.example`.

The destination was confirmed as an approved corporate cloud-storage platform used by the HR department.

The transfer contained `HR_Backup_September.zip` and was initiated by `hr.admin`. Similar monthly backups had previously been performed by the same user.

No suspicious processes, malware alerts, unusual authentication, or unexpected external connections were identified.

### Analyst Decision

The transfer was consistent with an authorized monthly HR backup.

**Alert closed as benign administrative activity.**

---

## SOC-005 — Suspicious Account Privilege Change

**Time:** 16:21
**Severity:** Medium
**Verdict:** Benign / Authorized Activity
**Action:** Monitor / Notify IT
**MITRE ATT&CK:** N/A

### Investigation

`svc_backup` was added to the `Backup Operators` group by `IT-ADMIN01`.

The activity matched approved change request `CHG-2026-0930-117` for scheduled monthly backup maintenance.

The backup service started immediately afterward and the backup completed successfully.

However, unlike the previous month's process, `svc_backup` remained in the privileged group after the backup completed.

### Analyst Decision

The privilege change was authorized, but the account's continued privileged membership required attention.

**Monitoring recommended and IT should verify whether the elevated membership is still required and remove it if appropriate.**

---

## Day 1 Lessons Learned

1. Correlate multiple events instead of investigating alerts in isolation.
2. A successful login after repeated failed attempts can significantly increase risk.
3. PowerShell `ExecutionPolicy Bypass` is a detection signal but does not automatically indicate malicious activity.
4. Phishing investigations should include email authentication, URL, attachment, and user-interaction analysis.
5. Large outbound transfers should be validated against approved business activity before declaring data exfiltration.
6. Authorized administrative changes can still create security risks when elevated privileges remain longer than required.

## End-of-Shift Status

**Day 1 completed successfully.**

Five alerts were investigated using an L1 SOC triage workflow involving alert validation, event correlation, evidence gathering, classification, escalation, closure, and monitoring.
