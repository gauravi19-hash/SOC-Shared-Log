# Final SOC Simulated Shift Report

## 1. Project Overview

This project simulates seven days of Security Operations Center (SOC) Analyst L1 shift activity.

The objective was to practice a structured SOC workflow covering alert validation, triage, investigation, evidence correlation, classification, MITRE ATT&CK mapping, escalation, monitoring, closure, and analyst documentation.

The project contains **31 simulated security alerts** across endpoint, identity, network, cloud, database, email, and data-security scenarios.

## 2. Project Objectives

* Practice an L1 SOC alert-triage workflow.
* Validate alerts using multiple sources of evidence.
* Correlate endpoint, authentication, network, cloud, DLP, and database activity.
* Distinguish malicious activity from legitimate business activity.
* Map confirmed techniques to MITRE ATT&CK.
* Practice escalation and evidence-preservation decisions.
* Maintain consistent analyst documentation.
* Produce a structured final alert log.

## 3. Seven-Day Overview

| Day   | Alerts | Primary Focus                                                                 |
| ----- | -----: | ----------------------------------------------------------------------------- |
| Day 1 |      5 | Authentication, phishing, PowerShell, privilege changes                       |
| Day 2 |      4 | Process analysis, web exploitation, administrative activity                   |
| Day 3 |      4 | DNS, network traffic, data-transfer validation                                |
| Day 4 |      5 | Malware, persistence, PowerShell, credential access                           |
| Day 5 |      4 | Account compromise, privilege escalation, RDP                                 |
| Day 6 |      4 | Malware execution, exfiltration, credential access                            |
| Day 7 |      5 | Cloud identity, persistence, scanning, privileged accounts, database activity |

**Total: 31 alerts**

## 4. Alert Classification Summary

* **True Positive:** 17
* **Suspicious / Needs Monitoring:** 2
* **Benign / Authorized:** 12

The final verdict for each alert was based on the simulated evidence available during the investigation.

Escalation was treated as an **analyst action**, not as a verdict.

## 5. Investigation Workflow

Each alert followed a structured workflow:

1. Alert validation
2. Initial severity assessment
3. User, host, and source identification
4. Timeline analysis
5. Process analysis
6. Authentication analysis
7. Network correlation
8. Business-context validation
9. IOC and suspicious-behavior review
10. Verdict assignment
11. MITRE ATT&CK mapping
12. Escalation, monitoring, or closure
13. Analyst documentation

## 6. Investigation Areas Practiced

### Endpoint Investigation

* Process-tree analysis
* Malicious executable detection
* PowerShell investigation
* Scheduled-task persistence
* Registry Run-key persistence
* DLL/rundll32 abuse
* Credential-access indicators
* Browser credential access

### Identity and Authentication

* Password spraying
* Suspicious authentication
* RDP authentication
* Account-compromise detection
* Privileged-account abuse
* Domain Admin membership changes
* Unauthorized account creation

### Network Security

* DNS beaconing
* C2-like traffic
* Internal network scanning
* SMB activity
* Suspicious outbound connections
* Data-transfer monitoring

### Cloud and Data Security

* Cloud identity anomalies
* Unregistered device detection
* Sensitive document downloads
* DLP investigations
* Cloud-storage exfiltration
* Database activity monitoring

## 7. Key SOC Lessons

### Context Matters

A suspicious command or event by itself does not always prove malicious activity. Approved tickets, signed software, scheduled jobs, known administrative workflows, and business context must be considered.

### Correlation Is Critical

Strong investigations combined multiple signals rather than relying on a single alert.

Examples included:

* Authentication + source endpoint + SMB activity
* PowerShell + persistence + external communication
* Database activity + task modification + outbound traffic
* Cloud login + device identity + VPN logs + sensitive downloads

### MFA Is Not Automatically Proof of Legitimacy

A successful MFA event still needs to be evaluated alongside source IP, device identity, VPN/session information, user behavior, and subsequent activity.

### ExecutionPolicy Bypass Is a Signal, Not a Verdict

PowerShell using ExecutionPolicy Bypass requires investigation, but authorized administrative scripts may also use it.

### Legitimate Tools Can Be Abused

Tools such as PowerShell, rundll32, ProcDump, Nmap, and scheduled tasks have legitimate purposes but can also appear in attack chains.

## 8. MITRE ATT&CK Coverage

The investigations included techniques across:

* Initial Access
* Execution
* Persistence
* Privilege Escalation
* Defense Evasion
* Credential Access
* Discovery
* Lateral Movement
* Collection
* Command and Control
* Exfiltration

Representative techniques included password spraying, PowerShell, malicious file execution, scheduled-task persistence, rundll32 execution, credential dumping, account manipulation, network discovery, valid accounts, and data access.

## 9. Analyst Skills Demonstrated

Alert triage
Log analysis
Endpoint investigation
Authentication analysis
Network security monitoring
SIEM-style correlation
EDR investigation
IOC analysis
MITRE ATT&CK mapping
Incident escalation
Evidence-based classification
SOC documentation
Analyst communication

## 10. Project Outcome

The seven simulated shifts provided structured practice in progressing from an initial alert to an evidence-supported analyst decision.

The final project contains:

7 daily shift reports
31 investigated alerts
Consolidated SOC alert CSV
Final project report
Reusable SOC investigation templates
Alert documentation
Screenshot evidence

This project demonstrates practical familiarity with the workflow expected of an entry-level SOC analyst.
