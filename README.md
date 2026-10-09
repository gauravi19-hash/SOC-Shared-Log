# 7-Day Simulated SOC Investigation Lab

## Overview

A self-created simulated Security Operations Center (SOC) project designed to practice entry-level alert triage, investigation, evidence correlation, incident classification, escalation, and documentation across seven simulated shifts.

**Project type:** Simulated SOC investigation
**Role focus:** SOC Analyst L1 / Junior SOC Analyst
**Dataset:** 31 synthetic alert scenarios
**Duration:** 7 simulated shifts

> **Disclaimer:** This project uses self-created simulated scenarios and synthetic investigation evidence. It was not conducted in a production SOC environment, and the scenarios do not represent real company incidents.

## Objectives

* Practice a structured SOC L1 alert-triage workflow.
* Investigate suspicious endpoint, identity, network, cloud, and database activity.
* Correlate evidence across multiple simulated data sources.
* Distinguish confirmed malicious activity from suspicious activity and authorized behavior.
* Assign verdicts and severity based on available evidence.
* Determine whether to escalate, monitor, or close an alert.
* Map relevant behaviors to MITRE ATT&CK.
* Maintain consistent investigation records and analyst notes.

## Project Structure

```text
SOC-Shared-Log/
├── shifts/
│   ├── Day-01.md
│   ├── Day-02.md
│   ├── Day-03.md
│   ├── Day-04.md
│   ├── Day-05.md
│   ├── Day-06.md
│   └── Day-07.md
├── alerts/
│   └── README.md
├── reports/
│   └── Final-SOC-Project-Report.md
├── screenshots/
│   └── README.md
├── templates/
│   ├── Alert-Triage-Template.md
│   └── Investigation-Template.md
├── SOC-Alert-Log.csv
└── README.md
```

## Investigation Coverage

The simulated scenarios cover:

* Password spraying and account compromise
* Phishing and malicious document execution
* PowerShell execution and persistence
* Credential access and privilege escalation
* Suspicious authentication and lateral movement
* Internal network scanning
* Cloud identity and access activity
* Potential data exfiltration
* Privileged account changes
* Unusual database access

## Investigation Workflow

Each scenario follows a structured workflow:

1. Validate the alert and identify the affected user or host.
2. Review available event details and supporting evidence.
3. Correlate endpoint, authentication, network, and other relevant activity.
4. Check authorization, business context, and approved changes.
5. Determine the investigation verdict and severity.
6. Map supported behaviors to MITRE ATT&CK.
7. Document the recommended action and analyst notes.

## Dataset and Documentation

| File or folder      | Purpose                                                     |
| ------------------- | ----------------------------------------------------------- |
| `shifts/`           | Seven daily investigation records                           |
| `SOC-Alert-Log.csv` | Consolidated dataset of 31 simulated alerts                 |
| `reports/`          | Final project-level report                                  |
| `templates/`        | Reusable alert-triage and investigation templates           |
| `alerts/`           | Explanation of alert documentation and dataset organization |

The consolidated alert log records fields such as alert ID, date, severity, source, affected user or host, investigation summary, verdict, action, MITRE ATT&CK mapping, and analyst notes.

## Skills Practiced

* SOC L1 alert triage
* Log and event analysis
* Authentication investigation
* Endpoint process-tree analysis
* Network activity analysis
* Evidence correlation
* Incident classification and prioritization
* MITRE ATT&CK mapping
* Escalation and investigation documentation

## Limitations

This is a documentation-based simulation, not a live SIEM or EDR deployment. The project does not claim production SOC experience, real incident response, or real-time threat detection. The scenarios are intended to demonstrate investigation reasoning and structured analyst documentation.

## Future Improvements

* Reproduce selected scenarios in a local lab.
* Collect actual Windows event logs from controlled test systems.
* Ingest events into Splunk or another SIEM.
* Build and validate detection queries against the collected logs.
* Capture genuine screenshots of queries, events, and investigation results.

## Author

BCA Graduate | Aspiring SOC Analyst L1 | Blue Team & Threat Detection
