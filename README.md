# AI Behavioural Threat Detection Platform

A Python-based cybersecurity monitoring prototype that analyses simulated user activity, identifies behavioural anomalies and generates explainable security alerts.

**Project type:** Independent cybersecurity engineering project  
**Focus:** Security Operations, Identity Threat Detection, Behavioural Analytics and Cyber Risk

## Overview

This project demonstrates how suspicious account activity can be identified by comparing security events against expected user behaviour.

It evaluates four indicators:

- Unusual login country
- Login activity outside expected working hours
- Unfamiliar devices
- Unusually high file-access volume

Each indicator contributes to a risk score between 0 and 100. Events are classified by severity, with alerts generated when the configured threshold is reached.

The current prototype uses rule-based detection and simulated security data. It does not currently implement machine-learning-based anomaly detection.

## Technology Stack

- Python — event processing and detection logic
- SQLite — event and alert persistence
- FastAPI — API endpoints
- Pydantic — input validation
- Git and GitHub — version control

## Current Features

- Processes multiple simulated security events
- Compares events with predefined individual user baselines
- Calculates multi-factor risk scores
- Classifies events as NORMAL, SUSPICIOUS or CRITICAL
- Generates structured alerts for suspicious events
- Saves events and alerts to a local SQLite database through the main processing script
- Provides FastAPI endpoints for retrieving alerts and analysing submitted events

**Current limitation:** The API's event-submission endpoint analyses events but does not yet persist them to the database.

## Risk Scoring

| Indicator | Risk points |
|---|---:|
| Country differs from baseline | +30 |
| Outside expected working hours | +20 |
| Device differs from baseline | +20 |
| File-access volume exceeds five times baseline | +30 |

**Severity classifications**

- NORMAL: 0–39
- SUSPICIOUS: 40–69
- CRITICAL: 70–100

Alerts are generated for events scoring 40 or above.

These weights and thresholds are demonstration values rather than statistically validated security thresholds.

## Example Scenario

A simulated user signs in from an unfamiliar country at an unusual hour, using an unfamiliar device, and accesses significantly more files than expected.

The platform identifies all four indicators and assigns a risk score of 100, resulting in a CRITICAL alert.

This demonstrates how multiple behavioural signals can be combined to support security investigation.

## Project Structure

```text
ai-security-platform/
├── main.py         # Simulated events and alert generation
├── detection.py    # Behavioural baselines and risk scoring
├── database.py     # SQLite storage and retrieval
├── api.py          # FastAPI interface
├── .gitignore      # Excluded local files
└── README.md       # Project documentation
```

## Current Limitations

- Uses fictional users and simulated security events
- Behavioural baselines are predefined rather than automatically learned
- Detection is rule-based, not machine-learning-based
- API event persistence is not yet implemented
- Risk weights require further validation
- No enterprise SIEM integration
- Not intended for production deployment

## Development Roadmap

- [ ] Implement database persistence for API-submitted events
- [ ] Add automated tests
- [ ] Improve alert identification and duplicate handling
- [ ] Introduce configurable behavioural baselines
- [ ] Add MITRE ATT&CK mappings
- [ ] Document false-positive scenarios
- [ ] Build a security monitoring dashboard
- [ ] Create incident investigation reports
- [ ] Connect technical findings to organisational cyber risk assessments

## Cybersecurity Relevance

This project demonstrates foundational security operations concepts, including security-event analysis, behavioural anomaly detection, alert prioritisation and evidence-based investigation.

Future development will connect technical detections to GRC activities such as security-control assessment, risk treatment and management reporting.

## Disclaimer

This is an independent educational cybersecurity project. All included user scenarios are fictional, and the system is not an enterprise security monitoring product.