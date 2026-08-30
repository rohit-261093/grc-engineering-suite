# GRC Engineering Suite: Continuous Compliance-as-Code

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Framework](https://img.shields.io/badge/Framework-EU%20DORA%20(2022%2F2554)-blue.svg)]()
[![Multi-Framework](https://img.shields.io/badge/Mapped--Frameworks-ISO%2027001%20%7C%20SOC%202-green.svg)]()

A modular **Compliance-as-Code** evaluation engine designed to continuously audit, verify, and document cloud infrastructure posture against European and global regulatory frameworks.

Instead of relying on manual point-in-time screenshots or passive questionnaire platforms (e.g., Vanta/Drata), this repository translates complex regulatory mandates—starting with **EU Digital Operational Resilience Act (DORA)**—into **executable Python scripts, continuous infrastructure telemetry, and auditor-ready evidence generation**.

---

## 🗂️ Suite Modules

```text
grc-engineering-suite/                <-- Root Directory
│
├── .github/                           <-- Root Level (Hidden Folder)
│   └── workflows/
│       └── continuous-compliance.yml  <-- Your Pipeline File
│
├── dora/
│   ├── dora_art9_access_protection_auditor.py       # Module 1: IAM MFA & Network Isolation
│   ├── dora_art11_resilience_checker.py              # Module 2: Cross-Region Failover & DNS
│   ├── dora_art12_backup_auditor.py                  # Module 3: Backup RPO & WORM Lock
│   ├── dora_art18_incident_classification_engine.py # Module 4: Major Incident Timers & RTS
│   └── dora_art28_third_party_register_generator.py  # Module 5: TPRM Vendor RTS Register
│
├── iso27001/               # Module 2: Access Control & Identity Audit (A.9 / A.5.15)
│   └── [Coming Soon]
│
├── soc2/                   # Module 3: Encryption & Key Management (CC6.1 / CC6.7)
│   └── [Coming Soon]
│
└── eu-ai-act/              # Module 4: High-Risk AI Governance & Model Cards
    └── [Coming Soon]
