# GRC Engineering Suite: Continuous Compliance-as-Code

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Frameworks](https://img.shields.io/badge/Frameworks-DORA%20%7C%20ISO%2027001%20%7C%20PSD2%20%7C%20EU%20AI%20Act-blue.svg)]()
[![CI Pipeline](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions%20Automated-green.svg)]()

A modular **Compliance-as-Code** evaluation engine designed to continuously audit, verify, and document cloud infrastructure and AI workloads against European and global regulatory frameworks.

Instead of relying on manual point-in-time screenshots or passive questionnaire platforms (e.g., Vanta, Drata), this repository translates complex regulatory mandates—specifically **EU Digital Operational Resilience Act (DORA)**, **ISO/IEC 27001:2022**, **EU Payment Services Directive 2 (PSD2)**, and the **EU Artificial Intelligence Act (EU 2024/1689)**—into **executable Python engines, active cloud telemetry checks, and automated daily CI/CD pipelines**.

---

## 📚 Core System Documentation

* **[Architecture & System Assumptions (`ARCHITECTURE.md`)](ARCHITECTURE.md):** Detailed breakdown of our pull-based telemetry model, zero-side-effect inspection design, fail-closed evidence guarantees, and multi-region AWS assumptions.
* **[Contributing & Engineering Principles (`CONTRIBUTING.md`)](CONTRIBUTING.md):** Guidelines detailing our read-only execution standards, regulatory traceability rules, and code review checklists.

---

## 🗂️ Suite Repository Structure

```text
grc-engineering-suite/
│
├── .github/
│   └── workflows/
│       └── continuous-compliance.yml                 # Daily Automated CI/CD Audit Pipeline
│
├── dora/                                             # Module 1: EU DORA (Regulation EU 2022/2554)
│   ├── README.md
│   ├── dora_art9_access_protection_auditor.py       # IAM MFA & Network Isolation
│   ├── dora_art11_resilience_checker.py              # Cross-Region Failover & DNS
│   ├── dora_art12_backup_auditor.py                  # Backup RPO & WORM Lock
│   ├── dora_art18_incident_classification_engine.py # Major Incident Timers & RTS
│   └── dora_art28_third_party_register_generator.py  # TPRM Vendor RTS Register
│
├── iso27001/                                         # Module 2: ISO/IEC 27001:2022 Annex A
│   ├── README.md
│   ├── iso_a8_5_stale_credential_deprovisioner.py   # Stale Credential Deprovisioning
│   ├── iso_a8_24_kms_rotation_auditor.py            # KMS Key Rotation & Deletion Windows
│   ├── iso_a8_12_dlp_and_retention_auditor.py       # S3 Public Block (DLP) & Object Retention
│   ├── iso_a8_9_config_and_redundancy_auditor.py    # EBS Default Encryption & Multi-AZ HA
│   └── iso_a8_16_monitoring_and_audit_logging_auditor.py # CloudTrail & Log Integrity Validation
│
├── psd2/                                             # Module 3: EU PSD2 (Directive EU 2015/2366)
│   ├── README.md
│   ├── psd2_art97_sca_mfa_auditor.py                # Strong Customer Authentication (SCA)
│   ├── psd2_art95_fraud_transaction_monitor.py      # Real-Time Fraud Telemetry Engine
│   └── psd2_art95_audit_trail_logging_auditor.py    # 5-Year Payment Log Retention & KMS Encryption
│
├── eu-ai-act/                                        # Module 4: EU AI Act (Regulation EU 2024/1689)
│   ├── README.md
│   ├── eu_ai_act_art11_model_card_validator.py      # Model Technical Docs & Data Lineage
│   ├── eu_ai_act_art12_telemetry_auditor.py         # Automated Inference Event Logging
│   └── eu_ai_act_art9_risk_classifier.py            # System Tier Classification & Risk Safeguards
│
├── ARCHITECTURE.md                                   # System Architecture & Technical Assumptions
├── CONTRIBUTING.md                                   # GRC Engineering Principles & Guidelines
├── README.md
└── requirements.txt
