# GRC Engineering Suite: Architecture & System Assumptions

This document outlines the system architecture, design principles, threat models, and technical assumptions governing the **Compliance-as-Code** evaluation engines in this repository.

---

## 🏗️ High-Level System Architecture

The suite operates on a **Pull-Based Continuous Telemetry Engine** model. Rather than relying on manual evidence collection or third-party agent installations, it uses native cloud APIs (`boto3`) and event payload evaluation to audit infrastructure state against regulatory control baselines.

```text
  ┌────────────────────────────────────────────────────────────────────────┐
  │                           Target Environment                           │
  │   (AWS IAM, KMS, S3, Route53, Backup, EC2, CloudTrail, Cognito, etc.)    │
  └─────────────────────────────────┬──────────────────────────────────────┘
                                    │ AWS API Telemetry (Read-Only)
                                    ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │                    Continuous Audit Pipeline (CI/CD)                   │
  │                  (.github/workflows/continuous-compliance.yml)         │
  │                                                                        │
  │   ┌───────────────┐   ┌───────────────┐   ┌───────────────┐   ┌─────────────┐ │
  │   │ DORA Engine   │   │ ISO 27001     │   │ PSD2 Engine   │   │ EU AI Act   │ │
  │   │ (5 Use Cases) │   │ (5 Use Cases) │   │ (3 Use Cases) │   │ (3 Use Cases)│ │
  │   └───────┬───────┘   └───────┬───────┘   └───────┬───────┘   └──────┬──────┘ │
  └───────────┼───────────────────┼───────────────────┼──────────────────┼─────┘
              │                   │                   │                  │
              └───────────────────┴─────────┬─────────┴──────────────────┘
                                            │ Emits Declarative Evidence
                                            ▼
                       ┌────────────────────────────────────────┐
                       │ Machine-Readable Evidence Artifacts    │
                       │ (*_evidence.json / RTS Registers)      │
                       └────────────────────────────────────────┘
