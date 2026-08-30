# EU AI Act Compliance-as-Code Module

This directory contains automated **Compliance-as-Code** evaluation engines targeting the **EU Artificial Intelligence Act (Regulation EU 2024/1689)**.

Unlike traditional static GRC platforms that rely on manual policy uploads or self-reported questionnaires, these Python engines programmatically parse machine learning model metadata artifacts (`model-card.json`), inspect live cloud inference telemetry streams (e.g., AWS SageMaker and Amazon Bedrock endpoints), and evaluate AI system operational profiles against statutory risk tier rules.

---

## 🗂️ Module Breakdown & Control Scope

### 1. `eu_ai_act_art11_model_card_validator.py`
* **Regulatory Focus:** Article 10 (Data and Data Governance) & Article 11 (Technical Documentation & Annex IV Requirements)
* **Engineering Action:**
  * Programmatically parses ML model metadata cards (`model-card.json`) prior to production deployment.
  * Verifies training dataset lineage tracking, training/validation split documentation, and bias/fairness mitigation audit execution (`EU-AI-ACT-ART10-DATA-GOVERNANCE`).
  * Validates Annex IV technical parameters including model architecture versioning, active automated event logging flags, and mandatory human-in-the-loop (HITL) oversight integration (`EU-AI-ACT-ART11-TECHNICAL-DOCS`).
* **Output Artifact:** `eu_ai_act_article11_evidence.json`

---

### 2. `eu_ai_act_art12_telemetry_auditor.py`
* **Regulatory Focus:** Article 12 (Record-Keeping & Automated Logging Throughout Lifespan)
* **Engineering Action:**
  * Audits AWS CloudWatch Log Groups bound to AI model inference endpoints to ensure continuous telemetry capture (`EU-AI-ACT-ART12-INFERENCE-LOGGING`).
  * Confirms mandatory storage encryption at rest using AWS Key Management Service (`EU-AI-ACT-ART12-LOG-KMS-ENCRYPTION`).
  * Enforces the statutory 6-month (180-day) minimum log retention rule required for post-market monitoring and auditability (`EU-AI-ACT-ART12-LOG-RETENTION`).
* **Output Artifact:** `eu_ai_act_article12_evidence.json`

---

### 3. `eu_ai_act_art9_risk_classifier.py`
* **Regulatory Focus:** Article 6 (Classification Rules for High-Risk AI) & Article 9 (Risk Management Systems)
* **Engineering Action:**
  * Ingests operational system profiles and classifies AI workloads against EU AI Act risk tiers (**Prohibited**, **High-Risk**, **Limited/Minimal Risk**) under Article 5 and Annex III domain criteria (`EU-AI-ACT-ART6-TIER-CLASSIFICATION`).
  * Checks Article 6(3) derogation rules for narrow procedural tasks operating without profiling.
  * Validates whether mandatory Article 9 continuous risk management safeguards—such as iterative risk assessments, residual risk evaluations, adversarial robustness testing, and human override capabilities—are actively configured for High-Risk workloads (`EU-AI-ACT-ART9-RISK-SAFEGUARDS`).
* **Output Artifact:** `eu_ai_act_article9_risk_evidence.json`

---

## 🛠️ Execution

To execute all EU AI Act evaluations sequentially from the repository root:

```bash
export AWS_DEFAULT_REGION="eu-west-1"

python eu-ai-act/eu_ai_act_art11_model_card_validator.py
python eu-ai-act/eu_ai_act_art12_telemetry_auditor.py
python eu-ai-act/eu_ai_act_art9_risk_classifier.py
