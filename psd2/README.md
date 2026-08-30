# EU PSD2 Compliance-as-Code Module

This directory contains automated **Compliance-as-Code** evaluation engines targeting the **EU Payment Services Directive 2 (Directive EU 2015/2366)** and the associated European Banking Authority (EBA) Regulatory Technical Standards (RTS).

Instead of relying on passive static policy questionnaires, these Python engines inspect live AWS payment infrastructure configurations, evaluate real-time transaction telemetry against regulatory risk metrics, and emit structured audit evidence artifacts (`JSON`).

---

## 🗂️ Module Breakdown & Control Scope

### 1. `psd2_art97_sca_mfa_auditor.py`
* **Article Focus:** Article 97 (Strong Customer Authentication — SCA)
* **Engineering Action:** Audits AWS Cognito User Pools and authentication gateways supporting payment workloads to confirm Multi-Factor Authentication (MFA) enforcement across customer and API identities.
* **Output Evidence:** `psd2_article97_evidence.json`

---

### 2. `psd2_art95_fraud_transaction_monitor.py`
* **Article Focus:** Article 95 (Operational & Security Risk Management — Fraud Telemetry)
* **Engineering Action:** Evaluates real-time payment telemetry payloads against EBA RTS fraud indicators (high-value transfers, velocity breaches, geographic IP anomalies) to trigger step-up verification and log compliance decisions.
* **Output Evidence:** `psd2_article95_fraud_evidence.json`

---

### 3. `psd2_art95_audit_trail_logging_auditor.py`
* **Article Focus:** Article 95 (Audit Trail Integrity & Statutory Retention)
* **Engineering Action:** Inspects CloudWatch Log Groups bound to payment APIs to enforce mandatory AWS KMS encryption at rest and the statutory 5-year (1825-day) audit trail retention rule for payment traceability.
* **Output Evidence:** `psd2_article95_logging_evidence.json`

---

## 🛠️ Execution

To execute all PSD2 evaluations sequentially from the repository root:

```bash
export AWS_DEFAULT_REGION="eu-west-1"

python psd2/psd2_art97_sca_mfa_auditor.py
python psd2/psd2_art95_fraud_transaction_monitor.py
python psd2/psd2_art95_audit_trail_logging_auditor.py
