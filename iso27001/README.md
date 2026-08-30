# ISO/IEC 27001:2022 Compliance-as-Code Module

This directory contains automated **Compliance-as-Code** evaluation engines targeting **ISO/IEC 27001:2022 Annex A** controls. 

Unlike traditional GRC platforms that rely on static administrative questionnaires or point-in-time screenshots, these Python engines programmatically inspect live cloud infrastructure, evaluate identity lifecycle states, and generate machine-readable, timestamped audit evidence (`JSON`).

---

## 🗂️ Module Breakdown & Control Scope

### 1. `iso_a8_5_stale_credential_deprovisioner.py`
* **ISO 27001 Control:** Control A.5.15 (Access Control) & Control A.8.5 (Secure Authentication Management)
* **Engineering Action:** Calculates time deltas on active IAM user access keys and password last-login dates against a strict 90-day threshold to identify dormant identities and unrotated access keys.
* **Output Evidence:** `iso27001_a8_5_evidence.json`

---

### 2. `iso_a8_24_kms_rotation_auditor.py`
* **ISO 27001 Control:** Control A.8.24 (Use of Cryptography — Key Lifecycle Management)
* **Engineering Action:** Programmatically verifies automatic annual rotation configuration on Customer Managed Keys (CMKs) in AWS KMS and enforces a minimum 7-day pending deletion safety window to prevent catastrophic data destruction.
* **Output Evidence:** `iso27001_a8_24_evidence.json`

---

### 3. `iso_a8_12_dlp_and_retention_auditor.py`
* **ISO 27001 Control:** Control A.8.12 (Data Leakage Prevention) & Control A.8.10 (Information Deletion)
* **Engineering Action:** Inspects cloud storage bucket configurations to confirm strict 4-point Public Access Block enforcement (preventing public data leaks) and validates active S3 object lifecycle expiration rules (enforcing compliant data purging).
* **Output Evidence:** `iso27001_a8_12_evidence.json`

---

### 4. `iso_a8_9_config_and_redundancy_auditor.py`
* **ISO 27001 Control:** Control A.8.9 (Configuration Management) & Control A.8.14 (Redundancy of Facilities)
* **Engineering Action:** Enforces mandatory account-level default encryption on block storage (AWS EBS) to prevent unencrypted volume creation and audits active compute topologies to verify multi-AZ distribution.
* **Output Evidence:** `iso27001_a8_9_evidence.json`

---

### 5. `iso_a8_16_monitoring_and_audit_logging_auditor.py`
* **ISO 27001 Control:** Control A.8.16 (Monitoring Activities) & Control A.5.24 (Incident Management Planning)
* **Engineering Action:** Audits AWS CloudTrail telemetry capture to ensure multi-region logging is active and verifies SHA-256 log file integrity validation to detect log tampering during security incident reviews.
* **Output Evidence:** `iso27001_a8_16_evidence.json`

---

## 🛠️ Execution

To execute all ISO 27001 evaluations sequentially from the repository root:

```bash
export AWS_DEFAULT_REGION="eu-west-1"

python iso27001/iso_a8_5_stale_credential_deprovisioner.py
python iso27001/iso_a8_24_kms_rotation_auditor.py
python iso27001/iso_a8_12_dlp_and_retention_auditor.py
python iso27001/iso_a8_9_config_and_redundancy_auditor.py
python iso27001/iso_a8_16_monitoring_and_audit_logging_auditor.py
