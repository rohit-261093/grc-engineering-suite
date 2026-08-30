# DORA Compliance-as-Code Module

This directory contains the Python-based continuous compliance engines designed specifically for the **EU Digital Operational Resilience Act (Regulation EU 2022/2554)**. 

Unlike generic GRC tools that only collect administrative PDFs or static vendor questionnaires, these engines programmatically inspect live cloud infrastructure, evaluate operational telemetry against Regulatory Technical Standards (RTS), and emit machine-readable evidence artifacts (`JSON`).

---

## 📑 Module Breakdown & Use Cases

### 1. `dora_art9_access_protection_auditor.py`
* **Regulatory Focus:** Article 9 (Protection and Prevention — Access Control & Network Isolation)
* **Engineering Action:** 
  * Audits AWS IAM to ensure Multi-Factor Authentication (MFA) is actively configured across all user accounts with console access.
  * Inspects EC2 Security Groups to verify that sensitive database ports (e.g., PostgreSQL `5432`, MySQL `3306`) and management interfaces (SSH `22`, RDP `3389`) are not publicly exposed to `0.0.0.0/0`.
* **Output Artifact:** `dora_article9_evidence.json`

---

### 2. `dora_art11_resilience_checker.py`
* **Regulatory Focus:** Article 11 (Response and Recovery Capabilities — High Availability & Failover)
* **Engineering Action:** 
  * Verifies active S3 Cross-Region Replication (CRR) from primary (`eu-west-1`) to secondary target regions (`eu-central-1`) to maintain continuous data mirroring.
  * Audits global Route53 DNS health checks to ensure multi-region failover endpoints meet quorum and routing availability standards.
* **Output Artifact:** `dora_article11_evidence.json`

---

### 3. `dora_art12_backup_auditor.py`
* **Regulatory Focus:** Article 12 (Backup Policies & Recovery Point Objective Validation)
* **Engineering Action:** 
  * Calculates time deltas on AWS Backup snapshot creation dates to enforce Recovery Point Objective (RPO) compliance (< 1 hour freshness target).
  * Validates AWS Backup Vault Lock configurations to confirm Write-Once-Read-Many (WORM) immutability, defending against unauthorized backup modification or ransomware deletion.
* **Output Artifact:** `dora_article12_evidence.json`

---

### 4. `dora_art18_incident_classification_engine.py`
* **Regulatory Focus:** Article 18 (ICT Incident Classification) & Article 19 (Regulatory Notification Timers)
* **Engineering Action:** 
  * Evaluates SIEM/alert payloads against DORA RTS impact criteria (critical service impact, >2 hours downtime, >10% client impact, data loss, geographical spread across EU states).
  * Automatically classifies incidents as **Major** and calculates strict UTC deadlines, initiating a 4-hour countdown timer for National Competent Authority (NCA) initial notifications.
* **Output Artifact:** `dora_article18_evidence.json`

---

### 5. `dora_art28_third_party_register_generator.py`
* **Regulatory Focus:** Article 28 & 30 (Register of Information for ICT Third-Party Services)
* **Engineering Action:** 
  * Ingests vendor metadata and isolates third-party providers supporting Critical or Important Functions (CIF).
  * Performs active TLS/SSL connection health checks on vendor domains.
  * Automatically compiles and exports a standardized Regulatory Technical Standards (RTS) JSON Register of Information ready for supervisory authority submission.
* **Output Artifact:** `dora_article28_vendor_register.json`

---

## 🛠️ Execution

To run all DORA evaluations sequentially from the repository root:

```bash
export AWS_DEFAULT_REGION="eu-west-1"

python dora/dora_art9_access_protection_auditor.py
python dora/dora_art11_resilience_checker.py
python dora/dora_art12_backup_auditor.py
python dora/dora_art18_incident_classification_engine.py
python dora/dora_art28_third_party_register_generator.py
