"""
EU AI Act Article 12 Automated Record-Keeping & Telemetry Auditor
------------------------------------------------------------------
Framework: EU AI Act (Regulation EU 2024/1689)
Control: Article 12 - Record-Keeping & Lifespan Event Logging
Author: Rohit (GRC Engineering Suite)
"""

import json
import logging
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("EU_AI_Act_Art12_Auditor")


class EuAiActTelemetryAuditor:
    """Audits AWS CloudWatch Log Groups bound to AI inference workloads to ensure

    Article 12 compliance (active logging, KMS encryption, and 6-month minimum retention).
    """

    MIN_AI_LOG_RETENTION_DAYS = 180  # Article 12 statutory 6-month retention baseline

    def __init__(self, region_name: str = "eu-west-1"):
        self.region_name = region_name
        self.logs_client = boto3.client("logs", region_name=self.region_name)

        self.audit_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "framework": "EU AI Act (Regulation EU 2024/1689)",
            "article": "Article 12 - Record-Keeping & Automated Logging",
            "region": self.region_name,
            "overall_status": "PASS",
            "evaluations": []
        }

    def audit_inference_logging_and_retention(self, log_group_prefix: str = "/aws/sagemaker/InferenceEndpoints") -> bool:
        """Inspects CloudWatch Log Groups matching the AI endpoint prefix for KMS key encryption and retention rules."""
        logger.info(f"Auditing CloudWatch Log Groups matching '{log_group_prefix}' in {self.region_name}...")

        control_logging = "EU-AI-ACT-ART12-INFERENCE-LOGGING"
        control_retention = "EU-AI-ACT-ART12-LOG-RETENTION"
        control_encryption = "EU-AI-ACT-ART12-LOG-KMS-ENCRYPTION"

        non_compliant_retention = []
        unencrypted_log_groups = []
        total_discovered = 0

        try:
            paginator = self.logs_client.get_paginator("describe_log_groups")
            for page in paginator.paginate(logGroupNamePrefix=log_group_prefix):
                for group in page.get("logGroups", []):
                    total_discovered += 1
                    name = group["logGroupName"]
                    retention = group.get("retentionInDays")
                    kms_key = group.get("kmsKeyId")

                    # 1. Audit Retention Period (Article 12 requires minimum 180-day retention)
                    if retention is None or retention < self.MIN_AI_LOG_RETENTION_DAYS:
                        non_compliant_retention.append(f"{name} ({retention if retention else 'Never Expire'} days)")

                    # 2. Audit Storage Encryption at Rest
                    if not kms_key:
                        unencrypted_log_groups.append(name)

            # Evaluate Active Logging Presence
            if total_discovered > 0:
                self._record_result(
                    control_id=control_logging,
                    status="PASS",
                    details=f"Active Telemetry Discovered: Found {total_discovered} CloudWatch log group(s) capturing AI inference events."
                )
            else:
                self._record_result(
                    control_id=control_logging,
                    status="FAIL",
                    details=f"ARTICLE 12 BREACH: No log groups discovered matching prefix '{log_group_prefix}'. Automated logging inactive."
                )

            # Evaluate Retention Compliance
            if not non_compliant_retention and total_discovered > 0:
                self._record_result(
                    control_id=control_retention,
                    status="PASS",
                    details=f"Retention Compliant: All inference log groups enforce the statutory {self.MIN_AI_LOG_RETENTION_DAYS}-day (6-month) audit trail requirement."
                )
            elif total_discovered > 0:
                msg = f"RETENTION BREACH: Log groups failing 180-day retention threshold: {', '.join(non_compliant_retention)}"
                self._record_result(control_id=control_retention, status="FAIL", details=msg)

            # Evaluate KMS Encryption Compliance
            if not unencrypted_log_groups and total_discovered > 0:
                self._record_result(
                    control_id=control_encryption,
                    status="PASS",
                    details="Encryption Compliant: All AI inference audit logs are encrypted at rest with AWS KMS."
                )
            elif total_discovered > 0:
                msg = f"TAMPER RISK: Unencrypted AI inference log groups detected: {', '.join(unencrypted_log_groups)}"
                self._record_result(control_id=control_encryption, status="FAIL", details=msg)

            return (total_discovered > 0 and len(non_compliant_retention) == 0 and len(unencrypted_log_groups) == 0)

        except ClientError as e:
            msg = f"AWS CloudWatch Logs API Error: {e.response['Error']['Code']}"
            logger.error(msg)
            self._record_result(control_id=control_logging, status="FAIL", details=msg)
            return False

    def _record_result(self, control_id: str, status: str, details: str):
        if status == "FAIL":
            self.audit_results["overall_status"] = "FAIL"

        self.audit_results["evaluations"].append({
            "control_id": control_id,
            "status": status,
            "details": details
        })

    def export_report(self, file_path: str = "eu_ai_act_article12_evidence.json"):
        with open(file_path, "w") as f:
            json.dump(self.audit_results, f, indent=2)
        logger.info(f"EU AI Act Article 12 evidence exported to '{file_path}'")


if __name__ == "__main__":
    auditor = EuAiActTelemetryAuditor(region_name="eu-west-1")
    auditor.audit_inference_logging_and_retention(log_group_prefix="/aws/sagemaker/InferenceEndpoints")
    auditor.export_report()
