"""
PSD2 Article 95 Payment Audit Trail & Log Retention Auditor
---------------------------------------------------------------------
Framework: EU Payment Services Directive 2 (Directive EU 2015/2366)
Control: Article 95 - Security Measures (Audit Trails & Data Retention)
Author: Rohit (GRC Engineering Suite)
"""

import json
import logging
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("PSD2_Art95_LoggingAuditor")


class Psd2LoggingAuditor:
    """Evaluates AWS CloudWatch Log Groups bound to payment APIs to ensure 5-year log retention

    and KMS encryption under PSD2 Article 95.
    """

    MIN_PSD2_RETENTION_DAYS = 1825  # Statutory 5-Year PSD2 Audit Trail Requirement

    def __init__(self, region_name: str = "eu-west-1"):
        self.region_name = region_name
        self.logs_client = boto3.client("logs", region_name=self.region_name)

        self.audit_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "framework": "EU PSD2 (Directive 2015/2366)",
            "article": "Article 95 - Audit Trail Integrity & Retention",
            "region": self.region_name,
            "overall_status": "PASS",
            "evaluations": []
        }

    def audit_payment_log_retention_and_encryption(self, log_group_prefix: str = "/aws/vendedlogs/payment") -> bool:
        """Audits target CloudWatch Log Groups for KMS encryption and 5-year retention compliance."""
        logger.info(f"Auditing CloudWatch Log Groups matching '{log_group_prefix}' in {self.region_name}...")
        
        control_retention = "PSD2-ART95-5YEAR-RETENTION"
        control_encryption = "PSD2-ART95-LOG-ENCRYPTION"

        non_compliant_retention = []
        unencrypted_log_groups = []

        try:
            paginator = self.logs_client.get_paginator("describe_log_groups")
            for page in paginator.paginate(logGroupNamePrefix=log_group_prefix):
                for group in page.get("logGroups", []):
                    name = group["logGroupName"]
                    retention = group.get("retentionInDays")
                    kms_key = group.get("kmsKeyId")

                    # 1. Audit Retention Period (PSD2 requires 5 years / 1825 days minimum)
                    if retention is None or retention < self.MIN_PSD2_RETENTION_DAYS:
                        non_compliant_retention.append(f"{name} ({retention if retention else 'Never Expire'} days)")

                    # 2. Audit Storage Encryption at Rest
                    if not kms_key:
                        unencrypted_log_groups.append(name)

            # Evaluate Retention Compliance
            if not non_compliant_retention:
                self._record_result(
                    control_id=control_retention,
                    status="PASS",
                    details=f"Retention Active: All payment log groups enforce the statutory {self.MIN_PSD2_RETENTION_DAYS}-day (5-year) audit trail requirement."
                )
            else:
                msg = f"NON-COMPLIANCE: Payment log groups failing 5-year retention threshold: {', '.join(non_compliant_retention)}"
                self._record_result(control_id=control_retention, status="FAIL", details=msg)

            # Evaluate Encryption Compliance
            if not unencrypted_log_groups:
                self._record_result(
                    control_id=control_encryption,
                    status="PASS",
                    details="Encryption Active: All payment audit log groups are encrypted at rest with AWS KMS."
                )
            else:
                msg = f"DATA PROTECTION RISK: Unencrypted payment log groups detected: {', '.join(unencrypted_log_groups)}"
                self._record_result(control_id=control_encryption, status="FAIL", details=msg)

            return (len(non_compliant_retention) == 0 and len(unencrypted_log_groups) == 0)

        except ClientError as e:
            msg = f"AWS CloudWatch Logs API Error: {e.response['Error']['Code']}"
            logger.error(msg)
            self._record_result(control_id=control_retention, status="FAIL", details=msg)
            return False

    def _record_result(self, control_id: str, status: str, details: str):
        if status == "FAIL":
            self.audit_results["overall_status"] = "FAIL"

        self.audit_results["evaluations"].append({
            "control_id": control_id,
            "status": status,
            "details": details
        })

    def export_report(self, file_path: str = "psd2_article95_logging_evidence.json"):
        with open(file_path, "w") as f:
            json.dump(self.audit_results, f, indent=2)
        logger.info(f"PSD2 Audit Trail evidence exported to '{file_path}'")


if __name__ == "__main__":
    auditor = Psd2LoggingAuditor(region_name="eu-west-1")
    auditor.audit_payment_log_retention_and_encryption(log_group_prefix="/aws/vendedlogs/payment")
    auditor.export_report()
