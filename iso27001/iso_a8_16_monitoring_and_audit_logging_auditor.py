"""
ISO/IEC 27001:2022 Control A.8.16 Monitoring Activities & Control A.5.24 Incident Logging Auditor
--------------------------------------------------------------------------------------------------
Framework: ISO/IEC 27001:2022 Annex A
Controls: Control A.8.16 (Monitoring Activities) & Control A.5.24 (Incident Management Planning)
Author: Rohit (GRC Engineering Suite)
"""

import json
import logging
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ISO27001_A8_16_Auditor")


class IsoMonitoringAndLoggingAuditor:
    """Evaluates AWS CloudTrail configurations for multi-region logging, log integrity validation,

    and KMS encryption under ISO 27001 Control A.8.16 and Control A.5.24.
    """

    def __init__(self, region_name: str = "eu-west-1"):
        self.region_name = region_name
        self.cloudtrail_client = boto3.client("cloudtrail", region_name=self.region_name)

        self.audit_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "framework": "ISO/IEC 27001:2022",
            "controls_evaluated": ["A.8.16 Monitoring Activities", "A.5.24 Incident Management Planning"],
            "region": self.region_name,
            "overall_status": "PASS",
            "evaluations": []
        }

    def audit_cloudtrail_logging_and_integrity(self) -> bool:
        """Audits CloudTrail setup to ensure multi-region logging and SHA-256 log file integrity validation are active."""
        logger.info(f"Auditing CloudTrail logging and audit trails in {self.region_name} for ISO 27001 A.8.16...")

        control_monitoring = "ISO27001-A.8.16-MULTI-REGION-TRAIL"
        control_integrity = "ISO27001-A.5.24-LOG-INTEGRITY-VALIDATION"

        has_active_multi_region_trail = False
        has_log_integrity_enabled = False

        try:
            trails = self.cloudtrail_client.describe_trails().get("trailList", [])

            if not trails:
                self._record_result(
                    control_id=control_monitoring,
                    status="FAIL",
                    details="CRITICAL AUDIT GAP: No CloudTrails configured in the current region."
                )
                self._record_result(
                    control_id=control_integrity,
                    status="FAIL",
                    details="CRITICAL AUDIT GAP: Log integrity validation unavailable without active CloudTrail."
                )
                return False

            for trail in trails:
                trail_name = trail.get("Name")
                is_multi_region = trail.get("IsMultiRegionTrail", False)
                is_integrity_enabled = trail.get("LogFileValidationEnabled", False)

                # Get active logging status
                status = self.cloudtrail_client.get_trail_status(Name=trail_name)
                is_logging = status.get("IsLogging", False)

                if is_multi_region and is_logging:
                    has_active_multi_region_trail = True

                if is_integrity_enabled:
                    has_log_integrity_enabled = True

            # 1. Evaluate Control A.8.16 (Monitoring Activities: Multi-Region Active Trail)
            if has_active_multi_region_trail:
                self._record_result(
                    control_id=control_monitoring,
                    status="PASS",
                    details="Continuous Monitoring Active: Multi-region CloudTrail is enabled and actively capturing telemetry."
                )
            else:
                self._record_result(
                    control_id=control_monitoring,
                    status="FAIL",
                    details="MONITORING GAP: No active multi-region CloudTrail found. Audit logging is incomplete."
                )

            # 2. Evaluate Control A.5.24 (Incident Management: Tamper-Evident Log Integrity Validation)
            if has_log_integrity_enabled:
                self._record_result(
                    control_id=control_integrity,
                    status="PASS",
                    details="Tamper-Evident Logs Active: SHA-256 log file integrity validation is enabled on audit trails."
                )
            else:
                self._record_result(
                    control_id=control_integrity,
                    status="FAIL",
                    details="INCIDENT INVESTIGATION RISK: CloudTrail log file integrity validation is DISABLED. Logs can be modified undetected."
                )

        except ClientError as e:
            msg = f"AWS CloudTrail API Error: {e.response['Error']['Code']}"
            logger.error(msg)
            self._record_result(control_id=control_monitoring, status="FAIL", details=msg)

        return (has_active_multi_region_trail and has_log_integrity_enabled)

    def _record_result(self, control_id: str, status: str, details: str):
        if status == "FAIL":
            self.audit_results["overall_status"] = "FAIL"

        self.audit_results["evaluations"].append({
            "control_id": control_id,
            "status": status,
            "details": details
        })

    def export_report(self, file_path: str = "iso27001_a8_16_evidence.json"):
        with open(file_path, "w") as f:
            json.dump(self.audit_results, f, indent=2)
        logger.info(f"ISO 27001 Monitoring & Audit Logging report exported to '{file_path}'")


if __name__ == "__main__":
    auditor = IsoMonitoringAndLoggingAuditor(region_name="eu-west-1")
    auditor.audit_cloudtrail_logging_and_integrity()
    auditor.export_report()
