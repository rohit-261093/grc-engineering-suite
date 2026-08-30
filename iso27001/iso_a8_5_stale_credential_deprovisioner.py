"""
ISO/IEC 27001:2022 Control A.5.15 & A.8.5 Stale Credential Auditor
-------------------------------------------------------------------
Framework: ISO/IEC 27001:2022 Annex A
Controls: A.5.15 (Access Control) & A.8.5 (Secure Authentication Management)
Author: Rohit (GRC Engineering Suite)
"""

import json
import logging
from datetime import datetime, timezone, timedelta
import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ISO27001_A8_5_Auditor")


class IsoStaleCredentialAuditor:
    """Evaluates IAM user credentials for staleness (keys/passwords > 90 days old)

    to enforce continuous ISO 27001 access control compliance.
    """

    MAX_CREDENTIAL_AGE_DAYS = 90

    def __init__(self):
        self.iam_client = boto3.client("iam")
        self.audit_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "framework": "ISO/IEC 27001:2022",
            "controls_evaluated": ["A.5.15 Access Control", "A.8.5 Secure Authentication"],
            "max_allowed_age_days": self.MAX_CREDENTIAL_AGE_DAYS,
            "overall_status": "PASS",
            "evaluations": []
        }

    def audit_iam_stale_credentials(self) -> bool:
        """Inspects IAM access keys and password usage dates against the 90-day threshold."""
        logger.info("Starting ISO 27001 stale credential audit...")
        control_id = "ISO27001-A.8.5-STALE-CREDENTIALS"
        stale_credentials = []
        now = datetime.now(timezone.utc)

        try:
            paginator = self.iam_client.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]

                    # 1. Audit Access Keys Age
                    access_keys = self.iam_client.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
                    for key in access_keys:
                        if key["Status"] == "Active":
                            key_age = (now - key["CreateDate"]).days
                            if key_age > self.MAX_CREDENTIAL_AGE_DAYS:
                                stale_credentials.append(
                                    f"User '{username}' Access Key '{key['AccessKeyId']}' is {key_age} days old"
                                )

                    # 2. Audit Password / Last Login Age
                    password_last_used = user.get("PasswordLastUsed")
                    if password_last_used:
                        password_age = (now - password_last_used).days
                        if password_age > self.MAX_CREDENTIAL_AGE_DAYS:
                            stale_credentials.append(
                                f"User '{username}' console password inactive for {password_age} days"
                            )

            if not stale_credentials:
                self._record_result(
                    control_id=control_id,
                    status="PASS",
                    details=f"All active IAM credentials comply with the <{self.MAX_CREDENTIAL_AGE_DAYS}-day rotation policy."
                )
                return True
            else:
                msg = f"NON-COMPLIANCE: Stale credentials detected: {'; '.join(stale_credentials)}"
                self._record_result(control_id=control_id, status="FAIL", details=msg)
                return False

        except ClientError as e:
            msg = f"AWS IAM API Error auditing stale credentials: {e.response['Error']['Code']}"
            logger.error(msg)
            self._record_result(control_id=control_id, status="FAIL", details=msg)
            return False

    def _record_result(self, control_id: str, status: str, details: str):
        if status == "FAIL":
            self.audit_results["overall_status"] = "FAIL"

        self.audit_results["evaluations"].append({
            "control_id": control_id,
            "status": status,
            "details": details
        })

    def export_report(self, file_path: str = "iso27001_a8_5_evidence.json"):
        with open(file_path, "w") as f:
            json.dump(self.audit_results, f, indent=2)
        logger.info(f"ISO 27001 audit report exported to '{file_path}'")


if __name__ == "__main__":
    auditor = IsoStaleCredentialAuditor()
    auditor.audit_iam_stale_credentials()
    auditor.export_report()
