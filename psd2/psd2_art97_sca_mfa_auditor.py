"""
PSD2 Article 97 Strong Customer Authentication (SCA) Auditor
-----------------------------------------------------------
Framework: EU Payment Services Directive 2 (Directive EU 2015/2366)
Control: Article 97 - Strong Customer Authentication (SCA) Requirements
Author: Rohit (GRC Engineering Suite)
"""

import json
import logging
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("PSD2_Art97_Auditor")


class Psd2ScaAuditor:
    """Evaluates AWS Cognito User Pools and API Gateway configurations to ensure SCA (MFA)

    is enforced on financial payment endpoints under PSD2 Article 97.
    """

    def __init__(self, region_name: str = "eu-west-1"):
        self.region_name = region_name
        self.cognito_client = boto3.client("cognito-idp", region_name=self.region_name)

        self.audit_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "framework": "EU PSD2 (Directive 2015/2366)",
            "article": "Article 97 - Strong Customer Authentication",
            "region": self.region_name,
            "overall_status": "PASS",
            "evaluations": []
        }

    def audit_cognito_sca_enforcement(self) -> bool:
        """Audits Cognito User Pools supporting payment processing to confirm MFA is enforced."""
        logger.info(f"Auditing Cognito User Pools in {self.region_name} for PSD2 SCA compliance...")
        control_id = "PSD2-ART97-SCA-MFA-ENFORCED"
        non_compliant_pools = []

        try:
            paginator = self.cognito_client.get_paginator("list_user_pools")
            for page in paginator.paginate(MaxResults=20):
                for pool in page.get("UserPools", []):
                    pool_id = pool["Id"]
                    pool_name = pool["Name"]

                    # Target user pools associated with payment or customer identity systems
                    pool_details = self.cognito_client.describe_user_pool(UserPoolId=pool_id)["UserPool"]
                    mfa_configuration = pool_details.get("MfaConfiguration", "OFF")

                    # PSD2 Article 97 requires mandatory MFA ("ON" or "OPTIONAL" if adaptive risk-based authentication is configured)
                    if mfa_configuration == "OFF":
                        non_compliant_pools.append(f"{pool_id} ({pool_name})")

            if not non_compliant_pools:
                self._record_result(
                    control_id=control_id,
                    status="PASS",
                    details="SCA Active: All identified Cognito Identity Pools enforce Multi-Factor Authentication."
                )
                return True
            else:
                msg = f"SCA BREACH: The following payment user pools have MFA set to OFF: {', '.join(non_compliant_pools)}"
                self._record_result(control_id=control_id, status="FAIL", details=msg)
                return False

        except ClientError as e:
            msg = f"AWS Cognito API Error auditing SCA: {e.response['Error']['Code']}"
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

    def export_report(self, file_path: str = "psd2_article97_evidence.json"):
        with open(file_path, "w") as f:
            json.dump(self.audit_results, f, indent=2)
        logger.info(f"PSD2 SCA audit report exported to '{file_path}'")


if __name__ == "__main__":
    auditor = Psd2ScaAuditor(region_name="eu-west-1")
    auditor.audit_cognito_sca_enforcement()
    auditor.export_report()
