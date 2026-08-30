"""
ISO/IEC 27001:2022 Control A.8.24 Cryptographic Key Rotation & Lifecycle Auditor
----------------------------------------------------------------------------------
Framework: ISO/IEC 27001:2022 Annex A
Control: Control A.8.24 (Use of Cryptography - Key Lifecycle & Rotation)
Author: Rohit (GRC Engineering Suite)
"""

import json
import logging
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ISO27001_A8_24_Auditor")


class IsoKmsKeyAuditor:
    """Evaluates AWS KMS Customer Managed Keys (CMKs) for automatic annual rotation

    and deletion protection compliance under ISO 27001 Control A.8.24.
    """

    MIN_DELETION_WINDOW_DAYS = 7  # Prevents instant malicious key wiping

    def __init__(self, region_name: str = "eu-west-1"):
        self.region_name = region_name
        self.kms_client = boto3.client("kms", region_name=self.region_name)
        
        self.audit_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "framework": "ISO/IEC 27001:2022",
            "control": "A.8.24 Use of Cryptography",
            "region": self.region_name,
            "overall_status": "PASS",
            "evaluations": []
        }

    def audit_kms_key_lifecycle(self) -> bool:
        """Audits all Customer Managed Keys (CMKs) in the region for rotation status and deletion protections."""
        logger.info(f"Auditing AWS KMS keys in {self.region_name} for ISO 27001 A.8.24 compliance...")
        
        control_id_rotation = "ISO27001-A.8.24-KEY-ROTATION"
        control_id_deletion = "ISO27001-A.8.24-DELETION-PROTECTION"
        
        unrotated_keys = []
        unsafe_deletion_keys = []

        try:
            paginator = self.kms_client.get_paginator("list_keys")
            for page in paginator.paginate():
                for key in page.get("Keys", []):
                    key_id = key["KeyId"]

                    try:
                        # 1. Describe key metadata to filter out AWS Managed Keys (e.g., aws/s3)
                        metadata = self.kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
                        
                        # Only evaluate enabled Customer Managed Keys (CMKs)
                        if metadata["KeyManager"] == "CUSTOMER" and metadata["KeyState"] == "Enabled":
                            
                            # Check Key Rotation Status
                            rotation_status = self.kms_client.get_key_rotation_status(KeyId=key_id)
                            if not rotation_status.get("KeyRotationEnabled", False):
                                unrotated_keys.append(key_id)

                            # Check Deletion Protection Window
                            deletion_window = metadata.get("PendingDeletionWindowInDays")
                            if deletion_window and deletion_window < self.MIN_DELETION_WINDOW_DAYS:
                                unsafe_deletion_keys.append(f"{key_id} ({deletion_window} days)")

                    except ClientError as e:
                        logger.warning(f"Skipping key '{key_id}': {e.response['Error']['Code']}")
                        continue

            # Evaluate Rotation Compliance
            if not unrotated_keys:
                self._record_result(
                    control_id=control_id_rotation,
                    status="PASS",
                    details="Automatic annual key rotation enabled on all active Customer Managed Keys (CMKs)."
                )
            else:
                msg = f"NON-COMPLIANCE: Automatic rotation DISABLED on keys: {', '.join(unrotated_keys)}"
                self._record_result(control_id=control_id_rotation, status="FAIL", details=msg)

            # Evaluate Deletion Safeguard Compliance
            if not unsafe_deletion_keys:
                self._record_result(
                    control_id=control_id_deletion,
                    status="PASS",
                    details=f"All KMS keys adhere to minimum {self.MIN_DELETION_WINDOW_DAYS}-day pending deletion safety buffer."
                )
            else:
                msg = f"RISK: Keys with insufficient deletion window (<{self.MIN_DELETION_WINDOW_DAYS} days): {', '.join(unsafe_deletion_keys)}"
                self._record_result(control_id=control_id_deletion, status="FAIL", details=msg)

            return (len(unrotated_keys) == 0 and len(unsafe_deletion_keys) == 0)

        except ClientError as e:
            msg = f"AWS KMS API Error auditing keys: {e.response['Error']['Code']}"
            logger.error(msg)
            self._record_result(control_id=control_id_rotation, status="FAIL", details=msg)
            return False

    def _record_result(self, control_id: str, status: str, details: str):
        if status == "FAIL":
            self.audit_results["overall_status"] = "FAIL"

        self.audit_results["evaluations"].append({
            "control_id": control_id,
            "status": status,
            "details": details
        })

    def export_report(self, file_path: str = "iso27001_a8_24_evidence.json"):
        with open(file_path, "w") as f:
            json.dump(self.audit_results, f, indent=2)
        logger.info(f"ISO 27001 cryptography audit report exported to '{file_path}'")


if __name__ == "__main__":
    auditor = IsoKmsKeyAuditor(region_name="eu-west-1")
    auditor.audit_kms_key_lifecycle()
    auditor.export_report()
