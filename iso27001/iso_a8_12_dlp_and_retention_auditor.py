"""
ISO/IEC 27001:2022 Control A.8.12 Data Leakage Prevention & A.8.10 Information Deletion Auditor
------------------------------------------------------------------------------------------------
Framework: ISO/IEC 27001:2022 Annex A
Controls: Control A.8.12 (Data Leakage Prevention) & Control A.8.10 (Information Deletion)
Author: Rohit (GRC Engineering Suite)
"""

import json
import logging
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ISO27001_A8_12_Auditor")


class IsoDataProtectionAuditor:
    """Evaluates AWS S3 storage for public exposure leakage risks (DLP)

    and lifecycle data deletion policies under ISO 27001 Control A.8.12 and A.8.10.
    """

    def __init__(self, region_name: str = "eu-west-1"):
        self.region_name = region_name
        self.s3_client = boto3.client("s3", region_name=self.region_name)
        
        self.audit_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "framework": "ISO/IEC 27001:2022",
            "controls_evaluated": ["A.8.12 Data Leakage Prevention", "A.8.10 Information Deletion"],
            "region": self.region_name,
            "overall_status": "PASS",
            "evaluations": []
        }

    def audit_s3_dlp_and_lifecycle(self, bucket_name: str) -> bool:
        """Audits an S3 bucket for Public Access Block settings (DLP) and active object lifecycle expiration rules (Deletion)."""
        logger.info(f"Auditing S3 Bucket '{bucket_name}' for ISO 27001 DLP and Data Retention controls...")
        
        control_dlp = "ISO27001-A.8.12-DLP-PUBLIC-BLOCK"
        control_deletion = "ISO27001-A.8.10-LIFECYCLE-DELETION"
        
        is_dlp_compliant = False
        is_deletion_compliant = False

        # 1. Evaluate Control A.8.12 (Data Leakage Prevention via Public Access Block)
        try:
            pab = self.s3_client.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
            
            # Enforce strict 4-point Public Access Block configuration
            if (pab.get("BlockPublicAcls", False) and 
                pab.get("IgnorePublicAcls", False) and 
                pab.get("BlockPublicPolicy", False) and 
                pab.get("RestrictPublicBuckets", False)):
                
                self._record_result(
                    control_id=control_dlp,
                    status="PASS",
                    details=f"DLP Guard Active: S3 bucket '{bucket_name}' has all 4 Public Access Block rules enabled."
                )
                is_dlp_compliant = True
            else:
                self._record_result(
                    control_id=control_dlp,
                    status="FAIL",
                    details=f"DLP LEAK RISK: S3 bucket '{bucket_name}' is missing one or more Public Access Block rules."
                )

        except ClientError as e:
            msg = f"AWS API Error checking Public Access Block on '{bucket_name}': {e.response['Error']['Code']}"
            logger.error(msg)
            self._record_result(control_id=control_dlp, status="FAIL", details=msg)

        # 2. Evaluate Control A.8.10 (Information Deletion via Lifecycle Configuration)
        try:
            lifecycle = self.s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            rules = lifecycle.get("Rules", [])
            
            active_expiration_rules = [r for r in rules if r.get("Status") == "Enabled" and "Expiration" in r]
            
            if active_expiration_rules:
                self._record_result(
                    control_id=control_deletion,
                    status="PASS",
                    details=f"Information Deletion Active: Found {len(active_expiration_rules)} active object expiration rule(s) in bucket '{bucket_name}'."
                )
                is_deletion_compliant = True
            else:
                self._record_result(
                    control_id=control_deletion,
                    status="FAIL",
                    details=f"NON-COMPLIANCE: No active object expiration/lifecycle rules found for bucket '{bucket_name}'."
                )

        except ClientError as e:
            err_code = e.response["Error"]["Code"]
            if err_code == "NoSuchLifecycleConfiguration":
                msg = f"NON-COMPLIANCE: Bucket '{bucket_name}' has no lifecycle rules configured for automatic information deletion."
            else:
                msg = f"AWS API Error checking Lifecycle rules on '{bucket_name}': {err_code}"
            
            logger.error(msg)
            self._record_result(control_id=control_deletion, status="FAIL", details=msg)

        return (is_dlp_compliant and is_deletion_compliant)

    def _record_result(self, control_id: str, status: str, details: str):
        if status == "FAIL":
            self.audit_results["overall_status"] = "FAIL"

        self.audit_results["evaluations"].append({
            "control_id": control_id,
            "status": status,
            "details": details
        })

    def export_report(self, file_path: str = "iso27001_a8_12_evidence.json"):
        with open(file_path, "w") as f:
            json.dump(self.audit_results, f, indent=2)
        logger.info(f"ISO 27001 DLP & Retention audit report exported to '{file_path}'")


if __name__ == "__main__":
    TARGET_DATA_BUCKET = "spacexai-sensitive-pii-storage"
    
    auditor = IsoDataProtectionAuditor(region_name="eu-west-1")
    auditor.audit_s3_dlp_and_lifecycle(bucket_name=TARGET_DATA_BUCKET)
    auditor.export_report()
