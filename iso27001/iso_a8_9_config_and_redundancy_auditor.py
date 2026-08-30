"""
ISO/IEC 27001:2022 Control A.8.9 Configuration Management & A.8.14 Redundancy Auditor
-------------------------------------------------------------------------------------
Framework: ISO/IEC 27001:2022 Annex A
Controls: Control A.8.9 (Configuration Management) & Control A.8.14 (Redundancy)
Author: Rohit (GRC Engineering Suite)
"""

import json
import logging
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ISO27001_A8_9_Auditor")


class IsoConfigAndRedundancyAuditor:
    """Evaluates AWS EC2 instances and EBS volumes for baseline configuration encryption (DLP/Config)

    and Multi-AZ redundancy under ISO 27001 Control A.8.9 and A.8.14.
    """

    def __init__(self, region_name: str = "eu-west-1"):
        self.region_name = region_name
        self.ec2_client = boto3.client("ec2", region_name=self.region_name)

        self.audit_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "framework": "ISO/IEC 27001:2022",
            "controls_evaluated": ["A.8.9 Configuration Management", "A.8.14 Redundancy"],
            "region": self.region_name,
            "overall_status": "PASS",
            "evaluations": []
        }

    def audit_storage_encryption_and_ha(self) -> bool:
        """Audits account-level EBS default encryption settings and verifies instance multi-AZ distribution."""
        logger.info(f"Auditing AWS EC2/EBS infrastructure in {self.region_name} for ISO 27001 A.8.9 and A.8.14...")

        control_config = "ISO27001-A.8.9-EBS-DEFAULT-ENCRYPTION"
        control_redundancy = "ISO27001-A.8.14-MULTI-AZ-REDUNDANCY"

        is_config_compliant = False
        is_redundancy_compliant = False

        # 1. Evaluate Control A.8.9 (Configuration Management: Mandatory Account-Level EBS Encryption)
        try:
            ebs_encryption = self.ec2_client.get_ebs_encryption_by_default()
            is_enabled = ebs_encryption.get("EbsEncryptionByDefault", False)

            if is_enabled:
                self._record_result(
                    control_id=control_config,
                    status="PASS",
                    details=f"Secure Baseline Active: Account-level EBS default encryption is ENABLED in region {self.region_name}."
                )
                is_config_compliant = True
            else:
                self._record_result(
                    control_id=control_config,
                    status="FAIL",
                    details=f"CONFIG DRIFT: Account-level EBS default encryption is DISABLED in region {self.region_name}."
                )

        except ClientError as e:
            msg = f"AWS EC2 API Error checking EBS default encryption: {e.response['Error']['Code']}"
            logger.error(msg)
            self._record_result(control_id=control_config, status="FAIL", details=msg)

        # 2. Evaluate Control A.8.14 (Redundancy: Compute Instance Multi-AZ Distribution)
        try:
            reservations = self.ec2_client.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
            ).get("Reservations", [])

            active_zones = set()
            total_instances = 0

            for res in reservations:
                for inst in res.get("Instances", []):
                    total_instances += 1
                    az = inst.get("Placement", {}).get("AvailabilityZone")
                    if az:
                        active_zones.add(az)

            if total_instances == 0:
                self._record_result(
                    control_id=control_redundancy,
                    status="PASS",
                    details="No active EC2 instances found running in target region."
                )
                is_redundancy_compliant = True
            elif len(active_zones) >= 2:
                self._record_result(
                    control_id=control_redundancy,
                    status="PASS",
                    details=f"Redundancy Verified: {total_instances} running instance(s) distributed across {len(active_zones)} Availability Zones ({', '.join(active_zones)})."
                )
                is_redundancy_compliant = True
            else:
                self._record_result(
                    control_id=control_redundancy,
                    status="FAIL",
                    details=f"SINGLE POINT OF FAILURE: All {total_instances} instance(s) reside in a single AZ ({', '.join(active_zones)}). Multi-AZ redundancy required."
                )

        except ClientError as e:
            msg = f"AWS EC2 API Error auditing instance availability zones: {e.response['Error']['Code']}"
            logger.error(msg)
            self._record_result(control_id=control_redundancy, status="FAIL", details=msg)

        return (is_config_compliant and is_redundancy_compliant)

    def _record_result(self, control_id: str, status: str, details: str):
        if status == "FAIL":
            self.audit_results["overall_status"] = "FAIL"

        self.audit_results["evaluations"].append({
            "control_id": control_id,
            "status": status,
            "details": details
        })

    def export_report(self, file_path: str = "iso27001_a8_9_evidence.json"):
        with open(file_path, "w") as f:
            json.dump(self.audit_results, f, indent=2)
        logger.info(f"ISO 27001 Configuration & Redundancy report exported to '{file_path}'")


if __name__ == "__main__":
    auditor = IsoConfigAndRedundancyAuditor(region_name="eu-west-1")
    auditor.audit_storage_encryption_and_ha()
    auditor.export_report()
