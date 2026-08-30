"""
DORA Article 9 ICT Protection & Access Control Auditor
-----------------------------------------------------------
Framework: EU Digital Operational Resilience Act (Regulation EU 2022/2554)
Control: Article 9 - Protection and Prevention (Access Control & Network Isolation)
Author: Rohit (GRC Engineering Suite)
"""

import json
import logging
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("DORA_Art9_Auditor")


class DoraAccessProtectionAuditor:
    """Evaluates IAM identity security and VPC network security group exposure for DORA Article 9 compliance."""

    # High-risk management and database ports that should NEVER be open to 0.0.0.0/0
    HIGH_RISK_PORTS = {
        22: "SSH",
        3389: "RDP",
        5432: "PostgreSQL",
        3306: "MySQL/MariaDB",
        27017: "MongoDB",
        6379: "Redis",
        1433: "MSSQL"
    }

    def __init__(self, region_name: str = "eu-west-1"):
        self.region_name = region_name
        self.iam_client = boto3.client("iam")
        self.ec2_client = boto3.client("ec2", region_name=self.region_name)

        self.audit_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "framework": "EU DORA (Regulation 2022/2554)",
            "article": "Article 9 - Protection and Prevention",
            "region": self.region_name,
            "overall_status": "PASS",
            "evaluations": []
        }

    def verify_iam_mfa_enforcement(0) -> bool:
        """Audits IAM users to ensure Multi-Factor Authentication (MFA) is active on all console accounts."""
        logger.info("Auditing IAM users for MFA enforcement...")
        control_id = "DORA-ART9-MFA-ENFORCED"
        unprotected_users = []

        try:
            paginator = self.iam_client.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]
                    
                    # Check if user has a console password/login profile
                    try:
                        self.iam_client.get_login_profile(UserName=username)
                        has_console_access = True
                    except ClientError as e:
                        if e.response["Error"]["Code"] == "NoSuchEntity":
                            has_console_access = False
                        else:
                            raise e

                    if has_console_access:
                        mfa_devices = self.iam_client.list_mfa_devices(UserName=username).get("MFADevices", [])
                        if not mfa_devices:
                            unprotected_users.append(username)

            if not unprotected_users:
                self._record_result(
                    control_id=control_id,
                    status="PASS",
                    details="All IAM console users have MFA active."
                )
                return True
            else:
                msg = f"MFA BREACH: The following console users lack MFA: {', '.join(unprotected_users)}"
                self._record_result(control_id=control_id, status="FAIL", details=msg)
                return False

        except ClientError as e:
            msg = f"AWS IAM API Error auditing MFA: {e.response['Error']['Code']}"
            logger.error(msg)
            self._record_result(control_id=control_id, status="FAIL", details=msg)
            return False

    def verify_network_segmentation_rules(self) -> bool:
        """Audits Security Groups to ensure high-risk management and DB ports are not exposed to 0.0.0.0/0."""
        logger.info(f"Auditing EC2 Security Groups in {self.region_name} for open exposure...")
        control_id = "DORA-ART9-NET-SEGMENTATION"
        violations = []

        try:
            sec_groups = self.ec2_client.describe_security_groups().get("SecurityGroups", [])

            for sg in sec_groups:
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "Unnamed")

                for ip_permission in sg.get("IpPermissions", []):
                    from_port = ip_permission.get("FromPort")
                    to_port = ip_permission.get("ToPort")

                    # Check for IPv4 public exposure (0.0.0.0/0)
                    ip_ranges = [ip["CidrIp"] for ip in ip_permission.get("IpRanges", [])]
                    if "0.0.0.0/0" in ip_ranges:
                        for port, service_name in self.HIGH_RISK_PORTS.items():
                            if from_port is None or (from_port <= port <= to_port):
                                violations.append(f"{sg_id} ({sg_name}) exposes port {port} ({service_name}) to 0.0.0.0/0")

            if not violations:
                self._record_result(
                    control_id=control_id,
                    status="PASS",
                    details="No high-risk management or database ports exposed to 0.0.0.0/0."
                )
                return True
            else:
                msg = f"EXPOSURE RISK: Security group violations detected: {'; '.join(violations)}"
                self._record_result(control_id=control_id, status="FAIL", details=msg)
                return False

        except ClientError as e:
            msg = f"AWS EC2 API Error auditing Security Groups: {e.response['Error']['Code']}"
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

    def export_report(self, file_path: str = "dora_article9_evidence.json"):
        with open(file_path, "w") as f:
            json.dump(self.audit_results, f, indent=2)
        logger.info(f"Audit report saved to '{file_path}'")


if __name__ == "__main__":
    logger.info("Starting DORA Article 9 Access & Protection Evaluation...")
    auditor = DoraAccessProtectionAuditor(region_name="eu-west-1")

    # Run Checks
    auditor.verify_iam_mfa_enforcement()
    auditor.verify_network_segmentation_rules()

    # Save Output Evidence
    auditor.export_report()
