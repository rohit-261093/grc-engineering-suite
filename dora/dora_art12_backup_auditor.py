"""
DORA Article 12 Backup Policies & RPO Auditor
-----------------------------------------------------------
Framework: EU Digital Operational Resilience Act (Regulation EU 2022/2554)
Control: Article 12 - Backup Policies and Procedures (RPO Compliance & Immutability)
Author: Rohit (GRC Engineering Suite)
"""

import json
import logging
from datetime import datetime, timezone, timedelta
import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("DORA_Art12_Auditor")


class DoraBackupAuditor:
    """Evaluates AWS Backup vaults and recovery point freshness for DORA Article 12 compliance."""

    def __init__(self, region_name: str = "eu-west-1", max_rpo_hours: int = 1):
        self.region_name = region_name
        self.max_rpo_hours = max_rpo_hours
        self.backup_client = boto3.client("backup", region_name=self.region_name)
        
        self.audit_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "framework": "EU DORA (Regulation 2022/2554)",
            "article": "Article 12 - Backup Policies and Procedures",
            "target_rpo_hours": self.max_rpo_hours,
            "overall_status": "PASS",
            "evaluations": []
        }

    def verify_backup_freshness_and_immutability(self, vault_name: str) -> bool:
        """Audits the latest recovery points in an AWS Backup vault to ensure RPO < max_rpo_hours

        and confirms WORM/Vault Lock immutability.
        """
        logger.info(f"Auditing Backup Vault: {vault_name}")
        control_id_rpo = "DORA-ART12-RPO-FRESHNESS"
        control_id_lock = "DORA-ART12-IMMUTABILITY-LOCK"
        
        try:
            # 1. Audit Vault Lock (Immutability protection against ransomware/tampering)
            vault_access = self.backup_client.describe_backup_vault(BackupVaultName=vault_name)
            is_locked = vault_access.get("Locked", False)
            
            if is_locked:
                self._record_result(
                    control_id=control_id_lock,
                    status="PASS",
                    details=f"Backup Vault '{vault_name}' has WORM/Vault Lock enabled."
                )
            else:
                self._record_result(
                    control_id=control_id_lock,
                    status="FAIL",
                    details=f"CRITICAL: Backup Vault '{vault_name}' lacks Vault Lock protection."
                )

            # 2. Audit Recovery Point Freshness (RPO verification)
            recovery_points = self.backup_client.list_recovery_points_by_backup_vault(
                BackupVaultName=vault_name,
                ByStatus="COMPLETED"
            ).get("RecoveryPoints", [])

            if not recovery_points:
                self._record_result(
                    control_id=control_id_rpo,
                    status="FAIL",
                    details=f"No completed recovery points found in vault '{vault_name}'."
                )
                return False

            # Check creation date of the newest recovery point
            latest_point = sorted(recovery_points, key=lambda x: x["CreationDate"], reverse=True)[0]
            latest_date = latest_point["CreationDate"]
            now = datetime.now(timezone.utc)
            age_hours = (now - latest_date).total_seconds() / 3600.0

            if age_hours <= self.max_rpo_hours:
                msg = f"Latest backup snapshot is {age_hours:.2f} hours old (Satisfies RPO target of {self.max_rpo_hours}h)."
                self._record_result(control_id=control_id_rpo, status="PASS", details=msg)
                return True
            else:
                msg = f"RPO BREACH: Latest backup snapshot is {age_hours:.2f} hours old (Exceeds target of {self.max_rpo_hours}h)."
                self._record_result(control_id=control_id_rpo, status="FAIL", details=msg)
                return False

        except ClientError as e:
            msg = f"AWS API Error auditing vault '{vault_name}': {e.response['Error']['Code']}"
            logger.error(msg)
            self._record_result(control_id=control_id_rpo, status="FAIL", details=msg)
            return False

    def _record_result(self, control_id: str, status: str, details: str):
        if status == "FAIL":
            self.audit_results["overall_status"] = "FAIL"
            
        self.audit_results["evaluations"].append({
            "control_id": control_id,
            "status": status,
            "details": details
        })

    def export_report(self, file_path: str = "dora_article12_evidence.json"):
        with open(file_path, "w") as f:
            json.dump(self.audit_results, f, indent=2)
        logger.info(f"Audit report saved to '{file_path}'")


if __name__ == "__main__":
    TARGET_VAULT = "production-financial-backup-vault"
    
    auditor = DoraBackupAuditor(region_name="eu-west-1", max_rpo_hours=1)
    auditor.verify_backup_freshness_and_immutability(vault_name=TARGET_VAULT)
    auditor.export_report()
