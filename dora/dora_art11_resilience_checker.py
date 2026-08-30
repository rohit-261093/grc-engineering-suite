"""
DORA Article 11 ICT Resilience & Continuous Failover Auditor
-----------------------------------------------------------
Framework: EU Digital Operational Resilience Act (Regulation EU 2022/2554)
Control: Article 11 - Response and Recovery Capabilities
Author: Rohit (GRC Engineering Suite)
"""

import json
import logging
import sys
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

# Configure structured JSON logging for audit trails
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("DORA_Art11_Auditor")


class DoraResilienceAuditor:
    """Evaluates AWS primary and secondary infrastructure for DORA Article 11 readiness."""

    def __init__(self, primary_region: str = "eu-west-1", secondary_region: str = "eu-central-1"):
        self.primary_region = primary_region
        self.secondary_region = secondary_region
        
        # AWS SDK Clients
        self.s3_primary = boto3.client("s3", region_name=self.primary_region)
        self.route53 = boto3.client("route53")
        
        # Execution Evidence Payload Structure
        self.audit_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "framework": "EU DORA (Regulation 2022/2554)",
            "article": "Article 11 - Response and Recovery Capabilities",
            "primary_region": self.primary_region,
            "secondary_region": self.secondary_region,
            "overall_status": "PASS",
            "evaluations": []
        }

    def verify_s3_cross_region_replication(self, bucket_name: str) -> bool:
        """Audits if Cross-Region Replication (CRR) is active to satisfy data availability RPO."""
        logger.info(f"Auditing S3 CRR for bucket: {bucket_name}")
        control_id = "DORA-ART11-CR-STORAGE"
        
        try:
            resp = self.s3_primary.get_bucket_replication(Bucket=bucket_name)
            rules = resp.get("ReplicationConfiguration", {}).get("Rules", [])
            
            active_rules = [r for r in rules if r.get("Status") == "Enabled"]
            
            if active_rules:
                dest_bucket = active_rules[0]["Destination"]["Bucket"]
                msg = f"Cross-region replication ACTIVE from '{bucket_name}' to '{dest_bucket}'."
                self._record_result(control_id=control_id, status="PASS", details=msg)
                return True
            else:
                msg = f"Replication configuration exists for '{bucket_name}', but no active/enabled rules found."
                self._record_result(control_id=control_id, status="FAIL", details=msg)
                return False

        except ClientError as e:
            err_code = e.response["Error"]["Code"]
            if err_code == "ReplicationConfigurationNotFoundError":
                msg = f"CRITICAL: No cross-region replication configured for primary bucket '{bucket_name}'."
            else:
                msg = f"AWS API Error checking S3 replication: {err_code}"
            
            logger.error(msg)
            self._record_result(control_id=control_id, status="FAIL", details=msg)
            return False

    def verify_route53_failover_health(self, health_check_id: str) -> bool:
        """Audits Route53 global health check statuses to verify DNS failover readiness."""
        logger.info(f"Auditing Route53 Health Check ID: {health_check_id}")
        control_id = "DORA-ART11-FAILOVER-DNS"
        
        try:
            status = self.route53.get_health_check_status(HealthCheckId=health_check_id)
            observations = status.get("HealthCheckObservations", [])
            
            if not observations:
                msg = f"No observation data returned for Route53 Health Check '{health_check_id}'."
                self._record_result(control_id=control_id, status="FAIL", details=msg)
                return False

            # Evaluate health checker quorum
            healthy_count = sum(1 for obs in observations if "OK" in obs.get("StatusReport", {}).get("Status", ""))
            total_checks = len(observations)
            is_healthy = healthy_count >= (total_checks / 2)

            if is_healthy:
                msg = f"Route53 Health Check '{health_check_id}' HEALTHY ({healthy_count}/{total_checks} checkers reporting OK)."
                self._record_result(control_id=control_id, status="PASS", details=msg)
                return True
            else:
                msg = f"DEGRADED: Route53 Health Check '{health_check_id}' failing quorum ({healthy_count}/{total_checks} checkers OK)."
                self._record_result(control_id=control_id, status="FAIL", details=msg)
                return False

        except ClientError as e:
            msg = f"AWS API Error checking Route53 health: {e.response['Error']['Code']}"
            logger.error(msg)
            self._record_result(control_id=control_id, status="FAIL", details=msg)
            return False

    def _record_result(self, control_id: str, status: str, details: str):
        """Helper to append individual control evaluation outputs to final payload."""
        if status == "FAIL":
            self.audit_results["overall_status"] = "FAIL"
            
        self.audit_results["evaluations"].append({
            "control_id": control_id,
            "status": status,
            "details": details
        })

    def export_report(self, file_path: str = "dora_article11_evidence.json"):
        """Exports timestamped evidence artifact for auditor review."""
        with open(file_path, "w") as f:
            json.dump(self.audit_results, f, indent=2)
        logger.info(f"Audit report saved to '{file_path}'")


if __name__ == "__main__":
    # Target AWS resources to evaluate
    TARGET_S3_BUCKET = "spacexai-critical-financial-data"
    TARGET_ROUTE53_CHECK_ID = "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"

    logger.info("Starting DORA Article 11 Resilience Evaluation...")
    auditor = DoraResilienceAuditor(primary_region="eu-west-1", secondary_region="eu-central-1")
    
    # Run Evaluations
    auditor.verify_s3_cross_region_replication(bucket_name=TARGET_S3_BUCKET)
    auditor.verify_route53_failover_health(health_check_id=TARGET_ROUTE53_CHECK_ID)
    
    # Save Report
    auditor.export_report()
