"""
DORA Article 18/19 Incident Classification & Regulatory Reporting Engine
-----------------------------------------------------------------------
Framework: EU Digital Operational Resilience Act (Regulation EU 2022/2554)
Controls: Article 18 (ICT Incident Classification) & Article 19 (Reporting)
Author: Rohit (GRC Engineering Suite)
"""

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("DORA_Art18_Engine")


class DoraIncidentClassifier:
    """Evaluates telemetry alert payloads against EU DORA RTS thresholds to classify major ICT incidents

    and calculate regulatory notification deadlines.
    """

    # EU DORA RTS Major Incident Threshold Limits
    CRITICAL_SERVICE_AFFECTED = True
    CLIENT_IMPACT_PERCENT_THRESHOLD = 10.0  # >10% of active users affected
    DOWNTIME_MINUTES_THRESHOLD = 120        # >2 hours of operational downtime
    DATA_LOSS_IMPACT = True                 # Loss of data integrity or confidentiality

    def __init__(self, incident_payload: Dict[str, Any]):
        self.payload = incident_payload
        self.incident_id = incident_payload.get("incident_id", "INC-UNKNOWN")
        self.detection_time = datetime.fromisoformat(
            incident_payload.get("timestamp", datetime.now(timezone.utc).isoformat())
        )

        self.classification_report = {
            "incident_id": self.incident_id,
            "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
            "framework": "EU DORA (Regulation 2022/2554)",
            "article": "Article 18 - ICT-related Incident Classification",
            "is_major_incident": False,
            "triggered_criteria": [],
            "regulatory_reporting": {}
        }

    def evaluate_incident_severity(self) -> bool:
        """Evaluates incident parameters against RTS quantitative and qualitative thresholds."""
        logger.info(f"Evaluating Incident ID: {self.incident_id}")

        triggers = []

        # 1. Critical Function Impact
        if self.payload.get("supports_critical_function", False):
            # 2. Downtime Duration Threshold
            downtime = self.payload.get("downtime_minutes", 0)
            if downtime >= self.DOWNTIME_MINUTES_THRESHOLD:
                triggers.append(f"Downtime breach: {downtime} mins (Threshold: {self.DOWNTIME_MINUTES_THRESHOLD} mins)")

            # 3. User/Client Impact Threshold
            affected_clients_pct = self.payload.get("affected_clients_percentage", 0.0)
            if affected_clients_pct >= self.CLIENT_IMPACT_PERCENT_THRESHOLD:
                triggers.append(f"Client impact breach: {affected_clients_pct}% (Threshold: {self.CLIENT_IMPACT_PERCENT_THRESHOLD}%)")

            # 4. Data Loss / Confidentiality Compromise
            if self.payload.get("data_compromised", False):
                triggers.append("Data Integrity Breach: Compromise of sensitive/financial data confirmed")

            # 5. Geographical Spread
            if self.payload.get("affected_eu_member_states", 0) >= 2:
                triggers.append("Geographical Spread: Impacts 2 or more EU Member States")

        self.classification_report["triggered_criteria"] = triggers

        # Classify as MAJOR INCIDENT if critical service is impacted along with at least one core threshold
        if len(triggers) > 0:
            self.classification_report["is_major_incident"] = True
            self._set_regulatory_deadlines()
            logger.warning(f"INCIDENT {self.incident_id} CLASSIFIED AS MAJOR DORA INCIDENT.")
            return True
        else:
            self.classification_report["is_major_incident"] = False
            self.classification_report["regulatory_reporting"] = {
                "initial_notification_required": False,
                "note": "Incident below major regulatory threshold. Standard internal SecOps playbooks apply."
            }
            logger.info(f"Incident {self.incident_id} classified as Minor/Operational.")
            return False

    def _set_regulatory_deadlines(self):
        """Calculates strict DORA Article 19 deadlines (4-Hour Initial Notification to National Competent Authority)."""
        # Article 19 mandate: Initial notification within 4 hours of classification
        nca_deadline = self.detection_time + timedelta(hours=4)
        
        # Intermediate report deadline: 72 hours
        intermediate_deadline = self.detection_time + timedelta(hours=72)

        self.classification_report["regulatory_reporting"] = {
            "initial_notification_required": True,
            "target_authority": "National Competent Authority (NCA) / EBA / ESMA",
            "classification_timestamp": self.detection_time.isoformat(),
            "initial_notification_deadline_utc": nca_deadline.isoformat(),
            "intermediate_report_deadline_utc": intermediate_deadline.isoformat(),
            "hours_remaining_for_initial_notice": round((nca_deadline - datetime.now(timezone.utc)).total_seconds() / 3600.0, 2)
        }

    def export_report(self, file_path: str = "dora_article18_evidence.json"):
        with open(file_path, "w") as f:
            json.dump(self.classification_report, f, indent=2)
        logger.info(f"Classification evidence saved to '{file_path}'")


if __name__ == "__main__":
    # Simulated Security Event Alert Payload (e.g., from Datadog, PagerDuty, or SIEM)
    simulated_event_payload = {
        "incident_id": "INC-2026-0830-01",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service_name": "eu-core-payment-gateway",
        "supports_critical_function": True,
        "downtime_minutes": 145,
        "affected_clients_percentage": 14.5,
        "data_compromised": True,
        "affected_eu_member_states": 3
    }

    engine = DoraIncidentClassifier(incident_payload=simulated_event_payload)
    engine.evaluate_incident_severity()
    engine.export_report()
