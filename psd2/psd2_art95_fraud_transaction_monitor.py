"""
PSD2 Article 95 Operational Risk & Real-Time Fraud Monitoring Engine
---------------------------------------------------------------------
Framework: EU Payment Services Directive 2 (Directive EU 2015/2366)
Control: Article 95 - Security Measures & Real-Time Transaction Risk Analysis
Author: Rohit (GRC Engineering Suite)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("PSD2_Art95_FraudEngine")


class Psd2FraudRiskEngine:
    """Evaluates payment transaction telemetry against PSD2 EBA RTS fraud risk thresholds."""

    # EBA RTS Fraud Risk Threshold Parameters
    HIGH_VALUE_THRESHOLD_EUR = 10000.00
    MAX_VELOCITY_TRANSACTIONS_PER_HOUR = 5
    HIGH_RISK_IP_FLAG = True

    def __init__(self, transaction_payload: Dict[str, Any]):
        self.payload = transaction_payload
        self.tx_id = transaction_payload.get("transaction_id", "TX-UNKNOWN")
        
        self.audit_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "framework": "EU PSD2 (Directive 2015/2366)",
            "article": "Article 95 - Operational & Security Risk Management",
            "transaction_id": self.tx_id,
            "risk_evaluation": "LOW_RISK",
            "flags_raised": [],
            "overall_status": "PASS"
        }

    def evaluate_transaction_risk(self) -> bool:
        """Evaluates financial transfer parameters for fraud indicators and regulatory compliance."""
        logger.info(f"Auditing Transaction ID: {self.tx_id} for fraud risk indicators...")

        flags = []
        amount = self.payload.get("amount_eur", 0.0)
        velocity = self.payload.get("hourly_velocity", 0)
        is_known_device = self.payload.get("trusted_device", True)
        ip_risk = self.payload.get("high_risk_ip", False)

        # 1. High-Value Payment Analysis
        if amount >= self.HIGH_VALUE_THRESHOLD_EUR:
            flags.append(f"HIGH_VALUE: Payment amount €{amount:,.2f} exceeds threshold (€{self.HIGH_VALUE_THRESHOLD_EUR:,.2f})")

        # 2. Velocity Monitoring
        if velocity > self.MAX_VELOCITY_TRANSACTIONS_PER_HOUR:
            flags.append(f"VELOCITY_BREACH: {velocity} transactions/hour exceeds limit ({self.MAX_VELOCITY_TRANSACTIONS_PER_HOUR}/h)")

        # 3. Untrusted Device & High-Risk IP Anomaly
        if not is_known_device and ip_risk:
            flags.append("GEOGRAPHIC_ANOMALY: Access from untrusted device via high-risk IP range")

        self.audit_results["flags_raised"] = flags

        # Risk Classification Logic
        if len(flags) >= 2:
            self.audit_results["risk_evaluation"] = "HIGH_RISK_SUSPECTED_FRAUD"
            self.audit_results["overall_status"] = "FAIL"
            logger.warning(f"TRANSACTION {self.tx_id} REJECTED / STEP-UP SCA REQUIRED.")
            return False
        elif len(flags) == 1:
            self.audit_results["risk_evaluation"] = "MEDIUM_RISK_STEP_UP_REQUIRED"
            logger.info(f"Transaction {self.tx_id} flagged for additional step-up verification.")
            return True
        else:
            self.audit_results["risk_evaluation"] = "LOW_RISK_CLEARED"
            logger.info(f"Transaction {self.tx_id} cleared risk evaluation.")
            return True

    def export_report(self, file_path: str = "psd2_article95_fraud_evidence.json"):
        with open(file_path, "w") as f:
            json.dump(self.audit_results, f, indent=2)
        logger.info(f"PSD2 Fraud audit evidence exported to '{file_path}'")


if __name__ == "__main__":
    # Simulated High-Risk Payment Telemetry Payload
    simulated_payment = {
        "transaction_id": "PSD2-TX-2026-9901",
        "user_id": "USR-EUR-88219",
        "amount_eur": 12500.50,
        "hourly_velocity": 8,
        "trusted_device": False,
        "high_risk_ip": True,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    engine = Psd2FraudRiskEngine(transaction_payload=simulated_payment)
    engine.evaluate_transaction_risk()
    engine.export_report()
