"""
EU AI Act Article 10 & 11 Technical Documentation & Governance Auditor
----------------------------------------------------------------------
Framework: EU AI Act (Regulation EU 2024/1689)
Controls: Article 10 (Data & Data Governance) & Article 11 (Technical Documentation & Annex IV)
Author: Rohit (GRC Engineering Suite)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("EU_AI_Act_Art11_Auditor")


class EuAiActModelAuditor:
    """Evaluates machine learning model metadata cards against EU AI Act High-Risk system compliance mandates."""

    def __init__(self, model_card_payload: Dict[str, Any]):
        self.payload = model_card_payload
        self.model_id = model_card_payload.get("model_id", "AI-MODEL-UNKNOWN")

        self.audit_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "framework": "EU AI Act (Regulation EU 2024/1689)",
            "articles_evaluated": ["Article 10 (Data Governance)", "Article 11 (Technical Documentation)"],
            "model_id": self.model_id,
            "overall_status": "PASS",
            "evaluations": []
        }

    def audit_model_governance_metadata(self) -> bool:
        """Audits model metadata for required data lineage, bias testing, and human oversight parameters."""
        logger.info(f"Auditing ML Model Card: {self.model_id} for EU AI Act compliance...")

        # 1. Article 10: Training Data Lineage & Bias Mitigation Checks
        control_data_gov = "EU-AI-ACT-ART10-DATA-GOVERNANCE"
        data_gov = self.payload.get("data_governance", {})

        has_lineage = data_gov.get("data_lineage_documented", False)
        has_bias_audit = data_gov.get("bias_and_fairness_audit_completed", False)

        if has_lineage and has_bias_audit:
            self._record_result(
                control_id=control_data_gov,
                status="PASS",
                details=f"Model '{self.model_id}' complies with Article 10 data lineage and bias auditing requirements."
            )
        else:
            self._record_result(
                control_id=control_data_gov,
                status="FAIL",
                details=f"ARTICLE 10 BREACH: Missing data lineage ({has_lineage}) or bias audit ({has_bias_audit})."
            )

        # 2. Article 11: Technical Documentation & Human Oversight Safeguards
        control_tech_doc = "EU-AI-ACT-ART11-TECHNICAL-DOCS"
        technical_docs = self.payload.get("technical_documentation", {})

        has_versioning = bool(technical_docs.get("model_version"))
        has_human_oversight = technical_docs.get("human_oversight_mechanism_enabled", False)
        logging_enabled = technical_docs.get("automated_event_logging_active", False)

        if has_versioning and has_human_oversight and logging_enabled:
            self._record_result(
                control_id=control_tech_doc,
                status="PASS",
                details=f"Model '{self.model_id}' satisfies Article 11 technical documentation and human oversight criteria."
            )
        else:
            self._record_result(
                control_id=control_tech_doc,
                status="FAIL",
                details=f"ARTICLE 11 BREACH: Missing human oversight ({has_human_oversight}) or automated logging ({logging_enabled})."
            )

        return self.audit_results["overall_status"] == "PASS"

    def _record_result(self, control_id: str, status: str, details: str):
        if status == "FAIL":
            self.audit_results["overall_status"] = "FAIL"

        self.audit_results["evaluations"].append({
            "control_id": control_id,
            "status": status,
            "details": details
        })

    def export_report(self, file_path: str = "eu_ai_act_article11_evidence.json"):
        with open(file_path, "w") as f:
            json.dump(self.audit_results, f, indent=2)
        logger.info(f"EU AI Act audit evidence exported to '{file_path}'")


if __name__ == "__main__":
    # Simulated High-Risk AI Model Card Metadata Payload
    simulated_model_card = {
        "model_id": "spacexai-llm-risk-classifier-v2",
        "intended_use": "High-risk decision assistance for automated regulatory screening",
        "data_governance": {
            "data_lineage_documented": True,
            "training_data_sources": ["eu-regulatory-corpus-2026", "sec-filings-v4"],
            "bias_and_fairness_audit_completed": True
        },
        "technical_documentation": {
            "model_version": "2.4.0",
            "human_oversight_mechanism_enabled": True,
            "automated_event_logging_active": True
        }
    }

    auditor = EuAiActModelAuditor(model_card_payload=simulated_model_card)
    auditor.audit_model_governance_metadata()
    auditor.export_report()
