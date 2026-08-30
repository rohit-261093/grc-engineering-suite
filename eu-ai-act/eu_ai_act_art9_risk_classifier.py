"""
EU AI Act Article 6 Classification & Article 9 Risk Safeguards Engine
----------------------------------------------------------------------
Framework: EU AI Act (Regulation EU 2024/1689)
Controls: Article 6 (High-Risk Classification) & Article 9 (Risk Management Systems)
Author: Rohit (GRC Engineering Suite)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("EU_AI_Act_Art9_Classifier")


class EuAiActRiskEngine:
    """Classifies AI systems into regulatory risk tiers under Article 6 and evaluates

    Article 9 risk management safeguards for High-Risk workloads.
    """

    # Annex III High-Risk Domains (EU AI Act)
    HIGH_RISK_DOMAINS = [
        "biometrics",
        "critical_infrastructure",
        "education_vocational_training",
        "employment_worker_management",
        "essential_private_public_services",  # Credit scoring, insurance, emergency response
        "law_enforcement",
        "migration_asylum_border_control",
        "administration_of_justice_democracy"
    ]

    # Article 5 Prohibited AI Practices
    PROHIBITED_PRACTICES = [
        "subliminal_manipulation",
        "social_scoring",
        "untargeted_facial_scraping",
        "biometric_categorization_sensitive_traits",
        "realtime_remote_biometric_public_spaces"
    ]

    def __init__(self, system_profile: Dict[str, Any]):
        self.profile = system_profile
        self.system_id = system_profile.get("system_id", "AI-SYS-UNKNOWN")

        self.audit_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "framework": "EU AI Act (Regulation EU 2024/1689)",
            "system_id": self.system_id,
            "classification": {
                "risk_tier": "MINIMAL_RISK",
                "is_prohibited": False,
                "is_high_risk": False,
                "derogation_applied": False
            },
            "article9_risk_management": {
                "compliant": False,
                "missing_safeguards": []
            },
            "overall_status": "PASS",
            "evaluations": []
        }

    def classify_system_tier(self) -> str:
        """Classifies the AI system into regulatory tiers under Article 5 (Prohibited) and Article 6 (High-Risk)."""
        logger.info(f"Classifying AI System '{self.system_id}' against EU AI Act risk tiers...")
        control_id = "EU-AI-ACT-ART6-TIER-CLASSIFICATION"

        use_case = self.profile.get("use_case_category", "general")
        capabilities = self.profile.get("capabilities", [])
        performs_profiling = self.profile.get("performs_profiling", False)

        # 1. Evaluate Article 5 Prohibited Practices
        for practice in self.PROHIBITED_PRACTICES:
            if practice in capabilities:
                self.audit_results["classification"]["is_prohibited"] = True
                self.audit_results["classification"]["risk_tier"] = "PROHIBITED"
                msg = f"UNACCEPTABLE RISK: System utilizes prohibited capability '{practice}' under Article 5."
                self._record_result(control_id=control_id, status="FAIL", details=msg)
                return "PROHIBITED"

        # 2. Evaluate Article 6 Annex III High-Risk Classification
        if use_case in self.HIGH_RISK_DOMAINS:
            # Check Article 6(3) Derogation: Not high-risk if perform narrow procedural task AND no profiling
            is_narrow_task = self.profile.get("is_narrow_procedural_task", False)
            
            if is_narrow_task and not performs_profiling:
                self.audit_results["classification"]["derogation_applied"] = True
                self.audit_results["classification"]["risk_tier"] = "LIMITED_OR_MINIMAL_RISK"
                msg = f"Derogation Applied (Art 6(3)): System in '{use_case}' is a narrow procedural task without profiling."
                self._record_result(control_id=control_id, status="PASS", details=msg)
                return "LIMITED_OR_MINIMAL_RISK"
            else:
                self.audit_results["classification"]["is_high_risk"] = True
                self.audit_results["classification"]["risk_tier"] = "HIGH_RISK"
                msg = f"HIGH-RISK SYSTEM: Deployed in Annex III domain '{use_case}'."
                self._record_result(control_id=control_id, status="PASS", details=msg)
                return "HIGH_RISK"

        self.audit_results["classification"]["risk_tier"] = "MINIMAL_RISK"
        self._record_result(
            control_id=control_id,
            status="PASS",
            details="System classified as Minimal/Low Risk (outside Annex III mandatory scope)."
        )
        return "MINIMAL_RISK"

    def audit_article9_safeguards(self) -> bool:
        """Audits Article 9 Risk Management System requirements for High-Risk workloads."""
        tier = self.audit_results["classification"]["risk_tier"]
        control_id = "EU-AI-ACT-ART9-RISK-SAFEGUARDS"

        if tier != "HIGH_RISK":
            self.audit_results["article9_risk_management"]["compliant"] = True
            self._record_result(
                control_id=control_id,
                status="PASS",
                details=f"Article 9 Risk Management controls exempt for system tier '{tier}'."
            )
            return True

        logger.info(f"Auditing Article 9 Risk Management safeguards for High-Risk system '{self.system_id}'...")
        safeguards = self.profile.get("risk_management_safeguards", {})
        missing = []

        # Article 9 Core Safeguard Checks
        if not safeguards.get("continuous_risk_assessment_active", False):
            missing.append("Continuous Iterative Risk Assessment (Art. 9(1))")

        if not safeguards.get("residual_risk_evaluation_documented", False):
            missing.append("Residual Risk Acceptability Assessment (Art. 9(4))")

        if not safeguards.get("human_in_the_loop_override_enabled", False):
            missing.append("Human Oversight / HITL Override Capabilities (Art. 9(2))")

        if not safeguards.get("adversarial_robustness_testing_completed", False):
            missing.append("Pre-market Testing & Robustness Metrics (Art. 9(5))")

        self.audit_results["article9_risk_management"]["missing_safeguards"] = missing

        if not missing:
            self.audit_results["article9_risk_management"]["compliant"] = True
            self._record_result(
                control_id=control_id,
                status="PASS",
                details="Article 9 Compliant: All required risk management safeguards and human oversight controls are active."
            )
            return True
        else:
            self.audit_results["article9_risk_management"]["compliant"] = False
            msg = f"ARTICLE 9 NON-COMPLIANCE: Missing mandatory risk safeguards: {'; '.join(missing)}"
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

    def export_report(self, file_path: str = "eu_ai_act_article9_risk_evidence.json"):
        with open(file_path, "w") as f:
            json.dump(self.audit_results, f, indent=2)
        logger.info(f"EU AI Act Article 9 risk classification report exported to '{file_path}'")


if __name__ == "__main__":
    # Simulated AI System Profile Payload (e.g., automated CV screening or credit scoring system)
    simulated_system_profile = {
        "system_id": "spacexai-automated-recruitment-screener",
        "use_case_category": "employment_worker_management",
        "capabilities": ["resume_parsing", "candidate_scoring"],
        "performs_profiling": True,
        "is_narrow_procedural_task": False,
        "risk_management_safeguards": {
            "continuous_risk_assessment_active": True,
            "residual_risk_evaluation_documented": True,
            "human_in_the_loop_override_enabled": True,
            "adversarial_robustness_testing_completed": True
        }
    }

    engine = EuAiActRiskEngine(system_profile=simulated_system_profile)
    engine.classify_system_tier()
    engine.audit_article9_safeguards()
    engine.export_report()
