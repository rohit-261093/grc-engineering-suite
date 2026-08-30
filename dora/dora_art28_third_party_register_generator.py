"""
DORA Article 28/30 ICT Third-Party Vendor Register Generator
-----------------------------------------------------------------------
Framework: EU Digital Operational Resilience Act (Regulation EU 2022/2554)
Controls: Article 28 (General Principles for TPRM) & Article 30 (Register of Information)
Author: Rohit (GRC Engineering Suite)
"""

import json
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import List, Dict, Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("DORA_Art28_VendorRegister")


class DoraVendorRegisterEngine:
    """Generates an EU DORA RTS-compliant Register of Information for ICT Third-Party Vendors

    and performs automated external endpoint security health checks.
    """

    def __init__(self, vendors_list: List[Dict[str, Any]]):
        self.raw_vendors = vendors_list
        self.register_output = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "framework": "EU DORA (Regulation 2022/2554)",
            "article": "Article 28/30 - Register of Information for ICT Third-Party Risk",
            "total_vendors_processed": len(vendors_list),
            "critical_vendors_count": 0,
            "vendor_register": []
        }

    def audit_vendor_endpoint_security(self, domain: str) -> Dict[str, Any]:
        """Performs lightweight automated connectivity and TLS/SSL certificate audits on vendor endpoints."""
        audit_results = {
            "domain": domain,
            "port_443_open": False,
            "valid_tls": False,
            "tls_error": None
        }

        try:
            # Check SSL/TLS endpoint health
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3.0) as sock:
                audit_results["port_443_open"] = True
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        audit_results["valid_tls"] = True
        except Exception as e:
            audit_results["tls_error"] = str(e)

        return audit_results

    def generate_rts_register(self) -> Dict[str, Any]:
        """Processes raw vendor inventory and outputs structured RTS compliance records."""
        logger.info("Processing vendor inventory against DORA Article 28/30 RTS requirements...")

        critical_count = 0

        for vendor in self.raw_vendors:
            name = vendor.get("vendor_name", "Unknown")
            domain = vendor.get("domain", "")
            is_cif = vendor.get("supports_critical_function", False)

            if is_cif:
                critical_count += 1

            # Conduct continuous security check
            security_health = self.audit_vendor_endpoint_security(domain) if domain else {}

            # Construct DORA RTS Register Entry
            register_entry = {
                "vendor_id": vendor.get("vendor_id"),
                "vendor_name": name,
                "country_of_registration": vendor.get("country", "EU"),
                "service_type": vendor.get("service_type", "Cloud Infrastructure"),
                "criticality": {
                    "supports_critical_or_important_function": is_cif,
                    "risk_classification": "HIGH" if is_cif else "MEDIUM"
                },
                "contract_metadata": {
                    "contract_start_date": vendor.get("contract_start"),
                    "governing_law": vendor.get("governing_law", "EU Member State Law"),
                    "exit_strategy_documented": vendor.get("exit_strategy_exists", False)
                },
                "automated_health_check": security_health,
                "dora_compliance_status": "COMPLIANT" if (vendor.get("exit_strategy_exists") and security_health.get("valid_tls", False)) else "REQUIRES_ATTENTION"
            }

            self.register_output["vendor_register"].append(register_entry)

        self.register_output["critical_vendors_count"] = critical_count
        return self.register_output

    def export_report(self, file_path: str = "dora_article28_vendor_register.json"):
        with open(file_path, "w") as f:
            json.dump(self.register_output, f, indent=2)
        logger.info(f"Vendor Register of Information exported to '{file_path}'")


if __name__ == "__main__":
    # Sample input inventory (simulating data pulled from procurement or TPRM software)
    sample_vendors = [
        {
            "vendor_id": "ICT-VEN-001",
            "vendor_name": "Cloud Infra Provider Corp",
            "domain": "aws.amazon.com",
            "country": "US/EU",
            "service_type": "IaaS Cloud Infrastructure",
            "supports_critical_function": True,
            "contract_start": "2024-01-01",
            "governing_law": "Irish Law",
            "exit_strategy_exists": True
        },
        {
            "vendor_id": "ICT-VEN-002",
            "vendor_name": "Legacy Analytics Tool",
            "domain": "example.com",
            "country": "DE",
            "service_type": "Marketing Data Analytics",
            "supports_critical_function": False,
            "contract_start": "2025-06-15",
            "governing_law": "German Law",
            "exit_strategy_exists": False
        }
    ]

    engine = DoraVendorRegisterEngine(vendors_list=sample_vendors)
    engine.generate_rts_register()
    engine.export_report()
