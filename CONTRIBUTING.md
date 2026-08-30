# Contributing to GRC Engineering Suite

Thank you for contributing! To ensure that all **Compliance-as-Code** evaluation engines remain auditor-ready, mathematically sound, and non-disruptive to production infrastructure, all modules must strictly adhere to our core engineering principles.

---

## 📜 Core GRC Engineering Principles

### 1. Zero-Side-Effect Inspections (Read-Only Enforcement)
* **Rule:** Compliance scripts MUST NEVER mutate, modify, or delete production infrastructure state.
* **Implementation:** Restrict all cloud API calls (`boto3`) to read-only actions (`describe_*`, `list_*`, `get_*`). Remediation scripts must be strictly isolated into opt-in, decoupled modules.

### 2. Fail-Closed Evidence Collection
* **Rule:** If an API call fails due to missing permissions, network timeouts, or unhandled exceptions, the control state MUST evaluate to `FAIL`—never `PASS` or silent skip.
* **Implementation:** Capture all `ClientError` exceptions and record explicit error metadata in the evaluation JSON.

### 3. Native Regulatory Traceability
* **Rule:** Every check must map directly to an official framework article, control ID, or Regulatory Technical Standard (RTS).
* **Implementation:** Audit outputs must emit structured `control_id` strings (e.g., `DORA-ART9-MFA-ENFORCED`, `ISO27001-A.8.24-KEY-ROTATION`, `PSD2-ART97-SCA-MFA-ENFORCED`).

### 4. Deterministic Compliance Evaluation
* **Rule:** Control logic must produce identical PASS/FAIL results for identical infrastructure telemetry inputs. Avoid speculative or subjective scoring algorithms.

### 5. Multi-Region Data Sovereignty Baseline
* **Rule:** All checks must operate assuming a multi-region deployment model in European Union sovereign zones (e.g., `eu-west-1` primary, `eu-central-1` secondary DR) to satisfy EU regulatory mandates (DORA, PSD2, EU AI Act).

---

## 🛠️ Code Review Checklist

Before submitting a pull request for a new regulatory module:

- [ ] Script uses standard Python logging (`logging.basicConfig`) rather than bare `print()` statements.
- [ ] Exported JSON evidence includes standardized metadata: `timestamp` (UTC ISO format), `framework`, `article`/`control`, and `evaluations` list.
- [ ] Added accompanying module documentation in `<framework>/README.md`.
- [ ] Added script execution step to `.github/workflows/continuous-compliance.yml`.
