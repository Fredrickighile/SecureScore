"""
PIPEDA Compliance Calculator
Maps security findings to Canada's Personal Information Protection
and Electronic Documents Act (PIPEDA) requirements.

PIPEDA requires organizations to protect personal information using
security safeguards appropriate to the sensitivity of the information.
"""

# PIPEDA Principle 7 — Safeguards
# Organizations must protect personal information against loss, theft,
# unauthorized access, disclosure, copying, use or modification.

PIPEDA_SAFEGUARDS = {
    "exposed_rdp": {
        "principle": "Principle 7 — Safeguards",
        "requirement": "Technical safeguards against unauthorized access",
        "pipeda_risk": "CRITICAL",
        "description": "Exposed RDP violates PIPEDA Principle 7. Direct remote access "
                       "to systems storing personal information is a severe safeguard failure.",
        "breach_risk": "HIGH — Ransomware via RDP frequently leads to reportable breaches",
        "points_deducted": 30
    },
    "exposed_smb": {
        "principle": "Principle 7 — Safeguards",
        "requirement": "Technical safeguards against unauthorized access",
        "pipeda_risk": "CRITICAL",
        "description": "Exposed SMB violates PIPEDA Principle 7. File share exposure "
                       "risks unauthorized access to personal information.",
        "breach_risk": "HIGH — SMB exploitation frequently leads to reportable breaches",
        "points_deducted": 25
    },
    "missing_dmarc": {
        "principle": "Principle 7 — Safeguards",
        "requirement": "Safeguards against unauthorized collection via phishing",
        "pipeda_risk": "HIGH",
        "description": "Missing DMARC enables phishing attacks that trick employees "
                       "into disclosing personal information — a PIPEDA Principle 7 gap.",
        "breach_risk": "HIGH — Phishing is the leading cause of reportable PIPEDA breaches",
        "points_deducted": 15
    },
    "missing_spf": {
        "principle": "Principle 7 — Safeguards",
        "requirement": "Email authentication safeguards",
        "pipeda_risk": "MEDIUM",
        "description": "Missing SPF enables email spoofing that facilitates "
                       "unauthorized collection of personal information.",
        "breach_risk": "MEDIUM — Increases phishing risk for customers and employees",
        "points_deducted": 10
    },
    "expired_cert": {
        "principle": "Principle 7 — Safeguards",
        "requirement": "Encryption of personal information in transit",
        "pipeda_risk": "CRITICAL",
        "description": "Expired SSL certificate means personal information may be "
                       "transmitted without encryption — direct PIPEDA Principle 7 violation.",
        "breach_risk": "HIGH — Unencrypted personal data transmission is reportable",
        "points_deducted": 25
    },
    "weak_ssl": {
        "principle": "Principle 7 — Safeguards",
        "requirement": "Adequate encryption standards for personal information",
        "pipeda_risk": "HIGH",
        "description": "Outdated TLS protocol fails to adequately protect personal "
                       "information in transit as required by PIPEDA.",
        "breach_risk": "MEDIUM — Weak encryption may not meet PIPEDA adequacy standard",
        "points_deducted": 15
    },
    "open_database_port": {
        "principle": "Principle 7 — Safeguards",
        "requirement": "Access controls for systems storing personal information",
        "pipeda_risk": "CRITICAL",
        "description": "Exposed database port risks unauthorized access to personal "
                       "information stores — severe PIPEDA Principle 7 violation.",
        "breach_risk": "HIGH — Database exposure almost always leads to reportable breaches",
        "points_deducted": 25
    },
    "missing_strict_transport_security": {
        "principle": "Principle 7 — Safeguards",
        "requirement": "Encryption enforcement for personal information in transit",
        "pipeda_risk": "MEDIUM",
        "description": "Missing HSTS allows downgrade attacks that expose personal "
                       "information transmitted over HTTP.",
        "breach_risk": "MEDIUM — Enables credential theft affecting personal information access",
        "points_deducted": 10
    }
}

# PIPEDA Breach Notification Thresholds (since November 2018)
# Organizations must report breaches that pose "real risk of significant harm"
SIGNIFICANT_HARM_FACTORS = [
    "Sensitive personal information involved (health, financial, SIN)",
    "Large number of individuals affected",
    "Combination of personal information elements",
    "Targeted attack vs opportunistic",
    "Vulnerable individuals affected (elderly, children)"
]


class PIPEDACalculator:
    """
    Calculates PIPEDA compliance score based on security findings.
    Maps technical vulnerabilities to PIPEDA Principle 7 safeguard requirements.
    """

    @staticmethod
    def calculate(scan_results: dict) -> dict:
        """
        Calculate PIPEDA compliance score from scan results.

        Args:
            scan_results: Combined results from all scanners

        Returns:
            PIPEDA compliance assessment
        """
        compliance_score = 100
        violations = []
        reportable_breach_risk = "LOW"

        # Check all vulnerabilities against PIPEDA safeguard requirements
        all_vulns = []
        for scanner in ['network', 'ssl', 'email', 'webapp']:
            data = scan_results.get(scanner, {})
            all_vulns.extend(data.get('vulnerabilities', []))

        high_risk_count = 0

        for vuln in all_vulns:
            vuln_type = vuln.get('type', '')
            if vuln_type in PIPEDA_SAFEGUARDS:
                safeguard = PIPEDA_SAFEGUARDS[vuln_type]
                compliance_score -= safeguard['points_deducted']
                violations.append({
                    "vulnerability": vuln.get('description', vuln_type),
                    "pipeda_principle": safeguard['principle'],
                    "requirement": safeguard['requirement'],
                    "pipeda_risk": safeguard['pipeda_risk'],
                    "pipeda_description": safeguard['description'],
                    "breach_notification_risk": safeguard['breach_risk']
                })
                if safeguard['pipeda_risk'] in ['CRITICAL', 'HIGH']:
                    high_risk_count += 1

        # Determine breach notification risk
        if high_risk_count >= 3:
            reportable_breach_risk = "HIGH"
        elif high_risk_count >= 1:
            reportable_breach_risk = "MEDIUM"

        compliance_score = max(0, compliance_score)

        # Determine compliance level
        if compliance_score >= 80:
            level = "COMPLIANT"
            color = "green"
            summary = "Organization demonstrates adequate PIPEDA safeguards."
        elif compliance_score >= 60:
            level = "PARTIAL"
            color = "yellow"
            summary = "Significant PIPEDA gaps identified. Remediation required."
        elif compliance_score >= 40:
            level = "NON-COMPLIANT"
            color = "orange"
            summary = "Multiple PIPEDA Principle 7 violations. Immediate action required."
        else:
            level = "AT RISK"
            color = "red"
            summary = "Critical PIPEDA violations. High probability of reportable breach."

        return {
            "pipeda_score": compliance_score,
            "compliance_level": level,
            "color": color,
            "summary": summary,
            "violations": violations,
            "total_violations": len(violations),
            "reportable_breach_risk": reportable_breach_risk,
            "breach_notification_required": reportable_breach_risk == "HIGH",
            "applicable_law": "PIPEDA (Federal) — Personal Information Protection and Electronic Documents Act",
            "provincial_laws": [
                "PIPA — Alberta and British Columbia",
                "Law 25 — Quebec (stricter requirements since 2023)"
            ],
            "recommendation": summary
        }