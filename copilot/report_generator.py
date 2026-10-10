"""
Security Copilot Report Generator — Formats incident investigations, executive summaries,
and post-mortem security audits into human-readable markdown and PDF templates.
"""

import logging
from datetime import datetime
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Constructs comprehensive security reporting documentation.
    """

    def generate_incident_report(self, incident_details: Dict[str, Any], compromised_hosts: List[str]) -> str:
        """Generates a detailed Incident Response / Analyst triage report."""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        hosts_str = ", ".join(compromised_hosts) if compromised_hosts else "None"
        
        report = f"""# INCIDENT TRIAGE & ANALYSIS REPORT
**Incident ID:** {incident_details.get('id', 'INC-9999')}
**Generated At:** {timestamp}
**Threat Classification:** {incident_details.get('classification', 'Unclassified')}
**Severity Level:** {incident_details.get('severity', 'MEDIUM')}

## Executive Summary
{incident_details.get('summary', 'No summary provided.')}

## Scope of Compromise
- **Affected Host Systems:** {hosts_str}
- **Vulnerability Triggered:** {incident_details.get('vulnerability', 'Unknown')}
- **Initial Entry Point:** {incident_details.get('entry_point', 'Unknown')}

## Remediation & Containment Tasks
1. Isolate all compromised hosts: {hosts_str}.
2. Deploy Sigma log query rule updates to SIEM.
3. Patch remote execution services immediately.
"""
        logger.info(f"Incident report generated for: {incident_details.get('id', 'INC-9999')}")
        return report

    def generate_executive_summary(self, risk_score: float, financial_loss: float, active_threats: int) -> str:
        """Generates a one-page summary designed for CISOs and CEOs."""
        report = f"""# CISO Executive Cyber Risk Summary
**Date:** {datetime.utcnow().strftime("%Y-%m-%d")}

## Strategic KPI Dashboard
- **Active Threat Indicators:** {active_threats}
- **Current Business Risk Score:** {risk_score:.1f}/100
- **Projected Financial Exposure:** ${financial_loss:,.2f} USD

## Actionable Strategy Recommendations
- **Micro-segmentation:** Restrict lateral paths from workstations to critical production database servers.
- **Continuous Auth:** Enforce multi-factor verification prompts for privileged active admin sessions.
- **Resource Patching:** Remediate CISA KEV vulnerabilities present on exposed DMZ web servers.
"""
        logger.info("Executive CISO summary report generated.")
        return report
