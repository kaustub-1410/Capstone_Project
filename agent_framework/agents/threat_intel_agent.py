"""
Threat Intelligence Agent — Monitors CVEs, MITRE ATT&CK, and CISA KEV.

Maintains an exploit database, correlates vulnerabilities with topology hosts,
and provides actionable intelligence to other agents. Works offline using
the existing MITRE matrix and cached CVE data; can integrate with live
NVD/CISA feeds when deployed.

Part of Phase 1: Multi-Agent Society.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from agent_framework.cognitive import CognitiveAgent
from agent_framework.reasoning import (
    DecisionExplanation,
    Evidence,
    EvidenceType,
)
from attack_engine.mitre import MITRE_ATTACK_MAP
from simulation_engine.core import SimulationEngine
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)

# Built-in CVE intelligence database (offline mode)
# In production, this is populated from NVD, CISA KEV, ExploitDB feeds
CVE_INTELLIGENCE_DB: Dict[str, Dict[str, Any]] = {
    "CVE-2017-0144": {
        "name": "EternalBlue",
        "description": "SMB Remote Code Execution via MS17-010",
        "cvss": 9.8,
        "epss": 0.975,
        "exploited_in_wild": True,
        "affected_service": "SMB",
        "affected_port": 445,
        "mitre_techniques": ["T1210", "T1021.002"],
        "cisa_kev": True,
        "remediation": "Apply MS17-010 patch, disable SMBv1",
    },
    "CVE-2021-44228": {
        "name": "Log4Shell",
        "description": "Apache Log4j2 JNDI Injection RCE",
        "cvss": 10.0,
        "epss": 0.976,
        "exploited_in_wild": True,
        "affected_service": "HTTP",
        "affected_port": 80,
        "mitre_techniques": ["T1190", "T1059"],
        "cisa_kev": True,
        "remediation": "Upgrade Log4j to 2.17.1+, set LOG4J_FORMAT_MSG_NO_LOOKUPS=true",
    },
    "CVE-2021-41773": {
        "name": "Apache Path Traversal",
        "description": "Apache HTTP Server 2.4.49 path traversal and RCE",
        "cvss": 7.5,
        "epss": 0.943,
        "exploited_in_wild": True,
        "affected_service": "HTTP",
        "affected_port": 80,
        "mitre_techniques": ["T1190"],
        "cisa_kev": True,
        "remediation": "Upgrade Apache HTTP Server to 2.4.51+",
    },
    "CVE-2020-1472": {
        "name": "Zerologon",
        "description": "Netlogon elevation of privilege vulnerability",
        "cvss": 10.0,
        "epss": 0.968,
        "exploited_in_wild": True,
        "affected_service": "LDAP",
        "affected_port": 389,
        "mitre_techniques": ["T1068", "T1003.006"],
        "cisa_kev": True,
        "remediation": "Apply KB4571694, enforce secure RPC",
    },
    "CVE-2021-34527": {
        "name": "PrintNightmare",
        "description": "Windows Print Spooler RCE",
        "cvss": 8.8,
        "epss": 0.950,
        "exploited_in_wild": True,
        "affected_service": "RPC",
        "affected_port": 135,
        "mitre_techniques": ["T1210", "T1068"],
        "cisa_kev": True,
        "remediation": "Disable Print Spooler service, apply KB5004945",
    },
    "CVE-2023-44228": {
        "name": "Citrix Bleed",
        "description": "Citrix NetScaler ADC buffer overflow",
        "cvss": 9.4,
        "epss": 0.910,
        "exploited_in_wild": True,
        "affected_service": "HTTPS",
        "affected_port": 443,
        "mitre_techniques": ["T1190"],
        "cisa_kev": True,
        "remediation": "Apply Citrix patch CTX579459",
    },
}


class ThreatIntelAgent(CognitiveAgent):
    """
    Monitors CVEs, MITRE ATT&CK, and CISA KEV catalogs.

    Responsibilities:
    - Maintain exploit database with CVSS and EPSS scoring
    - Correlate discovered vulnerabilities with topology hosts
    - Prioritize threats based on exploitability and asset criticality
    - Generate intelligence reports for other agents
    """

    def __init__(self, agent_id: str = "ThreatIntel-01", **kwargs):
        super().__init__(agent_id=agent_id, role="threat_intel", **kwargs)
        self.cve_database: Dict[str, Dict[str, Any]] = dict(CVE_INTELLIGENCE_DB)
        self.monitored_cves: List[str] = []
        self.intelligence_reports: List[Dict[str, Any]] = []
        logger.info(f"ThreatIntelAgent {agent_id} initialized with {len(self.cve_database)} CVEs in database")

    def reason(
        self, sim: SimulationEngine, topo: NetworkTopology
    ) -> Optional[DecisionExplanation]:
        """Analyze topology for known vulnerabilities and generate intelligence."""
        self.reasoning_engine.begin_reasoning()

        # Step 1: Scan topology for all CVEs present
        self.reasoning_engine.add_step(
            observation="Scanning network topology for known vulnerabilities",
            hypothesis="Hosts may be running services with known CVEs",
            confidence=0.95,
        )

        host_vulns: Dict[str, List[Dict[str, Any]]] = {}
        critical_findings: List[Dict[str, Any]] = []

        for host_id, host in topo.hosts.items():
            if host.isolated:
                continue
            for service in host.services:
                for cve_id in service.vulnerabilities:
                    intel = self.cve_database.get(cve_id)
                    if intel:
                        finding = {
                            "host_id": host_id,
                            "host_ip": host.ip,
                            "host_role": host.role,
                            "service": service.name,
                            "port": service.port,
                            "cve_id": cve_id,
                            "cve_name": intel["name"],
                            "cvss": intel["cvss"],
                            "epss": intel["epss"],
                            "exploited_in_wild": intel["exploited_in_wild"],
                            "cisa_kev": intel.get("cisa_kev", False),
                            "remediation": intel["remediation"],
                        }
                        if host_id not in host_vulns:
                            host_vulns[host_id] = []
                        host_vulns[host_id].append(finding)

                        if intel["cvss"] >= 9.0 or intel["exploited_in_wild"]:
                            critical_findings.append(finding)

        # Step 2: Prioritize findings
        self.reasoning_engine.add_step(
            observation=f"Found {sum(len(v) for v in host_vulns.values())} vulnerability instances across {len(host_vulns)} hosts",
            hypothesis="Critical CVEs on high-value assets require immediate attention",
            evidence=[
                Evidence(
                    evidence_type=EvidenceType.INTELLIGENCE,
                    description=f"Critical finding: {f['cve_name']} ({f['cve_id']}) on {f['host_id']} (CVSS={f['cvss']})",
                    data=f,
                    weight=f["cvss"] / 10.0,
                )
                for f in critical_findings[:10]
            ],
            confidence=0.9,
            conclusion=f"{len(critical_findings)} critical findings requiring immediate action",
        )

        # Step 3: Determine highest-priority recommendation
        if critical_findings:
            # Sort by composite risk: CVSS * EPSS * role_weight
            role_weights = {
                "domain_controller": 3.0,
                "db_server": 2.5,
                "web_server": 2.0,
                "file_server": 1.5,
                "workstation": 1.0,
            }
            for f in critical_findings:
                f["risk_score"] = (
                    f["cvss"] * f["epss"] * role_weights.get(f["host_role"], 1.0)
                )
            critical_findings.sort(key=lambda x: x["risk_score"], reverse=True)
            top = critical_findings[0]

            self.reasoning_engine.add_step(
                observation=f"Highest risk: {top['cve_name']} on {top['host_id']} (risk_score={top['risk_score']:.2f})",
                hypothesis="This vulnerability should be the top priority for patching",
                confidence=0.92,
                conclusion=f"Recommend patching {top['cve_id']} on {top['host_id']}",
            )

            # Store intelligence in knowledge base
            self.knowledge.assert_fact(
                category="vulnerability",
                key=f"{top['host_id']}_{top['cve_id']}",
                value=top,
                confidence=0.95,
                source="intelligence",
            )

            # Generate intelligence report
            report = {
                "timestamp": datetime.utcnow().isoformat(),
                "total_hosts_scanned": len(topo.hosts),
                "vulnerable_hosts": len(host_vulns),
                "critical_findings": len(critical_findings),
                "top_priority": top,
                "all_findings": critical_findings[:20],
            }
            self.intelligence_reports.append(report)

            return self.reasoning_engine.generate_explanation(
                decision="intelligence_report",
                reason=f"Critical vulnerability {top['cve_name']} ({top['cve_id']}, CVSS={top['cvss']}) "
                       f"found on {top['host_id']} ({top['host_role']}). "
                       f"Exploited in the wild: {top['exploited_in_wild']}. "
                       f"Remediation: {top['remediation']}",
                affected_assets=[f["host_id"] for f in critical_findings[:5]],
                recommended_actions=[
                    f"Patch {top['cve_id']} on {top['host_id']}: {top['remediation']}",
                    f"Prioritize {len(critical_findings)} critical vulnerabilities",
                ],
                mitre_techniques=self.cve_database.get(top["cve_id"], {}).get(
                    "mitre_techniques", []
                ),
            )
        else:
            self.reasoning_engine.add_step(
                observation="No critical vulnerabilities found in current topology",
                confidence=0.8,
                conclusion="Network posture appears acceptable",
            )
            return self.reasoning_engine.generate_explanation(
                decision="no_action",
                reason="No critical vulnerabilities detected in current network topology",
                affected_assets=[],
                recommended_actions=["Continue monitoring for new CVE disclosures"],
            )

    def explain(self) -> str:
        """Return human-readable explanation of last intelligence analysis."""
        if self.last_explanation:
            return self.last_explanation.to_summary()
        return "No intelligence analysis performed yet."

    def get_cve_info(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up detailed CVE information from the intelligence database."""
        return self.cve_database.get(cve_id)

    def get_latest_report(self) -> Optional[Dict[str, Any]]:
        """Retrieve the most recent intelligence report."""
        return self.intelligence_reports[-1] if self.intelligence_reports else None

    def register_cve(self, cve_id: str, intel: Dict[str, Any]) -> None:
        """Register a new CVE in the intelligence database."""
        self.cve_database[cve_id] = intel
        self.monitored_cves.append(cve_id)
        logger.info(f"Registered new CVE: {cve_id} ({intel.get('name', 'Unknown')})")
