"""
MITRE ATT&CK Navigator Module — Full enterprise matrix with technique tracking,
coverage scoring, detection gap analysis, and Navigator JSON layer export.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  Complete MITRE ATT&CK Enterprise Matrix (Key Techniques)
# ------------------------------------------------------------------ #

MITRE_ENTERPRISE_MATRIX: Dict[str, Dict[str, Any]] = {
    # --- Reconnaissance (TA0043) ---
    "T1595": {"tactic": "Reconnaissance", "name": "Active Scanning", "data_sources": ["Network Traffic"]},
    "T1595.001": {"tactic": "Reconnaissance", "name": "Active Scanning: Scanning IP Blocks", "data_sources": ["Network Traffic"]},
    "T1595.002": {"tactic": "Reconnaissance", "name": "Active Scanning: Vulnerability Scanning", "data_sources": ["Network Traffic"]},
    "T1589": {"tactic": "Reconnaissance", "name": "Gather Victim Identity Information", "data_sources": ["N/A"]},
    "T1590": {"tactic": "Reconnaissance", "name": "Gather Victim Network Information", "data_sources": ["N/A"]},
    "T1591": {"tactic": "Reconnaissance", "name": "Gather Victim Org Information", "data_sources": ["N/A"]},
    "T1598": {"tactic": "Reconnaissance", "name": "Phishing for Information", "data_sources": ["Email"]},

    # --- Resource Development (TA0042) ---
    "T1583": {"tactic": "Resource Development", "name": "Acquire Infrastructure", "data_sources": ["Domain Registration"]},
    "T1587": {"tactic": "Resource Development", "name": "Develop Capabilities", "data_sources": ["Malware Samples"]},
    "T1588": {"tactic": "Resource Development", "name": "Obtain Capabilities", "data_sources": ["Malware Samples"]},
    "T1585": {"tactic": "Resource Development", "name": "Establish Accounts", "data_sources": ["Social Media"]},

    # --- Initial Access (TA0001) ---
    "T1566": {"tactic": "Initial Access", "name": "Phishing", "data_sources": ["Email Gateway", "Application Log"]},
    "T1566.001": {"tactic": "Initial Access", "name": "Phishing: Spearphishing Attachment", "data_sources": ["Email Gateway", "File Monitoring"]},
    "T1566.002": {"tactic": "Initial Access", "name": "Phishing: Spearphishing Link", "data_sources": ["Email Gateway", "Web Proxy"]},
    "T1190": {"tactic": "Initial Access", "name": "Exploit Public-Facing Application", "data_sources": ["Application Log", "Network IDS"]},
    "T1133": {"tactic": "Initial Access", "name": "External Remote Services", "data_sources": ["Authentication Log"]},
    "T1078": {"tactic": "Initial Access", "name": "Valid Accounts", "data_sources": ["Authentication Log"]},
    "T1199": {"tactic": "Initial Access", "name": "Trusted Relationship", "data_sources": ["Authentication Log"]},
    "T1195": {"tactic": "Initial Access", "name": "Supply Chain Compromise", "data_sources": ["File Monitoring"]},

    # --- Execution (TA0002) ---
    "T1059": {"tactic": "Execution", "name": "Command and Scripting Interpreter", "data_sources": ["Process Monitoring", "Sysmon"]},
    "T1059.001": {"tactic": "Execution", "name": "PowerShell", "data_sources": ["PowerShell Logs", "Sysmon"]},
    "T1059.003": {"tactic": "Execution", "name": "Windows Command Shell", "data_sources": ["Process Monitoring"]},
    "T1059.004": {"tactic": "Execution", "name": "Unix Shell", "data_sources": ["Process Monitoring"]},
    "T1203": {"tactic": "Execution", "name": "Exploitation for Client Execution", "data_sources": ["Process Monitoring"]},
    "T1210": {"tactic": "Execution", "name": "Exploitation of Remote Services", "data_sources": ["Network IDS", "Process Monitoring"]},
    "T1053": {"tactic": "Execution", "name": "Scheduled Task/Job", "data_sources": ["Process Monitoring", "Scheduled Tasks"]},
    "T1053.005": {"tactic": "Execution", "name": "Scheduled Task", "data_sources": ["Windows Event Log"]},
    "T1047": {"tactic": "Execution", "name": "Windows Management Instrumentation", "data_sources": ["WMI Logs"]},
    "T1204": {"tactic": "Execution", "name": "User Execution", "data_sources": ["Process Monitoring"]},

    # --- Persistence (TA0003) ---
    "T1547": {"tactic": "Persistence", "name": "Boot or Logon Autostart Execution", "data_sources": ["Registry", "File Monitoring"]},
    "T1547.001": {"tactic": "Persistence", "name": "Registry Run Keys / Startup Folder", "data_sources": ["Registry"]},
    "T1136": {"tactic": "Persistence", "name": "Create Account", "data_sources": ["Authentication Log"]},
    "T1098": {"tactic": "Persistence", "name": "Account Manipulation", "data_sources": ["Authentication Log"]},
    "T1543": {"tactic": "Persistence", "name": "Create or Modify System Process", "data_sources": ["Process Monitoring"]},
    "T1505": {"tactic": "Persistence", "name": "Server Software Component", "data_sources": ["File Monitoring"]},
    "T1505.003": {"tactic": "Persistence", "name": "Web Shell", "data_sources": ["File Monitoring", "Web Logs"]},

    # --- Privilege Escalation (TA0004) ---
    "T1068": {"tactic": "Privilege Escalation", "name": "Exploitation for Privilege Escalation", "data_sources": ["Process Monitoring"]},
    "T1134": {"tactic": "Privilege Escalation", "name": "Access Token Manipulation", "data_sources": ["Process Monitoring"]},
    "T1134.001": {"tactic": "Privilege Escalation", "name": "Token Impersonation/Theft", "data_sources": ["Process Monitoring"]},
    "T1484": {"tactic": "Privilege Escalation", "name": "Domain Policy Modification", "data_sources": ["Active Directory"]},
    "T1484.001": {"tactic": "Privilege Escalation", "name": "Group Policy Modification", "data_sources": ["Active Directory"]},
    "T1548": {"tactic": "Privilege Escalation", "name": "Abuse Elevation Control Mechanism", "data_sources": ["Process Monitoring"]},

    # --- Defense Evasion (TA0005) ---
    "T1562": {"tactic": "Defense Evasion", "name": "Impair Defenses", "data_sources": ["Process Monitoring", "Security Software"]},
    "T1562.001": {"tactic": "Defense Evasion", "name": "Disable or Modify Tools", "data_sources": ["Security Software"]},
    "T1070": {"tactic": "Defense Evasion", "name": "Indicator Removal", "data_sources": ["File Monitoring", "Log Analysis"]},
    "T1070.001": {"tactic": "Defense Evasion", "name": "Clear Windows Event Logs", "data_sources": ["Windows Event Log"]},
    "T1036": {"tactic": "Defense Evasion", "name": "Masquerading", "data_sources": ["File Monitoring"]},
    "T1027": {"tactic": "Defense Evasion", "name": "Obfuscated Files or Information", "data_sources": ["File Analysis"]},
    "T1218": {"tactic": "Defense Evasion", "name": "System Binary Proxy Execution", "data_sources": ["Process Monitoring"]},
    "T1055": {"tactic": "Defense Evasion", "name": "Process Injection", "data_sources": ["Process Monitoring", "Sysmon"]},

    # --- Credential Access (TA0006) ---
    "T1003": {"tactic": "Credential Access", "name": "OS Credential Dumping", "data_sources": ["Process Monitoring", "Sysmon"]},
    "T1003.001": {"tactic": "Credential Access", "name": "LSASS Memory", "data_sources": ["Sysmon"]},
    "T1003.003": {"tactic": "Credential Access", "name": "NTDS", "data_sources": ["File Monitoring"]},
    "T1003.006": {"tactic": "Credential Access", "name": "DCSync", "data_sources": ["Active Directory", "Network Traffic"]},
    "T1558": {"tactic": "Credential Access", "name": "Steal or Forge Kerberos Tickets", "data_sources": ["Authentication Log"]},
    "T1558.001": {"tactic": "Credential Access", "name": "Golden Ticket", "data_sources": ["Authentication Log"]},
    "T1558.002": {"tactic": "Credential Access", "name": "Silver Ticket", "data_sources": ["Authentication Log"]},
    "T1558.003": {"tactic": "Credential Access", "name": "Kerberoasting", "data_sources": ["Authentication Log"]},
    "T1558.004": {"tactic": "Credential Access", "name": "AS-REP Roasting", "data_sources": ["Authentication Log"]},
    "T1110": {"tactic": "Credential Access", "name": "Brute Force", "data_sources": ["Authentication Log"]},
    "T1557": {"tactic": "Credential Access", "name": "Adversary-in-the-Middle", "data_sources": ["Network Traffic"]},
    "T1552": {"tactic": "Credential Access", "name": "Unsecured Credentials", "data_sources": ["File Monitoring"]},
    "T1552.005": {"tactic": "Credential Access", "name": "Cloud Instance Metadata API", "data_sources": ["Cloud Logs"]},

    # --- Discovery (TA0007) ---
    "T1046": {"tactic": "Discovery", "name": "Network Service Discovery", "data_sources": ["Network Traffic", "Firewall Logs"]},
    "T1087": {"tactic": "Discovery", "name": "Account Discovery", "data_sources": ["Process Monitoring", "Authentication Log"]},
    "T1018": {"tactic": "Discovery", "name": "Remote System Discovery", "data_sources": ["Process Monitoring"]},
    "T1069": {"tactic": "Discovery", "name": "Permission Groups Discovery", "data_sources": ["Process Monitoring"]},
    "T1082": {"tactic": "Discovery", "name": "System Information Discovery", "data_sources": ["Process Monitoring"]},
    "T1016": {"tactic": "Discovery", "name": "System Network Configuration Discovery", "data_sources": ["Process Monitoring"]},
    "T1049": {"tactic": "Discovery", "name": "System Network Connections Discovery", "data_sources": ["Process Monitoring"]},
    "T1083": {"tactic": "Discovery", "name": "File and Directory Discovery", "data_sources": ["Process Monitoring"]},
    "T1135": {"tactic": "Discovery", "name": "Network Share Discovery", "data_sources": ["Process Monitoring"]},
    "T1482": {"tactic": "Discovery", "name": "Domain Trust Discovery", "data_sources": ["Active Directory"]},

    # --- Lateral Movement (TA0008) ---
    "T1021": {"tactic": "Lateral Movement", "name": "Remote Services", "data_sources": ["Authentication Log"]},
    "T1021.001": {"tactic": "Lateral Movement", "name": "Remote Desktop Protocol", "data_sources": ["Authentication Log"]},
    "T1021.002": {"tactic": "Lateral Movement", "name": "SMB/Windows Admin Shares", "data_sources": ["Authentication Log"]},
    "T1021.003": {"tactic": "Lateral Movement", "name": "Distributed Component Object Model", "data_sources": ["Process Monitoring"]},
    "T1021.006": {"tactic": "Lateral Movement", "name": "Windows Remote Management", "data_sources": ["Process Monitoring"]},
    "T1550": {"tactic": "Lateral Movement", "name": "Use Alternate Authentication Material", "data_sources": ["Authentication Log"]},
    "T1550.002": {"tactic": "Lateral Movement", "name": "Pass the Hash", "data_sources": ["Authentication Log"]},
    "T1550.003": {"tactic": "Lateral Movement", "name": "Pass the Ticket", "data_sources": ["Authentication Log"]},
    "T1570": {"tactic": "Lateral Movement", "name": "Lateral Tool Transfer", "data_sources": ["File Monitoring"]},

    # --- Collection (TA0009) ---
    "T1005": {"tactic": "Collection", "name": "Data from Local System", "data_sources": ["File Monitoring"]},
    "T1039": {"tactic": "Collection", "name": "Data from Network Shared Drive", "data_sources": ["File Monitoring"]},
    "T1114": {"tactic": "Collection", "name": "Email Collection", "data_sources": ["Email Gateway"]},
    "T1560": {"tactic": "Collection", "name": "Archive Collected Data", "data_sources": ["Process Monitoring"]},
    "T1213": {"tactic": "Collection", "name": "Data from Information Repositories", "data_sources": ["Application Log"]},

    # --- Command and Control (TA0011) ---
    "T1071": {"tactic": "Command and Control", "name": "Application Layer Protocol", "data_sources": ["Network Traffic"]},
    "T1071.001": {"tactic": "Command and Control", "name": "Web Protocols", "data_sources": ["Network Traffic"]},
    "T1071.004": {"tactic": "Command and Control", "name": "DNS", "data_sources": ["DNS Logs"]},
    "T1105": {"tactic": "Command and Control", "name": "Ingress Tool Transfer", "data_sources": ["Network Traffic"]},
    "T1572": {"tactic": "Command and Control", "name": "Protocol Tunneling", "data_sources": ["Network Traffic"]},
    "T1573": {"tactic": "Command and Control", "name": "Encrypted Channel", "data_sources": ["Network Traffic"]},
    "T1219": {"tactic": "Command and Control", "name": "Remote Access Software", "data_sources": ["Process Monitoring"]},
    "T1090": {"tactic": "Command and Control", "name": "Proxy", "data_sources": ["Network Traffic"]},

    # --- Exfiltration (TA0010) ---
    "T1048": {"tactic": "Exfiltration", "name": "Exfiltration Over Alternative Protocol", "data_sources": ["Network Traffic"]},
    "T1048.001": {"tactic": "Exfiltration", "name": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "data_sources": ["Network Traffic"]},
    "T1041": {"tactic": "Exfiltration", "name": "Exfiltration Over C2 Channel", "data_sources": ["Network Traffic"]},
    "T1567": {"tactic": "Exfiltration", "name": "Exfiltration Over Web Service", "data_sources": ["Network Traffic"]},
    "T1029": {"tactic": "Exfiltration", "name": "Scheduled Transfer", "data_sources": ["Network Traffic"]},
    "T1537": {"tactic": "Exfiltration", "name": "Transfer Data to Cloud Account", "data_sources": ["Cloud Logs"]},

    # --- Impact (TA0040) ---
    "T1486": {"tactic": "Impact", "name": "Data Encrypted for Impact", "data_sources": ["File Monitoring", "Process Monitoring"]},
    "T1490": {"tactic": "Impact", "name": "Inhibit System Recovery", "data_sources": ["Process Monitoring"]},
    "T1489": {"tactic": "Impact", "name": "Service Stop", "data_sources": ["Process Monitoring"]},
    "T1491": {"tactic": "Impact", "name": "Defacement", "data_sources": ["File Monitoring", "Web Logs"]},
    "T1485": {"tactic": "Impact", "name": "Data Destruction", "data_sources": ["File Monitoring"]},
    "T1529": {"tactic": "Impact", "name": "System Shutdown/Reboot", "data_sources": ["Process Monitoring"]},
    "T1498": {"tactic": "Impact", "name": "Network Denial of Service", "data_sources": ["Network Traffic"]},
    "T1499": {"tactic": "Impact", "name": "Endpoint Denial of Service", "data_sources": ["Network Traffic"]},
    "T1528": {"tactic": "Impact", "name": "Steal Application Access Token", "data_sources": ["Cloud Logs", "OAuth Logs"]},
    "T1530": {"tactic": "Impact", "name": "Data from Cloud Storage", "data_sources": ["Cloud Logs"]},
    "T1611": {"tactic": "Impact", "name": "Escape to Host", "data_sources": ["Container Logs"]},
}

# Ordered tactic names for matrix display
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
]


class TechniqueStatus:
    """Tracks the lifecycle status of a single MITRE technique in the simulation."""
    def __init__(self):
        self.used: bool = False
        self.detected: bool = False
        self.mitigated: bool = False
        self.first_used: Optional[datetime] = None
        self.first_detected: Optional[datetime] = None
        self.first_mitigated: Optional[datetime] = None
        self.host_ids: List[str] = []
        self.usage_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "used": self.used,
            "detected": self.detected,
            "mitigated": self.mitigated,
            "first_used": self.first_used.isoformat() if self.first_used else None,
            "first_detected": self.first_detected.isoformat() if self.first_detected else None,
            "first_mitigated": self.first_mitigated.isoformat() if self.first_mitigated else None,
            "host_ids": self.host_ids,
            "usage_count": self.usage_count
        }


class MITRENavigator:
    """
    Full MITRE ATT&CK Navigator implementation for the AMCDS platform.
    
    Tracks technique usage, detection, and mitigation throughout simulation runs.
    Exports in the official ATT&CK Navigator JSON Layer format.
    """

    def __init__(self):
        self.coverage: Dict[str, TechniqueStatus] = defaultdict(TechniqueStatus)

    def record_technique_usage(self, technique_id: str, host_id: str,
                                detected: bool = False, mitigated: bool = False):
        """Record that a technique was used (and optionally detected/mitigated)."""
        status = self.coverage[technique_id]
        now = datetime.utcnow()

        if not status.used:
            status.used = True
            status.first_used = now

        status.usage_count += 1
        if host_id not in status.host_ids:
            status.host_ids.append(host_id)

        if detected and not status.detected:
            status.detected = True
            status.first_detected = now

        if mitigated and not status.mitigated:
            status.mitigated = True
            status.first_mitigated = now

    def mark_detected(self, technique_id: str):
        """Mark a previously used technique as detected."""
        if technique_id in self.coverage:
            status = self.coverage[technique_id]
            if not status.detected:
                status.detected = True
                status.first_detected = datetime.utcnow()

    def mark_mitigated(self, technique_id: str):
        """Mark a previously used technique as mitigated."""
        if technique_id in self.coverage:
            status = self.coverage[technique_id]
            if not status.mitigated:
                status.mitigated = True
                status.first_mitigated = datetime.utcnow()

    # ------------------------------------------------------------------ #
    #  Coverage Analysis
    # ------------------------------------------------------------------ #

    def get_coverage_matrix(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Returns the full matrix organized by tactic, with color-coding:
        - red: used, not detected
        - orange: used, detected but not mitigated
        - green: used, detected and mitigated
        - gray: not observed
        """
        matrix: Dict[str, List[Dict[str, Any]]] = {tactic: [] for tactic in TACTIC_ORDER}

        for tech_id, tech_info in MITRE_ENTERPRISE_MATRIX.items():
            tactic = tech_info["tactic"]
            status = self.coverage.get(tech_id, TechniqueStatus())

            if status.used and status.detected and status.mitigated:
                color = "green"
            elif status.used and status.detected:
                color = "orange"
            elif status.used:
                color = "red"
            else:
                color = "gray"

            entry = {
                "technique_id": tech_id,
                "name": tech_info["name"],
                "color": color,
                "status": status.to_dict(),
                "data_sources": tech_info.get("data_sources", [])
            }

            if tactic in matrix:
                matrix[tactic].append(entry)

        return matrix

    def get_coverage_score(self) -> Dict[str, Any]:
        """
        Computes coverage metrics:
        - Total techniques in matrix
        - Techniques used by attacker
        - Techniques detected by defender
        - Techniques fully mitigated
        - Detection rate (detected / used)
        - Mitigation rate (mitigated / used)
        """
        used = [t_id for t_id, s in self.coverage.items() if s.used]
        detected = [t_id for t_id, s in self.coverage.items() if s.used and s.detected]
        mitigated = [t_id for t_id, s in self.coverage.items() if s.used and s.mitigated]

        total_used = len(used)
        return {
            "total_techniques": len(MITRE_ENTERPRISE_MATRIX),
            "techniques_used": total_used,
            "techniques_detected": len(detected),
            "techniques_mitigated": len(mitigated),
            "detection_rate": round(len(detected) / max(total_used, 1) * 100, 1),
            "mitigation_rate": round(len(mitigated) / max(total_used, 1) * 100, 1),
            "undetected_techniques": [t_id for t_id in used if t_id not in detected]
        }

    def get_detection_gaps(self) -> List[Dict[str, Any]]:
        """Returns techniques that were used but never detected (blind spots)."""
        gaps = []
        for tech_id, status in self.coverage.items():
            if status.used and not status.detected:
                tech_info = MITRE_ENTERPRISE_MATRIX.get(tech_id, {})
                gaps.append({
                    "technique_id": tech_id,
                    "name": tech_info.get("name", "Unknown"),
                    "tactic": tech_info.get("tactic", "Unknown"),
                    "usage_count": status.usage_count,
                    "hosts_affected": status.host_ids,
                    "recommended_data_sources": tech_info.get("data_sources", [])
                })
        gaps.sort(key=lambda g: g["usage_count"], reverse=True)
        return gaps

    def get_tactic_breakdown(self) -> List[Dict[str, Any]]:
        """Per-tactic summary of coverage status."""
        breakdown = []
        for tactic in TACTIC_ORDER:
            tactic_techs = [t_id for t_id, info in MITRE_ENTERPRISE_MATRIX.items()
                           if info["tactic"] == tactic]
            used = sum(1 for t_id in tactic_techs if self.coverage.get(t_id, TechniqueStatus()).used)
            detected = sum(1 for t_id in tactic_techs
                          if self.coverage.get(t_id, TechniqueStatus()).used
                          and self.coverage.get(t_id, TechniqueStatus()).detected)
            mitigated = sum(1 for t_id in tactic_techs
                           if self.coverage.get(t_id, TechniqueStatus()).used
                           and self.coverage.get(t_id, TechniqueStatus()).mitigated)

            breakdown.append({
                "tactic": tactic,
                "total_techniques": len(tactic_techs),
                "used": used,
                "detected": detected,
                "mitigated": mitigated,
                "detection_rate": round(detected / max(used, 1) * 100, 1)
            })
        return breakdown

    # ------------------------------------------------------------------ #
    #  ATT&CK Navigator JSON Export
    # ------------------------------------------------------------------ #

    def export_navigator_json(self, layer_name: str = "AMCDS Simulation Coverage") -> str:
        """
        Exports in the official MITRE ATT&CK Navigator JSON Layer format.
        Compatible with https://mitre-attack.github.io/attack-navigator/
        """
        techniques = []
        for tech_id in MITRE_ENTERPRISE_MATRIX:
            status = self.coverage.get(tech_id, TechniqueStatus())

            # Color mapping for Navigator
            if status.used and status.detected and status.mitigated:
                color = "#00ff00"   # Green — fully handled
                score = 100
            elif status.used and status.detected:
                color = "#ff8c00"   # Orange — detected not mitigated
                score = 50
            elif status.used:
                color = "#ff0000"   # Red — undetected attack
                score = 0
            else:
                color = ""          # No color — not observed
                score = -1

            comment = ""
            if status.used:
                comment = f"Used {status.usage_count}x on hosts: {', '.join(status.host_ids)}"
                if status.detected:
                    comment += " | DETECTED"
                if status.mitigated:
                    comment += " | MITIGATED"

            # Handle sub-technique IDs (e.g., T1566.001)
            tech_entry = {"techniqueID": tech_id}
            if "." in tech_id:
                parts = tech_id.split(".")
                tech_entry["techniqueID"] = parts[0]
                tech_entry["tactic"] = MITRE_ENTERPRISE_MATRIX[tech_id]["tactic"].lower().replace(" ", "-")

            tech_entry.update({
                "color": color,
                "comment": comment,
                "enabled": True,
                "showSubtechniques": False
            })

            if score >= 0:
                tech_entry["score"] = score
            if "." in tech_id:
                tech_entry["showSubtechniques"] = True

            techniques.append(tech_entry)

        layer = {
            "name": layer_name,
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": f"AMCDS simulation coverage layer generated at {datetime.utcnow().isoformat()}",
            "filters": {
                "platforms": ["Windows", "Linux", "macOS", "Network", "Cloud"]
            },
            "sorting": 3,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#ff0000", "#ff8c00", "#00ff00"],
                "minValue": 0,
                "maxValue": 100
            },
            "legendItems": [
                {"label": "Undetected Attack", "color": "#ff0000"},
                {"label": "Detected (Not Mitigated)", "color": "#ff8c00"},
                {"label": "Detected & Mitigated", "color": "#00ff00"}
            ],
            "metadata": [],
            "links": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#205b8f",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False
        }

        return json.dumps(layer, indent=2)

    def reset(self):
        """Clear all tracked technique usage."""
        self.coverage.clear()
