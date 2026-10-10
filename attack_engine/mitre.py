"""
MITRE ATT&CK technique mapping for simulation actions.
Expanded to cover all attack types including Kerberos, AD escalation,
cloud attacks, and container escapes.
"""

from typing import Dict, Any

# Map simulation-level actions to MITRE ATT&CK techniques
MITRE_ATTACK_MAP: Dict[str, Dict[str, str]] = {
    # --- Discovery ---
    "network_scan": {
        "tactic": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery"
    },
    "account_discovery": {
        "tactic": "Discovery",
        "technique_id": "T1087",
        "technique_name": "Account Discovery"
    },
    "network_share_discovery": {
        "tactic": "Discovery",
        "technique_id": "T1135",
        "technique_name": "Network Share Discovery"
    },
    "domain_trust_discovery": {
        "tactic": "Discovery",
        "technique_id": "T1482",
        "technique_name": "Domain Trust Discovery"
    },

    # --- Initial Access ---
    "phishing_email": {
        "tactic": "Initial Access",
        "technique_id": "T1566.001",
        "technique_name": "Phishing: Spearphishing Attachment"
    },
    "exploit_public_app": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application"
    },
    "supply_chain_compromise": {
        "tactic": "Initial Access",
        "technique_id": "T1195",
        "technique_name": "Supply Chain Compromise"
    },

    # --- Execution ---
    "exploit_service": {
        "tactic": "Execution / Lateral Movement",
        "technique_id": "T1210",
        "technique_name": "Exploitation of Remote Services"
    },
    "powershell_execution": {
        "tactic": "Execution",
        "technique_id": "T1059.001",
        "technique_name": "PowerShell"
    },
    "wmi_execution": {
        "tactic": "Execution",
        "technique_id": "T1047",
        "technique_name": "Windows Management Instrumentation"
    },

    # --- Persistence ---
    "scheduled_task_persistence": {
        "tactic": "Persistence",
        "technique_id": "T1053.005",
        "technique_name": "Scheduled Task/Job: Scheduled Task"
    },
    "web_shell": {
        "tactic": "Persistence",
        "technique_id": "T1505.003",
        "technique_name": "Web Shell"
    },
    "registry_run_key": {
        "tactic": "Persistence",
        "technique_id": "T1547.001",
        "technique_name": "Registry Run Keys / Startup Folder"
    },

    # --- Privilege Escalation ---
    "token_impersonation": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1134.001",
        "technique_name": "Token Impersonation/Theft"
    },
    "group_policy_abuse": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1484.001",
        "technique_name": "Group Policy Modification"
    },

    # --- Credential Access ---
    "credentials_dump": {
        "tactic": "Credential Access",
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping"
    },
    "lsass_dump": {
        "tactic": "Credential Access",
        "technique_id": "T1003.001",
        "technique_name": "LSASS Memory"
    },
    "dcsync": {
        "tactic": "Credential Access",
        "technique_id": "T1003.006",
        "technique_name": "DCSync"
    },
    "kerberoasting": {
        "tactic": "Credential Access",
        "technique_id": "T1558.003",
        "technique_name": "Kerberoasting"
    },
    "as_rep_roasting": {
        "tactic": "Credential Access",
        "technique_id": "T1558.004",
        "technique_name": "AS-REP Roasting"
    },
    "golden_ticket": {
        "tactic": "Credential Access",
        "technique_id": "T1558.001",
        "technique_name": "Golden Ticket"
    },
    "silver_ticket": {
        "tactic": "Credential Access",
        "technique_id": "T1558.002",
        "technique_name": "Silver Ticket"
    },

    # --- Lateral Movement ---
    "lateral_movement_smb": {
        "tactic": "Lateral Movement",
        "technique_id": "T1021.002",
        "technique_name": "Remote Services: SMB/Windows Admin Shares"
    },
    "lateral_movement_rdp": {
        "tactic": "Lateral Movement",
        "technique_id": "T1021.001",
        "technique_name": "Remote Desktop Protocol"
    },
    "lateral_movement_winrm": {
        "tactic": "Lateral Movement",
        "technique_id": "T1021.006",
        "technique_name": "Windows Remote Management"
    },
    "pass_the_hash": {
        "tactic": "Lateral Movement",
        "technique_id": "T1550.002",
        "technique_name": "Pass the Hash"
    },
    "pass_the_ticket": {
        "tactic": "Lateral Movement",
        "technique_id": "T1550.003",
        "technique_name": "Pass the Ticket"
    },

    # --- Defense Evasion ---
    "disable_edr": {
        "tactic": "Defense Evasion",
        "technique_id": "T1562.001",
        "technique_name": "Disable or Modify Tools"
    },
    "clear_event_logs": {
        "tactic": "Defense Evasion",
        "technique_id": "T1070.001",
        "technique_name": "Clear Windows Event Logs"
    },
    "process_injection": {
        "tactic": "Defense Evasion",
        "technique_id": "T1055",
        "technique_name": "Process Injection"
    },

    # --- Collection ---
    "data_collection_local": {
        "tactic": "Collection",
        "technique_id": "T1005",
        "technique_name": "Data from Local System"
    },
    "data_collection_share": {
        "tactic": "Collection",
        "technique_id": "T1039",
        "technique_name": "Data from Network Shared Drive"
    },

    # --- Command and Control ---
    "c2_dns": {
        "tactic": "Command and Control",
        "technique_id": "T1071.004",
        "technique_name": "DNS"
    },
    "c2_http": {
        "tactic": "Command and Control",
        "technique_id": "T1071.001",
        "technique_name": "Web Protocols"
    },

    # --- Exfiltration ---
    "data_exfiltration": {
        "tactic": "Exfiltration",
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol"
    },
    "exfil_cloud": {
        "tactic": "Exfiltration",
        "technique_id": "T1537",
        "technique_name": "Transfer Data to Cloud Account"
    },

    # --- Impact ---
    "ransomware_encryption": {
        "tactic": "Impact",
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact"
    },
    "data_destruction": {
        "tactic": "Impact",
        "technique_id": "T1485",
        "technique_name": "Data Destruction"
    },
    "service_stop": {
        "tactic": "Impact",
        "technique_id": "T1489",
        "technique_name": "Service Stop"
    },

    # --- Cloud-specific ---
    "iam_privilege_escalation": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1098",
        "technique_name": "Account Manipulation"
    },
    "ssrf_metadata_exploit": {
        "tactic": "Credential Access",
        "technique_id": "T1552.005",
        "technique_name": "Cloud Instance Metadata API"
    },
    "container_escape": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1611",
        "technique_name": "Escape to Host"
    },
    "cloud_storage_access": {
        "tactic": "Collection",
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage"
    },
}


def get_mitre_mapping(action_name: str) -> Dict[str, str]:
    """Helper to return MITRE ATT&CK tactic, technique ID, and description."""
    return MITRE_ATTACK_MAP.get(action_name, {
        "tactic": "Unknown",
        "technique_id": "T0000",
        "technique_name": "Unknown Technique"
    })
