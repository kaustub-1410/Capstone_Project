"""
Security Copilot Rule Generator — Autogenerates Sigma, YARA, and Snort/Suricata rules
based on threat intelligence indicators and alert contexts.
"""

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class RuleGenerator:
    """
    Translates threat behaviors into network signatures and system log detection rules.
    """

    def generate_sigma_rule(self, event_type: str, details: Dict[str, Any]) -> str:
        """Generates a Sigma rule in YAML format to detect specific system events."""
        rule_title = details.get("title", f"Detect {event_type} event")
        process_name = details.get("process", "cmd.exe")
        
        rule = f"""title: {rule_title}
id: {details.get('id', 'uuid-placeholder')}
status: experimental
description: Auto-generated Sigma rule for system security threat containment.
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image|endswith: '\\{process_name}'
    condition: selection
falsepositives:
    - Administrative scripts
level: high
"""
        logger.info(f"Sigma rule generated for process: {process_name}")
        return rule

    def generate_yara_rule(self, rule_name: str, strings: Dict[str, str]) -> str:
        """Generates a YARA rule for memory and file signature scanning."""
        yara_strings = "\n        ".join([f"${k} = \"{v}\"" for k, v in strings.items()])
        
        rule = f"""rule {rule_name} {{
    meta:
        description = "Auto-generated YARA rule from AMCDS threat intel."
        author = "AMCDS Security Copilot"
        date = "2026-07-06"
    strings:
        {yara_strings}
    condition:
        any of them
}}
"""
        logger.info(f"YARA rule generated: {rule_name}")
        return rule

    def generate_suricata_rule(self, rule_id: int, port: int, payload_content: str, direction: str = "any -> any") -> str:
        """Generates a Suricata/Snort network intrusion detection system rule."""
        rule = f'alert tcp {direction} {port} (msg:"AMCDS Copilot Detected Potential Exploit"; content:"{payload_content}"; sid:{rule_id}; rev:1;)'
        logger.info(f"Suricata rule generated for port: {port}")
        return rule
