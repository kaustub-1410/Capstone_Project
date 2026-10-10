import json
import logging
from typing import Dict, Any, List
from llm_orchestration.client import UnifiedLLMClient

logger = logging.getLogger(__name__)

class StrategicPlannerAgent:
    """LLM agent responsible for mapping attacker steps and finding target nodes."""
    def __init__(self, client: UnifiedLLMClient):
        self.client = client

    def select_attack_target(self, host_states: List[Dict[str, Any]], risk_scores: Dict[str, float]) -> Dict[str, Any]:
        system_prompt = "You are a Principal Security Architect and Red Teaming Strategist. You output only valid JSON."
        
        prompt = f"""
Given the following enterprise hosts state summary:
{json.dumps(host_states, indent=2)}

And the calculated GNN attack path risk scoring index:
{json.dumps(risk_scores, indent=2)}

Analyze the graph topology and determine the next target system to attack.
Select the optimal host to compromise or move laterally into.

Return a valid JSON object using precisely the structure below:
{{
    "thought": "Reasoning explaining attack path choices, OSINT findings, and GNN risk score validations.",
    "action": "network_scan" | "phishing_email" | "exploit_service" | "credentials_dump" | "lateral_movement_smb",
    "target": "<Host ID to attack>",
    "explanation": "Summarized reason for attack action."
}}
"""
        raw_response = self.client.generate_completion(prompt, system_prompt, json_mode=True)
        try:
            return json.loads(raw_response)
        except Exception as e:
            logger.error(f"Failed to parse JSON for StrategicPlannerAgent: {e}. Raw response: {raw_response}")
            return {"thought": "Parsing failure", "action": "network_scan", "target": host_states[0]["id"] if host_states else "WS-01"}


class TacticalReasoningAgent:
    """LLM agent that selects CVE payloads and exploits for targeting services."""
    def __init__(self, client: UnifiedLLMClient):
        self.client = client

    def select_exploit(self, target_host: Dict[str, Any]) -> Dict[str, Any]:
        system_prompt = "You are an Exploit Development Researcher and Penetration Testing Agent. You output only valid JSON."
        
        prompt = f"""
We have targeted host: {json.dumps(target_host, indent=2)}.

Determine the most appropriate CVE or exploitation action name for this host's running services.
Ensure you match vulnerabilities list correctly.

Return a valid JSON object matching the schema below:
{{
    "thought": "Explain exploit mapping logic based on services running and vulnerabilities.",
    "service_name": "<Target service to exploit (e.g. SMB, HTTP)>",
    "exploit_id": "<CVE id or exploit action identifier>"
}}
"""
        raw_response = self.client.generate_completion(prompt, system_prompt, json_mode=True)
        try:
            return json.loads(raw_response)
        except Exception as e:
            logger.error(f"Failed to parse JSON for TacticalReasoningAgent: {e}")
            return {"thought": "Parsing failure", "service_name": "SMB", "exploit_id": "CVE-2017-0144"}


class IncidentAnalysisAgent:
    """LLM agent that processes telemetry alerts, triages incidents, and plans isolation."""
    def __init__(self, client: UnifiedLLMClient):
        self.client = client

    def analyze_telemetry_alerts(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        system_prompt = "You are a Senior Threat Hunter and Incident Response Specialist. You output only valid JSON."
        
        prompt = f"""
Review the following active security telemetry alerts:
{json.dumps(alerts, indent=2)}

Triage the alerts to identify the compromised hosts that pose the highest threat to the Active Directory domain controller.
Recommend which node should be isolated or patched immediately.

Return a valid JSON object matching the schema:
{{
    "thought": "Detail triage logic, telemetry indicators, alert matching, and threat score.",
    "action": "isolate_host" | "patch_service" | "restore_backup" | "block_port",
    "target": "<Host ID of node to remediate>",
    "service": "<Service to patch if applicable or null>"
}}
"""
        raw_response = self.client.generate_completion(prompt, system_prompt, json_mode=True)
        try:
            return json.loads(raw_response)
        except Exception as e:
            logger.error(f"Failed to parse JSON for IncidentAnalysisAgent: {e}")
            return {"thought": "Parsing failure", "action": "isolate_host", "target": alerts[0].get("host_id", "WS-01") if alerts else "WS-01"}
