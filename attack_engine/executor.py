import random
import logging
from typing import Dict, Any, Optional
from shared.models import Host, Service
from simulation_engine.network import NetworkTopology
from telemetry_service.producer import TelemetryProducer
from attack_engine.mitre import get_mitre_mapping

logger = logging.getLogger(__name__)

class AttackExecutor:
    def __init__(self, telemetry_producer: TelemetryProducer):
        self.telemetry = telemetry_producer

    def execute_action(self, action_name: str, run_id: Any, topo: NetworkTopology, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Executes an attack event and logs telemetry corresponding to the MITRE ATT&CK technique."""
        mapping = get_mitre_mapping(action_name)
        target_id = payload.get("target")
        source_id = payload.get("source")
        
        target_host: Optional[Host] = topo.hosts.get(target_id) if target_id else None
        
        result = {"status": "failed", "action": action_name, "mitre": mapping}

        if action_name == "network_scan":
            # Discovery Phase
            if target_host:
                services_info = [{"port": s.port, "name": s.name} for s in target_host.services]
                self.telemetry.log_event(
                    run_id=run_id,
                    host_id=target_id,
                    event_type="Firewall_Log",
                    source="Network Firewall",
                    severity="WARNING",
                    message=f"Network scan detected from external source to IP {target_host.ip}.",
                    metadata={"scanned_ports": [s.port for s in target_host.services], "mitre": mapping}
                )
                result["status"] = "success"
                result["details"] = services_info
                
        elif action_name == "phishing_email":
            # Initial Access Phase
            user_username = payload.get("user")
            user = topo.users.get(user_username)
            if user and target_host:
                clicked = random.random() < user.phishing_susceptibility
                self.telemetry.log_event(
                    run_id=run_id,
                    host_id=target_host.id,
                    event_type="Email_Log",
                    source="MailServer",
                    severity="INFO",
                    message=f"Phishing email received by user {user_username}.",
                    metadata={"clicked": clicked, "mitre": mapping}
                )
                if clicked:
                    # User clicked attachment
                    self.telemetry.log_event(
                        run_id=run_id,
                        host_id=target_host.id,
                        event_type="Sysmon_ProcessCreation",
                        source="Microsoft-Windows-Sysmon",
                        severity="CRITICAL",
                        message=f"Process execution spawned from outlook.exe on {target_host.name}.",
                        metadata={"parent_process": "outlook.exe", "process": "powershell.exe -enc ...", "mitre": mapping}
                    )
                    target_host.compromised = True
                    topo.sync_host_to_neo4j(target_host)
                    result["status"] = "success"
                    
        elif action_name == "exploit_service":
            # Remote Exploitation
            service_name = payload.get("service")
            if target_host:
                matched_service = next((s for s in target_host.services if s.name == service_name), None)
                if matched_service and matched_service.vulnerabilities:
                    # Exploit matches a vulnerability
                    self.telemetry.log_event(
                        run_id=run_id,
                        host_id=target_host.id,
                        event_type="IDS_Alert",
                        source="Snort IDS",
                        severity="CRITICAL",
                        message=f"IDS signature match for service exploit on port {matched_service.port}.",
                        metadata={"cves": matched_service.vulnerabilities, "mitre": mapping}
                    )
                    target_host.compromised = True
                    topo.sync_host_to_neo4j(target_host)
                    result["status"] = "success"

        elif action_name == "credentials_dump":
            # Credential Access
            if target_host and target_host.compromised:
                target_host.credentials_dumped = True
                self.telemetry.log_event(
                    run_id=run_id,
                    host_id=target_host.id,
                    event_type="Sysmon_AccessMask",
                    source="Microsoft-Windows-Sysmon",
                    severity="CRITICAL",
                    message=f"Process lsass.exe was accessed with suspicious privileges.",
                    metadata={"mitre": mapping}
                )
                result["status"] = "success"

        elif action_name == "lateral_movement_smb":
            # Lateral Movement
            source_host = topo.hosts.get(source_id)
            if source_host and source_host.compromised and target_host and not target_host.compromised:
                # Check network connectivity
                has_connection = any((h1 == source_id and h2 == target_id) or (h2 == source_id and h1 == target_id) for h1, h2 in topo.connections)
                if has_connection and not target_host.isolated:
                    self.telemetry.log_event(
                        run_id=run_id,
                        host_id=target_host.id,
                        event_type="Auth_Log",
                        source="Windows Event Log",
                        severity="WARNING",
                        message=f"Successful SMB logon from {source_host.ip} to {target_host.ip}.",
                        metadata={"logon_type": 3, "mitre": mapping}
                    )
                    target_host.compromised = True
                    topo.sync_host_to_neo4j(target_host)
                    result["status"] = "success"

        elif action_name == "data_exfiltration":
            # Exfiltration
            if target_host and target_host.compromised:
                self.telemetry.log_event(
                    run_id=run_id,
                    host_id=target_host.id,
                    event_type="Sysmon_NetworkConnection",
                    source="Microsoft-Windows-Sysmon",
                    severity="WARNING",
                    message=f"Data transfer initiated to external IP over DNS port 53.",
                    metadata={"exfil_size_bytes": 1048576, "mitre": mapping}
                )
                result["status"] = "success"

        elif action_name == "ransomware_encryption":
            # Impact
            if target_host and target_host.compromised:
                self.telemetry.log_event(
                    run_id=run_id,
                    host_id=target_host.id,
                    event_type="Sysmon_FileWrite",
                    source="Microsoft-Windows-Sysmon",
                    severity="CRITICAL",
                    message=f"Ransomware activity detected: large batch file rename/overwrite operations.",
                    metadata={"extension": ".locked", "mitre": mapping}
                )
                result["status"] = "success"

        return result
