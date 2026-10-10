import logging
from typing import Dict, Any, Optional
from shared.models import Host
from simulation_engine.network import NetworkTopology
from telemetry_service.producer import TelemetryProducer

logger = logging.getLogger(__name__)

class DefenseExecutor:
    def __init__(self, telemetry_producer: TelemetryProducer):
        self.telemetry = telemetry_producer

    def execute_action(self, action_name: str, run_id: Any, topo: NetworkTopology, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Executes a defensive containment/remediation action and creates telemetry logs."""
        target_id = payload.get("target")
        target_host: Optional[Host] = topo.hosts.get(target_id) if target_id else None
        
        result = {"status": "failed", "action": action_name}

        if action_name == "isolate_host":
            # Isolate compromised node
            if target_host and not target_host.isolated:
                target_host.isolated = True
                topo.sync_host_to_neo4j(target_host)
                
                self.telemetry.log_event(
                    run_id=run_id,
                    host_id=target_id,
                    event_type="Firewall_Log",
                    source="Network Firewall",
                    severity="INFO",
                    message=f"Host isolated: all inbound/outbound communication blocked for {target_host.ip}.",
                    metadata={"host_name": target_host.name}
                )
                result["status"] = "success"

        elif action_name == "patch_service":
            # Patch service vulnerability
            service_name = payload.get("service")
            if target_host:
                matched_service = next((s for s in target_host.services if s.name == service_name), None)
                if matched_service and matched_service.vulnerabilities:
                    removed_cves = matched_service.vulnerabilities.copy()
                    matched_service.vulnerabilities.clear()
                    topo.sync_host_to_neo4j(target_host)
                    
                    self.telemetry.log_event(
                        run_id=run_id,
                        host_id=target_id,
                        event_type="Sysmon_ProcessCreation",
                        source="Microsoft-Windows-Sysmon",
                        severity="INFO",
                        message=f"Patch management routine successfully completed for service {service_name}.",
                        metadata={"patched_cves": removed_cves}
                    )
                    result["status"] = "success"

        elif action_name == "block_port":
            # Firewall rule update
            port = payload.get("port")
            if target_host:
                self.telemetry.log_event(
                    run_id=run_id,
                    host_id=target_id,
                    event_type="Firewall_Log",
                    source="Network Firewall",
                    severity="INFO",
                    message=f"Firewall policy updated: block incoming traffic on port {port}.",
                    metadata={"blocked_port": port}
                )
                result["status"] = "success"

        elif action_name == "restore_backup":
            # Recovery Action
            if target_host and target_host.compromised:
                target_host.compromised = False
                target_host.compromised_by = None
                target_host.credentials_dumped = False
                target_host.isolated = False
                topo.sync_host_to_neo4j(target_host)
                
                self.telemetry.log_event(
                    run_id=run_id,
                    host_id=target_id,
                    event_type="Backup_Log",
                    source="System Recovery",
                    severity="INFO",
                    message=f"System state successfully restored to last clean snapshot for {target_host.ip}.",
                    metadata={"host_name": target_host.name}
                )
                result["status"] = "success"

        return result
