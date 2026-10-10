from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from shared.models import Host, TelemetryEvent
from simulation_engine.core import SimulationEngine
from simulation_engine.network import NetworkTopology
import logging
import random

logger = logging.getLogger(__name__)

class BaseAgent(ABC):
    def __init__(self, agent_id: str, role: str):
        self.agent_id = agent_id
        self.role = role
        self.knowledge_base: Dict[str, Any] = {}

    @abstractmethod
    def act(self, sim: SimulationEngine, topo: NetworkTopology) -> Optional[Dict[str, Any]]:
        """Core decision loop to select and return an action payload."""
        pass


class AttackerAgent(BaseAgent):
    def __init__(self, agent_id: str, sophistication: float = 0.8):
        super().__init__(agent_id, "attacker")
        self.sophistication = sophistication
        self.known_hosts: List[str] = []
        self.compromised_hosts: List[str] = []
        self.captured_credentials: List[Dict[str, Any]] = []

    def act(self, sim: SimulationEngine, topo: NetworkTopology) -> Optional[Dict[str, Any]]:
        # A template LLM / RL action choice strategy
        # Find reachable hosts
        if not self.known_hosts:
            # Reconnaissance phase
            workstations = [h.id for h in topo.hosts.values() if h.role == "workstation"]
            if workstations:
                target = random.choice(workstations)
                self.known_hosts.append(target)
                logger.info(f"Attacker {self.agent_id} discovered host {target} through OSINT.")
                return {"action": "reconnaissance", "target": target}
        
        # Select host to exploit
        uncompromised = [h_id for h_id in self.known_hosts if h_id not in self.compromised_hosts]
        if uncompromised:
            target = random.choice(uncompromised)
            host = topo.hosts[target]
            
            # Select exploit if vulnerability matches
            for service in host.services:
                if service.vulnerabilities:
                    exploit_id = random.choice(service.vulnerabilities)
                    logger.info(f"Attacker {self.agent_id} attempting exploit {exploit_id} on {target}:{service.port}")
                    
                    # Probabilistic success simulation
                    success = random.random() < 0.7
                    if success:
                        self.compromised_hosts.append(target)
                        host.compromised = True
                        host.compromised_by = self.agent_id
                        topo.sync_host_to_neo4j(host)
                        logger.info(f"Attacker {self.agent_id} successfully compromised {target}!")
                        return {"action": "exploit", "target": target, "status": "success"}
                    else:
                        logger.info(f"Attacker {self.agent_id} failed exploitation on {target}")
                        return {"action": "exploit", "target": target, "status": "failed"}
                        
        # Lateral movement attempt
        if self.compromised_hosts:
            source = random.choice(self.compromised_hosts)
            # Find connected nodes
            connected_hosts = []
            for h1, h2 in topo.connections:
                if h1 == source and h2 not in self.compromised_hosts:
                    connected_hosts.append(h2)
                elif h2 == source and h1 not in self.compromised_hosts:
                    connected_hosts.append(h1)
            
            if connected_hosts:
                target = random.choice(connected_hosts)
                if target not in self.known_hosts:
                    self.known_hosts.append(target)
                logger.info(f"Attacker {self.agent_id} performed lateral movement from {source} to {target}")
                return {"action": "lateral_movement", "source": source, "target": target}
                
        return None


class DefenderAgent(BaseAgent):
    def __init__(self, agent_id: str):
        super().__init__(agent_id, "defender")
        self.alerts_handled = 0

    def act(self, sim: SimulationEngine, topo: NetworkTopology) -> Optional[Dict[str, Any]]:
        # Scan for compromised hosts to isolate
        for host in topo.hosts.values():
            if host.compromised and not host.isolated:
                # Detect and isolate host
                host.isolated = True
                topo.sync_host_to_neo4j(host)
                self.alerts_handled += 1
                logger.info(f"Defender {self.agent_id} detected compromise and isolated host {host.id}!")
                return {"action": "isolate", "target": host.id}
        return None


class EmployeeAgent(BaseAgent):
    def __init__(self, agent_id: str, username: str):
        super().__init__(agent_id, "employee")
        self.username = username

    def act(self, sim: SimulationEngine, topo: NetworkTopology) -> Optional[Dict[str, Any]]:
        # Simulate background noise / activities
        activities = ["check_email", "browse_web", "access_file_share"]
        act_choice = random.choice(activities)
        logger.debug(f"Employee {self.username} performing action: {act_choice}")
        return {"action": act_choice, "user": self.username}


class SysAdminAgent(BaseAgent):
    def __init__(self, agent_id: str):
        super().__init__(agent_id, "sysadmin")

    def act(self, sim: SimulationEngine, topo: NetworkTopology) -> Optional[Dict[str, Any]]:
        # Look for vulnerable services to patch
        for host in topo.hosts.values():
            if not host.compromised:
                for service in host.services:
                    if service.vulnerabilities:
                        # Patch service (remove vulnerabilities)
                        vuln = service.vulnerabilities.pop(0)
                        logger.info(f"SysAdmin {self.agent_id} patched vulnerability {vuln} on {host.id}:{service.port}")
                        return {"action": "patch", "host": host.id, "exploit": vuln}
        return None
