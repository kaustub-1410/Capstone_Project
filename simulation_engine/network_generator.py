"""
Dynamic Network Generator Module — Generates large-scale synthetic enterprise network topologies.
Supports configurable sizes from 10 to 10,000 hosts with multiple departments, Active Directory forests,
cloud regions, and industrial IoT zones.
"""

import random
import logging
from typing import Dict, List, Tuple, Optional, Any
from shared.models import Host, Service, User, Credential
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)

# Common vulnerability pools mapping to CVEs
VULNERABILITY_POOL = {
    "SMB": ["CVE-2017-0144"],
    "HTTP": ["CVE-2021-44228", "CVE-2021-41773"],
    "LDAP": ["CVE-2020-1472"],
    "RPC": ["CVE-2021-34527"],
    "HTTPS": ["CVE-2023-44228"]
}

class NetworkGenerator:
    """
    Generates synthetic, structured enterprise topologies for defense simulation.
    """

    def __init__(self):
        self.host_roles = ["workstation", "web_server", "db_server", "file_server"]
        self.departments = ["HR", "Finance", "Engineering", "IT", "Sales", "Executive"]

    def generate_network(
        self,
        num_hosts: int = 100,
        domain_name: str = "enterprise.local",
        vuln_density: float = 0.3,
        include_cloud: bool = True,
        include_iot: bool = True
    ) -> NetworkTopology:
        """
        Generates a complete connected network topology of exact size num_hosts.
        """
        logger.info(f"Generating network topology of size: {num_hosts} hosts...")
        topo = NetworkTopology()
        topo.neo4j_enabled = False # Default off during generation to keep it fast
        
        # 1. Create Core infrastructure (Always counts as 1 host)
        dc_host = Host(
            id="DC-01",
            name="Domain-Controller-01",
            ip="10.0.1.2",
            os="Windows Server 2022",
            role="domain_controller",
            domain=domain_name,
            asset_value=10000.0,
            sensitivity_level="critical",
            services=[
                Service(name="LDAP", port=389),
                Service(name="SMB", port=445),
                Service(name="RPC", port=135)
            ]
        )
        topo.add_host(dc_host)
        
        if num_hosts <= 1:
            return topo
            
        # 2. Setup departments and hosts distribution
        dept_hosts_map = {dept: [] for dept in self.departments}
        host_counter = 1
        
        while len(topo.hosts) < num_hosts:
            dept = self.departments[host_counter % len(self.departments)]
            subnet_idx = len(topo.hosts) // 20 + 2
            i = len(dept_hosts_map[dept])
            
            role = random.choices(
                self.host_roles, 
                weights=[0.6, 0.15, 0.1, 0.15], 
                k=1
            )[0]
            
            host_id = f"WS-{host_counter:04d}" if role == "workstation" else f"SRV-{host_counter:04d}"
            
            # Assign operating system
            if role == "workstation":
                os = "Windows 11"
            else:
                os = random.choice(["Windows Server 2019", "Ubuntu 22.04", "RHEL 9"])
                
            # Services selection
            services = []
            if role == "workstation":
                services.append(Service(name="SMB", port=445))
            elif role == "web_server":
                services.append(Service(name="HTTP", port=80))
                services.append(Service(name="HTTPS", port=443))
            elif role == "db_server":
                services.append(Service(name="MySQL", port=3306))
            elif role == "file_server":
                services.append(Service(name="SMB", port=445))
                
            # Inject vulnerabilities probabilistically
            for svc in services:
                if random.random() < vuln_density:
                    cves = VULNERABILITY_POOL.get(svc.name, [])
                    if cves:
                        svc.vulnerabilities.extend(cves)
                        
            # Calculate asset value
            asset_val = 100.0
            sens = "low"
            if role == "db_server":
                asset_val = 2000.0
                sens = "high"
            elif role == "web_server":
                asset_val = 1000.0
                sens = "medium"
                
            host = Host(
                id=host_id,
                name=f"{dept}-{role}-{host_counter}",
                ip=f"10.0.{subnet_idx}.{10 + i}",
                os=os,
                role=role,
                domain=domain_name,
                department=dept,
                sensitivity_level=sens,
                asset_value=asset_val,
                services=services
            )
            
            # Cloud provider tag
            if include_cloud and random.random() < 0.15:
                host.cloud_provider = random.choice(["aws", "azure", "gcp"])
                
            # IoT device tag
            if include_iot and random.random() < 0.1:
                host.device_type = random.choice(["plc", "camera", "smart_sensor"])
                host.role = "iot_device"
                host.os = "Embedded RTOS"
                
            topo.add_host(host)
            dept_hosts_map[dept].append(host_id)
            host_counter += 1

        # 3. Connect department hosts sequentially (intra-dept connectivity) and to DC (inter-dept routing)
        for dept, dept_hosts in dept_hosts_map.items():
            for j in range(len(dept_hosts) - 1):
                topo.add_connection(dept_hosts[j], dept_hosts[j+1])
            if dept_hosts:
                topo.add_connection(dept_hosts[0], "DC-01")

        # 4. Connect departments to form a fully connected component (ring or hub-spoke model)
        dept_entry_points = [h_id for h_id, h in topo.hosts.items() if h.role == "web_server"]
        for k in range(len(dept_entry_points) - 1):
            topo.add_connection(dept_entry_points[k], dept_entry_points[k+1])

        # 5. Generate Users
        for dept in self.departments:
            username = f"{dept.lower()}_user"
            user = User(
                id=username,
                username=username,
                domain=domain_name,
                roles=[dept],
                phishing_susceptibility=round(random.uniform(0.1, 0.5), 2),
                credentials=[Credential(username=username, password_hash="secret", privilege_level="user")]
            )
            topo.add_user(user)
            
            # Map user active session to one workstation in department
            dept_workstations = [h.id for h in topo.hosts.values() if h.department == dept and h.role == "workstation"]
            if dept_workstations:
                target_ws = random.choice(dept_workstations)
                topo.hosts[target_ws].logged_in_users.append(username)

        logger.info(
            f"Successfully generated dynamic network: {len(topo.hosts)} hosts, "
            f"{len(topo.connections)} connections, {len(topo.users)} users."
        )
        return topo
