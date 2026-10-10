"""
Digital Twin Components — Reusable building blocks for enterprise environments.

Provides composable infrastructure components (departments, AD domains,
firewall zones, VPN gateways, cloud regions, IoT networks) that automatically
generate hosts, services, users, and connections for network topology.

Part of Phase 5: Digital Twin Environments.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from shared.models import Host, Service, User

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
#  Common Service Templates
# --------------------------------------------------------------------------- #

SERVICE_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "smb": {"name": "SMB", "port": 445, "version": "3.1.1"},
    "rdp": {"name": "RDP", "port": 3389, "version": "10.0"},
    "ssh": {"name": "SSH", "port": 22, "version": "OpenSSH 8.9"},
    "http": {"name": "HTTP", "port": 80, "version": "Apache 2.4"},
    "https": {"name": "HTTPS", "port": 443, "version": "nginx 1.24"},
    "ldap": {"name": "LDAP", "port": 389, "version": "AD DS"},
    "ldaps": {"name": "LDAPS", "port": 636, "version": "AD DS"},
    "dns": {"name": "DNS", "port": 53, "version": "BIND 9"},
    "mysql": {"name": "MySQL", "port": 3306, "version": "8.0"},
    "postgres": {"name": "PostgreSQL", "port": 5432, "version": "15.0"},
    "mssql": {"name": "MSSQL", "port": 1433, "version": "2022"},
    "ftp": {"name": "FTP", "port": 21, "version": "vsftpd 3.0"},
    "smtp": {"name": "SMTP", "port": 25, "version": "Postfix 3.7"},
    "imap": {"name": "IMAP", "port": 143, "version": "Dovecot 2.3"},
    "kerberos": {"name": "Kerberos", "port": 88, "version": "AD KDC"},
    "ntp": {"name": "NTP", "port": 123, "version": "ntpd 4.2"},
    "snmp": {"name": "SNMP", "port": 161, "version": "5c"},
    "modbus": {"name": "Modbus", "port": 502, "version": "TCP"},
    "opcua": {"name": "OPC-UA", "port": 4840, "version": "1.04"},
    "dicom": {"name": "DICOM", "port": 104, "version": "3.0"},
    "hl7": {"name": "HL7-FHIR", "port": 8080, "version": "R4"},
}

# Common CVE sets by service type
VULN_PROFILES: Dict[str, List[str]] = {
    "windows_legacy": ["CVE-2017-0144", "CVE-2020-1472"],  # EternalBlue, Zerologon
    "windows_modern": ["CVE-2021-34527"],  # PrintNightmare
    "apache": ["CVE-2021-41773", "CVE-2021-44228"],  # Path Traversal, Log4Shell
    "web_generic": ["CVE-2021-44228"],  # Log4Shell
    "rdp_exposed": ["CVE-2019-0708"],  # BlueKeep
    "scada": ["CVE-2022-22965"],  # Spring4Shell (common in SCADA web HMIs)
    "medical": ["CVE-2020-27216"],  # Eclipse Jetty vulnerability
}


def create_service(
    template: str, vulnerabilities: Optional[List[str]] = None
) -> Service:
    """Create a Service from a template name with optional vulnerabilities."""
    tmpl = SERVICE_TEMPLATES.get(template, {"name": template.upper(), "port": 0})
    return Service(
        name=tmpl["name"],
        port=tmpl["port"],
        version=tmpl.get("version", ""),
        vulnerabilities=vulnerabilities or [],
    )


# --------------------------------------------------------------------------- #
#  Department Component
# --------------------------------------------------------------------------- #

class Department:
    """
    Generates hosts, services, and users for an organizational department.

    Creates workstations, a department file server, and department users
    with appropriate service profiles and phishing susceptibility.
    """

    def __init__(
        self,
        name: str,
        subnet: str,
        num_workstations: int = 5,
        domain: str = "enterprise.local",
        os: str = "Windows 11",
        vuln_profile: str = "windows_modern",
        phishing_base: float = 0.4,
    ):
        self.name = name
        self.subnet = subnet
        self.num_workstations = num_workstations
        self.domain = domain
        self.os = os
        self.vuln_profile = vuln_profile
        self.phishing_base = phishing_base
        self._prefix = name.upper()[:3]

    def generate(self) -> Tuple[List[Host], List[User], List[Tuple[str, str]]]:
        """Generate department hosts, users, and internal connections."""
        hosts: List[Host] = []
        users: List[User] = []
        connections: List[Tuple[str, str]] = []

        vulns = VULN_PROFILES.get(self.vuln_profile, [])

        # Department file server
        fs_id = f"{self._prefix}-FS-01"
        fs = Host(
            id=fs_id,
            name=f"{self.name}-FileServer",
            ip=f"{self.subnet}.2",
            os="Windows Server 2022",
            role="file_server",
            domain=self.domain,
            services=[
                create_service("smb", vulns),
                create_service("rdp"),
            ],
            department=self.name,
        )
        hosts.append(fs)

        # Workstations
        for i in range(1, self.num_workstations + 1):
            ws_id = f"{self._prefix}-WS-{i:02d}"
            ws = Host(
                id=ws_id,
                name=f"{self.name}-Workstation-{i}",
                ip=f"{self.subnet}.{20 + i}",
                os=self.os,
                role="workstation",
                domain=self.domain,
                services=[create_service("smb", vulns if i <= 2 else [])],
                department=self.name,
            )
            hosts.append(ws)
            connections.append((ws_id, fs_id))

            # Create a user for each workstation
            username = f"{self.name.lower()}_user{i}"
            user = User(
                id=f"U-{self._prefix}-{i:02d}",
                username=username,
                domain=self.domain,
                roles=[self.name.lower()],
                phishing_susceptibility=min(
                    self.phishing_base + (i * 0.05), 0.95
                ),
            )
            users.append(user)

        # Connect workstations in a chain (simulating switch topology)
        for i in range(len(hosts) - 1):
            connections.append((hosts[i].id, hosts[i + 1].id))

        return hosts, users, connections


# --------------------------------------------------------------------------- #
#  Active Directory Domain
# --------------------------------------------------------------------------- #

class ActiveDirectoryDomain:
    """
    Generates Domain Controller(s) and core AD infrastructure.

    Creates DC, DNS, DHCP, and certificate services with
    appropriate service profiles and MITRE-relevant vulnerabilities.
    """

    def __init__(
        self,
        domain_name: str = "enterprise.local",
        subnet: str = "10.0.0",
        num_dcs: int = 2,
        vuln_profile: str = "windows_legacy",
    ):
        self.domain_name = domain_name
        self.subnet = subnet
        self.num_dcs = num_dcs
        self.vuln_profile = vuln_profile

    def generate(self) -> Tuple[List[Host], List[Tuple[str, str]]]:
        """Generate AD domain infrastructure."""
        hosts: List[Host] = []
        connections: List[Tuple[str, str]] = []
        vulns = VULN_PROFILES.get(self.vuln_profile, [])

        for i in range(1, self.num_dcs + 1):
            dc_id = f"DC-{i:02d}"
            dc = Host(
                id=dc_id,
                name=f"Domain-Controller-{i}",
                ip=f"{self.subnet}.{i}",
                os="Windows Server 2022",
                role="domain_controller",
                domain=self.domain_name,
                services=[
                    create_service("ldap"),
                    create_service("ldaps"),
                    create_service("kerberos"),
                    create_service("dns"),
                    create_service("smb", vulns),
                ],
                sensitivity_level="critical",
                asset_value=100000.0,
            )
            hosts.append(dc)

        # Connect DCs to each other (replication)
        for i in range(len(hosts)):
            for j in range(i + 1, len(hosts)):
                connections.append((hosts[i].id, hosts[j].id))

        return hosts, connections


# --------------------------------------------------------------------------- #
#  Firewall Zone
# --------------------------------------------------------------------------- #

class FirewallZone:
    """
    Defines a network security zone with firewall and IDS/IPS.

    Can be used to segment DMZ, internal, and restricted zones.
    """

    def __init__(
        self,
        zone_name: str,
        subnet: str,
        zone_type: str = "internal",  # dmz, internal, restricted
    ):
        self.zone_name = zone_name
        self.subnet = subnet
        self.zone_type = zone_type

    def generate_firewall_host(self) -> Host:
        """Generate a firewall/gateway host for this zone."""
        fw_id = f"FW-{self.zone_name.upper()}"
        return Host(
            id=fw_id,
            name=f"Firewall-{self.zone_name}",
            ip=f"{self.subnet}.1",
            os="Palo Alto PAN-OS 11.0",
            role="firewall",
            services=[
                create_service("https"),
                create_service("snmp"),
            ],
            sensitivity_level="critical",
            asset_value=50000.0,
        )


# --------------------------------------------------------------------------- #
#  VPN Gateway
# --------------------------------------------------------------------------- #

class VPNGateway:
    """Generates a VPN concentrator/gateway for remote access."""

    def __init__(self, gateway_id: str, subnet: str, name: str = "VPN-Gateway"):
        self.gateway_id = gateway_id
        self.subnet = subnet
        self.name = name

    def generate(self) -> Host:
        return Host(
            id=self.gateway_id,
            name=self.name,
            ip=f"{self.subnet}.1",
            os="Cisco ASA 9.18",
            role="vpn_gateway",
            services=[
                Service(name="IKEv2", port=500, version="2.0"),
                Service(name="IPSec", port=4500, version="ESP"),
                create_service("https"),
            ],
            sensitivity_level="high",
            asset_value=30000.0,
        )


# --------------------------------------------------------------------------- #
#  Cloud Region
# --------------------------------------------------------------------------- #

class CloudRegion:
    """Generates cloud infrastructure components (VMs, load balancers, storage)."""

    def __init__(
        self,
        provider: str = "aws",
        region: str = "us-east-1",
        subnet: str = "172.16.0",
        num_instances: int = 3,
    ):
        self.provider = provider
        self.region = region
        self.subnet = subnet
        self.num_instances = num_instances

    def generate(self) -> Tuple[List[Host], List[Tuple[str, str]]]:
        hosts: List[Host] = []
        connections: List[Tuple[str, str]] = []

        prefix = self.provider.upper()[:3]

        # Load balancer
        lb_id = f"{prefix}-LB-01"
        lb = Host(
            id=lb_id,
            name=f"{self.provider}-LoadBalancer",
            ip=f"{self.subnet}.1",
            os=f"{self.provider.upper()} ELB/ALB",
            role="load_balancer",
            services=[create_service("https"), create_service("http")],
            cloud_provider=self.provider,
            sensitivity_level="high",
        )
        hosts.append(lb)

        # Compute instances
        for i in range(1, self.num_instances + 1):
            vm_id = f"{prefix}-VM-{i:02d}"
            vm = Host(
                id=vm_id,
                name=f"{self.provider}-Instance-{i}",
                ip=f"{self.subnet}.{10 + i}",
                os="Ubuntu 22.04 LTS",
                role="web_server",
                services=[
                    create_service("http", VULN_PROFILES.get("web_generic", [])),
                    create_service("ssh"),
                ],
                cloud_provider=self.provider,
            )
            hosts.append(vm)
            connections.append((lb_id, vm_id))

        # Connect VMs to each other (VPC internal)
        for i in range(1, len(hosts)):
            for j in range(i + 1, len(hosts)):
                if hosts[i].role != "load_balancer" and hosts[j].role != "load_balancer":
                    connections.append((hosts[i].id, hosts[j].id))

        return hosts, connections


# --------------------------------------------------------------------------- #
#  IoT Network
# --------------------------------------------------------------------------- #

class IoTNetwork:
    """Generates IoT device clusters (cameras, sensors, controllers)."""

    def __init__(
        self,
        network_name: str,
        subnet: str,
        num_devices: int = 5,
        device_type: str = "sensor",
    ):
        self.network_name = network_name
        self.subnet = subnet
        self.num_devices = num_devices
        self.device_type = device_type

    def generate(self) -> Tuple[List[Host], List[Tuple[str, str]]]:
        hosts: List[Host] = []
        connections: List[Tuple[str, str]] = []

        # IoT gateway
        gw_id = f"IOT-GW-{self.network_name.upper()[:4]}"
        gw = Host(
            id=gw_id,
            name=f"IoT-Gateway-{self.network_name}",
            ip=f"{self.subnet}.1",
            os="Embedded Linux 5.10",
            role="iot_gateway",
            services=[create_service("https"), Service(name="MQTT", port=1883, version="3.1.1")],
            device_type="gateway",
        )
        hosts.append(gw)

        for i in range(1, self.num_devices + 1):
            dev_id = f"IOT-{self.network_name.upper()[:4]}-{i:02d}"
            dev = Host(
                id=dev_id,
                name=f"IoT-{self.device_type}-{i}",
                ip=f"{self.subnet}.{10 + i}",
                os="RTOS 2.0",
                role="iot_device",
                services=[Service(name="MQTT", port=1883, version="3.1.1")],
                device_type=self.device_type,
            )
            hosts.append(dev)
            connections.append((gw_id, dev_id))

        return hosts, connections
