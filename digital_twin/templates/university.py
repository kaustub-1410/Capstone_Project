"""
University Environment — Academic institution digital twin.

Models a university with student labs, research computing clusters,
library systems, multi-domain trusts, and guest Wi-Fi networks.

Part of Phase 5: Digital Twin Environments.
"""

import logging

from digital_twin.components import (
    ActiveDirectoryDomain,
    Department,
    FirewallZone,
    VPNGateway,
    create_service,
    VULN_PROFILES,
)
from digital_twin.environment_factory import EnvironmentTemplate, add_topology_components
from shared.models import Host, Service, User
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)


class UniversityEnvironment(EnvironmentTemplate):
    """
    Digital twin of a research university.

    Network segments:
    - Campus Core (AD, DNS, DHCP, web services)
    - Research Computing (HPC cluster, GPU nodes, data storage)
    - Student Labs (open-access workstations, printers)
    - Library Systems (catalog, digital archives, public kiosks)
    - Administrative (Registrar, Finance, HR, IT)
    - Guest/eduroam Wi-Fi (isolated BYOD network)
    """

    def __init__(self, **kwargs):
        super().__init__(
            name="Research University",
            description="University with HPC research cluster, student labs, library, "
                        "and multi-department administration (30+ hosts)",
        )

    def build(self) -> NetworkTopology:
        topo = NetworkTopology()
        topo.neo4j_enabled = False

        # === Active Directory ===
        ad = ActiveDirectoryDomain(domain_name="university.edu", subnet="10.20.0", num_dcs=2)
        dc_hosts, dc_conns = ad.generate()
        add_topology_components(topo, dc_hosts, connections=dc_conns)

        # === Campus Core ===
        core_fw = FirewallZone("Campus-Core", "10.20.1", zone_type="internal")
        add_topology_components(topo, [core_fw.generate_firewall_host()],
                                connections=[("FW-CAMPUS-CORE", "DC-01")])

        # Campus web server
        campus_web = Host(id="WEB-CAMPUS-01", name="University-Web-Portal", ip="10.20.1.10",
                          os="Ubuntu 22.04", role="web_server",
                          services=[create_service("https"),
                                    create_service("http", VULN_PROFILES["apache"])],
                          sensitivity_level="medium")
        add_topology_components(topo, [campus_web],
                                connections=[("FW-CAMPUS-CORE", "WEB-CAMPUS-01")])

        # LMS (Learning Management System)
        lms = Host(id="LMS-01", name="Moodle-LMS-Server", ip="10.20.1.11",
                   os="Ubuntu 22.04", role="web_server",
                   services=[create_service("https"), create_service("postgres")],
                   sensitivity_level="high", asset_value=50000.0)
        add_topology_components(topo, [lms],
                                connections=[("FW-CAMPUS-CORE", "LMS-01")])

        # === Research Computing ===
        hpc_head = Host(id="HPC-HEAD-01", name="HPC-Head-Node", ip="10.20.10.2",
                        os="CentOS Stream 9", role="hpc_head",
                        services=[create_service("ssh"),
                                  Service(name="SLURM", port=6817, version="23.02")],
                        sensitivity_level="high", asset_value=100000.0, department="Research")

        for i in range(1, 5):
            compute = Host(id=f"HPC-NODE-{i:02d}", name=f"HPC-Compute-{i}",
                           ip=f"10.20.10.{10+i}",
                           os="CentOS Stream 9", role="compute_node",
                           services=[create_service("ssh")],
                           department="Research")
            add_topology_components(topo, [compute],
                                    connections=[(f"HPC-NODE-{i:02d}", "HPC-HEAD-01")])

        # GPU node
        gpu_node = Host(id="HPC-GPU-01", name="GPU-Compute-Node", ip="10.20.10.20",
                        os="Ubuntu 22.04", role="gpu_node",
                        services=[create_service("ssh"),
                                  Service(name="JupyterHub", port=8888, version="4.0")],
                        department="Research")

        # Research data storage
        research_nas = Host(id="RES-NAS-01", name="Research-NAS", ip="10.20.10.30",
                            os="TrueNAS Scale", role="file_server",
                            services=[Service(name="NFS", port=2049, version="4.2"),
                                      create_service("smb")],
                            sensitivity_level="high", asset_value=80000.0, department="Research")

        add_topology_components(topo, [hpc_head, gpu_node, research_nas],
                                connections=[("HPC-HEAD-01", "HPC-GPU-01"),
                                             ("HPC-HEAD-01", "RES-NAS-01"),
                                             ("HPC-HEAD-01", "FW-CAMPUS-CORE")])

        # === Student Labs ===
        for lab_num in range(1, 3):
            for ws_num in range(1, 6):
                ws_id = f"LAB{lab_num}-WS-{ws_num:02d}"
                ws = Host(id=ws_id, name=f"Lab{lab_num}-Workstation-{ws_num}",
                          ip=f"10.20.{20+lab_num}.{10+ws_num}",
                          os="Windows 11", role="workstation",
                          services=[create_service("smb", VULN_PROFILES["windows_modern"])],
                          department=f"Lab-{lab_num}")
                add_topology_components(topo, [ws],
                                        connections=[(ws_id, "FW-CAMPUS-CORE")])

        # === Library ===
        library_catalog = Host(id="LIB-CAT-01", name="Library-Catalog", ip="10.20.30.2",
                               os="Ubuntu 22.04", role="app_server",
                               services=[create_service("https"), create_service("postgres")],
                               department="Library")

        for i in range(1, 4):
            kiosk = Host(id=f"LIB-KIOSK-{i:02d}", name=f"Library-Kiosk-{i}",
                         ip=f"10.20.30.{10+i}",
                         os="Chrome OS", role="kiosk",
                         services=[create_service("https")],
                         department="Library", device_type="kiosk")
            add_topology_components(topo, [kiosk],
                                    connections=[(f"LIB-KIOSK-{i:02d}", "LIB-CAT-01")])

        add_topology_components(topo, [library_catalog],
                                connections=[("LIB-CAT-01", "FW-CAMPUS-CORE")])

        # === Administrative Departments ===
        for dept_name, subnet, num_ws in [("Registrar", "10.20.50", 4),
                                           ("Finance", "10.20.51", 3),
                                           ("IT-Dept", "10.20.52", 5),
                                           ("HR", "10.20.53", 3)]:
            dept = Department(name=dept_name, subnet=subnet, num_workstations=num_ws,
                              domain="university.edu", phishing_base=0.5)
            hosts, users, conns = dept.generate()
            add_topology_components(topo, hosts, users, conns)
            fs_id = f"{dept_name.upper()[:3]}-FS-01"
            if fs_id in topo.hosts:
                add_topology_components(topo, [], connections=[(fs_id, "DC-01")])

        # === VPN ===
        vpn = VPNGateway("VPN-EDU-01", "10.20.99", "University-VPN")
        add_topology_components(topo, [vpn.generate()],
                                connections=[("VPN-EDU-01", "FW-CAMPUS-CORE")])

        # Add student and faculty users
        for i in range(1, 6):
            student = User(id=f"U-STU-{i:02d}", username=f"student{i}",
                           domain="university.edu", roles=["student"],
                           phishing_susceptibility=0.6 + (i * 0.04))
            topo.add_user(student)

        for i in range(1, 4):
            faculty = User(id=f"U-FAC-{i:02d}", username=f"prof{i}",
                           domain="university.edu", roles=["faculty"],
                           phishing_susceptibility=0.3 + (i * 0.05))
            topo.add_user(faculty)

        logger.info(f"UniversityEnvironment built: {len(topo.hosts)} hosts, {len(topo.connections)} connections")
        return topo
