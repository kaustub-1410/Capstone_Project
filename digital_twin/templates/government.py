"""
Government Environment — Multi-level security government network digital twin.

Models a government agency with classified/unclassified networks,
VPN enclaves, CAC authentication, cross-domain solutions, and
multi-level security boundaries.

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


class GovernmentEnvironment(EnvironmentTemplate):
    """
    Digital twin of a government agency.

    Network segments:
    - SIPRNet (Secret-level classified network)
    - NIPRNet (Unclassified but sensitive network)
    - Cross-Domain Solution (CDS) boundary
    - DMZ (public web services)
    - Administrative (HR, Finance, Legal, IT)
    - Enclave VPN (remote site connectivity)
    """

    def __init__(self, **kwargs):
        super().__init__(
            name="Government Agency",
            description="Government agency with classified/unclassified networks, "
                        "CDS boundary, CAC auth, and enclave VPN (25+ hosts)",
        )

    def build(self) -> NetworkTopology:
        topo = NetworkTopology()
        topo.neo4j_enabled = False

        # === NIPRNet (Unclassified) Active Directory ===
        nipr_ad = ActiveDirectoryDomain(domain_name="agency.gov", subnet="10.40.0", num_dcs=2)
        dc_hosts, dc_conns = nipr_ad.generate()
        add_topology_components(topo, dc_hosts, connections=dc_conns)

        # === NIPRNet Core Services ===
        nipr_fw = FirewallZone("NIPRNet", "10.40.1", zone_type="internal")
        add_topology_components(topo, [nipr_fw.generate_firewall_host()],
                                connections=[("FW-NIPRNET", "DC-01")])

        # Email (NIPRNet)
        nipr_email = Host(id="NIPR-EMAIL-01", name="NIPRNet-Exchange", ip="10.40.1.10",
                          os="Windows Server 2022", role="email_server",
                          services=[create_service("smtp"), create_service("https")],
                          sensitivity_level="high", department="IT")

        # Web portal
        nipr_web = Host(id="NIPR-WEB-01", name="Agency-Public-Website", ip="10.40.1.11",
                        os="Red Hat 8", role="web_server",
                        services=[create_service("https"),
                                  create_service("http", VULN_PROFILES["web_generic"])],
                        sensitivity_level="medium")

        # PKI / CAC Authentication
        pki = Host(id="PKI-01", name="CAC-PKI-Server", ip="10.40.1.12",
                   os="Windows Server 2022", role="pki_server",
                   services=[Service(name="OCSP", port=80, version="2.0"),
                             create_service("ldaps")],
                   sensitivity_level="critical", asset_value=100000.0)

        add_topology_components(topo, [nipr_email, nipr_web, pki],
                                connections=[("FW-NIPRNET", "NIPR-EMAIL-01"),
                                             ("FW-NIPRNET", "NIPR-WEB-01"),
                                             ("FW-NIPRNET", "PKI-01"),
                                             ("PKI-01", "DC-01")])

        # === SIPRNet (Classified) ===
        sipr_fw = FirewallZone("SIPRNet", "10.40.10", zone_type="restricted")
        add_topology_components(topo, [sipr_fw.generate_firewall_host()])

        # SIPRNet DC (separate AD forest)
        sipr_dc = Host(id="SIPR-DC-01", name="SIPRNet-Domain-Controller", ip="10.40.10.2",
                       os="Windows Server 2022 STIG'd", role="domain_controller",
                       services=[create_service("ldaps"), create_service("kerberos"),
                                 create_service("dns")],
                       sensitivity_level="critical", asset_value=500000.0)

        # Classified file server
        sipr_fs = Host(id="SIPR-FS-01", name="SIPRNet-Classified-Store", ip="10.40.10.3",
                       os="Windows Server 2022 STIG'd", role="file_server",
                       services=[create_service("smb")],
                       sensitivity_level="critical", asset_value=300000.0)

        # Classified database
        sipr_db = Host(id="SIPR-DB-01", name="SIPRNet-Intel-Database", ip="10.40.10.4",
                       os="Oracle Linux 8", role="db_server",
                       services=[Service(name="Oracle-DB", port=1521, version="19c")],
                       sensitivity_level="critical", asset_value=400000.0)

        for i in range(1, 4):
            sipr_ws = Host(id=f"SIPR-WS-{i:02d}", name=f"SIPRNet-Workstation-{i}",
                           ip=f"10.40.10.{20+i}",
                           os="Windows 10 STIG'd", role="workstation",
                           services=[create_service("smb")],
                           sensitivity_level="high")
            add_topology_components(topo, [sipr_ws],
                                    connections=[(f"SIPR-WS-{i:02d}", "SIPR-DC-01")])

        add_topology_components(topo, [sipr_dc, sipr_fs, sipr_db],
                                connections=[("FW-SIPRNET", "SIPR-DC-01"),
                                             ("SIPR-DC-01", "SIPR-FS-01"),
                                             ("SIPR-DC-01", "SIPR-DB-01")])

        # === Cross-Domain Solution (CDS) ===
        cds = Host(id="CDS-01", name="Cross-Domain-Solution", ip="10.40.5.2",
                   os="Raytheon HGS CDS", role="cross_domain_solution",
                   services=[Service(name="CDS-Transfer", port=9443, version="5.0")],
                   sensitivity_level="critical", asset_value=250000.0)

        add_topology_components(topo, [cds],
                                connections=[("CDS-01", "FW-NIPRNET"), ("CDS-01", "FW-SIPRNET")])

        # === Administrative Departments ===
        for dept_name, subnet, num_ws in [("Admin", "10.40.50", 4),
                                           ("Legal", "10.40.51", 3),
                                           ("IT", "10.40.52", 5),
                                           ("HR", "10.40.53", 3)]:
            dept = Department(name=dept_name, subnet=subnet, num_workstations=num_ws,
                              domain="agency.gov", phishing_base=0.3)
            hosts, users, conns = dept.generate()
            add_topology_components(topo, hosts, users, conns)
            fs_id = f"{dept_name.upper()[:3]}-FS-01"
            if fs_id in topo.hosts:
                add_topology_components(topo, [], connections=[(fs_id, "DC-01")])

        # === Enclave VPN ===
        vpn = VPNGateway("VPN-GOV-01", "10.40.99", "Agency-Enclave-VPN")
        add_topology_components(topo, [vpn.generate()],
                                connections=[("VPN-GOV-01", "FW-NIPRNET")])

        # Add government users
        for i in range(1, 4):
            analyst = User(id=f"U-ANALYST-{i:02d}", username=f"analyst{i}",
                           domain="agency.gov", roles=["analyst", "siprnet_cleared"],
                           phishing_susceptibility=0.2 + (i * 0.05))
            topo.add_user(analyst)

        logger.info(f"GovernmentEnvironment built: {len(topo.hosts)} hosts, {len(topo.connections)} connections")
        return topo
