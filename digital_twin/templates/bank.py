"""
Bank Environment — Full banking enterprise digital twin.

Models a financial institution with trading floor, ATM network,
SWIFT messaging, customer portal, and departmental segmentation
across IT, Trading, Retail, Compliance, and HR.

Part of Phase 5: Digital Twin Environments.
"""

import logging
from typing import Any, Dict

from digital_twin.components import (
    ActiveDirectoryDomain,
    CloudRegion,
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


class BankEnvironment(EnvironmentTemplate):
    """
    Digital twin of a mid-size banking institution.

    Network segments:
    - Core Banking (SWIFT, core banking app, database cluster)
    - Trading Floor (low-latency trading servers, market data)
    - ATM Network (ATM controllers, transaction processors)
    - Customer Portal (web/mobile APIs, CDN)
    - Corporate (IT, HR, Compliance, Legal departments)
    - DMZ (web servers, email gateway, VPN)
    """

    def __init__(self, **kwargs):
        super().__init__(
            name="Financial Institution",
            description="Mid-size bank with trading floor, ATM network, SWIFT, "
                        "and departmental segmentation (35+ hosts)",
        )

    def build(self) -> NetworkTopology:
        topo = NetworkTopology()
        topo.neo4j_enabled = False

        # === Active Directory ===
        ad = ActiveDirectoryDomain(domain_name="bank.local", subnet="10.0.0", num_dcs=2)
        dc_hosts, dc_conns = ad.generate()
        add_topology_components(topo, dc_hosts, connections=dc_conns)

        # === DMZ Zone ===
        dmz_fw = FirewallZone("DMZ", "10.0.1", zone_type="dmz")
        add_topology_components(topo, [dmz_fw.generate_firewall_host()])

        # Web Application Firewall
        waf = Host(id="WAF-01", name="Web-App-Firewall", ip="10.0.1.2",
                   os="F5 BIG-IP 17.1", role="waf",
                   services=[create_service("https")],
                   sensitivity_level="high", asset_value=40000.0)

        # Email Gateway
        email_gw = Host(id="EMAIL-GW-01", name="Email-Gateway", ip="10.0.1.3",
                        os="Proofpoint ESS", role="email_gateway",
                        services=[create_service("smtp"), create_service("https")],
                        sensitivity_level="high")

        add_topology_components(topo, [waf, email_gw],
                                connections=[("FW-DMZ", "WAF-01"), ("FW-DMZ", "EMAIL-GW-01"),
                                             ("FW-DMZ", "DC-01")])

        # === Core Banking ===
        swift = Host(id="SWIFT-01", name="SWIFT-Alliance-Gateway", ip="10.0.10.2",
                     os="Windows Server 2019", role="swift_gateway",
                     services=[Service(name="SWIFT-Net", port=48000, version="7.4")],
                     sensitivity_level="critical", asset_value=500000.0)

        core_db = Host(id="CORE-DB-01", name="Core-Banking-DB", ip="10.0.10.3",
                       os="Oracle Linux 8", role="db_server",
                       services=[Service(name="Oracle-DB", port=1521, version="19c")],
                       sensitivity_level="critical", asset_value=300000.0)

        core_app = Host(id="CORE-APP-01", name="Core-Banking-App", ip="10.0.10.4",
                        os="Red Hat 8", role="app_server",
                        services=[create_service("https"), create_service("http", VULN_PROFILES["web_generic"])],
                        sensitivity_level="critical", asset_value=200000.0)

        add_topology_components(topo, [swift, core_db, core_app],
                                connections=[("SWIFT-01", "CORE-DB-01"), ("CORE-APP-01", "CORE-DB-01"),
                                             ("CORE-APP-01", "DC-01")])

        # === Trading Floor ===
        trading_srv = Host(id="TRADE-SRV-01", name="Trading-Engine", ip="10.0.20.2",
                           os="Red Hat 8", role="trading_server",
                           services=[Service(name="FIX", port=9876, version="4.4"),
                                     create_service("https")],
                           sensitivity_level="critical", asset_value=250000.0)

        market_data = Host(id="MKTDATA-01", name="Market-Data-Feed", ip="10.0.20.3",
                           os="Ubuntu 22.04", role="data_feed",
                           services=[Service(name="Multicast-Feed", port=30000, version="2.0")],
                           sensitivity_level="high")

        add_topology_components(topo, [trading_srv, market_data],
                                connections=[("TRADE-SRV-01", "MKTDATA-01"),
                                             ("TRADE-SRV-01", "CORE-DB-01")])

        # === ATM Network ===
        atm_ctrl = Host(id="ATM-CTRL-01", name="ATM-Controller", ip="10.0.30.2",
                        os="Windows Server 2016", role="atm_controller",
                        services=[create_service("https"),
                                  Service(name="NCR-APTRA", port=8443, version="4.0")],
                        sensitivity_level="high", asset_value=80000.0)

        for i in range(1, 4):
            atm = Host(id=f"ATM-{i:02d}", name=f"ATM-Terminal-{i}", ip=f"10.0.30.{10+i}",
                       os="Windows XP Embedded", role="atm_terminal",
                       services=[Service(name="XFS", port=7500, version="3.30")],
                       device_type="atm")
            add_topology_components(topo, [atm], connections=[(f"ATM-{i:02d}", "ATM-CTRL-01")])

        add_topology_components(topo, [atm_ctrl],
                                connections=[("ATM-CTRL-01", "CORE-APP-01")])

        # === Customer Portal ===
        portal_web = Host(id="PORTAL-WEB-01", name="Customer-Portal-Web", ip="10.0.40.2",
                          os="Ubuntu 22.04", role="web_server",
                          services=[create_service("https"), create_service("http", VULN_PROFILES["apache"])],
                          sensitivity_level="high")

        portal_api = Host(id="PORTAL-API-01", name="Customer-Portal-API", ip="10.0.40.3",
                          os="Ubuntu 22.04", role="api_server",
                          services=[create_service("https")],
                          sensitivity_level="high")

        add_topology_components(topo, [portal_web, portal_api],
                                connections=[("WAF-01", "PORTAL-WEB-01"),
                                             ("PORTAL-WEB-01", "PORTAL-API-01"),
                                             ("PORTAL-API-01", "CORE-DB-01")])

        # === Corporate Departments ===
        for dept_name, subnet, num_ws in [("IT", "10.0.50", 6), ("Trading-Ops", "10.0.51", 4),
                                           ("Compliance", "10.0.52", 3), ("HR", "10.0.53", 3)]:
            dept = Department(name=dept_name, subnet=subnet, num_workstations=num_ws,
                              domain="bank.local", phishing_base=0.35)
            hosts, users, conns = dept.generate()
            add_topology_components(topo, hosts, users, conns)
            # Connect department file server to DC
            fs_id = f"{dept_name.upper()[:3]}-FS-01"
            if fs_id in topo.hosts:
                add_topology_components(topo, [], connections=[(fs_id, "DC-01")])

        # === VPN ===
        vpn = VPNGateway("VPN-BANK-01", "10.0.99", "Bank-VPN-Gateway")
        add_topology_components(topo, [vpn.generate()],
                                connections=[("VPN-BANK-01", "FW-DMZ")])

        logger.info(f"BankEnvironment built: {len(topo.hosts)} hosts, {len(topo.connections)} connections")
        return topo
