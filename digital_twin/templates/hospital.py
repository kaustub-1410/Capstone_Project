"""
Hospital Environment — Healthcare enterprise digital twin.

Models a hospital with EHR systems, medical imaging (PACS/DICOM),
pharmacy, IoT medical devices, HIPAA compliance zones, and
clinical/administrative segmentation.

Part of Phase 5: Digital Twin Environments.
"""

import logging

from digital_twin.components import (
    ActiveDirectoryDomain,
    Department,
    FirewallZone,
    IoTNetwork,
    VPNGateway,
    create_service,
    VULN_PROFILES,
)
from digital_twin.environment_factory import EnvironmentTemplate, add_topology_components
from shared.models import Host, Service, User
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)


class HospitalEnvironment(EnvironmentTemplate):
    """
    Digital twin of a regional hospital.

    Network segments:
    - Clinical Systems (EHR, Lab, Pharmacy, Radiology)
    - Medical Devices (IoT monitors, infusion pumps, ventilators)
    - PACS/Imaging (DICOM servers, radiology workstations)
    - Administrative (Billing, HR, IT, Administration)
    - Guest Wi-Fi (isolated patient/visitor network)
    """

    def __init__(self, **kwargs):
        super().__init__(
            name="Regional Hospital",
            description="Hospital with EHR, PACS, IoT medical devices, pharmacy, "
                        "and HIPAA compliance zones (30+ hosts)",
        )

    def build(self) -> NetworkTopology:
        topo = NetworkTopology()
        topo.neo4j_enabled = False

        # === Active Directory ===
        ad = ActiveDirectoryDomain(domain_name="hospital.local", subnet="10.10.0", num_dcs=2)
        dc_hosts, dc_conns = ad.generate()
        add_topology_components(topo, dc_hosts, connections=dc_conns)

        # === Clinical Firewall Zone ===
        clinical_fw = FirewallZone("Clinical", "10.10.1", zone_type="restricted")
        add_topology_components(topo, [clinical_fw.generate_firewall_host()],
                                connections=[("FW-CLINICAL", "DC-01")])

        # === EHR System ===
        ehr_app = Host(id="EHR-APP-01", name="EHR-Application-Server", ip="10.10.10.2",
                       os="Red Hat 8", role="app_server",
                       services=[create_service("https"), create_service("http", VULN_PROFILES["web_generic"])],
                       sensitivity_level="critical", asset_value=200000.0, department="Clinical")

        ehr_db = Host(id="EHR-DB-01", name="EHR-Database", ip="10.10.10.3",
                      os="Oracle Linux 8", role="db_server",
                      services=[Service(name="Oracle-DB", port=1521, version="19c")],
                      sensitivity_level="critical", asset_value=500000.0, department="Clinical")

        add_topology_components(topo, [ehr_app, ehr_db],
                                connections=[("FW-CLINICAL", "EHR-APP-01"),
                                             ("EHR-APP-01", "EHR-DB-01")])

        # === Pharmacy System ===
        pharmacy = Host(id="PHARM-01", name="Pharmacy-Dispensing", ip="10.10.10.5",
                        os="Windows Server 2019", role="app_server",
                        services=[create_service("https"), create_service("mssql")],
                        sensitivity_level="high", department="Pharmacy")

        add_topology_components(topo, [pharmacy],
                                connections=[("PHARM-01", "EHR-DB-01")])

        # === Lab Information System ===
        lis = Host(id="LIS-01", name="Lab-Information-System", ip="10.10.10.6",
                   os="Windows Server 2019", role="app_server",
                   services=[create_service("https"),
                             Service(name="HL7-FHIR", port=8080, version="R4")],
                   sensitivity_level="high", department="Laboratory")

        add_topology_components(topo, [lis],
                                connections=[("LIS-01", "EHR-APP-01")])

        # === PACS / Radiology ===
        pacs = Host(id="PACS-01", name="PACS-Server", ip="10.10.20.2",
                    os="Ubuntu 22.04", role="imaging_server",
                    services=[Service(name="DICOM", port=104, version="3.0"),
                              create_service("https")],
                    sensitivity_level="critical", asset_value=150000.0, department="Radiology")

        rad_ws1 = Host(id="RAD-WS-01", name="Radiology-Workstation-1", ip="10.10.20.10",
                       os="Windows 10", role="workstation",
                       services=[Service(name="DICOM-Viewer", port=11112, version="2.0")],
                       department="Radiology")

        rad_ws2 = Host(id="RAD-WS-02", name="Radiology-Workstation-2", ip="10.10.20.11",
                       os="Windows 10", role="workstation",
                       services=[Service(name="DICOM-Viewer", port=11112, version="2.0")],
                       department="Radiology")

        add_topology_components(topo, [pacs, rad_ws1, rad_ws2],
                                connections=[("FW-CLINICAL", "PACS-01"),
                                             ("PACS-01", "RAD-WS-01"), ("PACS-01", "RAD-WS-02"),
                                             ("PACS-01", "EHR-APP-01")])

        # === IoT Medical Devices ===
        iot_monitors = IoTNetwork("Monitors", "10.10.30", num_devices=4, device_type="patient_monitor")
        mon_hosts, mon_conns = iot_monitors.generate()
        add_topology_components(topo, mon_hosts, connections=mon_conns)
        # Connect IoT gateway to clinical network
        add_topology_components(topo, [], connections=[("IOT-GW-MONI", "FW-CLINICAL")])

        iot_pumps = IoTNetwork("Pumps", "10.10.31", num_devices=3, device_type="infusion_pump")
        pump_hosts, pump_conns = iot_pumps.generate()
        add_topology_components(topo, pump_hosts, connections=pump_conns)
        add_topology_components(topo, [], connections=[("IOT-GW-PUMP", "FW-CLINICAL")])

        # === Administrative Departments ===
        for dept_name, subnet, num_ws in [("Admin", "10.10.50", 4), ("Billing", "10.10.51", 3),
                                           ("IT", "10.10.52", 5), ("HR", "10.10.53", 3)]:
            dept = Department(name=dept_name, subnet=subnet, num_workstations=num_ws,
                              domain="hospital.local", phishing_base=0.45)
            hosts, users, conns = dept.generate()
            add_topology_components(topo, hosts, users, conns)
            fs_id = f"{dept_name.upper()[:3]}-FS-01"
            if fs_id in topo.hosts:
                add_topology_components(topo, [], connections=[(fs_id, "DC-01")])

        # === VPN for remote physicians ===
        vpn = VPNGateway("VPN-HOSP-01", "10.10.99", "Physician-Remote-Access")
        add_topology_components(topo, [vpn.generate()],
                                connections=[("VPN-HOSP-01", "FW-CLINICAL")])

        logger.info(f"HospitalEnvironment built: {len(topo.hosts)} hosts, {len(topo.connections)} connections")
        return topo
