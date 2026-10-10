"""
Manufacturing Environment — OT/IT convergence digital twin.

Models a manufacturing plant with SCADA, PLCs, HMIs, MES, ERP,
industrial DMZ, and Purdue model layer segmentation.

Part of Phase 5: Digital Twin Environments.
"""

import logging

from digital_twin.components import (
    ActiveDirectoryDomain,
    Department,
    FirewallZone,
    IoTNetwork,
    create_service,
    VULN_PROFILES,
)
from digital_twin.environment_factory import EnvironmentTemplate, add_topology_components
from shared.models import Host, Service, User
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)


class ManufacturingEnvironment(EnvironmentTemplate):
    """
    Digital twin of a manufacturing facility.

    Follows the Purdue Model for ICS/SCADA segmentation:
    - Level 0: Physical process (sensors, actuators)
    - Level 1: Basic control (PLCs, RTUs)
    - Level 2: Area supervision (HMIs, SCADA servers)
    - Level 3: Site operations (MES, historian, engineering workstations)
    - Level 3.5: Industrial DMZ
    - Level 4-5: Enterprise IT (ERP, email, corporate)
    """

    def __init__(self, **kwargs):
        super().__init__(
            name="Manufacturing Plant",
            description="ICS/SCADA manufacturing with Purdue model segmentation, "
                        "PLCs, HMIs, MES, historian, and IT/OT convergence (30+ hosts)",
        )

    def build(self) -> NetworkTopology:
        topo = NetworkTopology()
        topo.neo4j_enabled = False

        # === Enterprise IT (Level 4-5) ===
        ad = ActiveDirectoryDomain(domain_name="mfg.local", subnet="10.30.0", num_dcs=1)
        dc_hosts, dc_conns = ad.generate()
        add_topology_components(topo, dc_hosts, connections=dc_conns)

        # ERP System
        erp = Host(id="ERP-01", name="SAP-ERP-Server", ip="10.30.5.2",
                    os="SUSE Linux 15", role="app_server",
                    services=[Service(name="SAP-GUI", port=3200, version="7.70"),
                              create_service("https")],
                    sensitivity_level="critical", asset_value=200000.0, department="IT")

        email = Host(id="EMAIL-01", name="Exchange-Server", ip="10.30.5.3",
                     os="Windows Server 2022", role="email_server",
                     services=[create_service("smtp"), create_service("https"),
                               Service(name="MAPI", port=443, version="Exchange 2019")],
                     department="IT")

        add_topology_components(topo, [erp, email],
                                connections=[("ERP-01", "DC-01"), ("EMAIL-01", "DC-01")])

        # Corporate departments
        dept = Department(name="Engineering", subnet="10.30.10", num_workstations=4,
                          domain="mfg.local", phishing_base=0.3)
        hosts, users, conns = dept.generate()
        add_topology_components(topo, hosts, users, conns)
        add_topology_components(topo, [], connections=[("ENG-FS-01", "DC-01")])

        # === Industrial DMZ (Level 3.5) ===
        idmz_fw = FirewallZone("IDMZ", "10.30.20", zone_type="dmz")
        add_topology_components(topo, [idmz_fw.generate_firewall_host()],
                                connections=[("FW-IDMZ", "DC-01")])

        # Data diode / jump server
        jump = Host(id="JUMP-01", name="OT-Jump-Server", ip="10.30.20.2",
                    os="Windows Server 2022", role="jump_server",
                    services=[create_service("rdp"), create_service("ssh")],
                    sensitivity_level="critical")
        add_topology_components(topo, [jump],
                                connections=[("JUMP-01", "FW-IDMZ")])

        # Historian mirror (DMZ side)
        historian_mirror = Host(id="HIST-DMZ-01", name="Historian-DMZ-Mirror", ip="10.30.20.3",
                                os="Windows Server 2019", role="historian",
                                services=[create_service("https"),
                                          Service(name="OSIsoft-PI", port=5450, version="2023")],
                                sensitivity_level="high")
        add_topology_components(topo, [historian_mirror],
                                connections=[("HIST-DMZ-01", "FW-IDMZ"), ("HIST-DMZ-01", "ERP-01")])

        # === Site Operations (Level 3) ===
        ot_fw = FirewallZone("OT-Core", "10.30.30", zone_type="restricted")
        add_topology_components(topo, [ot_fw.generate_firewall_host()],
                                connections=[("FW-OT-CORE", "JUMP-01")])

        # MES
        mes = Host(id="MES-01", name="MES-Server", ip="10.30.30.2",
                    os="Windows Server 2019", role="mes_server",
                    services=[create_service("https"),
                              Service(name="OPC-UA", port=4840, version="1.04")],
                    sensitivity_level="critical", asset_value=150000.0)

        # Historian (OT side)
        historian = Host(id="HIST-OT-01", name="OT-Historian", ip="10.30.30.3",
                         os="Windows Server 2019", role="historian",
                         services=[Service(name="OSIsoft-PI", port=5450, version="2023")],
                         sensitivity_level="critical", asset_value=120000.0)

        # Engineering Workstation
        eng_ws = Host(id="ENG-WS-01", name="Engineering-Workstation-OT", ip="10.30.30.10",
                      os="Windows 10", role="engineering_workstation",
                      services=[create_service("rdp"),
                                Service(name="TIA-Portal", port=0, version="17.0")],
                      sensitivity_level="high")

        add_topology_components(topo, [mes, historian, eng_ws],
                                connections=[("MES-01", "FW-OT-CORE"),
                                             ("HIST-OT-01", "FW-OT-CORE"),
                                             ("ENG-WS-01", "FW-OT-CORE"),
                                             ("MES-01", "HIST-OT-01")])

        # === SCADA / Area Supervision (Level 2) ===
        scada = Host(id="SCADA-01", name="SCADA-Server", ip="10.30.40.2",
                     os="Windows Server 2016", role="scada_server",
                     services=[Service(name="Modbus", port=502, version="TCP"),
                               Service(name="OPC-DA", port=135, version="2.0"),
                               create_service("https")],
                     sensitivity_level="critical", asset_value=300000.0)

        for i in range(1, 4):
            hmi = Host(id=f"HMI-{i:02d}", name=f"HMI-Panel-{i}", ip=f"10.30.40.{10+i}",
                       os="Windows 10 IoT Enterprise", role="hmi",
                       services=[Service(name="HMI-Web", port=8080, version="WinCC 7.5")],
                       device_type="hmi", sensitivity_level="high")
            add_topology_components(topo, [hmi],
                                    connections=[(f"HMI-{i:02d}", "SCADA-01")])

        add_topology_components(topo, [scada],
                                connections=[("SCADA-01", "MES-01"), ("SCADA-01", "HIST-OT-01")])

        # === Basic Control (Level 1) — PLCs ===
        for i in range(1, 5):
            plc = Host(id=f"PLC-{i:02d}", name=f"Siemens-S7-PLC-{i}", ip=f"10.30.50.{10+i}",
                       os="Siemens S7-1500 FW v3.0", role="plc",
                       services=[Service(name="S7comm", port=102, version="S7-1500"),
                                 Service(name="Modbus", port=502, version="TCP")],
                       device_type="plc", sensitivity_level="critical",
                       asset_value=80000.0)
            add_topology_components(topo, [plc],
                                    connections=[(f"PLC-{i:02d}", "SCADA-01")])

        # === Level 0 — IoT Sensors/Actuators ===
        iot_sensors = IoTNetwork("Floor-Sensors", "10.30.60", num_devices=6, device_type="industrial_sensor")
        sensor_hosts, sensor_conns = iot_sensors.generate()
        add_topology_components(topo, sensor_hosts, connections=sensor_conns)
        add_topology_components(topo, [], connections=[("IOT-GW-FLOO", "SCADA-01")])

        logger.info(f"ManufacturingEnvironment built: {len(topo.hosts)} hosts, {len(topo.connections)} connections")
        return topo
