"""
Cloud Enterprise Environment — Hybrid cloud-native digital twin.

Models a cloud-native enterprise with AWS/Azure/GCP services,
Kubernetes clusters, hybrid on-prem + cloud with VPN tunnels,
CI/CD pipelines, and cloud IAM.

Part of Phase 5: Digital Twin Environments.
"""

import logging

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


class CloudEnterpriseEnvironment(EnvironmentTemplate):
    """
    Digital twin of a cloud-native enterprise.

    Infrastructure:
    - On-Premises (AD, legacy apps, VPN gateway)
    - AWS Region (EKS, RDS, EC2, S3 gateway)
    - Azure Region (AKS, Azure SQL, App Services)
    - CI/CD Pipeline (Jenkins, GitLab, artifact registry)
    - Hybrid connectivity (VPN tunnels, Transit Gateway)
    """

    def __init__(self, **kwargs):
        super().__init__(
            name="Cloud-Native Enterprise",
            description="Hybrid cloud with AWS/Azure regions, Kubernetes, CI/CD, "
                        "and on-prem AD connectivity (35+ hosts)",
        )

    def build(self) -> NetworkTopology:
        topo = NetworkTopology()
        topo.neo4j_enabled = False

        # === On-Premises Core ===
        ad = ActiveDirectoryDomain(domain_name="cloudcorp.io", subnet="10.50.0", num_dcs=1)
        dc_hosts, dc_conns = ad.generate()
        add_topology_components(topo, dc_hosts, connections=dc_conns)

        onprem_fw = FirewallZone("OnPrem", "10.50.1", zone_type="internal")
        add_topology_components(topo, [onprem_fw.generate_firewall_host()],
                                connections=[("FW-ONPREM", "DC-01")])

        # Legacy app server
        legacy_app = Host(id="LEGACY-01", name="Legacy-Monolith", ip="10.50.1.10",
                          os="Windows Server 2016", role="app_server",
                          services=[create_service("https"),
                                    create_service("mssql")],
                          sensitivity_level="medium", department="IT")
        add_topology_components(topo, [legacy_app],
                                connections=[("LEGACY-01", "FW-ONPREM")])

        # On-prem department
        dept = Department(name="DevOps", subnet="10.50.10", num_workstations=4,
                          domain="cloudcorp.io", os="macOS Sonoma", phishing_base=0.25)
        hosts, users, conns = dept.generate()
        add_topology_components(topo, hosts, users, conns)
        add_topology_components(topo, [], connections=[("DEV-FS-01", "DC-01")])

        # === VPN Gateway (On-Prem to Cloud) ===
        vpn_gw = VPNGateway("VPN-CLOUD-01", "10.50.99", "Cloud-Transit-Gateway")
        add_topology_components(topo, [vpn_gw.generate()],
                                connections=[("VPN-CLOUD-01", "FW-ONPREM")])

        # === AWS Region ===
        # EKS Control Plane
        eks_cp = Host(id="AWS-EKS-CP", name="EKS-Control-Plane", ip="172.16.0.2",
                      os="Amazon EKS 1.28", role="k8s_control_plane",
                      services=[Service(name="K8s-API", port=6443, version="1.28"),
                                create_service("https")],
                      cloud_provider="aws", sensitivity_level="critical",
                      asset_value=100000.0)

        # EKS Worker Nodes
        for i in range(1, 4):
            worker = Host(id=f"AWS-WORKER-{i:02d}", name=f"EKS-Worker-{i}",
                          ip=f"172.16.0.{10+i}",
                          os="Amazon Linux 2023", role="k8s_worker",
                          services=[Service(name="Kubelet", port=10250, version="1.28"),
                                    create_service("http", VULN_PROFILES["web_generic"])],
                          cloud_provider="aws")
            add_topology_components(topo, [worker],
                                    connections=[(f"AWS-WORKER-{i:02d}", "AWS-EKS-CP")])

        # RDS
        rds = Host(id="AWS-RDS-01", name="AWS-RDS-PostgreSQL", ip="172.16.1.2",
                   os="Amazon RDS", role="db_server",
                   services=[create_service("postgres")],
                   cloud_provider="aws", sensitivity_level="high",
                   asset_value=80000.0)

        # S3 Gateway Endpoint
        s3_gw = Host(id="AWS-S3-GW", name="S3-VPC-Endpoint", ip="172.16.1.3",
                     os="AWS VPC Endpoint", role="storage_gateway",
                     services=[create_service("https")],
                     cloud_provider="aws", sensitivity_level="high")

        # ECR (Container Registry)
        ecr = Host(id="AWS-ECR-01", name="ECR-Registry", ip="172.16.1.4",
                   os="AWS ECR", role="container_registry",
                   services=[create_service("https")],
                   cloud_provider="aws", sensitivity_level="high")

        add_topology_components(topo, [eks_cp, rds, s3_gw, ecr],
                                connections=[("AWS-EKS-CP", "AWS-RDS-01"),
                                             ("AWS-EKS-CP", "AWS-S3-GW"),
                                             ("AWS-EKS-CP", "AWS-ECR-01"),
                                             ("AWS-EKS-CP", "VPN-CLOUD-01")])

        # === Azure Region ===
        # AKS Control Plane
        aks_cp = Host(id="AZ-AKS-CP", name="AKS-Control-Plane", ip="172.17.0.2",
                      os="Azure AKS 1.28", role="k8s_control_plane",
                      services=[Service(name="K8s-API", port=6443, version="1.28"),
                                create_service("https")],
                      cloud_provider="azure", sensitivity_level="critical")

        for i in range(1, 3):
            az_worker = Host(id=f"AZ-WORKER-{i:02d}", name=f"AKS-Worker-{i}",
                             ip=f"172.17.0.{10+i}",
                             os="Ubuntu 22.04", role="k8s_worker",
                             services=[Service(name="Kubelet", port=10250, version="1.28")],
                             cloud_provider="azure")
            add_topology_components(topo, [az_worker],
                                    connections=[(f"AZ-WORKER-{i:02d}", "AZ-AKS-CP")])

        # Azure SQL
        az_sql = Host(id="AZ-SQL-01", name="Azure-SQL-Managed", ip="172.17.1.2",
                      os="Azure SQL MI", role="db_server",
                      services=[create_service("mssql")],
                      cloud_provider="azure", sensitivity_level="high")

        # Azure App Service
        az_app = Host(id="AZ-APP-01", name="Azure-App-Service", ip="172.17.1.3",
                      os="Azure App Service", role="web_server",
                      services=[create_service("https")],
                      cloud_provider="azure")

        add_topology_components(topo, [aks_cp, az_sql, az_app],
                                connections=[("AZ-AKS-CP", "AZ-SQL-01"),
                                             ("AZ-AKS-CP", "AZ-APP-01"),
                                             ("AZ-AKS-CP", "VPN-CLOUD-01")])

        # === CI/CD Pipeline ===
        jenkins = Host(id="CI-JENKINS-01", name="Jenkins-Controller", ip="10.50.20.2",
                       os="Ubuntu 22.04", role="ci_server",
                       services=[create_service("https"),
                                 Service(name="Jenkins", port=8080, version="2.426")],
                       sensitivity_level="high", asset_value=50000.0)

        gitlab = Host(id="CI-GITLAB-01", name="GitLab-CE", ip="10.50.20.3",
                      os="Ubuntu 22.04", role="scm_server",
                      services=[create_service("https"),
                                create_service("ssh"),
                                Service(name="GitLab", port=8080, version="16.8")],
                      sensitivity_level="high", asset_value=60000.0)

        artifact = Host(id="CI-ARTIFACT-01", name="Nexus-Artifact-Registry", ip="10.50.20.4",
                        os="Ubuntu 22.04", role="artifact_registry",
                        services=[create_service("https")],
                        sensitivity_level="high")

        add_topology_components(topo, [jenkins, gitlab, artifact],
                                connections=[("CI-JENKINS-01", "FW-ONPREM"),
                                             ("CI-GITLAB-01", "FW-ONPREM"),
                                             ("CI-ARTIFACT-01", "CI-JENKINS-01"),
                                             ("CI-JENKINS-01", "CI-GITLAB-01"),
                                             ("CI-JENKINS-01", "AWS-ECR-01")])

        # Add cloud/DevOps users
        for i, (uname, role) in enumerate([
            ("cloud_admin", "cloud_admin"), ("devops_lead", "devops"),
            ("sre_engineer", "sre"), ("security_engineer", "security"),
        ], 1):
            user = User(id=f"U-CLOUD-{i:02d}", username=uname,
                        domain="cloudcorp.io", roles=[role],
                        phishing_susceptibility=0.2 + (i * 0.05))
            topo.add_user(user)

        logger.info(f"CloudEnterpriseEnvironment built: {len(topo.hosts)} hosts, {len(topo.connections)} connections")
        return topo
