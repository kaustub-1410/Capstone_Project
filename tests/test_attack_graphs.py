import pytest
from shared.models import Host, Service, User, Credential
from simulation_engine.network import NetworkTopology
from attack_engine.attack_graph import AttackGraph
from attack_engine.privilege_graph import PrivilegeGraph
from attack_engine.trust_graph import TrustGraph
from attack_engine.lateral_movement_graph import LateralMovementGraph
from attack_engine.blast_radius import BlastRadiusCalculator

def test_privilege_graph_escalation():
    topo = NetworkTopology()
    topo.neo4j_enabled = False
    
    # Setup hosts
    topo.add_host(Host(id="WS-01", name="WS-01", ip="10.0.1.5", os="Windows 11", role="workstation", domain="corp.local"))
    topo.add_host(Host(id="DC-01", name="DC-01", ip="10.0.1.2", os="Windows Server 2022", role="domain_controller", domain="corp.local"))
    
    # Setup users
    admin_cred = Credential(username="admin", password_hash="hash", privilege_level="domain_admin")
    user_cred = Credential(username="user1", password_hash="hash", privilege_level="user")
    
    user1 = User(id="user1", username="user1", domain="corp.local", credentials=[user_cred])
    admin_user = User(id="admin", username="admin", domain="corp.local", credentials=[admin_cred])
    
    topo.add_user(user1)
    topo.add_user(admin_user)
    
    # Log in admin to DC, user to workstation
    topo.hosts["WS-01"].logged_in_users.append("user1")
    topo.hosts["DC-01"].logged_in_users.append("admin")
    
    priv_graph = PrivilegeGraph(topo)
    
    # Check nodes
    assert priv_graph.graph.has_node("user:user1")
    assert priv_graph.graph.has_node("host:WS-01")
    assert priv_graph.graph.has_node("host:DC-01")
    
    # Get high risk credentials
    high_risk = priv_graph.get_high_risk_credentials()
    assert len(high_risk) > 0
    assert high_risk[0]["username"] == "admin"

def test_trust_graph():
    topo = NetworkTopology()
    topo.neo4j_enabled = False
    
    trust_graph = TrustGraph(topo)
    
    # Add a trust parent-child relationship corp.local trusts sales.corp.local
    trust_graph.add_trust("corp.local", "sales.corp.local", trust_type="parent_child", transitive=True, bidirectional=True)
    
    assert trust_graph.is_trust_reachable("sales.corp.local", "corp.local")
    assert trust_graph.is_trust_reachable("corp.local", "sales.corp.local")
    
    # Test non-transitive external trust
    trust_graph.add_trust("corp.local", "partner.local", trust_type="external", transitive=False, bidirectional=False)
    # Direction is partner.local (tgt) can reach corp.local (src)
    assert trust_graph.is_trust_reachable("partner.local", "corp.local")
    assert not trust_graph.is_trust_reachable("corp.local", "partner.local")

def test_lateral_movement_graph():
    topo = NetworkTopology()
    topo.neo4j_enabled = False
    
    host1 = Host(
        id="WS-01", name="WS-01", ip="10.0.1.5", os="Windows 11", role="workstation",
        services=[Service(name="SMB", port=445)]
    )
    host2 = Host(
        id="SRV-01", name="SRV-01", ip="10.0.1.10", os="Ubuntu 22.04", role="web_server",
        services=[Service(name="SSH", port=22)]
    )
    
    topo.add_host(host1)
    topo.add_host(host2)
    topo.add_connection("WS-01", "SRV-01")
    
    lm_graph = LateralMovementGraph(topo)
    
    # WS-01 has connection to SRV-01 and SRV-01 has SSH on port 22
    assert lm_graph.graph.has_edge("WS-01", "SRV-01")
    # SRV-01 has connection to WS-01 and WS-01 has SMB on port 445
    assert lm_graph.graph.has_edge("SRV-01", "WS-01")
    
    techniques = lm_graph.graph.get_edge_data("WS-01", "SRV-01")["techniques"]
    assert "T1021.004 (SSH)" in techniques

def test_blast_radius_computation():
    topo = NetworkTopology()
    topo.neo4j_enabled = False
    
    topo.add_host(Host(id="WS-01", name="WS-01", ip="10.0.1.5", os="Windows 11", role="workstation", asset_value=100.0, sensitivity_level="low"))
    topo.add_host(Host(id="WS-02", name="WS-02", ip="10.0.1.6", os="Windows 11", role="workstation", asset_value=200.0, sensitivity_level="medium"))
    topo.add_host(Host(id="DC-01", name="DC-01", ip="10.0.1.2", os="Windows Server 2022", role="domain_controller", asset_value=1000.0, sensitivity_level="critical"))
    
    # Add services for lateral movement paths
    topo.hosts["WS-01"].services.append(Service(name="SMB", port=445))
    topo.hosts["WS-02"].services.append(Service(name="SMB", port=445))
    topo.hosts["DC-01"].services.append(Service(name="SMB", port=445))
    
    topo.add_connection("WS-01", "WS-02")
    topo.add_connection("WS-02", "DC-01")
    
    calculator = BlastRadiusCalculator(topo)
    
    # Blast radius from WS-01 with 2 hops
    analysis = calculator.calculate_blast_radius("WS-01", max_hops=2)
    assert "WS-02" in analysis["reachable_nodes"]
    assert "DC-01" in analysis["reachable_nodes"]
    assert analysis["total_impact_value"] == 1200.0
    assert analysis["max_sensitivity"] == "critical"

def test_attack_graph_centrality():
    topo = NetworkTopology()
    topo.neo4j_enabled = False
    
    topo.add_host(Host(id="WS-01", name="WS-01", ip="10.0.1.5", os="Windows 11", role="workstation"))
    topo.add_host(Host(id="WS-02", name="WS-02", ip="10.0.1.6", os="Windows 11", role="workstation"))
    topo.add_host(Host(id="DC-01", name="DC-01", ip="10.0.1.2", os="Windows Server 2022", role="domain_controller"))
    
    topo.add_connection("WS-01", "WS-02")
    topo.add_connection("WS-02", "DC-01")
    
    attack_graph = AttackGraph(topo)
    critical_nodes = attack_graph.compute_critical_nodes()
    
    # WS-02 lies between WS-01 and DC-01, should have highest betweenness centrality
    assert len(critical_nodes) > 0
    assert critical_nodes[0][0] == "WS-02"
