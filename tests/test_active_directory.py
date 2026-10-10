import pytest
from shared.models import Host, User, Credential, Service
from simulation_engine.network import NetworkTopology
from simulation_engine.active_directory import ActiveDirectorySimulator

@pytest.fixture(scope="module")
def setup_ad_subnet():
    topo = NetworkTopology()
    topo.neo4j_enabled = False
    
    dc = Host(id="DC-01", name="DC-01", ip="10.0.1.2", os="Windows Server", role="domain_controller")
    ws = Host(id="WS-01", name="WS-01", ip="10.0.1.5", os="Windows 11", role="workstation", compromised=True)
    
    topo.add_host(dc)
    topo.add_host(ws)
    topo.add_connection("WS-01", "DC-01")
    
    # Add domain users
    admin_cred = Credential(username="admin", password_hash="admin_hash", privilege_level="domain_admin")
    normal_cred = Credential(username="user1", password_hash="user_hash", privilege_level="user")
    
    topo.add_user(User(id="admin", username="admin", domain="corp.local", roles=["IT", "admin"], credentials=[admin_cred]))
    topo.add_user(User(id="user1", username="user1", domain="corp.local", roles=["HR"], credentials=[normal_cred]))
    
    return topo

def test_kerberos_ticket_flow(setup_ad_subnet):
    sim = ActiveDirectorySimulator(setup_ad_subnet)
    
    # 1. Request TGT
    tgt = sim.request_tgt("user1", "corp.local")
    assert tgt is not None
    assert tgt.ticket_type == "TGT"
    assert tgt.privilege_level == "user"
    
    # 2. Request TGS
    tgs = sim.request_tgs(tgt, "CIFS/DC-01")
    assert tgs is not None
    assert tgs.ticket_type == "TGS"
    assert tgs.spn == "CIFS/DC-01"

def test_kerberoasting(setup_ad_subnet):
    sim = ActiveDirectorySimulator(setup_ad_subnet)
    
    roasted = sim.simulate_kerberoasting("WS-01", ["HTTP/web.corp.local", "MSSQL/db.corp.local"])
    assert len(roasted) == 2
    assert roasted[0].spn == "HTTP/web.corp.local"
    assert "$kerb5tgs$" in roasted[0].password_hash

def test_pass_the_hash(setup_ad_subnet):
    sim = ActiveDirectorySimulator(setup_ad_subnet)
    
    admin_cred = Credential(username="admin", password_hash="hash", privilege_level="domain_admin")
    user_cred = Credential(username="user1", password_hash="hash", privilege_level="user")
    
    # DC-01 is clean initially
    assert setup_ad_subnet.hosts["DC-01"].compromised is False
    
    # PtH with user cred should fail to compromise DC
    success = sim.simulate_pass_the_hash("WS-01", "DC-01", user_cred)
    assert success is False
    assert setup_ad_subnet.hosts["DC-01"].compromised is False
    
    # PtH with admin cred should succeed
    success = sim.simulate_pass_the_hash("WS-01", "DC-01", admin_cred)
    assert success is True
    assert setup_ad_subnet.hosts["DC-01"].compromised is True

def test_golden_ticket_dcsync(setup_ad_subnet):
    sim = ActiveDirectorySimulator(setup_ad_subnet)
    
    # Forging Golden ticket
    golden = sim.simulate_golden_ticket("corp.local", "forged_admin")
    assert golden is not None
    assert golden.privilege_level == "domain_admin"
    assert golden.ticket_type == "TGT"
    
    # DCSync using Golden Ticket (domain_admin privilege)
    hashes = sim.simulate_dcsync(golden)
    assert hashes is not None
    assert len(hashes) > 0
    
    # DCSync with normal ticket should fail
    normal = Credential(username="user1", password_hash="hash", privilege_level="user")
    failed_dcsync = sim.simulate_dcsync(normal)
    assert failed_dcsync is None
