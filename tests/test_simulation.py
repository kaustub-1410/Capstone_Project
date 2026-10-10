import pytest
import uuid
from datetime import datetime, timedelta
from shared.models import Host, Service, User, Credential
from simulation_engine.core import SimulationEngine, Event
from simulation_engine.network import NetworkTopology
from agent_framework.base import AttackerAgent, DefenderAgent, SysAdminAgent, EmployeeAgent

def test_simulation_engine_scheduling():
    sim = SimulationEngine()
    
    events_triggered = []
    
    def dummy_handler(event: Event):
        events_triggered.append(event.payload.get("msg"))
        
    sim.register_handler("dummy", dummy_handler)
    
    sim.schedule_event(delay_seconds=1.0, event_type="TEST", handler_name="dummy", payload={"msg": "first"})
    sim.schedule_event(delay_seconds=2.0, event_type="TEST", handler_name="dummy", payload={"msg": "second"})
    
    # Run the simulator step-by-step
    assert len(sim.event_queue) == 2
    
    sim.step()
    assert len(events_triggered) == 1
    assert events_triggered[0] == "first"
    
    sim.step()
    assert len(events_triggered) == 2
    assert events_triggered[1] == "second"


def test_network_topology_management():
    topo = NetworkTopology()
    topo.neo4j_enabled = False # Disable Neo4j integration for purely offline unit tests
    
    host1 = Host(
        id="H1",
        name="WS-01",
        ip="10.0.0.5",
        os="Windows 10",
        services=[Service(id="S1", name="SMB", port=445, vulnerabilities=["CVE-2017-0144"])]
    )
    
    host2 = Host(
        id="H2",
        name="DC-01",
        ip="10.0.0.2",
        os="Windows Server 2019",
        services=[]
    )
    
    topo.add_host(host1)
    topo.add_host(host2)
    topo.add_connection("H1", "H2")
    
    assert len(topo.hosts) == 2
    assert len(topo.connections) == 1
    assert "H1" in topo.hosts
    assert "H2" in topo.hosts


def test_agent_decision_cycles():
    topo = NetworkTopology()
    topo.neo4j_enabled = False
    
    host = Host(
        id="H1",
        name="WS-01",
        ip="10.0.0.5",
        os="Windows 10",
        services=[Service(id="S1", name="SMB", port=445, vulnerabilities=["CVE-2017-0144"])]
    )
    topo.add_host(host)
    
    attacker = AttackerAgent(agent_id="attacker-1")
    defender = DefenderAgent(agent_id="defender-1")
    sysadmin = SysAdminAgent(agent_id="sysadmin-1")
    
    # 1. Attacker reconnaissance action
    act1 = attacker.act(None, topo)
    assert act1 is not None
    assert act1["action"] == "reconnaissance"
    assert "H1" in attacker.known_hosts
    
    # 2. Attacker exploit action
    act2 = attacker.act(None, topo)
    assert act2 is not None
    assert act2["action"] == "exploit"
    
    # 3. Defender containment actions
    act3 = defender.act(None, topo)
    if host.compromised:
        assert act3 is not None
        assert act3["action"] == "isolate"
        assert host.isolated is True
    else:
        assert act3 is None
