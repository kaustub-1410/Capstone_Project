import pytest
import uuid
import numpy as np
from shared.models import Host, Service
from simulation_engine.network import NetworkTopology
from telemetry_service.producer import TelemetryProducer
from attack_engine.executor import AttackExecutor
from defense_engine.executor import DefenseExecutor
from rl_service.environment import AMCDSEnv

def test_telemetry_and_mitre_mapping():
    # Setup network topology
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
    
    producer = TelemetryProducer()
    executor = AttackExecutor(producer)
    
    # Test network scan
    run_id = uuid.uuid4()
    payload = {"target": "H1"}
    res = executor.execute_action("network_scan", run_id, topo, payload)
    
    assert res["status"] == "success"
    assert res["mitre"]["technique_id"] == "T1046"
    assert res["mitre"]["tactic"] == "Discovery"

def test_defense_execution():
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
    
    producer = TelemetryProducer()
    executor = DefenseExecutor(producer)
    
    # Test isolating host
    res = executor.execute_action("isolate_host", uuid.uuid4(), topo, {"target": "H1"})
    assert res["status"] == "success"
    assert host.isolated is True

def test_rl_environment_wrapper():
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
    
    env = AMCDSEnv(topo)
    obs = env.reset()
    
    # Obs shape should represent 1 host * 3 states = 3 float values
    assert obs.shape == (3,)
    assert np.array_equal(obs, np.array([0.0, 0.0, 0.0]))
    
    # Take an exploit action
    action = {
        "agent_type": "attacker",
        "action_id": 1, # exploit service
        "target_host_id": "H1",
        "service_name": "SMB"
    }
    obs, att_reward, def_reward, done, info = env.step(action)
    
    assert host.compromised is True
    assert att_reward > 0.0
    assert obs[0] == 1.0 # compromised state index 0 is 1.0
