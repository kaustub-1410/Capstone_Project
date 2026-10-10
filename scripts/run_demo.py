import os
import sys
import uuid
import random
from datetime import datetime
from unittest.mock import MagicMock

# Mock third-party libraries before imports to allow running without installations
sys.modules['neo4j'] = MagicMock()
sys.modules['redis'] = MagicMock()
sys.modules['clickhouse_connect'] = MagicMock()
sys.modules['psycopg2'] = MagicMock()

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from shared.models import Host, Service, User, Credential
from simulation_engine.network import NetworkTopology
from simulation_engine.core import SimulationEngine, Event
from agent_framework.base import AttackerAgent, DefenderAgent, SysAdminAgent, EmployeeAgent
from telemetry_service.producer import TelemetryProducer
from attack_engine.executor import AttackExecutor
from defense_engine.executor import DefenseExecutor
from rl_service.environment import AMCDSEnv

def print_header(title: str):
    print("=" * 60)
    print(f" {title.upper()} ".center(60, "="))
    print("=" * 60)

def main():
    print_header("Autonomous Multi-Agent Cyber Defense Simulator (AMCDS)")
    
    # 1. Initialize Network Topology
    print("\n[+] Creating Enterprise Network Topology...")
    topo = NetworkTopology()
    topo.neo4j_enabled = False # Offline mode for visual demonstration
    
    # Create services
    smb_service = Service(name="SMB", port=445, vulnerabilities=["CVE-2017-0144"]) # EternalBlue
    http_service = Service(name="HTTP", port=80, vulnerabilities=["CVE-2021-41773"]) # Apache Path Traversal
    rdp_service = Service(name="RDP", port=3389)
    
    # Create hosts
    dc = Host(id="DC-01", name="Domain-Controller", ip="10.0.1.5", os="Windows Server 2022", role="domain_controller", services=[smb_service, rdp_service])
    web_server = Host(id="WEB-01", name="Public-Web-Server", ip="10.0.1.10", os="Ubuntu 22.04", role="web_server", services=[http_service])
    ws1 = Host(id="WS-01", name="Workstation-User1", ip="10.0.2.20", os="Windows 11", role="workstation", services=[smb_service])
    ws2 = Host(id="WS-02", name="Workstation-User2", ip="10.0.2.21", os="Windows 11", role="workstation", services=[smb_service])
    
    topo.add_host(dc)
    topo.add_host(web_server)
    topo.add_host(ws1)
    topo.add_host(ws2)
    
    # Establish connections
    topo.add_connection("WEB-01", "WS-01")
    topo.add_connection("WS-01", "WS-02")
    topo.add_connection("WS-02", "DC-01")
    
    # Create user
    jdoe = User(id="U-01", username="jdoe", domain="enterprise.local", phishing_susceptibility=0.8) # highly susceptible
    topo.add_user(jdoe)
    
    print(f"    - Network configured with {len(topo.hosts)} hosts and {len(topo.connections)} link routes.")
    print("    - Hosts: " + ", ".join([h.name for h in topo.hosts.values()]))
    
    # 2. Initialize Agents
    print("\n[+] Initializing Intelligent Agents...")
    attacker = AttackerAgent(agent_id="APT-29", sophistication=0.9)
    defender = DefenderAgent(agent_id="SOC-Defender")
    sysadmin = SysAdminAgent(agent_id="SysAdmin-Bot")
    employee = EmployeeAgent(agent_id="Employee-jdoe", username="jdoe")
    
    # 3. Setup Gym Environment and telemetry
    env = AMCDSEnv(topo)
    env.reset()
    
    # 4. Simulation Execution Loop
    print_header("Simulating Co-Evolution Execution Loop")
    
    # Cycle 1: Attacker Reconnaissance
    print("\n>>> TICK 1: Attacker begins reconnaissance...")
    act = attacker.act(None, topo)
    # Execute action in Gym environment
    action_dict = {
        "agent_type": "attacker",
        "action_id": 0, # Scan target
        "target_host_id": "WS-01"
    }
    obs, att_rew, def_rew, done, info = env.step(action_dict)
    print(f"    Result: {info['action_result']['status'].upper()}")
    print(f"    MITRE Tactic: {info['action_result']['mitre']['tactic']} (Technique: {info['action_result']['mitre']['technique_id']})")
    print(f"    Attacker Reward: {att_rew}")
    
    # Cycle 2: Employee Phishing Email
    print("\n>>> TICK 2: Attacker sends phishing email to jdoe...")
    action_dict = {
        "agent_type": "attacker",
        "action_id": 1, # exploit/phishing
        "target_host_id": "WS-01",
        "user": "jdoe"
    }
    # Simulate action check
    res = env.attack_exec.execute_action("phishing_email", env.run_id, env.topo, {"target": "WS-01", "user": "jdoe"})
    print(f"    Employee jdoe click status: {'COMPROMISED' if ws1.compromised else 'SAFE'}")
    print(f"    Attacker success state: {res['status'].upper()}")
    
    # Cycle 3: Lateral Movement SMB
    print("\n>>> TICK 3: Attacker attempts lateral movement from WS-01 to WS-02...")
    action_dict = {
        "agent_type": "attacker",
        "action_id": 1,
        "target_host_id": "WS-02",
        "source": "WS-01"
    }
    res = env.attack_exec.execute_action("lateral_movement_smb", env.run_id, env.topo, {"target": "WS-02", "source": "WS-01"})
    print(f"    Lateral Movement status: {res['status'].upper()}")
    print(f"    MITRE Tactic: {res['mitre']['tactic']} (Technique: {res['mitre']['technique_id']})")
    
    # Cycle 4: Defender Detection and Isolation
    print("\n>>> TICK 4: Defender detects malicious lateral movement and attempts host isolation...")
    action_dict = {
        "agent_type": "defender",
        "action_id": 3, # Isolate
        "target_host_id": "WS-02"
    }
    obs, att_rew, def_rew, done, info = env.step(action_dict)
    print(f"    Defender Action Status: {info['action_result']['status'].upper()}")
    print(f"    Is WS-02 Isolated: {ws2.isolated}")
    print(f"    Defender Reward: {def_rew}")
    
    # Cycle 5: Sysadmin patch service
    print("\n>>> TICK 5: System Admin applies security patch to DC-01 SMB service...")
    action_dict = {
        "agent_type": "defender",
        "action_id": 4, # Patch
        "target_host_id": "DC-01",
        "service_name": "SMB"
    }
    obs, att_rew, def_rew, done, info = env.step(action_dict)
    print(f"    Patch Status: {info['action_result']['status'].upper()}")
    print(f"    Active DC-01 SMB Vulnerabilities: {dc.services[0].vulnerabilities}")
    
    # 5. Final Report Summary
    print_header("Simulation Summary Report")
    print(f"Run ID: {env.run_id}")
    print(f"Workstation WS-01 compromised: {ws1.compromised}")
    print(f"Workstation WS-02 compromised: {ws2.compromised} (Isolated: {ws2.isolated})")
    print(f"Domain Controller compromised: {dc.compromised}")
    print(f"Defensive Action Score: {defender.alerts_handled} alerts handled successfully")
    print("=" * 60)

if __name__ == "__main__":
    main()
