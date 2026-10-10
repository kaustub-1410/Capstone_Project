import os
import sys
import uuid
import random
import time
from datetime import datetime

# Mock external DB modules for standard python environments
from unittest.mock import MagicMock
sys.modules['neo4j'] = MagicMock()
sys.modules['redis'] = MagicMock()
sys.modules['clickhouse_connect'] = MagicMock()
sys.modules['psycopg2'] = MagicMock()

# Include workspace root
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from shared.models import Host, Service, User, Credential
from simulation_engine.network import NetworkTopology
from agent_framework.base import AttackerAgent, DefenderAgent, SysAdminAgent, EmployeeAgent
from rl_service.environment import AMCDSEnv

def print_banner():
    print("""
======================================================================
     AMCDS CO-EVOLUTIONARY SIMULATOR: DYNAMIC ADVERSARIAL RUN
======================================================================
""")

def print_header(title: str):
    print("=" * 60)
    print(f" {title.upper()} ".center(60, "="))
    print("=" * 60)

def print_system_status(topo: NetworkTopology):
    print("\n" + "-"*50)
    print(" CURRENT NETWORK DEFENSE STATUS STATE ".center(50, "|"))
    print("-"*50)
    for host in topo.hosts.values():
        status = "COMPROMISED" if host.compromised else "CLEAN"
        shield = " [ISOLATED]" if host.isolated else ""
        print(f"  {host.id:<7} ({host.role:<18}): {status:<12} {shield}")
    print("-"*50)

def main():
    print_banner()

    # 1. Initialize Network Topology (10 nodes)
    topo = NetworkTopology()
    topo.neo4j_enabled = False # Offline simulation demo mode
    
    # Define exploits and vulnerabilities
    eternal_blue = "CVE-2017-0144"
    log4shell = "CVE-2021-44228"
    apache_pt = "CVE-2021-41773"

    print("[*] Generating 10-node Enterprise Active Directory Subnet...")
    
    # Domain Controller
    topo.add_host(Host(
        id="DC-01", name="Domain-Controller", ip="10.0.1.2", os="Windows Server 22", role="domain_controller",
        services=[Service(name="LDAP", port=389), Service(name="SMB", port=445, vulnerabilities=[eternal_blue])]
    ))
    # DB Servers
    topo.add_host(Host(
        id="DB-01", name="SQL-Primary", ip="10.0.1.10", os="Ubuntu 22.04", role="db_server",
        services=[Service(name="MySQL", port=3306)]
    ))
    # Web Servers
    topo.add_host(Host(
        id="WEB-01", name="IIS-Public", ip="10.0.2.80", os="Windows Server 19", role="web_server",
        services=[Service(name="HTTP", port=80, vulnerabilities=[apache_pt])]
    ))
    topo.add_host(Host(
        id="WEB-02", name="Apache-Internal", ip="10.0.2.81", os="RedHat 8", role="web_server",
        services=[Service(name="HTTP", port=80, vulnerabilities=[log4shell])]
    ))
    # Workstations
    for i in range(1, 7):
        ws_id = f"WS-0{i}"
        topo.add_host(Host(
            id=ws_id, name=f"Workstation-User{i}", ip=f"10.0.3.{20+i}", os="Windows 11", role="workstation",
            services=[Service(name="SMB", port=445, vulnerabilities=[eternal_blue])]
        ))

    # Add network connection routes
    # Router 1 connects workstations to internal web servers
    for i in range(1, 7):
        topo.add_connection(f"WS-0{i}", "WEB-02")
    # Web Servers connect to database and Domain Controller
    topo.add_connection("WEB-01", "WEB-02")
    topo.add_connection("WEB-02", "DB-01")
    topo.add_connection("WEB-02", "DC-01")

    # Add employees
    for i in range(1, 7):
        username = f"user{i}"
        topo.add_user(User(id=f"U-0{i}", username=username, phishing_susceptibility=0.4 + (i * 0.08)))

    print(f"Subnet generated successfully. Active hosts: {len(topo.hosts)} | Trust paths: {len(topo.connections)}")

    # 2. Setup Gym Environment Wrapper
    env = AMCDSEnv(topo, max_steps=30)
    obs = env.reset()

    # Create Agents
    attacker = AttackerAgent(agent_id="APT-41")
    defender = DefenderAgent(agent_id="Sentinel-AI")
    
    attacker_cumulative_reward = 0.0
    defender_cumulative_reward = 0.0

    # 3. Step Loop (30 Ticks)
    print("\n[+] Initiating co-evolution steps...")
    for tick in range(1, 31):
        print(f"\n[TICK {tick:02d}]")
        
        # Attacker decision
        attacker_act = attacker.act(None, topo)
        if attacker_act:
            target_host = attacker_act.get("target")
            action_id = 0 if attacker_act["action"] == "reconnaissance" else 1
            action_payload = {
                "agent_type": "attacker",
                "action_id": action_id,
                "target_host_id": target_host,
                "service_name": "SMB" if target_host and "WS" in target_host else "HTTP"
            }
            obs, att_rew, def_rew, done, info = env.step(action_payload)
            attacker_cumulative_reward += att_rew
            print(f"  * Attacker ({attacker.agent_id}): Execute {attacker_act['action'].upper()} on {target_host} -> Reward: {att_rew:+.1f}")
            
        # Defender decision
        defender_act = defender.act(None, topo)
        if defender_act:
            target_host = defender_act.get("target")
            action_payload = {
                "agent_type": "defender",
                "action_id": 3, # Isolate
                "target_host_id": target_host
            }
            obs, att_rew, def_rew, done, info = env.step(action_payload)
            defender_cumulative_reward += def_rew
            print(f"  * Defender ({defender.agent_id}): Execute ISOLATE on {target_host} -> Reward: {def_rew:+.1f}")
            
        # Passive Telemetry check
        time.sleep(0.05)

    # 4. Final Evaluation Dashboard
    print_system_status(topo)
    
    print_header("AMCDS Co-Evolution Dashboard Metrics")
    total_hosts = len(topo.hosts)
    compromised_hosts = len([h for h in topo.hosts.values() if h.compromised])
    clean_hosts = total_hosts - compromised_hosts
    isolated_hosts = len([h for h in topo.hosts.values() if h.isolated])
    
    asset_protection_score = (clean_hosts / total_hosts) * 100
    
    print(f"  - Total Network Nodes       : {total_hosts}")
    print(f"  - Compromised Systems       : {compromised_hosts} ({(compromised_hosts/total_hosts)*100:.1f}%)")
    print(f"  - Protected systems         : {clean_hosts} ({(clean_hosts/total_hosts)*100:.1f}%)")
    print(f"  - Defender Isolated Nodes   : {isolated_hosts}")
    print(f"  - Asset Protection Score    : {asset_protection_score:.1f}%")
    print(f"  - Attacker Net Reward       : {attacker_cumulative_reward:+.2f}")
    print(f"  - Defender Net Reward       : {defender_cumulative_reward:+.2f}")
    print("=" * 60)

    # 5. Export Report to Markdown File
    report_content = f"""# AMCDS Simulation Execution Report

**Simulation Run ID:** `{env.run_id}`  
**Timestamp:** `{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC`

## Executive Summary
This report summarizes the co-evolution of attacker agent `{attacker.agent_id}` and defender agent `{defender.agent_id}` across 30 ticks on a 10-node enterprise network.

### Performance Dashboard
* **Total Network Nodes:** `{total_hosts}`
* **Compromised Systems:** `{compromised_hosts}` ({(compromised_hosts/total_hosts)*100:.1f}%)
* **Protected (Clean) Systems:** `{clean_hosts}` ({(clean_hosts/total_hosts)*100:.1f}%)
* **Defender Isolated Nodes:** `{isolated_hosts}`
* **Asset Protection Score:** `{asset_protection_score:.1f}%`
* **Attacker Net Reward:** `{attacker_cumulative_reward:+.2f}`
* **Defender Net Reward:** `{defender_cumulative_reward:+.2f}`

---

## Network State Representation
| Host ID | Role | Status | Defense Isolation |
|---------|------|--------|-------------------|
"""
    for host in topo.hosts.values():
        status = "COMPROMISED" if host.compromised else "clean"
        shield = "isolated" if host.isolated else "connected"
        report_content += f"| `{host.id}` | {host.role} | {status} | {shield} |\n"

    report_content += "\n---\n\nReport generated by AMCDS.\n"

    os.makedirs(os.path.join(ROOT, "reports"), exist_ok=True)
    report_path = os.path.join(ROOT, "reports", "simulation_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    print(f"\n[+] Successfully exported simulation report to: {report_path}\n")

if __name__ == "__main__":
    main()
