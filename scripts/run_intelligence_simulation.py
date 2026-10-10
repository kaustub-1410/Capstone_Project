import os
import sys
import uuid
import time
from datetime import datetime

# Mock out external DB modules for offline demonstration
from unittest.mock import MagicMock
sys.modules['neo4j'] = MagicMock()
sys.modules['redis'] = MagicMock()
sys.modules['clickhouse_connect'] = MagicMock()
sys.modules['psycopg2'] = MagicMock()

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from shared.models import Host, Service, User
from simulation_engine.network import NetworkTopology
from telemetry_service.producer import TelemetryProducer
from attack_engine.executor import AttackExecutor
from defense_engine.executor import DefenseExecutor
from gnn_layer.predictor import NetworkRiskPredictor
from llm_orchestration.client import UnifiedLLMClient
from llm_orchestration.agents import StrategicPlannerAgent, TacticalReasoningAgent, IncidentAnalysisAgent
from rl_service.environment import AMCDSEnv

def print_banner():
    print("""
======================================================================
      AMCDS FULL INTELLIGENCE SIMULATOR RUN: GNN + LLM + TELEMETRY
======================================================================
""")

def main():
    print_banner()
    
    # 1. Setup Network
    print("[+] Building 8-node subnet...")
    topo = NetworkTopology()
    topo.neo4j_enabled = False
    
    eternal_blue = "CVE-2017-0144"
    log4shell = "CVE-2021-44228"
    
    topo.add_host(Host(id="DC-01", name="Domain-Controller", ip="10.0.1.2", os="Windows Server 22", role="domain_controller",
                       services=[Service(name="SMB", port=445, vulnerabilities=[eternal_blue])]))
    topo.add_host(Host(id="DB-01", name="SQL-Server", ip="10.0.1.10", os="Ubuntu 22.04", role="db_server",
                       services=[Service(name="MySQL", port=3306)]))
    topo.add_host(Host(id="WEB-01", name="IIS-Web", ip="10.0.2.80", os="Windows Server 19", role="web_server",
                       services=[Service(name="HTTP", port=80, vulnerabilities=[log4shell])]))
    
    for i in range(1, 6):
        topo.add_host(Host(id=f"WS-0{i}", name=f"Workstation-{i}", ip=f"10.0.3.{20+i}", os="Windows 11", role="workstation",
                           services=[Service(name="SMB", port=445, vulnerabilities=[eternal_blue])]))

    # Link paths
    for i in range(1, 6):
        topo.add_connection(f"WS-0{i}", "WEB-01")
    topo.add_connection("WEB-01", "DB-01")
    topo.add_connection("DB-01", "DC-01")

    # Add user
    topo.add_user(User(id="U-01", username="jdoe", phishing_susceptibility=0.9))

    # Initialize environment, predictor, and LLM clients
    env = AMCDSEnv(topo, max_steps=10)
    env.reset()
    predictor = NetworkRiskPredictor(model_type="gat")
    client = UnifiedLLMClient()
    
    # Planners
    strat_planner = StrategicPlannerAgent(client)
    tactical_agent = TacticalReasoningAgent(client)
    incident_hunter = IncidentAnalysisAgent(client)

    run_log = []
    
    print("\n[+] Initiating co-evolution loop (10 Ticks)...")
    for tick in range(1, 11):
        tick_str = f"--- TICK {tick:02d} ---"
        print(f"\n{tick_str}")
        run_log.append(tick_str)
        
        # 1. GNN Step
        risk_scores = predictor.predict_risk_scores(topo)
        gnn_log = f"GNN Top Exposure Score: WS-01 ({risk_scores.get('WS-01', 0.0):.4f})"
        print(f"  [GNN] {gnn_log}")
        run_log.append(f"  [GNN] {gnn_log}")
        
        # 2. Attacker LLM Choice
        host_summary = [{"id": h.id, "compromised": h.compromised} for h in topo.hosts.values()]
        attack_plan = strat_planner.select_attack_target(host_summary, risk_scores)
        target_id = attack_plan.get("target", "WS-01")
        action_name = attack_plan.get("action", "network_scan")
        
        att_log1 = f"Attacker Strategic Plan: {attack_plan.get('thought')}"
        att_log2 = f"Attacker executing action: {action_name.upper()} on target: {target_id}"
        print(f"  [ATTACKER] {att_log1}")
        print(f"  [ATTACKER] {att_log2}")
        run_log.append(f"  [ATTACKER] {att_log1}")
        run_log.append(f"  [ATTACKER] {att_log2}")
        
        # Execute Attack
        res = env.attack_exec.execute_action(action_name, env.run_id, topo, {"target": target_id, "user": "jdoe"})
        
        # 3. Defender LLM Alert Triage
        mock_alerts = [
            {"host_id": target_id, "severity": "CRITICAL", "message": f"Suspicious activity {action_name} detected."}
        ]
        defense_plan = incident_hunter.analyze_telemetry_alerts(mock_alerts)
        def_target = defense_plan.get("target", target_id)
        def_action = defense_plan.get("action", "isolate_host")
        
        def_log1 = f"Defender Triage: {defense_plan.get('thought')}"
        def_log2 = f"Defender executing response: {def_action.upper()} on node: {def_target}"
        print(f"  [DEFENDER] {def_log1}")
        print(f"  [DEFENDER] {def_log2}")
        run_log.append(f"  [DEFENDER] {def_log1}")
        run_log.append(f"  [DEFENDER] {def_log2}")
        
        # Execute Defense
        env.defense_exec.execute_action(def_action, env.run_id, topo, {"target": def_target})
        
        time.sleep(0.05)

    # Export markdown report
    total_hosts = len(topo.hosts)
    compromised_hosts = len([h for h in topo.hosts.values() if h.compromised])
    clean_hosts = total_hosts - compromised_hosts
    isolated_hosts = len([h for h in topo.hosts.values() if h.isolated])
    
    report_content = f"""# AMCDS Integrated GNN & LLM Simulation Report

**Run ID:** `{env.run_id}`  
**Generated At:** `{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC`

## Performance Metrics
* **Total Hosts:** `{total_hosts}`
* **Compromised Nodes:** `{compromised_hosts}` ({(compromised_hosts/total_hosts)*100:.1f}%)
* **Clean Nodes:** `{clean_hosts}` ({(clean_hosts/total_hosts)*100:.1f}%)
* **Defender Isolated Nodes:** `{isolated_hosts}`
* **Asset Protection Score:** `{(clean_hosts/total_hosts)*100:.1f}%`

---

## Network Health Matrix
| Host ID | Role | Status | Containment Isolation |
|---------|------|--------|-------------------|
"""
    for host in topo.hosts.values():
        status = "COMPROMISED" if host.compromised else "clean"
        shield = "isolated" if host.isolated else "connected"
        report_content += f"| `{host.id}` | {host.role} | {status} | {shield} |\n"

    report_content += "\n---\n\n## Execution log\n"
    for line in run_log:
        report_content += f"{line}\n"

    os.makedirs(os.path.join(ROOT, "reports"), exist_ok=True)
    report_path = os.path.join(ROOT, "reports", "intelligence_simulation_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
        
    print(f"\n[+] Successfully exported final report to: {report_path}\n")

if __name__ == "__main__":
    main()
