import os
import sys
import uuid
from unittest.mock import MagicMock

# Mock out databases
sys.modules['neo4j'] = MagicMock()
sys.modules['redis'] = MagicMock()
sys.modules['clickhouse_connect'] = MagicMock()
sys.modules['psycopg2'] = MagicMock()

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from shared.models import Host, Service
from simulation_engine.network import NetworkTopology
from gnn_layer.predictor import NetworkRiskPredictor
from llm_orchestration.client import UnifiedLLMClient
from llm_orchestration.agents import StrategicPlannerAgent, TacticalReasoningAgent, IncidentAnalysisAgent

def main():
    print("=" * 70)
    print("      AMCDS CO-EVOLUTION INTELLIGENCE PLATFORM DEMO (PHASE 3)      ")
    print("=" * 70)

    # 1. Setup Network Topology
    topo = NetworkTopology()
    topo.neo4j_enabled = False
    
    dc = Host(id="DC-01", name="Domain-Controller", ip="10.0.1.2", os="Windows Server 22", role="domain_controller",
              services=[Service(name="SMB", port=445, vulnerabilities=["CVE-2017-0144"])])
    db = Host(id="DB-01", name="SQLServer", ip="10.0.1.10", os="Ubuntu 22.04", role="db_server",
              services=[Service(name="MySQL", port=3306)])
    ws = Host(id="WS-01", name="Workstation-1", ip="10.0.2.20", os="Windows 11", role="workstation",
              services=[Service(name="SMB", port=445, vulnerabilities=["CVE-2017-0144"])])
    
    topo.add_host(dc)
    topo.add_host(db)
    topo.add_host(ws)
    topo.add_connection("WS-01", "DB-01")
    topo.add_connection("DB-01", "DC-01")
    
    print("[+] Formatted 3-host network environment.")

    # 2. Run GNN Predictor Risk Analysis
    print("\n[+] Executing Graph Neural Network Layer Risk Analysis...")
    predictor = NetworkRiskPredictor(model_type="gat")
    risk_scores = predictor.predict_risk_scores(topo)
    
    for host_id, score in risk_scores.items():
        print(f"  * Host {host_id:<7} -> GNN Attack Path Exposure Score: {score:.4f}")

    # 3. Setup LLM Strategic Planner
    print("\n[+] Invoking Strategic LLM Agent to select target...")
    client = UnifiedLLMClient()
    planner = StrategicPlannerAgent(client)
    
    host_summary = [
        {"id": h.id, "role": h.role, "compromised": h.compromised, "isolated": h.isolated}
        for h in topo.hosts.values()
    ]
    
    plan = planner.select_attack_target(host_summary, risk_scores)
    print(f"  * LLM Plan Thought : {plan.get('thought')}")
    print(f"  * Selected Action  : {plan.get('action')}")
    print(f"  * Chosen Target    : {plan.get('target')}")

    # 4. Setup LLM Tactical Reasoning Agent
    print("\n[+] Invoking Tactical LLM Exploit Agent...")
    tactical = TacticalReasoningAgent(client)
    chosen_host_id = plan.get("target", "WS-01")
    chosen_host = topo.hosts.get(chosen_host_id)
    
    if chosen_host:
        host_dict = {"id": chosen_host.id, "services": [{"name": s.name, "vulnerabilities": s.vulnerabilities} for s in chosen_host.services]}
        exploit_choice = tactical.select_exploit(host_dict)
        print(f"  * Tactical Thought : {exploit_choice.get('thought')}")
        print(f"  * Target Service   : {exploit_choice.get('service_name')}")
        print(f"  * Chosen Exploit   : {exploit_choice.get('exploit_id')}")

    # 5. Setup LLM Incident Triage Analyst
    print("\n[+] Triggering Security Alerts Incident Triage...")
    analyst = IncidentAnalysisAgent(client)
    
    mock_alerts = [
        {"host_id": "WS-01", "severity": "CRITICAL", "message": "Potential LSASS credential access detected."},
        {"host_id": "DB-01", "severity": "WARNING", "message": "Unusual SSH connection from workstation."}
    ]
    
    triage_result = analyst.analyze_telemetry_alerts(mock_alerts)
    print(f"  * Threat Analyst Thought: {triage_result.get('thought')}")
    print(f"  * Recommended Action    : {triage_result.get('action')}")
    print(f"  * Target Host Node      : {triage_result.get('target')}")
    print("=" * 70)

if __name__ == "__main__":
    main()
