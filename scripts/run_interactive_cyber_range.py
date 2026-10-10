import os
import sys
import uuid
import time
from datetime import datetime

# Add root folder to sys.path
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

# Mock out external DB modules for offline execution
from unittest.mock import MagicMock
sys.modules['neo4j'] = MagicMock()
sys.modules['redis'] = MagicMock()
sys.modules['clickhouse_connect'] = MagicMock()
sys.modules['psycopg2'] = MagicMock()

from shared.models import Host, Service, User, TelemetryEvent
from simulation_engine.network import NetworkTopology
from simulation_engine.ingestor import RealWorldIngestor
from attack_engine.executor import AttackExecutor
from defense_engine.executor import DefenseExecutor
from defense_engine.real_world_mitigation import RealWorldMitigationRunner
from gnn_layer.predictor import NetworkRiskPredictor
from telemetry_service.producer import TelemetryProducer
from telemetry_service.file_ingestor import TelemetryFileIngestor
from llm_orchestration.client import UnifiedLLMClient
from llm_orchestration.agents import StrategicPlannerAgent, IncidentAnalysisAgent

def print_menu():
    print("""
========================================================================
                      AMCDS OPERATIONAL CYBER RANGE
========================================================================
Choose a topology initialization source:
[1] Initialize with Mock Enterprise Topology (Default)
[2] Ingest from custom Asset Inventory CSV
[3] Ingest from Nessus Vulnerability Scan (CSV)
[4] Ingest from BloodHound Active Directory JSON
========================================================================
""")

def print_network_status(topo: NetworkTopology, risk_scores: dict):
    print("\n" + "=" * 80)
    print(" " * 25 + "CURRENT ENTERPRISE NETWORK HEALTH")
    print("=" * 80)
    print(f"{'Host ID':<10} | {'IP Address':<15} | {'Role':<18} | {'Status':<13} | {'Shield':<10} | {'GNN Exposure'}")
    print("-" * 80)
    for host in topo.hosts.values():
        status = "COMPROMISED" if host.compromised else "CLEAN"
        shield = "ISOLATED" if host.isolated else "CONNECTED"
        risk = risk_scores.get(host.id, 0.0)
        print(f"{host.id:<10} | {host.ip:<15} | {host.role:<18} | {status:<13} | {shield:<10} | {risk:.4f}")
    print("=" * 80)

def main():
    print_menu()
    choice = input("Select an option [1-4]: ").strip()
    
    topo = NetworkTopology()
    topo.neo4j_enabled = False # Run offline for range environment
    
    ingestor = RealWorldIngestor(topo)
    
    if choice == "2":
        path = input("Enter Asset CSV file path: ").strip()
        if os.path.exists(path):
            ingestor.import_assets_csv(path)
        else:
            print("[-] File not found! Falling back to default mock topology.")
            choice = "1"
    elif choice == "3":
        path = input("Enter Nessus Scan CSV file path: ").strip()
        if os.path.exists(path):
            ingestor.import_nessus_csv(path)
        else:
            print("[-] File not found! Falling back to default mock topology.")
            choice = "1"
    elif choice == "4":
        path = input("Enter BloodHound JSON file path: ").strip()
        if os.path.exists(path):
            ingestor.import_bloodhound_json(path)
        else:
            print("[-] File not found! Falling back to default mock topology.")
            choice = "1"
            
    if choice == "1" or len(topo.hosts) == 0:
        # Default mock setup
        print("[+] Generating baseline Enterprise Network Topology...")
        eternal_blue = "CVE-2017-0144"
        log4shell = "CVE-2021-44228"
        
        topo.add_host(Host(id="DC-01", name="Domain-Controller", ip="10.0.1.2", os="Windows Server 2022", role="domain_controller",
                           services=[Service(name="SMB", port=445, vulnerabilities=[eternal_blue])]))
        topo.add_host(Host(id="DB-01", name="SQL-Server", ip="10.0.1.10", os="Ubuntu 22.04", role="db_server",
                           services=[Service(name="MySQL", port=3306)]))
        topo.add_host(Host(id="WEB-01", name="IIS-Web", ip="10.0.2.80", os="Windows Server 2019", role="web_server",
                           services=[Service(name="HTTP", port=80, vulnerabilities=[log4shell])]))
        
        for i in range(1, 4):
            topo.add_host(Host(id=f"WS-0{i}", name=f"Workstation-{i}", ip=f"10.0.3.{20+i}", os="Windows 11", role="workstation",
                               services=[Service(name="SMB", port=445, vulnerabilities=[eternal_blue])]))

        for i in range(1, 4):
            topo.add_connection(f"WS-0{i}", "WEB-01")
        topo.add_connection("WEB-01", "DB-01")
        topo.add_connection("DB-01", "DC-01")
        topo.add_user(User(id="U-01", username="jdoe", phishing_susceptibility=0.8))

    # Initialize Services
    producer = TelemetryProducer()
    producer.clickhouse_enabled = False # Disconnect db for standalone cyber range
    
    attack_exec = AttackExecutor(producer)
    defense_exec = DefenseExecutor(producer)
    mitigation_runner = RealWorldMitigationRunner(dry_run=True)
    predictor = NetworkRiskPredictor(model_type="gat")
    
    # Try initializing LLM clients (handles offline seamlessly)
    llm_client = UnifiedLLMClient()
    strat_planner = StrategicPlannerAgent(llm_client)
    incident_agent = IncidentAnalysisAgent(llm_client)

    run_id = uuid.uuid4()
    tick = 1
    
    print("\n[+] Operational Cyber Range loaded. Press Enter to start simulation.")
    input()
    
    while True:
        print(f"\n==================== TICK {tick:02d} ====================")
        
        # 1. GNN Step (Continuous Risk Quantification)
        risk_scores = predictor.predict_risk_scores(topo)
        print_network_status(topo, risk_scores)
        
        # 2. Attacker AI Action Choice
        host_summary = [{"id": h.id, "compromised": h.compromised} for h in topo.hosts.values()]
        
        # Attacker decision
        attack_plan = strat_planner.select_attack_target(host_summary, risk_scores)
        target_id = attack_plan.get("target", "WS-01")
        action_name = attack_plan.get("action", "network_scan")
        
        print(f"\n[!] ATTACKER THOUGHTS: {attack_plan.get('thought')}")
        print(f"[!] ATTACKER ACTION: {action_name.upper()} on target {target_id}")
        
        # Run Attack Event
        res = attack_exec.execute_action(action_name, run_id, topo, {"target": target_id, "user": "jdoe"})
        print(f"[!] ATTACK STATUS: {res['status'].upper()}")
        
        # Show new generated telemetry events
        events = producer.get_offline_events()
        if events:
            print("\n--- INCOMING TELEMETRY ALERTS ---")
            for ev in events:
                print(f"[{ev.severity}] {ev.source}: {ev.message}")
            producer.clear_offline_events()
        
        # 3. Defender Human-in-the-Loop Decisions
        print("\n--- DEFENDER MITIGATION ACTIONS ---")
        print("[1] Isolate Host (Quarantine)")
        print("[2] Patch Service Vulnerability")
        print("[3] Block Incoming Service Port")
        print("[4] Generate Ansible Incident Playbook")
        print("[5] Use AI-Triage Analysis")
        print("[6] Proceed to Next Tick (Do nothing)")
        print("[7] Exit Cyber Range")
        
        action_choice = input("Enter selection [1-7]: ").strip()
        
        if action_choice == "1":
            target = input("Enter Host ID to isolate: ").strip().upper()
            if target in topo.hosts:
                # Run simulator state containment
                defense_exec.execute_action("isolate_host", run_id, topo, {"target": target})
                # Show real firewall quarantine command script
                mitigation_runner.execute_quarantine_rules(os_type="windows")
                print(f"[+] Successfully isolated {target} and generated local quarantine rules.")
            else:
                print("[-] Host not found in topology.")
                
        elif action_choice == "2":
            target = input("Enter Host ID to patch: ").strip().upper()
            service = input("Enter Service Name to patch (e.g. SMB): ").strip()
            if target in topo.hosts:
                defense_exec.execute_action("patch_service", run_id, topo, {"target": target, "service": service})
                print(f"[+] Patched {service} on {target}.")
            else:
                print("[-] Host not found in topology.")
                
        elif action_choice == "3":
            target = input("Enter Host ID: ").strip().upper()
            try:
                port = int(input("Enter Port Number: ").strip())
                if target in topo.hosts:
                    defense_exec.execute_action("block_port", run_id, topo, {"target": target, "port": port})
                    mitigation_runner.execute_port_block(port, os_type="windows")
                else:
                    print("[-] Host not found in topology.")
            except ValueError:
                print("[-] Port must be an integer.")
                
        elif action_choice == "4":
            target = input("Enter Host ID: ").strip().upper()
            action = input("Enter Action type (isolate_host / block_port): ").strip()
            port_input = input("Enter Port (only for block_port): ").strip()
            port = int(port_input) if port_input else None
            
            if target in topo.hosts:
                host = topo.hosts[target]
                playbook = mitigation_runner.generate_ansible_playbook(action, target, host.ip, port)
                print("\n[+] GENERATED ANSIBLE PLAYBOOK:")
                print(playbook)
            else:
                print("[-] Host not found in topology.")
                
        elif action_choice == "5":
            # Ask LLM Threat Hunter to analyze the incident and propose remediation
            mock_alerts = [
                {"host_id": target_id, "severity": "CRITICAL", "message": f"Suspicious activity {action_name} detected."}
            ]
            print("\n[+] Sending telemetry logs to AI Incident Response Specialist...")
            recommendation = incident_agent.analyze_telemetry_alerts(mock_alerts)
            print(f"[*] AI TRIAGE ANALYSIS: {recommendation.get('thought')}")
            print(f"[*] RECOMMENDATION: {recommendation.get('action').upper()} on target {recommendation.get('target')}")
            
        elif action_choice == "7":
            print("\n[-] Exiting AMCDS Cyber Range. Summary reports exported.")
            break
            
        tick += 1
        time.sleep(0.5)

if __name__ == "__main__":
    main()
