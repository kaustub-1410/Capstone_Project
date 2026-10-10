import os
import sys
import uuid
import random
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Mock external DB modules for standard python environments
from unittest.mock import MagicMock
sys.modules['neo4j'] = MagicMock()
sys.modules['redis'] = MagicMock()
sys.modules['clickhouse_connect'] = MagicMock()
sys.modules['psycopg2'] = MagicMock()

# Ensure current directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.models import Host, Service, User
from simulation_engine.network import NetworkTopology
from agent_framework.base import AttackerAgent, DefenderAgent
from rl_service.environment import AMCDSEnv
from gnn_layer.predictor import NetworkRiskPredictor
from llm_orchestration.client import UnifiedLLMClient
from llm_orchestration.agents import StrategicPlannerAgent, TacticalReasoningAgent, IncidentAnalysisAgent

app = FastAPI(title="AMCDS Simulation Dashboard Backend")

# Add CORS Middleware to enable frontend calls from other ports/origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def setup_standard_topology():
    topo = NetworkTopology()
    topo.neo4j_enabled = False

    eternal_blue = "CVE-2017-0144"
    log4shell = "CVE-2021-44228"
    apache_pt = "CVE-2021-41773"

    # Domain Controller
    topo.add_host(Host(
        id="DC-01", name="Domain-Controller", ip="10.0.1.2", os="Windows Server 22", role="domain_controller",
        services=[
            Service(name="LDAP", port=389),
            Service(name="SMB", port=445, vulnerabilities=[eternal_blue])
        ]
    ))
    # DB Server
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
    for i in range(1, 7):
        topo.add_connection(f"WS-0{i}", "WEB-02")
    topo.add_connection("WEB-01", "WEB-02")
    topo.add_connection("WEB-02", "DB-01")
    topo.add_connection("WEB-02", "DC-01")

    # Add employees
    for i in range(1, 7):
        username = f"user{i}"
        topo.add_user(User(id=f"U-0{i}", username=username, phishing_susceptibility=0.4 + (i * 0.08)))

    return topo

def setup_intelligent_topology():
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
    
    return topo

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.post("/api/run")
def run_simulation(mode: str = Query("standard", regex="^(standard|intelligent)$")):
    try:
        if mode == "standard":
            topo = setup_standard_topology()
            env = AMCDSEnv(topo, max_steps=30)
            env.reset()
            
            attacker = AttackerAgent(agent_id="APT-41")
            defender = DefenderAgent(agent_id="Sentinel-AI")
            
            logs = []
            
            for tick in range(1, 31):
                events = []
                
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
                    
                    action_name = attacker_act["action"]
                    status = "SUCCESS" if attacker_act.get("status") != "failed" else "failed"
                    
                    events.append({
                        "agent": f"Attacker ({attacker.agent_id})",
                        "target": target_host,
                        "action": action_name,
                        "status": status,
                        "reward": att_rew,
                        "detail": f"Attacker ({attacker.agent_id}): Executed {action_name.upper()} on {target_host} -> Reward: {att_rew:+.1f}"
                    })
                    
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
                    
                    events.append({
                        "agent": f"Defender ({defender.agent_id})",
                        "target": target_host,
                        "action": "isolate",
                        "status": "SUCCESS",
                        "reward": def_rew,
                        "detail": f"Defender ({defender.agent_id}): Executed ISOLATE on {target_host} -> Reward: {def_rew:+.1f}"
                    })
                    
                logs.append({
                    "tick": tick,
                    "events": events
                })
                
            run_id = str(env.run_id)
            
        else:  # mode == "intelligent"
            topo = setup_intelligent_topology()
            env = AMCDSEnv(topo, max_steps=10)
            env.reset()
            
            predictor = NetworkRiskPredictor(model_type="gat")
            client = UnifiedLLMClient()
            
            strat_planner = StrategicPlannerAgent(client)
            incident_hunter = IncidentAnalysisAgent(client)
            
            logs = []
            
            for tick in range(1, 11):
                events = []
                
                # GNN Step
                risk_scores = predictor.predict_risk_scores(topo)
                top_risk_host = max(risk_scores, key=risk_scores.get) if risk_scores else "N/A"
                top_risk_score = risk_scores.get(top_risk_host, 0.0)
                
                events.append({
                    "agent": "GNN Risk Engine",
                    "target": top_risk_host,
                    "action": "risk_prediction",
                    "status": "SUCCESS",
                    "reward": 0.0,
                    "detail": f"GNN risk assessment completed. Highest risk target: {top_risk_host} (Score: {top_risk_score:.4f})"
                })
                
                # Attacker LLM Choice
                host_summary = [{"id": h.id, "compromised": h.compromised} for h in topo.hosts.values()]
                attack_plan = strat_planner.select_attack_target(host_summary, risk_scores)
                target_id = attack_plan.get("target", "WS-01")
                action_name = attack_plan.get("action", "network_scan")
                
                # Execute Attack
                res = env.attack_exec.execute_action(action_name, env.run_id, topo, {"target": target_id, "user": "jdoe"})
                att_rew = env.reward_calc.calculate_attacker_reward(res)
                
                events.append({
                    "agent": "Attacker LLM (APT-Strategic)",
                    "target": target_id,
                    "action": action_name,
                    "status": "SUCCESS" if res["status"] == "success" else "failed",
                    "reward": att_rew,
                    "detail": f"Strategic: {attack_plan.get('thought')}. Executed {action_name.upper()} on {target_id}."
                })
                
                # Defender LLM Choice
                mock_alerts = [
                    {"host_id": target_id, "severity": "CRITICAL", "message": f"Suspicious activity {action_name} detected."}
                ]
                defense_plan = incident_hunter.analyze_telemetry_alerts(mock_alerts)
                def_target = defense_plan.get("target", target_id)
                def_action = defense_plan.get("action", "isolate_host")
                
                # Execute Defense
                res_def = env.defense_exec.execute_action(def_action, env.run_id, topo, {"target": def_target})
                def_rew = env.reward_calc.calculate_defender_reward(res_def, topo)
                
                action_normalized = "isolate" if def_action == "isolate_host" else def_action
                
                events.append({
                    "agent": "Defender LLM (Incident-Hunter)",
                    "target": def_target,
                    "action": action_normalized,
                    "status": "SUCCESS" if res_def["status"] == "success" else "failed",
                    "reward": def_rew,
                    "detail": f"Triage: {defense_plan.get('thought')}. Executed {def_action.upper()} on {def_target}."
                })
                
                logs.append({
                    "tick": tick,
                    "events": events
                })
                
            run_id = str(env.run_id)

        # Build final hosts response
        hosts_list = []
        for h in topo.hosts.values():
            hosts_list.append({
                "id": h.id,
                "ip": h.ip,
                "role": h.role,
                "compromised": h.compromised,
                "isolated": h.isolated,
                "os": h.os,
                "services": [{"name": s.name, "port": s.port, "vulnerabilities": s.vulnerabilities} for s in h.services]
            })

        connections_list = [{"source": c[0], "target": c[1]} for c in topo.connections]

        # Calculate final metrics
        total = len(topo.hosts)
        compromised = len([h for h in topo.hosts.values() if h.compromised and not h.isolated])
        isolated = len([h for h in topo.hosts.values() if h.isolated])
        clean = total - len([h for h in topo.hosts.values() if h.compromised])
        score = int((clean / total) * 100) if total > 0 else 0

        attacker_accumulated = sum(ev["reward"] for t in logs for ev in t["events"] if "attacker" in ev["agent"].lower())
        defender_accumulated = sum(ev["reward"] for t in logs for ev in t["events"] if "defender" in ev["agent"].lower())

        metrics = {
            "total_nodes": total,
            "compromised_nodes": compromised,
            "clean_nodes": clean,
            "isolated_nodes": isolated,
            "protection_score": score,
            "attacker_reward": round(attacker_accumulated, 2),
            "defender_reward": round(defender_accumulated, 2)
        }

        return {
            "run_id": run_id,
            "connections": connections_list,
            "hosts": hosts_list,
            "metrics": metrics,
            "logs": logs
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/dashboard/soc")
def get_soc_dashboard():
    """Triage alerts, compromised hosts, and high-risk nodes (centrality)."""
    try:
        topo = setup_standard_topology()
        # Mock some compromises
        topo.hosts["WS-01"].compromised = True
        topo.hosts["WS-02"].compromised = True
        
        from attack_engine.attack_graph import AttackGraph
        ag = AttackGraph(topo)
        critical_nodes = ag.compute_critical_nodes()
        
        compromised = [h.id for h in topo.hosts.values() if h.compromised]
        
        alerts = [
            {"host_id": "WS-01", "severity": "CRITICAL", "message": "Suspicious SMB write detected."},
            {"host_id": "WS-02", "severity": "HIGH", "message": "Failed administrative logon."}
        ]
        
        return {
            "compromised_hosts": compromised,
            "active_alerts": alerts,
            "critical_nodes": [{"host_id": node[0], "centrality": round(node[1], 4)} for node in critical_nodes[:5]]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/dashboard/engineer")
def get_engineer_dashboard():
    """GNN risk scores, patch statuses, and active services."""
    try:
        topo = setup_standard_topology()
        from gnn_layer.predictor import NetworkRiskPredictor
        predictor = NetworkRiskPredictor(model_type="gcn")
        risk_scores = predictor.predict_risk_scores(topo)
        
        services = []
        for h in topo.hosts.values():
            for s in h.services:
                services.append({
                    "host_id": h.id,
                    "service_name": s.name,
                    "port": s.port,
                    "vulnerabilities": s.vulnerabilities
                })
                
        return {
            "risk_scores": {k: round(v, 4) for k, v in risk_scores.items()},
            "monitored_services": services
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/dashboard/hunter")
def get_hunter_dashboard():
    """Lateral movement vectors and blast radius calculations."""
    try:
        topo = setup_standard_topology()
        from attack_engine.blast_radius import BlastRadiusCalculator
        calc = BlastRadiusCalculator(topo)
        
        exposure = calc.get_highest_exposure_nodes(top_k=5)
        
        return {
            "highest_exposure_nodes": exposure,
            "blast_radius_default": calc.calculate_blast_radius("WEB-01", max_hops=2)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/dashboard/ir")
def get_ir_dashboard():
    """Incident response logs and containment/isolation controls."""
    try:
        topo = setup_standard_topology()
        # Isolate one compromised node for illustration
        topo.hosts["WS-01"].compromised = True
        topo.hosts["WS-01"].isolated = True
        
        isolated = [h.id for h in topo.hosts.values() if h.isolated]
        compromised = [h.id for h in topo.hosts.values() if h.compromised]
        
        return {
            "compromised_hosts": compromised,
            "isolated_hosts": isolated,
            "incident_response_logs": [
                {"timestamp": "2026-07-06T12:00:00Z", "event": "WS-01 network isolation successfully completed."}
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/dashboard/ciso")
def get_ciso_dashboard():
    """Enterprise risk score, compliance gap, and economic impact overview."""
    try:
        topo = setup_standard_topology()
        topo.hosts["WS-01"].compromised = True
        
        from economics.risk_scoring import RiskScoringEngine
        from economics.financial_model import FinancialLossEstimator
        
        rse = RiskScoringEngine()
        fle = FinancialLossEstimator()
        
        risk = rse.calculate_enterprise_risk(topo)
        loss = fle.estimate_loss(topo, [{"type": "ransomware"}])
        
        return {
            "enterprise_risk_score": risk,
            "financial_loss_estimate": loss
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/dashboard/executive")
def get_executive_dashboard():
    """CEO summary reports, projected financial exposure, and downtime cost estimation."""
    try:
        topo = setup_standard_topology()
        topo.hosts["WS-01"].compromised = True
        
        from economics.business_impact import BusinessImpactAnalyzer
        from economics.financial_model import FinancialLossEstimator
        from copilot.report_generator import ReportGenerator
        
        bia = BusinessImpactAnalyzer()
        fle = FinancialLossEstimator()
        rg = ReportGenerator()
        
        impact = bia.analyze_impact(topo)
        loss = fle.estimate_loss(topo, [{"type": "ransomware"}])
        summary = rg.generate_executive_summary(
            risk_score=75.0,
            financial_loss=loss["total_estimated_loss_usd"],
            active_threats=1
        )
        
        return {
            "business_impact": impact,
            "financial_summary": loss,
            "markdown_executive_summary": summary
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
