import pytest
import torch
import numpy as np
from shared.models import Host, Service
from simulation_engine.network import NetworkTopology
from gnn_layer.models import GCNModel, GraphSAGEModel, GATModel
from gnn_layer.predictor import NetworkRiskPredictor
from llm_orchestration.client import UnifiedLLMClient
from llm_orchestration.agents import StrategicPlannerAgent, TacticalReasoningAgent, IncidentAnalysisAgent

def test_gnn_model_forward_passes():
    in_dim = 4
    hidden_dim = 8
    out_dim = 1
    N = 5 # 5 nodes
    
    # Random feature matrix X and symmetric adjacency matrix A
    X = torch.rand((N, in_dim))
    A = torch.eye(N)
    A[0, 1] = A[1, 0] = 1.0
    A[2, 3] = A[3, 2] = 1.0
    
    gcn = GCNModel(in_dim, hidden_dim, out_dim)
    sage = GraphSAGEModel(in_dim, hidden_dim, out_dim)
    gat = GATModel(in_dim, hidden_dim, out_dim)
    
    out_gcn = gcn(X, A)
    out_sage = sage(X, A)
    out_gat = gat(X, A)
    
    assert out_gcn.shape == (N, out_dim)
    assert out_sage.shape == (N, out_dim)
    assert out_gat.shape == (N, out_dim)
    
    # Sigmoid should constrain outputs to [0, 1]
    assert torch.all(out_gcn >= 0.0) and torch.all(out_gcn <= 1.0)

def test_network_risk_predictor():
    topo = NetworkTopology()
    topo.neo4j_enabled = False
    
    host1 = Host(id="WS-01", name="WS-01", ip="10.0.0.5", os="Windows 11", role="workstation")
    host2 = Host(id="DC-01", name="DC-01", ip="10.0.0.2", os="Windows Server 22", role="domain_controller")
    topo.add_host(host1)
    topo.add_host(host2)
    topo.add_connection("WS-01", "DC-01")
    
    predictor = NetworkRiskPredictor(model_type="gat")
    scores = predictor.predict_risk_scores(topo)
    
    assert "WS-01" in scores
    assert "DC-01" in scores
    assert isinstance(scores["WS-01"], float)

def test_llm_agents_structured_planning():
    client = UnifiedLLMClient()
    planner = StrategicPlannerAgent(client)
    tactical = TacticalReasoningAgent(client)
    analyst = IncidentAnalysisAgent(client)
    
    # Test Strategic planner target choices
    host_summary = [{"id": "WS-01", "compromised": False, "isolated": False}]
    risk_scores = {"WS-01": 0.85}
    plan = planner.select_attack_target(host_summary, risk_scores)
    
    assert "action" in plan
    assert "target" in plan
    
    # Test Tactical exploit planning
    target = {"id": "WS-01", "services": [{"name": "SMB", "vulnerabilities": ["CVE-2017-0144"]}]}
    expl = tactical.select_exploit(target)
    assert "service_name" in expl
    
    # Test incident response recommendations
    alerts = [{"host_id": "WS-01", "severity": "CRITICAL", "message": "Malicious task registered."}]
    remedy = analyst.analyze_telemetry_alerts(alerts)
    assert "action" in remedy
    assert remedy["target"] == "WS-01"
