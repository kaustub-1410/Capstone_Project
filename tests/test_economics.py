import pytest
from shared.models import Host, Service
from simulation_engine.network import NetworkTopology
from economics.financial_model import FinancialLossEstimator
from economics.risk_scoring import RiskScoringEngine
from economics.business_impact import BusinessImpactAnalyzer

@pytest.fixture
def test_network():
    topo = NetworkTopology()
    topo.neo4j_enabled = False
    
    # Setup hosts
    dc = Host(id="DC-01", name="DC-01", ip="10.0.1.2", os="Windows Server", role="domain_controller", asset_value=10000.0, sensitivity_level="critical")
    ws1 = Host(id="WS-01", name="WS-01", ip="10.0.1.5", os="Windows 11", role="workstation", asset_value=100.0, sensitivity_level="low")
    ws2 = Host(id="WS-02", name="WS-02", ip="10.0.1.6", os="Windows 11", role="workstation", asset_value=100.0, sensitivity_level="low")
    
    # Add vulnerabilities
    ws1.services.append(Service(name="SMB", port=445, vulnerabilities=["CVE-2017-0144"]))
    
    topo.add_host(dc)
    topo.add_host(ws1)
    topo.add_host(ws2)
    
    topo.add_connection("WS-01", "WS-02")
    topo.add_connection("WS-02", "DC-01")
    return topo

def test_financial_loss_estimation(test_network):
    estimator = FinancialLossEstimator()
    
    # Initial status (no compromises)
    loss1 = estimator.estimate_loss(test_network, [])
    assert loss1["total_estimated_loss_usd"] == 0.0
    
    # Compromise workstation 01
    test_network.hosts["WS-01"].compromised = True
    loss2 = estimator.estimate_loss(test_network, [{"type": "ransomware"}])
    
    # Direct asset loss = 100
    # Interruption = 4 hours * 100 = 400
    # Compliance = 500 * 1.0 = 500
    # Response = 50000 (ransomware)
    # Total = 100 + 400 + 500 + 50000 = 51000
    assert loss2["total_estimated_loss_usd"] == 51000.0
    assert loss2["breakdown"]["direct_asset_loss"] == 100.0

def test_risk_scoring(test_network):
    engine = RiskScoringEngine()
    
    # Baseline risk
    risk1 = engine.calculate_enterprise_risk(test_network)
    # 1 vuln, 3 hosts => vuln_density = 0.33 => vuln_factor = 0.33 * 5 = 1.66
    assert risk1 > 0.0
    assert risk1 < 5.0
    
    # Compromise DC
    test_network.hosts["DC-01"].compromised = True
    risk2 = engine.calculate_enterprise_risk(test_network)
    
    # DC compromise should push risk index up significantly
    assert risk2 > 30.0

def test_business_impact(test_network):
    analyzer = BusinessImpactAnalyzer()
    
    impact1 = analyzer.analyze_impact(test_network)
    assert impact1["service_availability_percent"] == 100.0
    assert impact1["operational_status"] == "OPERATIONAL"
    
    # Compromise workstation 1 and isolate DC
    test_network.hosts["WS-01"].compromised = True
    test_network.hosts["DC-01"].isolated = True
    
    impact2 = analyzer.analyze_impact(test_network)
    # 1 operational out of 3 = 33.3% availability
    assert impact2["service_availability_percent"] == 33.3
    assert impact2["operational_status"] == "CRITICAL_OUTAGE"
    assert impact2["rto_hours"] > 0.0
