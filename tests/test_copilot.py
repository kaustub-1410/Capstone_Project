import pytest
from shared.models import Host
from simulation_engine.network import NetworkTopology
from llm_orchestration.client import UnifiedLLMClient
from copilot.copilot_engine import CopilotEngine
from copilot.rule_generators import RuleGenerator
from copilot.report_generator import ReportGenerator

def test_copilot_engine():
    # Setup simple topology
    topo = NetworkTopology()
    topo.neo4j_enabled = False
    
    h1 = Host(id="H1", name="WS-01", ip="10.0.1.5", os="Windows", compromised=True)
    topo.add_host(h1)
    
    client = UnifiedLLMClient() # Will use fallback mock
    copilot = CopilotEngine(llm_client=client)
    
    res = copilot.ask("Tell me about compromised hosts and next steps.", topo)
    
    assert "answer" in res
    assert "recommended_actions" in res
    assert "confidence" in res
    assert isinstance(res["answer"], str)
    assert len(res["recommended_actions"]) > 0

def test_rule_generation():
    generator = RuleGenerator()
    
    # 1. Sigma
    sigma = generator.generate_sigma_rule(
        event_type="process_creation",
        details={"title": "Detect powershell shell", "process": "powershell.exe", "id": "1234-abcd"}
    )
    assert "title: Detect powershell shell" in sigma
    assert "powershell.exe" in sigma
    
    # 2. YARA
    yara = generator.generate_yara_rule(
        rule_name="Detect_CobaltStrike",
        strings={"s1": "cobaltstrike_beacon", "s2": "cobaltstrike_shellcode"}
    )
    assert "rule Detect_CobaltStrike" in yara
    assert "cobaltstrike_beacon" in yara
    
    # 3. Suricata
    suricata = generator.generate_suricata_rule(
        rule_id=10001,
        port=445,
        payload_content="|FF|SMB"
    )
    assert "alert tcp" in suricata
    assert "sid:10001" in suricata
    assert "|FF|SMB" in suricata

def test_report_generation():
    generator = ReportGenerator()
    
    incident = {
        "id": "INC-1002",
        "classification": "Ransomware Attack",
        "severity": "CRITICAL",
        "summary": "Ransomware execution spread laterally to the core DC.",
        "vulnerability": "CVE-2017-0144",
        "entry_point": "WS-01 phishing click"
    }
    
    report = generator.generate_incident_report(incident, ["WS-01", "DC-01"])
    assert "Ransomware Attack" in report
    assert "INC-1002" in report
    assert "WS-01, DC-01" in report
    
    exec_summary = generator.generate_executive_summary(
        risk_score=78.5,
        financial_loss=450000.0,
        active_threats=3
    )
    assert "78.5/100" in exec_summary
    assert "$450,000.00" in exec_summary
