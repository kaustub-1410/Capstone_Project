import pytest
from simulation_engine.insider_threat import InsiderThreatSimulator

def test_insider_activity_baseline():
    sim = InsiderThreatSimulator()
    
    # 1. Normal access (low score)
    score1 = sim.log_activity("hr_user", "SRV-HR", 5.0, is_working_hours=True)
    assert score1 < 0.3
    assert len(sim.security_alerts) == 0
    
    # 2. Out of department server access
    score2 = sim.log_activity("hr_user", "SRV-FIN", 5.0, is_working_hours=True)
    assert score2 >= 0.4
    
    # 3. High data volume outside working hours (should trigger alert)
    score3 = sim.log_activity("hr_user", "SRV-HR", 100.0, is_working_hours=False)
    assert score3 >= 0.6
    assert len(sim.security_alerts) == 1
    assert sim.security_alerts[0]["user"] == "hr_user"

def test_usb_exfiltration():
    sim = InsiderThreatSimulator()
    
    success = sim.simulate_usb_exfiltration("eng_user", "WS-02", ["design_plans.dwg", "source_code.zip"])
    assert success is True
    assert len(sim.security_alerts) == 1
    assert sim.security_alerts[0]["alert_type"] == "USB_Data_Exfiltration"
    assert sim.security_alerts[0]["score"] == 0.95

def test_financial_fraud():
    sim = InsiderThreatSimulator()
    
    success = sim.simulate_financial_fraud("finance_user", 500000.0)
    assert success is True
    assert len(sim.security_alerts) == 1
    assert sim.security_alerts[0]["alert_type"] == "Financial_Fraud_Transaction"
    assert sim.security_alerts[0]["amount"] == 500000.0
