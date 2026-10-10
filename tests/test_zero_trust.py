import pytest
from defense_engine.zero_trust.trust_scoring import TrustScoringEngine
from defense_engine.zero_trust.continuous_auth import ContinuousAuthentication
from defense_engine.zero_trust.micro_segmentation import MicroSegmentationEngine
from defense_engine.zero_trust.least_privilege import LeastPrivilegeEngine

def test_trust_scoring():
    te = TrustScoringEngine()
    
    assert te.get_trust_score("H1") == 100.0
    
    # Evaluate a failed login
    te.evaluate_activity("H1", "failed_login")
    assert te.get_trust_score("H1") == 90.0
    
    # Evaluate a critical threat detection
    te.evaluate_activity("H1", "malicious_process", severity="CRITICAL")
    assert te.get_trust_score("H1") == 40.0
    
    # Reset score
    te.reset_score("H1")
    assert te.get_trust_score("H1") == 100.0

def test_continuous_auth():
    te = TrustScoringEngine()
    ca = ContinuousAuthentication(te)
    
    ca.start_session("session_01", "user1")
    
    # Triggering failed MFA challenges
    success = ca.trigger_mfa_challenge("session_01", success_probability=0.0)
    assert success is False
    assert te.get_trust_score("user1") == 80.0 # -20 due to WARNING level
    
    success = ca.trigger_mfa_challenge("session_01", success_probability=0.0)
    assert success is False
    assert ca.sessions["session_01"]["valid"] is False

def test_micro_segmentation():
    mse = MicroSegmentationEngine()
    
    mse.assign_host_to_segment("WS-01", "Corp")
    mse.assign_host_to_segment("WS-02", "Corp")
    mse.assign_host_to_segment("SRV-01", "Prod")
    mse.assign_host_to_segment("IOT-01", "IoT")
    
    # Corp -> Corp should be allowed
    assert mse.authorize_connection("WS-01", "WS-02") is True
    # Corp -> Prod is in allowed rules
    assert mse.authorize_connection("WS-01", "SRV-01") is True
    # Corp -> IoT should be blocked
    assert mse.authorize_connection("WS-01", "IOT-01") is False

def test_least_privilege():
    lpe = LeastPrivilegeEngine()
    
    # Register cred with permissions
    lpe.register_credential("cred_01", ["s3:Read", "s3:Write", "iam:DeleteAccessKey"])
    
    # Verify permission
    assert lpe.verify_permission("cred_01", "s3:Read") is True
    assert lpe.verify_permission("cred_01", "s3:List") is False
    
    # Audit JIT permissions usage
    revoked = lpe.revoke_unused_privileges("cred_01", ["s3:Read"])
    
    assert "s3:Write" in revoked
    assert "iam:DeleteAccessKey" in revoked
    
    assert lpe.verify_permission("cred_01", "s3:Write") is False
    assert lpe.verify_permission("cred_01", "s3:Read") is True
