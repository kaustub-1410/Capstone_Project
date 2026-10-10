import pytest
from simulation_engine.kubernetes.k8s_simulator import K8sSimulator
from simulation_engine.kubernetes.k8s_attacks import K8sAttackSimulator

def test_k8s_rbac():
    k8s = K8sSimulator()
    
    # default-sa only has get/list pods
    assert k8s.check_rbac_permission("default-sa", "get", "pods") is True
    assert k8s.check_rbac_permission("default-sa", "get", "secrets") is False
    
    # admin-sa has wildcard permissions
    assert k8s.check_rbac_permission("admin-sa", "delete", "deployments") is True

def test_k8s_admission_controller():
    k8s = K8sSimulator()
    
    # Deploying privileged pod in default namespace should fail
    spec = {"service_account": "default-sa", "privileged": True}
    success = k8s.create_pod("rogue-pod", spec, namespace="default")
    assert success is False
    
    # Deploying privileged pod in kube-system namespace should succeed
    success = k8s.create_pod("system-agent", spec, namespace="kube-system")
    assert success is True

def test_container_escape():
    attacker = K8sAttackSimulator()
    
    # Escape from default web-pod (not privileged) should fail
    assert attacker.execute_container_escape("web-pod") is False
    
    # Escape from admin-dashboard (privileged) should succeed
    assert attacker.execute_container_escape("admin-dashboard") is True

def test_sa_token_abuse():
    attacker = K8sAttackSimulator()
    
    # web-pod uses default-sa, which cannot read secrets
    secret = attacker.execute_sa_token_abuse("web-pod", "db-credentials")
    assert secret is None
    
    # admin-dashboard uses admin-sa, which has full privileges
    secret = attacker.execute_sa_token_abuse("admin-dashboard", "db-credentials")
    assert secret is not None
    assert secret["password"] == "dbpassword"
