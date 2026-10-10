"""
Kubernetes Security Simulator — Models Pods, Namespaces, RBAC, Secrets,
Service Accounts, and Admission Controllers.
"""

import logging
from typing import Dict, List, Set, Optional, Any

logger = logging.getLogger(__name__)

class K8sSimulator:
    """
    Simulates Kubernetes cluster orchestration security and configuration state.
    """

    def __init__(self):
        self.namespaces = ["default", "kube-system", "dev", "prod"]
        self.pods: Dict[str, Dict[str, Any]] = {
            "web-pod": {
                "namespace": "default",
                "service_account": "default-sa",
                "privileged": False,
                "host_path_mounted": False,
                "status": "Running"
            },
            "admin-dashboard": {
                "namespace": "kube-system",
                "service_account": "admin-sa",
                "privileged": True,
                "host_path_mounted": True,
                "status": "Running"
            }
        }
        self.secrets: Dict[str, Dict[str, String]] = {
            "db-credentials": {"namespace": "default", "username": "dbuser", "password": "dbpassword"},
            "api-keys": {"namespace": "dev", "key": "dev-api-key-secret"}
        }
        self.rbac: Dict[str, Dict[str, List[str]]] = {
            "default-sa": {"verbs": ["get", "list"], "resources": ["pods"]},
            "admin-sa": {"verbs": ["*"], "resources": ["*"]}
        }
        self.admission_controller_enabled = True

    def check_rbac_permission(self, service_account: str, verb: str, resource: str) -> bool:
        """Evaluates RBAC role permissions for a service account token."""
        permissions = self.rbac.get(service_account)
        if not permissions:
            return False
            
        verbs = permissions.get("verbs", [])
        resources = permissions.get("resources", [])
        
        if "*" in verbs or verb in verbs:
            if "*" in resources or resource in resources:
                return True
        return False

    def retrieve_secret(self, service_account: str, secret_name: str) -> Optional[Dict[str, Any]]:
        """Simulates requesting a Kubernetes secret."""
        secret = self.secrets.get(secret_name)
        if not secret:
            return None
            
        # Verify RBAC permission to read secrets
        if self.check_rbac_permission(service_account, "get", "secrets"):
            logger.info(f"Access granted for SA '{service_account}' to secret '{secret_name}'")
            return secret
            
        logger.warning(f"Access denied for SA '{service_account}' to secret '{secret_name}'")
        return None

    def create_pod(self, pod_name: str, spec: Dict[str, Any], namespace: str = "default") -> bool:
        """Simulates creating a new Pod, validating against Admission Controllers if active."""
        if self.admission_controller_enabled:
            # Simple Admission Controller policy: reject privileged pods in non-admin namespaces
            if spec.get("privileged") and namespace != "kube-system":
                logger.warning(f"Admission Controller REJECTED pod '{pod_name}' creation: Privileged pods restricted.")
                return False
                
        self.pods[pod_name] = {
            "namespace": namespace,
            "service_account": spec.get("service_account", "default-sa"),
            "privileged": spec.get("privileged", False),
            "host_path_mounted": spec.get("host_path_mounted", False),
            "status": "Running"
        }
        logger.info(f"Pod '{pod_name}' successfully created in namespace '{namespace}'")
        return True
