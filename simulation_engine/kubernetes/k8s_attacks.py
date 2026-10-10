"""
Kubernetes Attacks Module — Simulates container escape, token abuse, and RBAC exploits.
"""

import logging
from typing import Dict, Any, Optional
from simulation_engine.kubernetes.k8s_simulator import K8sSimulator

logger = logging.getLogger(__name__)

class K8sAttackSimulator:
    """
    Executes Kubernetes-specific exploits against a K8sSimulator cluster instance.
    """

    def __init__(self):
        self.k8s = K8sSimulator()

    def execute_container_escape(self, pod_name: str) -> bool:
        """
        Escapes a container to compromise the physical node.
        Succeeds if pod runs with privileged flag or has hostPath volume mounts.
        """
        pod = self.k8s.pods.get(pod_name)
        if not pod:
            logger.warning(f"Escape failed: Pod '{pod_name}' does not exist.")
            return False
            
        if pod["privileged"] or pod["host_path_mounted"]:
            logger.info(f"Container escape successful from pod '{pod_name}' to host node!")
            return True
            
        logger.warning(f"Container escape blocked on pod '{pod_name}': Pod is securely isolated.")
        return False

    def execute_sa_token_abuse(self, pod_name: str, target_secret: str) -> Optional[Dict[str, Any]]:
        """
        Attempts to exfiltrate and abuse the mounted ServiceAccount token to read secrets.
        """
        pod = self.k8s.pods.get(pod_name)
        if not pod:
            return None
            
        sa = pod["service_account"]
        logger.info(f"Exfiltrating service account token '{sa}' from pod '{pod_name}'")
        
        # Query API Server using exfiltrated token
        secret = self.k8s.retrieve_secret(sa, target_secret)
        if secret:
            logger.info(f"Successfully exfiltrated secret '{target_secret}' using token '{sa}'")
            return secret
            
        return None

    def execute_malicious_deployment(self, malicious_pod_name: str, spec: Dict[str, Any], namespace: str = "default") -> bool:
        """
        Attempts to deploy a malicious privileged pod to gain cluster execution.
        """
        logger.info(f"Attempting to deploy malicious pod '{malicious_pod_name}' in namespace '{namespace}'")
        success = self.k8s.create_pod(malicious_pod_name, spec, namespace)
        return success
