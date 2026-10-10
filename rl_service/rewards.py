from typing import Dict, Any
from simulation_engine.network import NetworkTopology

class RewardCalculator:
    def __init__(self, config: Dict[str, float] = None):
        # Default reward engineering weights
        self.weights = config or {
            "attacker_compromise_host": 10.0,
            "attacker_dump_credentials": 5.0,
            "attacker_lateral_movement": 8.0,
            "attacker_data_exfiltrated": 20.0,
            "attacker_failed_action": -2.0,
            
            "defender_isolate_compromised": 15.0,
            "defender_patch_vulnerability": 5.0,
            "defender_isolate_healthy": -10.0, # False positive penalty
            "defender_compromised_host_penalty": -1.0 # Step-wise cost for active infections
        }
        self.curriculum_stage = 1  # 1: Basic, 2: Intermediate, 3: Advanced

    def set_curriculum_stage(self, stage: int):
        """Sets the curriculum learning stage, dynamically modifying reward scaling."""
        self.curriculum_stage = max(1, stage)

    def calculate_attacker_reward(self, action_result: Dict[str, Any]) -> float:
        """Computes instantaneous reward for the Attacker agent based on action success."""
        if action_result.get("status") == "failed":
            return self.weights.get("attacker_failed_action", -2.0)
            
        action = action_result.get("action")
        reward = 0.0
        if action == "exploit_service" or action == "phishing_email":
            reward = self.weights.get("attacker_compromise_host", 10.0)
        elif action == "credentials_dump":
            reward = self.weights.get("attacker_dump_credentials", 5.0)
        elif action == "lateral_movement_smb":
            reward = self.weights.get("attacker_lateral_movement", 8.0)
        elif action == "data_exfiltration":
            reward = self.weights.get("attacker_data_exfiltrated", 20.0)
            
        # Curriculum-based reward shaping:
        # In early stages, we reward basic compromises more to encourage initial exploration
        if self.curriculum_stage == 1:
            reward *= 1.5
        elif self.curriculum_stage >= 3:
            # In advanced stages, exfiltration / ultimate goal is prioritized
            if action == "data_exfiltration":
                reward *= 2.0
            else:
                reward *= 0.8
                
        return reward

    def calculate_defender_reward(self, action_result: Dict[str, Any], topo: NetworkTopology) -> float:
        """Computes reward for the Defender agent, balancing actions and network uptime."""
        reward = 0.0
        
        # Action-specific rewards/penalties
        action = action_result.get("action") if action_result else None
        if action == "isolate_host":
            target_id = action_result.get("target")
            target_host = topo.hosts.get(target_id)
            if target_host:
                if target_host.compromised:
                    reward += self.weights.get("defender_isolate_compromised", 15.0)
                else:
                    reward += self.weights.get("defender_isolate_healthy", -10.0)
        elif action == "patch_service":
            reward += self.weights.get("defender_patch_vulnerability", 5.0)
            
        # Global state penalties (e.g. hourly cost of compromised machines remaining unmitigated)
        for host in topo.hosts.values():
            if host.compromised and not host.isolated:
                penalty = self.weights.get("defender_compromised_host_penalty", -1.0)
                # In advanced stages, we penalize active compromises much more severely
                if self.curriculum_stage >= 3:
                    penalty *= 3.0
                reward += penalty
                
        return reward
