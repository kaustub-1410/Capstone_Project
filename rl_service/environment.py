import numpy as np
import uuid
import logging
from typing import Dict, Any, Tuple, Optional, Union

logger = logging.getLogger(__name__)

# Fallback Gym/Gymnasium mock implementation if not installed
try:
    import gym
    from gym import spaces
    gym_env_class = gym.Env
except ImportError:
    try:
        import gymnasium as gym
        from gymnasium import spaces
        gym_env_class = gym.Env
    except ImportError:
        logger.warning("Neither 'gym' nor 'gymnasium' is installed. Using custom fallback classes.")
        class MockDiscrete:
            def __init__(self, n):
                self.n = n
            def sample(self):
                import random
                return random.randint(0, self.n - 1)
        class MockBox:
            def __init__(self, low, high, shape, dtype):
                self.low = low
                self.high = high
                self.shape = shape
                self.dtype = dtype
            def sample(self):
                return np.random.uniform(self.low, self.high, self.shape).astype(self.dtype)
        
        class MockSpaces:
            Discrete = MockDiscrete
            Box = MockBox
            
        spaces = MockSpaces()
        gym_env_class = object

from shared.models import Host, Service
from simulation_engine.core import SimulationEngine
from simulation_engine.network import NetworkTopology
from telemetry_service.producer import TelemetryProducer
from attack_engine.executor import AttackExecutor
from defense_engine.executor import DefenseExecutor
from rl_service.rewards import RewardCalculator

class AMCDSEnv(gym_env_class):
    """
    A Gym-compliant environment wrapper for AMCDS network simulations.
    Supports both single-agent (attacker or defender) and co-evolutionary/multi-agent training.
    """
    def __init__(self, topology: NetworkTopology, max_steps: int = 100, mode: str = "multi_agent"):
        if gym_env_class is not object:
            super().__init__()
            
        self.topo = topology
        self.max_steps = max_steps
        self.current_step = 0
        self.run_id = uuid.uuid4()
        self.mode = mode # "attacker", "defender", or "multi_agent"
        
        # Telemetry and Execution Engines
        self.telemetry = TelemetryProducer()
        self.attack_exec = AttackExecutor(self.telemetry)
        self.defense_exec = DefenseExecutor(self.telemetry)
        self.reward_calc = RewardCalculator()
        
        self.host_ids = list(self.topo.hosts.keys())
        self.num_hosts = len(self.host_ids)
        
        # Gym Spaces Definition
        # Actions: 5 categories x num_hosts
        # 0: Scan Host i
        # 1: Exploit Host i
        # 2: Dump credentials on Host i
        # 3: Isolate Host i
        # 4: Patch service on Host i
        self.action_space_size = 5 * self.num_hosts if self.num_hosts > 0 else 5
        self.action_space = spaces.Discrete(self.action_space_size)
        
        # Features per host: [compromised, isolated, credentials_dumped]
        self.observation_space_shape = (max(1, self.num_hosts) * 3,)
        self.observation_space = spaces.Box(
            low=0.0, 
            high=1.0, 
            shape=self.observation_space_shape, 
            dtype=np.float32
        )

    def reset(self) -> np.ndarray:
        """Resets the state of the simulation."""
        self.current_step = 0
        self.run_id = uuid.uuid4()
        
        # Reset compromises and isolations
        for host in self.topo.hosts.values():
            host.compromised = False
            host.compromised_by = None
            host.isolated = False
            host.credentials_dumped = False
            self.topo.sync_host_to_neo4j(host)
            
        return self._get_observation()

    def _get_observation(self) -> np.ndarray:
        """Returns the vectorized host metrics representing the network state."""
        obs = []
        for host_id in self.host_ids:
            host = self.topo.hosts[host_id]
            obs.extend([
                1.0 if host.compromised else 0.0,
                1.0 if host.isolated else 0.0,
                1.0 if host.credentials_dumped else 0.0
            ])
        if not obs:
            obs = [0.0, 0.0, 0.0]
        return np.array(obs, dtype=np.float32)

    def step(self, action: Union[int, Dict[str, Any]]) -> Tuple[np.ndarray, float, Union[float, bool], bool, Dict[str, Any]]:
        """
        Advances the simulation by executing an action.
        Supports both dict-based action format and standard gym integer action formats.
        """
        self.current_step += 1
        
        # 1. Parse integer action into action_dict if needed
        if isinstance(action, (int, np.integer)):
            action_dict = self._parse_integer_action(int(action))
        else:
            action_dict = action
            
        agent_type = action_dict.get("agent_type", "attacker")
        action_id = action_dict.get("action_id", 0)
        target_id = action_dict.get("target_host_id")
        service_name = action_dict.get("service_name")
        
        # Default payload
        payload = {"target": target_id, "service": service_name}
        
        attacker_reward = 0.0
        defender_reward = 0.0
        result = {}

        if agent_type == "attacker":
            if action_id == 0:
                result = self.attack_exec.execute_action("network_scan", self.run_id, self.topo, payload)
            elif action_id == 1:
                # Find first service with vulnerability or default SMB
                host = self.topo.hosts.get(target_id)
                if host:
                    svc = next((s.name for s in host.services if s.vulnerabilities), "SMB")
                    payload["service"] = svc
                result = self.attack_exec.execute_action("exploit_service", self.run_id, self.topo, payload)
            elif action_id == 2:
                result = self.attack_exec.execute_action("credentials_dump", self.run_id, self.topo, payload)
            attacker_reward = self.reward_calc.calculate_attacker_reward(result)
            
        elif agent_type == "defender":
            if action_id == 3:
                result = self.defense_exec.execute_action("isolate_host", self.run_id, self.topo, payload)
            elif action_id == 4:
                # Find first service on target host to patch
                host = self.topo.hosts.get(target_id)
                if host:
                    svc = next((s.name for s in host.services), "SMB")
                    payload["service"] = svc
                result = self.defense_exec.execute_action("patch_service", self.run_id, self.topo, payload)
            defender_reward = self.reward_calc.calculate_defender_reward(result, self.topo)

        # Retrieve new state observation
        obs = self._get_observation()
        
        # Check termination condition
        done = self.current_step >= self.max_steps
        
        info = {
            "action_result": result,
            "current_step": self.current_step
        }
        
        # Return format based on environment mode
        if self.mode == "attacker":
            return obs, attacker_reward, done, info
        elif self.mode == "defender":
            return obs, defender_reward, done, info
        elif self.mode == "multi_agent":
            # Return custom structure: obs, attacker_reward, defender_reward, done, info
            return obs, attacker_reward, defender_reward, done, info
        else:
            # Backward compatible default: (obs, attacker_reward, defender_reward, done, info)
            return obs, attacker_reward, defender_reward, done, info

    def _parse_integer_action(self, action_idx: int) -> Dict[str, Any]:
        """Maps flat integer action index to action dictionary."""
        if self.num_hosts == 0:
            return {"agent_type": "attacker", "action_id": 0, "target_host_id": None}
            
        action_type = action_idx // self.num_hosts
        host_idx = action_idx % self.num_hosts
        target_host_id = self.host_ids[host_idx]
        
        if action_type in (0, 1, 2):
            return {
                "agent_type": "attacker",
                "action_id": action_type,
                "target_host_id": target_host_id
            }
        else:
            return {
                "agent_type": "defender",
                "action_id": action_type,
                "target_host_id": target_host_id
            }
