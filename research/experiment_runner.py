"""
Experiment Runner Module — Automates large-scale cyber security simulation campaigns,
collating and saving structured results across trials.
"""

import logging
import json
import os
from typing import Dict, List, Any
from simulation_engine.network import NetworkTopology
from rl_service.environment import AMCDSEnv

logger = logging.getLogger(__name__)

class ExperimentRunner:
    """
    Manages batch execution of simulation scenarios for statistical evaluation.
    """

    def __init__(self, output_dir: str = "research_outputs"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def run_batch_simulation(
        self,
        topo_factory_fn,
        agent_type: str,
        num_trials: int = 5,
        steps_per_trial: int = 50
    ) -> List[Dict[str, Any]]:
        """Runs multiple trials of a simulation scenario and collects metrics."""
        trial_results = []
        
        logger.info(f"Kicking off simulation campaign: {num_trials} trials of {agent_type}...")
        
        for trial in range(1, num_trials + 1):
            topo = topo_factory_fn()
            env = AMCDSEnv(topo, max_steps=steps_per_trial, mode="attacker")
            env.reset()
            
            total_reward = 0.0
            compromised_sequence = []
            
            for step in range(steps_per_trial):
                # Pick random action for the agent
                action = env.action_space.sample()
                obs, reward, done, info = env.step(action)
                total_reward += reward
                
                # Log compromised ratio
                comp = sum(1 for h in topo.hosts.values() if h.compromised)
                compromised_sequence.append(comp)
                
                if done:
                    break
                    
            final_compromise_rate = (sum(1 for h in topo.hosts.values() if h.compromised) / len(topo.hosts))
            
            trial_results.append({
                "trial": trial,
                "total_reward": round(total_reward, 2),
                "final_compromise_rate": round(final_compromise_rate, 4),
                "compromise_sequence": compromised_sequence
            })
            
        # Save results to disk
        out_path = os.path.join(self.output_dir, f"campaign_{agent_type}.json")
        with open(out_path, "w") as f:
            json.dump(trial_results, f, indent=2)
            
        logger.info(f"Campaign results successfully saved to {out_path}")
        return trial_results
