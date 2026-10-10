"""
Evaluation Module — Evaluates trained Reinforcement Learning models
and computes win rates, mitigation success, and network survival uptime metrics.
"""

import logging
from typing import Dict, Any, List
import numpy as np
import matplotlib.pyplot as plt
from rl_service.environment import AMCDSEnv

logger = logging.getLogger(__name__)

def evaluate_agent(env: AMCDSEnv, agent: Any, episodes: int = 20, max_steps: int = 100) -> Dict[str, Any]:
    """
    Evaluates a trained RL agent (attacker or defender) over multiple episodes.
    Computes average reward, network compromise rates, and isolated nodes counts.
    """
    rewards = []
    compromise_rates = []
    isolation_counts = []
    
    for ep in range(episodes):
        state = env.reset()
        ep_reward = 0.0
        
        for step in range(max_steps):
            # Select action deterministically if agent has select_action
            if hasattr(agent, "policy_net"):
                # DQN deterministic action
                import torch
                state_t = torch.FloatTensor(state).unsqueeze(0)
                with torch.no_grad():
                    action = int(agent.policy_net(state_t).argmax(dim=1).item())
            elif hasattr(agent, "policy"):
                # PPO deterministic action
                import torch
                state_t = torch.FloatTensor(state)
                with torch.no_grad():
                    action = int(agent.policy.actor(state_t).argmax(dim=-1).item())
            else:
                action = env.action_space.sample()
                
            obs, reward, done, info = env.step(action)
            ep_reward += reward
            state = obs
            if done:
                break
                
        rewards.append(ep_reward)
        
        # Calculate final stats from topology
        total_hosts = len(env.topo.hosts)
        compromised = sum(1 for h in env.topo.hosts.values() if h.compromised)
        isolated = sum(1 for h in env.topo.hosts.values() if h.isolated)
        
        compromise_rates.append(compromised / total_hosts if total_hosts > 0 else 0.0)
        isolation_counts.append(isolated)

    return {
        "avg_reward": float(np.mean(rewards)),
        "std_reward": float(np.std(rewards)),
        "avg_compromise_rate": float(np.mean(compromise_rates)),
        "avg_isolation_count": float(np.mean(isolation_counts))
    }

def plot_training_rewards(rewards: List[float], output_path: str, title: str = "RL Training Rewards"):
    """
    Saves a plot of the reward trajectory over training episodes.
    """
    plt.figure(figsize=(8, 5))
    plt.plot(rewards, label="Episode Reward", color="blue", alpha=0.6)
    
    # Calculate running average
    if len(rewards) >= 10:
        running_avg = np.convolve(rewards, np.ones(10)/10, mode='valid')
        plt.plot(range(9, len(rewards)), running_avg, label="10-Ep Running Avg", color="red", linewidth=2)
        
    plt.xlabel("Episode")
    plt.ylabel("Reward")
    plt.title(title)
    plt.legend()
    plt.grid(True)
    plt.savefig(output_path, bbox_inches='tight')
    plt.close()
