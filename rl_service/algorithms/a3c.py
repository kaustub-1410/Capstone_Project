"""
A3C Algorithm Module — Asynchronous Advantage Actor-Critic implementation.
"""

from typing import List, Tuple, Dict, Any
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from torch.distributions import Categorical
from rl_service.algorithms.ppo import ActorCritic

class A3CAgent:
    """
    Asynchronous Advantage Actor-Critic (A3C) Agent.
    In worker threads, it runs agent steps and computes gradients to update the global network.
    """
    def __init__(self, state_dim: int, action_dim: int, lr: float = 1e-4, gamma: float = 0.99):
        self.gamma = gamma
        self.global_model = ActorCritic(state_dim, action_dim)
        self.optimizer = optim.Adam(self.global_model.parameters(), lr=lr)

    def select_action(self, state: np.ndarray, model: nn.Module) -> Tuple[int, torch.Tensor]:
        state_t = torch.FloatTensor(state)
        action_probs, _ = model(state_t)
        dist = Categorical(action_probs)
        action = dist.sample()
        return int(action.item()), dist.log_prob(action)

    def train_worker(self, local_model: nn.Module, states: List[np.ndarray], actions: List[int], rewards: List[float], next_states: List[np.ndarray], dones: List[bool]) -> float:
        """Computes gradients on local worker data and applies them to the global model."""
        states_t = torch.FloatTensor(np.array(states))
        actions_t = torch.LongTensor(actions)
        
        action_probs, state_values = local_model(states_t)
        state_values = state_values.squeeze()
        
        # Calculate policy logs
        dist = Categorical(action_probs)
        log_probs = dist.log_prob(actions_t)
        entropy = dist.entropy()
        
        # Compute Monte Carlo returns
        q_values = []
        q_val = 0
        if not dones[-1]:
            # Bootstrap if not done
            _, val = local_model(torch.FloatTensor(next_states[-1]))
            q_val = val.item()
            
        for r, d in zip(reversed(rewards), reversed(dones)):
            q_val = r + self.gamma * q_val * (1.0 - float(d))
            q_values.insert(0, q_val)
            
        q_values = torch.FloatTensor(q_values)
        advantages = q_values - state_values
        
        policy_loss = -(log_probs * advantages.detach()).mean() - 0.01 * entropy.mean()
        value_loss = 0.5 * advantages.pow(2).mean()
        total_loss = policy_loss + value_loss
        
        # Backward pass on local model
        self.optimizer.zero_grad()
        total_loss.backward()
        
        # Copy local gradients to global model and step optimizer
        for local_param, global_param in zip(local_model.parameters(), self.global_model.parameters()):
            if global_param.grad is not None:
                return 0.0
            global_param.grad = local_param.grad
            
        self.optimizer.step()
        return total_loss.item()
