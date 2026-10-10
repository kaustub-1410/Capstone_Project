"""
PPO Algorithm Module — Proximal Policy Optimization implementation.
"""

from typing import Tuple, List, Dict, Any
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from torch.distributions import Categorical

class ActorCritic(nn.Module):
    def __init__(self, state_dim: int, action_dim: int, hidden_dim: int = 64):
        super().__init__()
        self.actor = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, action_dim),
            nn.Softmax(dim=-1)
        )
        self.critic = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1)
        )

    def forward(self, state: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        action_probs = self.actor(state)
        state_value = self.critic(state)
        return action_probs, state_value

class PPOAgent:
    def __init__(
        self,
        state_dim: int,
        action_dim: int,
        lr: float = 3e-4,
        gamma: float = 0.99,
        k_epochs: int = 4,
        eps_clip: float = 0.2,
        gae_lambda: float = 0.95
    ):
        self.gamma = gamma
        self.gae_lambda = gae_lambda
        self.eps_clip = eps_clip
        self.k_epochs = k_epochs
        
        self.policy = ActorCritic(state_dim, action_dim)
        self.optimizer = optim.Adam(self.policy.parameters(), lr=lr)
        self.policy_old = ActorCritic(state_dim, action_dim)
        self.policy_old.load_state_dict(self.policy.state_dict())
        
        self.MseLoss = nn.MSELoss()

    def select_action(self, state: np.ndarray) -> Tuple[int, float]:
        state_t = torch.FloatTensor(state)
        with torch.no_grad():
            action_probs, _ = self.policy_old(state_t)
        dist = Categorical(action_probs)
        action = dist.sample()
        return int(action.item()), float(dist.log_prob(action).item())

    def update(self, memory: List[Dict[str, Any]]) -> float:
        """Updates policy using stored transitions."""
        if not memory:
            return 0.0
            
        states = torch.FloatTensor(np.array([m["state"] for m in memory]))
        actions = torch.LongTensor([m["action"] for m in memory])
        old_logprobs = torch.FloatTensor([m["logprob"] for m in memory])
        rewards = [m["reward"] for m in memory]
        dones = [m["done"] for m in memory]
        
        # Monte Carlo returns & GAE calculation
        returns = []
        discounted_reward = 0
        for reward, done in zip(reversed(rewards), reversed(dones)):
            if done:
                discounted_reward = 0
            discounted_reward = reward + (self.gamma * discounted_reward)
            returns.insert(0, discounted_reward)
            
        returns = torch.FloatTensor(returns)
        # Normalize returns
        returns = (returns - returns.mean()) / (returns.std() + 1e-7)
        
        loss_val = 0.0
        # Optimize policy for K epochs
        for _ in range(self.k_epochs):
            # Evaluating old actions and values
            action_probs, state_values = self.policy(states)
            state_values = state_values.squeeze()
            
            dist = Categorical(action_probs)
            logprobs = dist.log_prob(actions)
            dist_entropy = dist.entropy()
            
            # Finding the ratio (pi_theta / pi_theta__old)
            ratios = torch.exp(logprobs - old_logprobs)
            
            # Finding Surrogate Loss
            advantages = returns - state_values.detach()
            surr1 = ratios * advantages
            surr2 = torch.clamp(ratios, 1 - self.eps_clip, 1 + self.eps_clip) * advantages
            
            loss = -torch.min(surr1, surr2) + 0.5 * self.MseLoss(state_values, returns) - 0.01 * dist_entropy
            
            # Take gradient step
            self.optimizer.zero_grad()
            loss.mean().backward()
            self.optimizer.step()
            
            loss_val += loss.mean().item()
            
        # Copy new weights to old policy
        self.policy_old.load_state_dict(self.policy.state_dict())
        return loss_val / self.k_epochs
