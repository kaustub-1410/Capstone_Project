"""
MAPPO Algorithm Module — Multi-Agent PPO (MAPPO) implementation.
Uses Centralized Critic with Decentralized Actor structures (CTDE).
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from torch.distributions import Categorical

class MAPPOActor(nn.Module):
    def __init__(self, obs_dim: int, action_dim: int, hidden_dim: int = 64):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(obs_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, action_dim),
            nn.Softmax(dim=-1)
        )

    def forward(self, obs: torch.Tensor) -> torch.Tensor:
        return self.net(obs)

class MAPPOCritic(nn.Module):
    def __init__(self, global_state_dim: int, hidden_dim: int = 64):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(global_state_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1)
        )

    def forward(self, global_state: torch.Tensor) -> torch.Tensor:
        return self.net(global_state)

from typing import List, Dict, Any, Tuple

class MAPPOAgent:
    """
    Multi-Agent PPO (MAPPO) implementation.
    Implements Centralized Training with Decentralized Execution (CTDE).
    """
    def __init__(
        self,
        num_agents: int,
        obs_dim: int,
        action_dim: int,
        lr: float = 3e-4,
        gamma: float = 0.99,
        eps_clip: float = 0.2,
        k_epochs: int = 4
    ):
        self.num_agents = num_agents
        self.gamma = gamma
        self.eps_clip = eps_clip
        self.k_epochs = k_epochs
        
        # Define decentralized actors for each agent, sharing weights or having separate policies.
        # Here we model them as separate local policies.
        self.actors = nn.ModuleList([MAPPOActor(obs_dim, action_dim) for _ in range(num_agents)])
        # Centralized Critic takes observations of all agents concatenated as the global state.
        self.critic = MAPPOCritic(obs_dim * num_agents)
        
        self.actor_optimizers = [optim.Adam(actor.parameters(), lr=lr) for actor in self.actors]
        self.critic_optimizer = optim.Adam(self.critic.parameters(), lr=lr)
        
        self.actors_old = nn.ModuleList([MAPPOActor(obs_dim, action_dim) for _ in range(num_agents)])
        self.actors_old.load_state_dict(self.actors.state_dict())

    def select_actions(self, observations: List[np.ndarray]) -> Tuple[List[int], List[float]]:
        """Select actions for all agents based on their respective local observations."""
        actions = []
        logprobs = []
        for i in range(self.num_agents):
            obs_t = torch.FloatTensor(observations[i]).unsqueeze(0)
            with torch.no_grad():
                probs = self.actors_old[i](obs_t)
            dist = Categorical(probs)
            action = dist.sample()
            actions.append(int(action.item()))
            logprobs.append(float(dist.log_prob(action).item()))
        return actions, logprobs

    def update(self, memories: List[List[Dict[str, Any]]]) -> Tuple[float, float]:
        """
        Updates policy networks for all agents.
        memories is a list of lists of length num_agents containing trajectory buffers.
        """
        actor_loss_sum = 0.0
        critic_loss_sum = 0.0
        
        for i in range(self.num_agents):
            memory = memories[i]
            if not memory:
                continue
                
            obs = torch.FloatTensor(np.array([m["obs"] for m in memory]))
            actions = torch.LongTensor([m["action"] for m in memory])
            old_logprobs = torch.FloatTensor([m["logprob"] for m in memory])
            global_states = torch.FloatTensor(np.array([m["global_state"] for m in memory]))
            rewards = [m["reward"] for m in memory]
            dones = [m["done"] for m in memory]
            
            # Compute returns
            returns = []
            discounted_reward = 0
            for reward, done in zip(reversed(rewards), reversed(dones)):
                if done:
                    discounted_reward = 0
                discounted_reward = reward + (self.gamma * discounted_reward)
                returns.insert(0, discounted_reward)
            returns = torch.FloatTensor(returns)
            returns = (returns - returns.mean()) / (returns.std() + 1e-7)
            
            for _ in range(self.k_epochs):
                # Centralized Critic loss
                state_values = self.critic(global_states).squeeze()
                critic_loss = nn.MSELoss()(state_values, returns)
                
                self.critic_optimizer.zero_grad()
                critic_loss.backward()
                self.critic_optimizer.step()
                critic_loss_sum += critic_loss.item()
                
                # Decentralized Actor loss
                probs = self.actors[i](obs)
                dist = Categorical(probs)
                logprobs = dist.log_prob(actions)
                dist_entropy = dist.entropy()
                
                ratios = torch.exp(logprobs - old_logprobs)
                advantages = returns - state_values.detach()
                
                surr1 = ratios * advantages
                surr2 = torch.clamp(ratios, 1 - self.eps_clip, 1 + self.eps_clip) * advantages
                
                actor_loss = -torch.min(surr1, surr2) - 0.01 * dist_entropy
                
                self.actor_optimizers[i].zero_grad()
                actor_loss.mean().backward()
                self.actor_optimizers[i].step()
                actor_loss_sum += actor_loss.mean().item()
                
        self.actors_old.load_state_dict(self.actors.state_dict())
        return actor_loss_sum / self.num_agents, critic_loss_sum / self.num_agents
