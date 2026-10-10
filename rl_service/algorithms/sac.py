"""
SAC Algorithm Module — Soft Actor-Critic (Discrete) implementation.
"""

from typing import Tuple, List, Dict, Any
import random
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from collections import deque
from torch.distributions import Categorical

class SACActor(nn.Module):
    def __init__(self, state_dim: int, action_dim: int, hidden_dim: int = 64):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, action_dim)
        )

    def forward(self, state: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        logits = self.net(state)
        probs = torch.softmax(logits, dim=-1)
        # Avoid log(0)
        z = probs == 0.0
        log_probs = torch.log(probs + z.float() * 1e-8)
        return probs, log_probs

class SACCritic(nn.Module):
    def __init__(self, state_dim: int, action_dim: int, hidden_dim: int = 64):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, action_dim)
        )

    def forward(self, state: torch.Tensor) -> torch.Tensor:
        return self.net(state)

class SACAgent:
    """
    Discrete Soft Actor-Critic (SAC) Agent.
    Implements maximum entropy reinforcement learning for discrete action spaces.
    """
    def __init__(
        self,
        state_dim: int,
        action_dim: int,
        lr: float = 3e-4,
        gamma: float = 0.99,
        tau: float = 0.005,
        alpha: float = 0.2, # Entropy regularization coefficient
        buffer_size: int = 10000,
        batch_size: int = 64
    ):
        self.action_dim = action_dim
        self.gamma = gamma
        self.tau = tau
        self.alpha = alpha
        self.batch_size = batch_size
        
        self.actor = SACActor(state_dim, action_dim)
        self.critic1 = SACCritic(state_dim, action_dim)
        self.critic2 = SACCritic(state_dim, action_dim)
        
        self.critic1_target = SACCritic(state_dim, action_dim)
        self.critic2_target = SACCritic(state_dim, action_dim)
        self.critic1_target.load_state_dict(self.critic1.state_dict())
        self.critic2_target.load_state_dict(self.critic2.state_dict())
        
        self.actor_optimizer = optim.Adam(self.actor.parameters(), lr=lr)
        self.critic1_optimizer = optim.Adam(self.critic1.parameters(), lr=lr)
        self.critic2_optimizer = optim.Adam(self.critic2.parameters(), lr=lr)
        
        self.memory = deque(maxlen=buffer_size)

    def select_action(self, state: np.ndarray) -> int:
        state_t = torch.FloatTensor(state).unsqueeze(0)
        with torch.no_grad():
            probs, _ = self.actor(state_t)
        dist = Categorical(probs)
        action = dist.sample()
        return int(action.item())

    def store_transition(self, state, action, reward, next_state, done):
        self.memory.append((state, action, reward, next_state, done))

    def train_step(self) -> Tuple[float, float]:
        if len(self.memory) < self.batch_size:
            return 0.0, 0.0
            
        batch = random.sample(self.memory, self.batch_size)
        states, actions, rewards, next_states, dones = zip(*batch)
        
        states = torch.FloatTensor(np.array(states))
        actions = torch.LongTensor(actions).unsqueeze(1)
        rewards = torch.FloatTensor(rewards).unsqueeze(1)
        next_states = torch.FloatTensor(np.array(next_states))
        dones = torch.FloatTensor(dones).unsqueeze(1)
        
        # 1. Critic Update
        with torch.no_grad():
            next_probs, next_log_probs = self.actor(next_states)
            q1_next = self.critic1_target(next_states)
            q2_next = self.critic2_target(next_states)
            min_q_next = torch.min(q1_next, q2_next)
            
            # Value of next state incorporating entropy
            next_state_value = torch.sum(next_probs * (min_q_next - self.alpha * next_log_probs), dim=-1, keepdim=True)
            target_q = rewards + (1 - dones) * self.gamma * next_state_value
            
        q1 = self.critic1(states).gather(1, actions)
        q2 = self.critic2(states).gather(1, actions)
        
        critic1_loss = nn.MSELoss()(q1, target_q)
        critic2_loss = nn.MSELoss()(q2, target_q)
        
        self.critic1_optimizer.zero_grad()
        critic1_loss.backward()
        self.critic1_optimizer.step()
        
        self.critic2_optimizer.zero_grad()
        critic2_loss.backward()
        self.critic2_optimizer.step()
        
        # 2. Actor Update
        probs, log_probs = self.actor(states)
        q1_eval = self.critic1(states)
        q2_eval = self.critic2(states)
        min_q_eval = torch.min(q1_eval, q2_eval)
        
        actor_loss = torch.mean(torch.sum(probs * (self.alpha * log_probs - min_q_eval), dim=-1))
        
        self.actor_optimizer.zero_grad()
        actor_loss.backward()
        self.actor_optimizer.step()
        
        # Target network soft updates
        self._soft_update(self.critic1, self.critic1_target)
        self._soft_update(self.critic2, self.critic2_target)
        
        return critic1_loss.item(), actor_loss.item()

    def _soft_update(self, local_model, target_model):
        for target_param, local_param in zip(target_model.parameters(), local_model.parameters()):
            target_param.data.copy_(self.tau * local_param.data + (1.0 - self.tau) * target_param.data)
