"""
RL Training Module — Co-evolutionary reinforcement learning training harness.
Supports single-agent training (DQN, PPO) and co-evolutionary self-play training.
"""

import os
import logging
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
try:
    from torch.utils.tensorboard import SummaryWriter
except Exception:
    class SummaryWriter:
        def __init__(self, *args, **kwargs): pass
        def add_scalar(self, *args, **kwargs): pass
        def close(self): pass
from rl_service.environment import AMCDSEnv

logger = logging.getLogger(__name__)

def train_single_agent(
    env: AMCDSEnv,
    agent: Any, # DQNAgent, PPOAgent, SACAgent, etc.
    agent_type: str = "dqn",
    episodes: int = 100,
    max_steps: int = 100,
    checkpoint_dir: str = "checkpoints/rl",
    log_dir: str = "runs/rl"
) -> List[float]:
    """
    Trains a single RL agent (Attacker or Defender) in the environment.
    """
    os.makedirs(checkpoint_dir, exist_ok=True)
    writer = SummaryWriter(log_dir=log_dir)
    
    episode_rewards = []
    logger.info(f"Starting {agent_type.upper()} single-agent training for {episodes} episodes...")
    
    for ep in range(1, episodes + 1):
        state = env.reset()
        ep_reward = 0.0
        
        # PPO memory buffer
        ppo_memory = []
        
        for step in range(max_steps):
            if agent_type == "ppo":
                action, logprob = agent.select_action(state)
            else:
                action = agent.select_action(state)
                logprob = 0.0
                
            obs, reward, done, info = env.step(action)
            ep_reward += reward
            
            # Store in agent-specific memory
            if agent_type == "ppo":
                ppo_memory.append({
                    "state": state,
                    "action": action,
                    "reward": reward,
                    "logprob": logprob,
                    "done": done
                })
            else:
                agent.store_transition(state, action, reward, obs, done)
                
            state = obs
            
            # Perform training step
            if agent_type == "dqn":
                loss = agent.train_step()
            elif agent_type == "sac":
                critic_loss, actor_loss = agent.train_step()
                
            if done:
                break
                
        # PPO policy update at end of episode
        if agent_type == "ppo":
            loss = agent.update(ppo_memory)
            
        episode_rewards.append(ep_reward)
        writer.add_scalar("Reward/Episode", ep_reward, ep)
        
        if ep % 10 == 0:
            logger.info(f"Episode {ep:03d} | Reward: {ep_reward:.2f} | Epsilon: {getattr(agent, 'epsilon', 0.0):.3f}")
            # Save checkpoint
            checkpoint_path = os.path.join(checkpoint_dir, f"{agent_type}_model.pt")
            if hasattr(agent, "policy"):
                torch.save(agent.policy.state_dict(), checkpoint_path)
            elif hasattr(agent, "policy_net"):
                torch.save(agent.policy_net.state_dict(), checkpoint_path)
                
    writer.close()
    return episode_rewards

def train_self_play(
    env: AMCDSEnv,
    attacker_agent: Any,
    defender_agent: Any,
    episodes: int = 100,
    max_steps: int = 100,
    checkpoint_dir: str = "checkpoints/self_play",
    log_dir: str = "runs/self_play"
) -> Tuple[List[float], List[float]]:
    """
    Trains both Attacker and Defender agents in a competitive self-play paradigm.
    """
    os.makedirs(checkpoint_dir, exist_ok=True)
    writer = SummaryWriter(log_dir=log_dir)
    
    attacker_rewards = []
    defender_rewards = []
    
    logger.info(f"Starting co-evolutionary self-play training for {episodes} episodes...")
    
    for ep in range(1, episodes + 1):
        state = env.reset()
        ep_att_reward = 0.0
        self_play_def_reward = 0.0
        
        for step in range(max_steps):
            # 1. Attacker Action Selection
            state_att = state
            action_att = attacker_agent.select_action(state_att)
            
            # Map action_att (0-2) to the action_dict payload
            action_dict_att = env._parse_integer_action(action_att)
            obs, reward_att, _, done, info = env.step(action_dict_att)
            ep_att_reward += reward_att
            attacker_agent.store_transition(state_att, action_att, reward_att, obs, done)
            
            state = obs
            
            # 2. Defender Action Selection
            state_def = state
            # Defender action is mapped offset (3-4)
            action_def = defender_agent.select_action(state_def)
            action_dict_def = env._parse_integer_action(action_def)
            obs, _, reward_def, done, info = env.step(action_dict_def)
            self_play_def_reward += reward_def
            defender_agent.store_transition(state_def, action_def, reward_def, obs, done)
            
            state = obs
            
            # Train steps
            attacker_agent.train_step()
            defender_agent.train_step()
            
            if done:
                break
                
        attacker_rewards.append(ep_att_reward)
        defender_rewards.append(self_play_def_reward)
        
        writer.add_scalar("Reward/Attacker", ep_att_reward, ep)
        writer.add_scalar("Reward/Defender", self_play_def_reward, ep)
        
        if ep % 10 == 0:
            logger.info(f"Episode {ep:03d} | Att Reward: {ep_att_reward:.2f} | Def Reward: {self_play_def_reward:.2f}")
            torch.save(attacker_agent.policy_net.state_dict(), os.path.join(checkpoint_dir, "attacker_dqn.pt"))
            torch.save(defender_agent.policy_net.state_dict(), os.path.join(checkpoint_dir, "defender_dqn.pt"))
            
    writer.close()
    return attacker_rewards, defender_rewards
