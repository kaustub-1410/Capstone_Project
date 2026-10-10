import os
import shutil
import pytest
import numpy as np
from shared.models import Host, Service
from simulation_engine.network import NetworkTopology
from rl_service.environment import AMCDSEnv
from rl_service.rewards import RewardCalculator
from rl_service.algorithms.dqn import DQNAgent
from rl_service.algorithms.ppo import PPOAgent
from rl_service.algorithms.sac import SACAgent
from rl_service.algorithms.a3c import A3CAgent
from rl_service.algorithms.mappo import MAPPOAgent
from rl_service.training import train_single_agent, train_self_play
from rl_service.evaluation import evaluate_agent, plot_training_rewards

@pytest.fixture(scope="module")
def setup_topology():
    topo = NetworkTopology()
    topo.neo4j_enabled = False
    
    # 2 host subnet
    h1 = Host(id="WS-01", name="WS-01", ip="10.0.1.5", os="Windows 11", role="workstation", asset_value=100.0)
    h2 = Host(id="DC-01", name="DC-01", ip="10.0.1.2", os="Windows Server", role="domain_controller", asset_value=1000.0)
    
    h1.services.append(Service(name="SMB", port=445))
    h2.services.append(Service(name="SMB", port=445))
    
    topo.add_host(h1)
    topo.add_host(h2)
    topo.add_connection("WS-01", "DC-01")
    return topo

def test_gym_compatibility(setup_topology):
    env = AMCDSEnv(setup_topology, max_steps=5, mode="attacker")
    obs = env.reset()
    
    # Check spaces
    assert env.observation_space.shape == (6,) # 2 hosts x 3 states
    assert env.action_space.n == 10 # 5 actions x 2 hosts
    
    # Step environment
    action = env.action_space.sample()
    next_obs, reward, done, info = env.step(action)
    
    assert len(next_obs) == 6
    assert isinstance(reward, float)
    assert isinstance(done, bool)

def test_curriculum_rewards():
    rc = RewardCalculator()
    assert rc.curriculum_stage == 1
    
    action_result = {"status": "success", "action": "exploit_service"}
    r1 = rc.calculate_attacker_reward(action_result)
    
    rc.set_curriculum_stage(3)
    r2 = rc.calculate_attacker_reward(action_result)
    
    # At stage 1, rewards should be scaled up (+50%) compared to advanced
    assert r1 > r2

def test_rl_algorithms_initialization(setup_topology):
    env = AMCDSEnv(setup_topology)
    state_dim = env.observation_space.shape[0]
    action_dim = env.action_space.n
    
    dqn = DQNAgent(state_dim, action_dim)
    ppo = PPOAgent(state_dim, action_dim)
    sac = SACAgent(state_dim, action_dim)
    a3c = A3CAgent(state_dim, action_dim)
    mappo = MAPPOAgent(num_agents=2, obs_dim=state_dim, action_dim=action_dim)
    
    assert dqn.policy_net is not None
    assert ppo.policy is not None
    assert sac.actor is not None
    assert a3c.global_model is not None
    assert len(mappo.actors) == 2

def test_single_agent_training_run(setup_topology):
    checkpoint_dir = "test_checkpoints_rl"
    log_dir = "test_runs_rl"
    
    if os.path.exists(checkpoint_dir):
        shutil.rmtree(checkpoint_dir)
    if os.path.exists(log_dir):
        shutil.rmtree(log_dir)
        
    env = AMCDSEnv(setup_topology, max_steps=5, mode="attacker")
    state_dim = env.observation_space.shape[0]
    action_dim = env.action_space.n
    
    agent = DQNAgent(state_dim, action_dim)
    rewards = train_single_agent(
        env=env,
        agent=agent,
        agent_type="dqn",
        episodes=3,
        max_steps=5,
        checkpoint_dir=checkpoint_dir,
        log_dir=log_dir
    )
    
    assert len(rewards) == 3
    assert os.path.exists(checkpoint_dir)
    
    # Test evaluation
    eval_stats = evaluate_agent(env, agent, episodes=2, max_steps=5)
    assert "avg_reward" in eval_stats
    assert isinstance(eval_stats["avg_reward"], float)
    
    # Test plotting
    plot_path = os.path.join(checkpoint_dir, "test_plot.png")
    plot_training_rewards(rewards, plot_path)
    assert os.path.exists(plot_path)

    # Clean up
    if os.path.exists(checkpoint_dir):
        shutil.rmtree(checkpoint_dir)
    if os.path.exists(log_dir):
        shutil.rmtree(log_dir)

def test_self_play_training_run(setup_topology):
    checkpoint_dir = "test_checkpoints_sp"
    log_dir = "test_runs_sp"
    
    if os.path.exists(checkpoint_dir):
        shutil.rmtree(checkpoint_dir)
    if os.path.exists(log_dir):
        shutil.rmtree(log_dir)
        
    env = AMCDSEnv(setup_topology, max_steps=5, mode="multi_agent")
    state_dim = env.observation_space.shape[0]
    action_dim = env.action_space.n
    
    attacker = DQNAgent(state_dim, action_dim)
    defender = DQNAgent(state_dim, action_dim)
    
    att_rewards, def_rewards = train_self_play(
        env=env,
        attacker_agent=attacker,
        defender_agent=defender,
        episodes=2,
        max_steps=5,
        checkpoint_dir=checkpoint_dir,
        log_dir=log_dir
    )
    
    assert len(att_rewards) == 2
    assert len(def_rewards) == 2
    
    # Clean up
    if os.path.exists(checkpoint_dir):
        shutil.rmtree(checkpoint_dir)
    if os.path.exists(log_dir):
        shutil.rmtree(log_dir)
