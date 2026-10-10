"""
RL Explainer — Action probability distributions, Q-value analysis, and counterfactuals.

Provides interpretability for RL-based defensive and offensive decisions
by analyzing action probabilities, state feature importance, Q-value
distributions, and counterfactual "what-if" scenarios.

Part of Phase 4: Explainable AI.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from explainable_ai.explanation_engine import (
    Explanation,
    ExplanationEngine,
    ExplanationLevel,
    ExplanationSource,
    FeatureContribution,
)

logger = logging.getLogger(__name__)

# Action names for human-readable explanations
ATTACKER_ACTIONS = {
    0: "network_scan",
    1: "exploit_service",
    2: "lateral_movement",
    3: "credentials_dump",
    4: "data_exfiltration",
    5: "establish_persistence",
}

DEFENDER_ACTIONS = {
    0: "monitor",
    1: "scan_host",
    2: "block_port",
    3: "isolate_host",
    4: "patch_service",
    5: "restore_backup",
}

# State feature names (must match rl_service/environment.py observation space)
STATE_FEATURES = [
    "host_compromised",
    "host_isolated",
    "host_vulnerability_level",
]


class RLExplainer:
    """
    Explainability module for RL-based agent decisions.

    Provides:
    - Action probability distributions with reasoning
    - Q-value analysis and comparison
    - State feature importance ranking
    - Counterfactual "what-if" scenario analysis
    """

    def __init__(self, explanation_engine: Optional[ExplanationEngine] = None):
        self.engine = explanation_engine or ExplanationEngine()
        logger.info("RLExplainer initialized")

    def explain_action(
        self,
        agent_type: str,
        chosen_action_id: int,
        state: np.ndarray,
        q_values: Optional[np.ndarray] = None,
        action_probs: Optional[np.ndarray] = None,
        reward: float = 0.0,
        target_host: str = "",
    ) -> Explanation:
        """
        Explain why the RL agent chose a particular action.

        Args:
            agent_type: "attacker" or "defender"
            chosen_action_id: Index of the chosen action
            state: Current state observation vector
            q_values: Q-values for each action (if DQN-based)
            action_probs: Action probabilities (if policy-based)
            reward: Reward received for this action
            target_host: Target host of the action
        """
        action_map = ATTACKER_ACTIONS if agent_type == "attacker" else DEFENDER_ACTIONS
        action_name = action_map.get(chosen_action_id, f"action_{chosen_action_id}")

        # Feature contributions from state
        feature_contribs = self._analyze_state_features(state, agent_type)

        # Action analysis
        action_analysis = self._analyze_action_selection(
            chosen_action_id, q_values, action_probs, action_map
        )

        # Build detail text
        detail_lines = [
            f"Agent Type: {agent_type.upper()}",
            f"Chosen Action: {action_name} (ID={chosen_action_id})",
            f"Target: {target_host or 'N/A'}",
            f"Reward: {reward:+.2f}",
            "",
        ]

        # State analysis
        detail_lines.append("State Analysis:")
        for fc in feature_contribs[:5]:
            detail_lines.append(f"  • {fc.feature_name} = {fc.feature_value}: {fc.description}")

        # Q-value or probability analysis
        if action_analysis:
            detail_lines.append("")
            detail_lines.append("Action Selection Rationale:")
            for line in action_analysis:
                detail_lines.append(f"  {line}")

        # Counterfactual
        counterfactual = self._generate_counterfactual(
            chosen_action_id, q_values, action_probs, action_map
        )
        if counterfactual:
            detail_lines.append("")
            detail_lines.append(f"Counterfactual: {counterfactual}")

        # Determine confidence
        if action_probs is not None:
            confidence = float(action_probs[chosen_action_id]) if chosen_action_id < len(action_probs) else 0.5
        elif q_values is not None and len(q_values) > 0:
            max_q = float(np.max(q_values))
            min_q = float(np.min(q_values))
            range_q = max_q - min_q if max_q != min_q else 1.0
            confidence = (float(q_values[chosen_action_id]) - min_q) / range_q
        else:
            confidence = 0.5

        return self.engine.create_explanation(
            source=ExplanationSource.RL,
            subject=f"{agent_type}_{action_name}",
            summary=f"{agent_type.capitalize()} selected '{action_name}' on {target_host} "
                    f"(reward={reward:+.2f})",
            detail="\n".join(detail_lines),
            confidence=confidence,
            feature_contributions=feature_contribs,
            affected_assets=[target_host] if target_host else [],
            visual_data={
                "action_name": action_name,
                "q_values": q_values.tolist() if q_values is not None else None,
                "action_probs": action_probs.tolist() if action_probs is not None else None,
                "state": state.tolist() if isinstance(state, np.ndarray) else state,
                "reward": reward,
            },
        )

    def explain_episode(
        self,
        episode_actions: List[Dict[str, Any]],
        total_reward: float,
        agent_type: str,
    ) -> Explanation:
        """
        Explain the overall strategy of an RL episode.

        Args:
            episode_actions: List of {action_id, state, reward, target} dicts
            total_reward: Cumulative episode reward
            agent_type: "attacker" or "defender"
        """
        action_map = ATTACKER_ACTIONS if agent_type == "attacker" else DEFENDER_ACTIONS

        # Action distribution analysis
        from collections import Counter
        action_counts = Counter(
            action_map.get(a.get("action_id", 0), f"unknown")
            for a in episode_actions
        )

        detail_lines = [
            f"Episode Summary for {agent_type.upper()} Agent",
            f"Total Steps: {len(episode_actions)}",
            f"Total Reward: {total_reward:+.2f}",
            f"Average Reward: {total_reward / max(len(episode_actions), 1):+.2f}",
            "",
            "Action Distribution:",
        ]
        for action_name, count in action_counts.most_common():
            pct = count / len(episode_actions) * 100
            detail_lines.append(f"  • {action_name}: {count} ({pct:.1f}%)")

        # Identify key turning points (large reward changes)
        rewards = [a.get("reward", 0.0) for a in episode_actions]
        if rewards:
            max_reward_step = int(np.argmax(rewards))
            min_reward_step = int(np.argmin(rewards))
            detail_lines.append(f"\nBest action at step {max_reward_step}: "
                                f"reward={rewards[max_reward_step]:+.2f}")
            detail_lines.append(f"Worst action at step {min_reward_step}: "
                                f"reward={rewards[min_reward_step]:+.2f}")

        targets = set(a.get("target", "") for a in episode_actions if a.get("target"))

        return self.engine.create_explanation(
            source=ExplanationSource.RL,
            subject=f"{agent_type}_episode",
            summary=f"{agent_type.capitalize()} episode: {len(episode_actions)} steps, "
                    f"reward={total_reward:+.2f}, primary action={action_counts.most_common(1)[0][0]}",
            detail="\n".join(detail_lines),
            confidence=min(abs(total_reward) / 10.0, 0.95),
            affected_assets=sorted(targets),
            visual_data={
                "action_distribution": dict(action_counts),
                "reward_timeline": rewards[:50],
                "total_reward": total_reward,
            },
        )

    def _analyze_state_features(
        self, state: np.ndarray, agent_type: str
    ) -> List[FeatureContribution]:
        """Analyze which state features are most influential."""
        contributions = []
        num_hosts = len(state) // len(STATE_FEATURES) if len(STATE_FEATURES) > 0 else 1

        for i, val in enumerate(state):
            host_idx = i // len(STATE_FEATURES) if len(STATE_FEATURES) > 0 else i
            feat_idx = i % len(STATE_FEATURES) if len(STATE_FEATURES) > 0 else i
            feat_name = STATE_FEATURES[feat_idx] if feat_idx < len(STATE_FEATURES) else f"feature_{feat_idx}"

            contributions.append(FeatureContribution(
                feature_name=f"host{host_idx}_{feat_name}",
                feature_value=round(float(val), 4),
                contribution=round(float(val) * (0.5 if agent_type == "attacker" else -0.5), 6),
                direction="notable" if val > 0.5 else "neutral",
                description=self._state_feature_description(feat_name, float(val)),
            ))

        # Sort by absolute contribution
        contributions.sort(key=lambda fc: abs(fc.contribution), reverse=True)
        return contributions

    def _analyze_action_selection(
        self,
        chosen_id: int,
        q_values: Optional[np.ndarray],
        action_probs: Optional[np.ndarray],
        action_map: Dict[int, str],
    ) -> List[str]:
        """Analyze why a particular action was selected."""
        lines = []

        if q_values is not None:
            lines.append("Q-Value Analysis:")
            sorted_q = sorted(enumerate(q_values), key=lambda x: x[1], reverse=True)
            for aid, qval in sorted_q:
                marker = " ← CHOSEN" if aid == chosen_id else ""
                aname = action_map.get(aid, f"action_{aid}")
                lines.append(f"    {aname}: Q={qval:+.4f}{marker}")

        if action_probs is not None:
            lines.append("Action Probabilities:")
            sorted_p = sorted(enumerate(action_probs), key=lambda x: x[1], reverse=True)
            for aid, prob in sorted_p:
                marker = " ← CHOSEN" if aid == chosen_id else ""
                aname = action_map.get(aid, f"action_{aid}")
                lines.append(f"    {aname}: P={prob:.4f} ({prob*100:.1f}%){marker}")

        return lines

    def _generate_counterfactual(
        self,
        chosen_id: int,
        q_values: Optional[np.ndarray],
        action_probs: Optional[np.ndarray],
        action_map: Dict[int, str],
    ) -> str:
        """Generate a counterfactual explanation."""
        values = q_values if q_values is not None else action_probs
        if values is None or len(values) <= 1:
            return ""

        # Find the best alternative action
        sorted_indices = np.argsort(values)[::-1]
        alt_id = sorted_indices[0] if sorted_indices[0] != chosen_id else sorted_indices[1]
        alt_name = action_map.get(int(alt_id), f"action_{alt_id}")
        chosen_name = action_map.get(chosen_id, f"action_{chosen_id}")
        value_diff = float(values[alt_id]) - float(values[chosen_id])

        if abs(value_diff) < 0.01:
            return f"If '{alt_name}' had been chosen instead of '{chosen_name}', the expected outcome would be similar (difference={value_diff:+.4f})."
        else:
            better_worse = "better" if value_diff > 0 else "worse"
            return f"If '{alt_name}' had been chosen instead of '{chosen_name}', the expected outcome would be {better_worse} by {abs(value_diff):.4f}."

    @staticmethod
    def _state_feature_description(name: str, value: float) -> str:
        """Human-readable description of a state feature."""
        if "compromised" in name:
            return "Host is compromised" if value > 0.5 else "Host is clean"
        elif "isolated" in name:
            return "Host is isolated" if value > 0.5 else "Host is online"
        elif "vulnerability" in name:
            return f"Vulnerability exposure level: {value:.2f}"
        return f"{name} = {value:.4f}"
