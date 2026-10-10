"""
CognitiveAgent — Extended base agent with memory, reasoning, and explainability.

Provides the abstract foundation for all intelligent AMCDS agents (Phase 1+).
Extends the existing BaseAgent without modifying it, adding short-term memory,
long-term memory, a structured knowledge base, reasoning capabilities, and
confidence-tracked decision-making.

Part of Phase 1: Multi-Agent Society.
"""

import logging
from abc import abstractmethod
from typing import Any, Dict, List, Optional

from agent_framework.base import BaseAgent
from agent_framework.memory import (
    ExperienceEntry,
    KnowledgeBase,
    LongTermMemory,
    ShortTermMemory,
)
from agent_framework.reasoning import (
    DecisionExplanation,
    Evidence,
    EvidenceType,
    ReasoningEngine,
    ReasoningStep,
)
from simulation_engine.core import SimulationEngine
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)


class CognitiveAgent(BaseAgent):
    """
    Abstract cognitive agent with memory, reasoning, and decision explanation.

    Extends BaseAgent (preserving full backward compatibility) by adding:
    - Short-term memory: Rolling window of recent observations
    - Long-term memory: Persistent experience store
    - Knowledge base: Structured facts with confidence and TTL
    - Reasoning engine: Chain-of-thought analysis with evidence
    - Confidence score: Self-assessed reliability of current state
    - Decision explanation: Structured XAI output for every decision

    All new cognitive agents (ThreatIntelAgent, SOCAnalystAgent, etc.)
    inherit from this class rather than directly from BaseAgent.
    """

    def __init__(
        self,
        agent_id: str,
        role: str,
        short_term_capacity: int = 50,
        memory_storage_dir: Optional[str] = None,
    ):
        super().__init__(agent_id, role)

        # Memory systems
        self.short_term_memory = ShortTermMemory(capacity=short_term_capacity)
        self.long_term_memory = LongTermMemory(
            agent_id=agent_id, storage_dir=memory_storage_dir
        )
        # Upgrade the inherited knowledge_base from a plain dict
        self.knowledge: KnowledgeBase = KnowledgeBase()

        # Reasoning
        self.reasoning_engine = ReasoningEngine(agent_id=agent_id)
        self.reasoning_history: List[ReasoningStep] = []

        # Confidence and explanation tracking
        self.confidence_score: float = 0.5
        self.last_explanation: Optional[DecisionExplanation] = None

        logger.info(
            f"CognitiveAgent {agent_id} ({role}) initialized with "
            f"STM_capacity={short_term_capacity}"
        )

    # ------------------------------------------------------------------ #
    #  Abstract Methods for Subclasses
    # ------------------------------------------------------------------ #

    @abstractmethod
    def reason(
        self, sim: SimulationEngine, topo: NetworkTopology
    ) -> Optional[DecisionExplanation]:
        """
        Execute the agent's reasoning cycle.

        Must be implemented by each specialized agent. Should use
        self.reasoning_engine to build a chain-of-thought and return
        a DecisionExplanation.
        """
        pass

    @abstractmethod
    def explain(self) -> str:
        """
        Return a human-readable explanation of the agent's last decision.

        Must be implemented by each specialized agent.
        """
        pass

    # ------------------------------------------------------------------ #
    #  Core Decision Loop
    # ------------------------------------------------------------------ #

    def act(
        self, sim: SimulationEngine, topo: NetworkTopology
    ) -> Optional[Dict[str, Any]]:
        """
        Execute the agent's decision loop with full cognitive support.

        This method:
        1. Invokes reason() to produce a decision explanation
        2. Records the experience in short-term and long-term memory
        3. Updates the knowledge base
        4. Returns the action payload

        Subclasses should override reason() to implement domain-specific
        logic. They may also override act() for additional pre/post
        processing, but must call super().act() or replicate the
        memory bookkeeping.
        """
        try:
            explanation = self.reason(sim, topo)
        except Exception as e:
            logger.error(
                f"Agent {self.agent_id} reasoning failed: {e}", exc_info=True
            )
            explanation = None

        if explanation is None:
            return None

        self.last_explanation = explanation
        self.confidence_score = explanation.confidence

        # Build action payload from the explanation
        action_payload = self._explanation_to_action(explanation)

        # Record experience
        experience = ExperienceEntry(
            agent_id=self.agent_id,
            action=explanation.decision,
            target=(
                explanation.affected_assets[0]
                if explanation.affected_assets
                else None
            ),
            result="pending",
            confidence=explanation.confidence,
            context={
                "reason": explanation.reason,
                "mitre_techniques": explanation.mitre_techniques,
            },
            explanation=explanation.reason,
        )
        self.short_term_memory.add(experience)
        self.long_term_memory.store(experience)

        return action_payload

    def _explanation_to_action(
        self, explanation: DecisionExplanation
    ) -> Dict[str, Any]:
        """
        Convert a DecisionExplanation into a standard action payload.

        Subclasses may override to customize action payload format.
        """
        return {
            "action": explanation.decision,
            "target": (
                explanation.affected_assets[0]
                if explanation.affected_assets
                else None
            ),
            "confidence": explanation.confidence,
            "explanation": explanation.reason,
            "agent_id": self.agent_id,
            "agent_role": self.role,
        }

    # ------------------------------------------------------------------ #
    #  Memory Utilities
    # ------------------------------------------------------------------ #

    def record_outcome(self, action: str, target: str, result: str, reward: float = 0.0) -> None:
        """Record the outcome of a previously executed action."""
        experience = ExperienceEntry(
            agent_id=self.agent_id,
            action=action,
            target=target,
            result=result,
            confidence=self.confidence_score,
            reward=reward,
        )
        self.short_term_memory.add(experience)
        self.long_term_memory.store(experience)

        # Update knowledge base with outcome
        self.knowledge.assert_fact(
            category="action_result",
            key=f"{action}_{target}",
            value=result,
            confidence=self.confidence_score,
            source="observation",
        )

    def recall_similar_actions(
        self, action: str, limit: int = 10
    ) -> List[ExperienceEntry]:
        """Recall past experiences with the same action type."""
        return self.long_term_memory.query(action=action, limit=limit)

    def recall_target_history(
        self, target: str, limit: int = 10
    ) -> List[ExperienceEntry]:
        """Recall past experiences involving a specific target."""
        return self.long_term_memory.query(target=target, limit=limit)

    def get_action_success_rate(self, action: str) -> float:
        """Compute historical success rate for an action type."""
        return self.long_term_memory.get_success_rate(action=action)

    # ------------------------------------------------------------------ #
    #  Serialization
    # ------------------------------------------------------------------ #

    def get_state_summary(self) -> Dict[str, Any]:
        """Return a serializable summary of the agent's cognitive state."""
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "confidence_score": self.confidence_score,
            "short_term_memory_size": len(self.short_term_memory),
            "long_term_memory_size": self.long_term_memory.count(),
            "knowledge_fact_count": self.knowledge.fact_count(),
            "reasoning_history_count": len(
                self.reasoning_engine.get_history()
            ),
            "last_explanation": (
                self.last_explanation.to_summary()
                if self.last_explanation
                else None
            ),
        }

    def reset_cognitive_state(self) -> None:
        """Reset all cognitive subsystems (memory, knowledge, reasoning)."""
        self.short_term_memory.clear()
        self.long_term_memory.clear()
        self.knowledge.clear()
        self.reasoning_engine.clear_history()
        self.confidence_score = 0.5
        self.last_explanation = None
        logger.info(f"Cognitive state reset for agent {self.agent_id}")

    def close(self) -> None:
        """Clean up resources (database connections, etc.)."""
        self.long_term_memory.close()
