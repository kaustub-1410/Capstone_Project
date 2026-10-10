"""
Reasoning Engine — Structured chain-of-thought reasoning and decision explanations.

Provides reasoning capabilities for cognitive agents, including step-by-step
analysis, evidence tracking, confidence scoring, and structured explanation
generation. All reasoning is serializable for audit trails and XAI integration.

Part of Phase 1: Multi-Agent Society.
"""

import logging
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
#  Enumerations
# --------------------------------------------------------------------------- #

class ConfidenceLevel(str, Enum):
    """Categorical confidence levels for human-readable explanations."""
    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"

    @classmethod
    def from_score(cls, score: float) -> "ConfidenceLevel":
        if score >= 0.9:
            return cls.VERY_HIGH
        elif score >= 0.7:
            return cls.HIGH
        elif score >= 0.5:
            return cls.MEDIUM
        elif score >= 0.3:
            return cls.LOW
        else:
            return cls.VERY_LOW


class EvidenceType(str, Enum):
    """Type classification for supporting evidence."""
    TELEMETRY = "telemetry"
    GNN_PREDICTION = "gnn_prediction"
    RL_POLICY = "rl_policy"
    LLM_ANALYSIS = "llm_analysis"
    GRAPH_STRUCTURE = "graph_structure"
    HISTORICAL = "historical"
    INTELLIGENCE = "intelligence"
    HEURISTIC = "heuristic"


# --------------------------------------------------------------------------- #
#  Data Models
# --------------------------------------------------------------------------- #

class Evidence(BaseModel):
    """A single piece of supporting evidence for a reasoning step."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_type: EvidenceType
    description: str
    data: Dict[str, Any] = Field(default_factory=dict)
    weight: float = 1.0  # Relative importance of this evidence
    source: str = ""


class ReasoningStep(BaseModel):
    """
    A single step in a chain-of-thought reasoning process.

    Each step captures an observation, a hypothesis formed, evidence gathered,
    a confidence assessment, and a conclusion drawn.
    """
    step_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    step_number: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    observation: str = ""
    hypothesis: str = ""
    evidence: List[Evidence] = Field(default_factory=list)
    confidence: float = 0.5
    conclusion: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DecisionExplanation(BaseModel):
    """
    Structured explanation for an agent decision.

    Contains the primary reason, supporting evidence chain, confidence metrics,
    affected assets, recommended actions, and optional visual explanation data.
    Designed for both human consumption and programmatic integration with the
    Explainable AI engine (Phase 4).
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent_id: str = ""
    decision: str = ""
    reason: str = ""
    supporting_evidence: List[Evidence] = Field(default_factory=list)
    confidence: float = 0.5
    confidence_level: ConfidenceLevel = ConfidenceLevel.MEDIUM
    affected_assets: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    reasoning_chain: List[ReasoningStep] = Field(default_factory=list)
    visual_data: Dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: List[str] = Field(default_factory=list)

    def to_summary(self) -> str:
        """Human-readable summary of the decision explanation."""
        lines = [
            f"Decision: {self.decision}",
            f"Reason: {self.reason}",
            f"Confidence: {self.confidence:.2f} ({self.confidence_level.value})",
        ]
        if self.affected_assets:
            lines.append(f"Affected Assets: {', '.join(self.affected_assets)}")
        if self.recommended_actions:
            lines.append(f"Recommended Actions: {', '.join(self.recommended_actions)}")
        if self.supporting_evidence:
            lines.append(f"Supporting Evidence ({len(self.supporting_evidence)} items):")
            for ev in self.supporting_evidence[:5]:
                lines.append(f"  - [{ev.evidence_type.value}] {ev.description}")
        if self.mitre_techniques:
            lines.append(f"MITRE Techniques: {', '.join(self.mitre_techniques)}")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  Reasoning Engine
# --------------------------------------------------------------------------- #

class ReasoningEngine:
    """
    Chain-of-thought reasoning engine for cognitive agents.

    Supports multi-step analysis with evidence accumulation, confidence
    propagation, and structured explanation generation. Maintains a
    full audit trail of reasoning history.
    """

    def __init__(self, agent_id: str, max_history: int = 200):
        self.agent_id = agent_id
        self._max_history = max_history
        self._current_chain: List[ReasoningStep] = []
        self._history: List[DecisionExplanation] = []
        logger.debug(f"ReasoningEngine initialized for agent {agent_id}")

    def begin_reasoning(self) -> None:
        """Start a new reasoning chain, resetting the current chain."""
        self._current_chain = []

    def add_step(
        self,
        observation: str,
        hypothesis: str = "",
        evidence: Optional[List[Evidence]] = None,
        confidence: float = 0.5,
        conclusion: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ReasoningStep:
        """Add a reasoning step to the current chain."""
        step = ReasoningStep(
            step_number=len(self._current_chain) + 1,
            observation=observation,
            hypothesis=hypothesis,
            evidence=evidence or [],
            confidence=confidence,
            conclusion=conclusion,
            metadata=metadata or {},
        )
        self._current_chain.append(step)
        return step

    def compute_chain_confidence(self) -> float:
        """
        Compute aggregate confidence across the reasoning chain.

        Uses weighted geometric mean to penalize any low-confidence step
        disproportionately (a chain is only as strong as its weakest link).
        """
        if not self._current_chain:
            return 0.0

        confidences = [s.confidence for s in self._current_chain]
        # Geometric mean: penalizes weak links
        product = 1.0
        for c in confidences:
            product *= max(c, 0.01)  # Avoid zero
        return product ** (1.0 / len(confidences))

    def generate_explanation(
        self,
        decision: str,
        reason: str,
        affected_assets: Optional[List[str]] = None,
        recommended_actions: Optional[List[str]] = None,
        mitre_techniques: Optional[List[str]] = None,
    ) -> DecisionExplanation:
        """
        Finalize the current reasoning chain into a structured explanation.

        Collects all evidence from the chain, computes final confidence,
        and produces a DecisionExplanation suitable for XAI rendering.
        """
        # Aggregate all evidence from the chain
        all_evidence: List[Evidence] = []
        for step in self._current_chain:
            all_evidence.extend(step.evidence)

        chain_confidence = self.compute_chain_confidence()

        explanation = DecisionExplanation(
            agent_id=self.agent_id,
            decision=decision,
            reason=reason,
            supporting_evidence=all_evidence,
            confidence=chain_confidence,
            confidence_level=ConfidenceLevel.from_score(chain_confidence),
            affected_assets=affected_assets or [],
            recommended_actions=recommended_actions or [],
            reasoning_chain=list(self._current_chain),
            mitre_techniques=mitre_techniques or [],
        )

        # Archive to history
        self._history.append(explanation)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        # Reset current chain
        self._current_chain = []

        logger.debug(
            f"Agent {self.agent_id} generated explanation: "
            f"decision={decision}, confidence={chain_confidence:.3f}"
        )
        return explanation

    def get_history(self, limit: int = 50) -> List[DecisionExplanation]:
        """Retrieve recent explanation history."""
        return self._history[-limit:]

    def get_current_chain(self) -> List[ReasoningStep]:
        """Access the in-progress reasoning chain."""
        return list(self._current_chain)

    def clear_history(self) -> None:
        self._history.clear()
        self._current_chain.clear()
