"""
Explanation Engine — Central explanation generation for all AMCDS AI subsystems.

Aggregates explanations from GNN, RL, LLM, and agent reasoning into unified,
human-readable, audit-ready explanations. Supports both textual and structured
visual explanations for the dashboard.

Part of Phase 4: Explainable AI.
"""

import logging
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ExplanationSource(str, Enum):
    """Source subsystem of an explanation."""
    GNN = "gnn"
    RL = "rl"
    LLM = "llm"
    AGENT = "agent"
    RULE = "rule"
    GRAPH = "graph"
    COMPOSITE = "composite"


class ExplanationLevel(str, Enum):
    """Detail level of an explanation."""
    EXECUTIVE = "executive"    # One-liner for C-suite
    ANALYST = "analyst"        # Detailed for SOC analysts
    TECHNICAL = "technical"    # Full technical detail for engineers
    DEBUG = "debug"            # Maximum detail for debugging


class FeatureContribution(BaseModel):
    """Contribution of a single feature to a prediction or decision."""
    feature_name: str
    feature_value: Any
    contribution: float  # Positive = increases risk, negative = decreases
    direction: str = ""  # "increases_risk" or "decreases_risk"
    description: str = ""


class Explanation(BaseModel):
    """
    Unified explanation model for any AI decision in the AMCDS platform.

    Designed for audit trails, dashboard rendering, and downstream processing
    by the SOC analyst and CISO agents.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: ExplanationSource
    level: ExplanationLevel = ExplanationLevel.ANALYST
    subject: str = ""  # What is being explained (host_id, action, decision)
    summary: str = ""  # One-line summary
    detail: str = ""  # Full explanation text
    confidence: float = 0.5
    feature_contributions: List[FeatureContribution] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    visual_data: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_executive_summary(self) -> str:
        """Generate a brief executive-level summary."""
        return f"{self.summary} (Confidence: {self.confidence:.0%})"

    def to_analyst_report(self) -> str:
        """Generate an analyst-level report."""
        lines = [
            f"=== {self.source.value.upper()} Explanation ===",
            f"Subject: {self.subject}",
            f"Summary: {self.summary}",
            f"Confidence: {self.confidence:.2%}",
            "",
            "Detail:",
            self.detail,
        ]
        if self.feature_contributions:
            lines.append("\nKey Factors:")
            for fc in self.feature_contributions[:10]:
                sign = "↑" if fc.contribution > 0 else "↓"
                lines.append(
                    f"  {sign} {fc.feature_name}: {fc.feature_value} "
                    f"({fc.contribution:+.4f}) — {fc.description}"
                )
        if self.affected_assets:
            lines.append(f"\nAffected Assets: {', '.join(self.affected_assets)}")
        if self.recommended_actions:
            lines.append("\nRecommended Actions:")
            for ra in self.recommended_actions:
                lines.append(f"  • {ra}")
        if self.mitre_techniques:
            lines.append(f"\nMITRE ATT&CK: {', '.join(self.mitre_techniques)}")
        return "\n".join(lines)


class ExplanationEngine:
    """
    Central explanation generation and management engine.

    Coordinates explanations from multiple AI subsystems (GNN, RL, LLM, agents)
    and provides unified explanation generation, storage, and retrieval.
    """

    def __init__(self, max_history: int = 500):
        self._history: List[Explanation] = []
        self._max_history = max_history
        logger.info("ExplanationEngine initialized")

    def create_explanation(
        self,
        source: ExplanationSource,
        subject: str,
        summary: str,
        detail: str,
        confidence: float = 0.5,
        level: ExplanationLevel = ExplanationLevel.ANALYST,
        feature_contributions: Optional[List[FeatureContribution]] = None,
        evidence: Optional[List[Dict[str, Any]]] = None,
        affected_assets: Optional[List[str]] = None,
        recommended_actions: Optional[List[str]] = None,
        mitre_techniques: Optional[List[str]] = None,
        visual_data: Optional[Dict[str, Any]] = None,
    ) -> Explanation:
        """Create and store a new explanation."""
        explanation = Explanation(
            source=source,
            level=level,
            subject=subject,
            summary=summary,
            detail=detail,
            confidence=confidence,
            feature_contributions=feature_contributions or [],
            evidence=evidence or [],
            affected_assets=affected_assets or [],
            recommended_actions=recommended_actions or [],
            mitre_techniques=mitre_techniques or [],
            visual_data=visual_data or {},
        )

        self._history.append(explanation)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        logger.debug(
            f"Explanation created: source={source.value}, subject={subject}, "
            f"confidence={confidence:.3f}"
        )
        return explanation

    def compose_explanations(
        self,
        explanations: List[Explanation],
        subject: str,
        summary: str,
    ) -> Explanation:
        """
        Compose multiple explanations from different sources into a unified explanation.

        Aggregates evidence, feature contributions, and recommendations.
        Confidence is the weighted average of component confidences.
        """
        all_features: List[FeatureContribution] = []
        all_evidence: List[Dict[str, Any]] = []
        all_assets: set = set()
        all_actions: List[str] = []
        all_mitre: set = set()
        all_visual: Dict[str, Any] = {}
        total_confidence = 0.0

        for exp in explanations:
            all_features.extend(exp.feature_contributions)
            all_evidence.extend(exp.evidence)
            all_assets.update(exp.affected_assets)
            all_actions.extend(exp.recommended_actions)
            all_mitre.update(exp.mitre_techniques)
            all_visual[exp.source.value] = exp.visual_data
            total_confidence += exp.confidence

        avg_confidence = total_confidence / max(len(explanations), 1)

        detail_parts = []
        for exp in explanations:
            detail_parts.append(f"[{exp.source.value.upper()}] {exp.detail}")

        return self.create_explanation(
            source=ExplanationSource.COMPOSITE,
            subject=subject,
            summary=summary,
            detail="\n\n".join(detail_parts),
            confidence=avg_confidence,
            feature_contributions=all_features,
            evidence=all_evidence,
            affected_assets=sorted(all_assets),
            recommended_actions=list(dict.fromkeys(all_actions)),  # Deduplicate preserving order
            mitre_techniques=sorted(all_mitre),
            visual_data=all_visual,
        )

    def get_history(
        self,
        source: Optional[ExplanationSource] = None,
        subject: Optional[str] = None,
        limit: int = 50,
    ) -> List[Explanation]:
        """Retrieve explanation history with optional filters."""
        filtered = self._history
        if source:
            filtered = [e for e in filtered if e.source == source]
        if subject:
            filtered = [e for e in filtered if e.subject == subject]
        return filtered[-limit:]

    def get_by_id(self, explanation_id: str) -> Optional[Explanation]:
        """Retrieve a specific explanation by ID."""
        for exp in self._history:
            if exp.id == explanation_id:
                return exp
        return None

    def clear_history(self) -> None:
        self._history.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Return explanation engine statistics."""
        from collections import Counter
        source_counts = Counter(e.source.value for e in self._history)
        avg_confidence = (
            sum(e.confidence for e in self._history) / max(len(self._history), 1)
        )
        return {
            "total_explanations": len(self._history),
            "by_source": dict(source_counts),
            "average_confidence": round(avg_confidence, 3),
        }
