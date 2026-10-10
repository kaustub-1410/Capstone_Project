"""
LLM Explainer — Structured reasoning chain extraction and evidence linking.

Provides interpretability for LLM-based decisions by extracting structured
reasoning chains, linking conclusions to telemetry evidence, and providing
confidence calibration based on response quality analysis.

Part of Phase 4: Explainable AI.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

from explainable_ai.explanation_engine import (
    Explanation,
    ExplanationEngine,
    ExplanationLevel,
    ExplanationSource,
    FeatureContribution,
)

logger = logging.getLogger(__name__)


class LLMExplainer:
    """
    Explainability module for LLM-based agent decisions.

    Provides:
    - Structured reasoning chain extraction from LLM responses
    - Evidence linking to telemetry events and graph data
    - Confidence calibration based on response quality
    - Decision decomposition into atomic reasoning steps
    """

    def __init__(self, explanation_engine: Optional[ExplanationEngine] = None):
        self.engine = explanation_engine or ExplanationEngine()
        logger.info("LLMExplainer initialized")

    def explain_llm_decision(
        self,
        agent_name: str,
        decision: Dict[str, Any],
        prompt_context: str = "",
        telemetry_evidence: Optional[List[Dict[str, Any]]] = None,
    ) -> Explanation:
        """
        Generate an explanation for an LLM agent's decision.

        Args:
            agent_name: Name of the LLM agent (e.g., "StrategicPlanner")
            decision: The structured decision output from the LLM
            prompt_context: The context that was provided to the LLM
            telemetry_evidence: Related telemetry events to link
        """
        # Extract reasoning chain from the decision
        reasoning_chain = self._extract_reasoning_chain(decision)

        # Link evidence
        evidence_links = self._link_evidence(
            decision, telemetry_evidence or []
        )

        # Calibrate confidence
        calibrated_confidence = self._calibrate_confidence(
            decision, reasoning_chain, evidence_links
        )

        # Build detail
        action = decision.get("action", "unknown")
        target = decision.get("target", "unknown")
        thought = decision.get("thought", decision.get("reasoning", ""))

        detail_lines = [
            f"LLM Agent: {agent_name}",
            f"Decision: {action}",
            f"Target: {target}",
            f"Calibrated Confidence: {calibrated_confidence:.2%}",
            "",
            "Reasoning Chain:",
        ]

        for i, step in enumerate(reasoning_chain, 1):
            detail_lines.append(f"  Step {i}: {step}")

        if evidence_links:
            detail_lines.append("")
            detail_lines.append("Supporting Evidence:")
            for ev in evidence_links:
                detail_lines.append(f"  • [{ev['type']}] {ev['description']}")

        if thought:
            detail_lines.append("")
            detail_lines.append(f"Agent Thought Process: {thought}")

        # Generate feature contributions from decision fields
        feature_contribs = self._decision_to_features(decision)

        # Recommendations
        recs = decision.get("recommended_actions", [])
        if isinstance(recs, str):
            recs = [recs]

        affected = [target] if target != "unknown" else []
        if "affected_hosts" in decision:
            affected = decision["affected_hosts"] if isinstance(decision["affected_hosts"], list) else [decision["affected_hosts"]]

        return self.engine.create_explanation(
            source=ExplanationSource.LLM,
            subject=f"{agent_name}_{action}",
            summary=f"{agent_name} decided to '{action}' targeting {target}: {thought[:100]}",
            detail="\n".join(detail_lines),
            confidence=calibrated_confidence,
            feature_contributions=feature_contribs,
            evidence=[
                {"type": ev["type"], "description": ev["description"]}
                for ev in evidence_links
            ],
            affected_assets=affected,
            recommended_actions=recs,
            visual_data={
                "reasoning_chain": reasoning_chain,
                "evidence_links": evidence_links,
                "raw_decision": decision,
            },
        )

    def explain_planning_decision(
        self,
        plan: Dict[str, Any],
        risk_scores: Optional[Dict[str, float]] = None,
    ) -> Explanation:
        """Explain an attack planning decision from the Strategic Planner."""
        action = plan.get("action", "unknown")
        target = plan.get("target", "unknown")
        thought = plan.get("thought", "")

        detail_lines = [
            "Strategic Attack Planning Decision",
            f"Selected Action: {action}",
            f"Target Host: {target}",
            f"Strategic Reasoning: {thought}",
        ]

        if risk_scores:
            detail_lines.append("\nGNN Risk Context:")
            sorted_scores = sorted(risk_scores.items(), key=lambda x: x[1], reverse=True)
            for host_id, score in sorted_scores[:5]:
                marker = " ← TARGET" if host_id == target else ""
                detail_lines.append(f"  {host_id}: {score:.4f}{marker}")

        contribs = []
        if risk_scores and target in risk_scores:
            contribs.append(FeatureContribution(
                feature_name="target_risk_score",
                feature_value=round(risk_scores[target], 4),
                contribution=round(risk_scores[target] * 0.5, 4),
                direction="increases_risk",
                description=f"GNN risk score of target {target}",
            ))

        return self.engine.create_explanation(
            source=ExplanationSource.LLM,
            subject=f"strategic_plan_{action}",
            summary=f"Strategic planner selected '{action}' on {target} — {thought[:80]}",
            detail="\n".join(detail_lines),
            confidence=0.7,
            feature_contributions=contribs,
            affected_assets=[target],
        )

    def explain_incident_response(
        self,
        response: Dict[str, Any],
        alerts: Optional[List[Dict[str, Any]]] = None,
    ) -> Explanation:
        """Explain an incident response decision."""
        action = response.get("action", "unknown")
        target = response.get("target", "unknown")
        thought = response.get("thought", "")

        detail_lines = [
            "Incident Response Decision",
            f"Response Action: {action}",
            f"Target Host: {target}",
            f"Analysis: {thought}",
        ]

        if alerts:
            detail_lines.append(f"\nTriggering Alerts ({len(alerts)}):")
            for alert in alerts[:5]:
                detail_lines.append(
                    f"  [{alert.get('severity', 'INFO')}] {alert.get('host_id', '?')}: "
                    f"{alert.get('message', '')}"
                )

        return self.engine.create_explanation(
            source=ExplanationSource.LLM,
            subject=f"incident_response_{action}",
            summary=f"Incident response: '{action}' on {target} — {thought[:80]}",
            detail="\n".join(detail_lines),
            confidence=0.75,
            affected_assets=[target],
            recommended_actions=[f"Execute {action} on {target}"],
        )

    # ------------------------------------------------------------------ #
    #  Internal Analysis Methods
    # ------------------------------------------------------------------ #

    def _extract_reasoning_chain(
        self, decision: Dict[str, Any]
    ) -> List[str]:
        """Extract a structured reasoning chain from an LLM decision."""
        chain = []

        # Look for explicit reasoning fields
        thought = decision.get("thought", decision.get("reasoning", ""))
        if thought:
            # Split by sentence boundaries
            sentences = re.split(r'[.!?]+\s*', thought)
            chain.extend(s.strip() for s in sentences if s.strip())

        # Add action rationale
        action = decision.get("action", "")
        target = decision.get("target", "")
        if action and target:
            chain.append(f"Decided to execute '{action}' on target '{target}'")

        # Add service/vulnerability context
        service = decision.get("service_name", decision.get("service", ""))
        if service:
            chain.append(f"Targeting service: {service}")

        cve = decision.get("cve", decision.get("exploit", ""))
        if cve:
            chain.append(f"Using exploit/CVE: {cve}")

        return chain if chain else ["No explicit reasoning chain available"]

    def _link_evidence(
        self,
        decision: Dict[str, Any],
        telemetry: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Link the LLM decision to supporting telemetry evidence."""
        links = []
        target = decision.get("target", "")

        for event in telemetry:
            # Check if telemetry event relates to the decision target
            if event.get("host_id") == target or target in str(event.get("message", "")):
                links.append({
                    "type": event.get("severity", "INFO"),
                    "description": event.get("message", str(event)),
                    "host_id": event.get("host_id", ""),
                    "timestamp": event.get("timestamp", ""),
                })

        # Add graph-derived evidence
        if decision.get("thought"):
            links.append({
                "type": "LLM_REASONING",
                "description": f"Agent reasoning: {decision['thought'][:200]}",
            })

        return links

    def _calibrate_confidence(
        self,
        decision: Dict[str, Any],
        reasoning_chain: List[str],
        evidence_links: List[Dict[str, Any]],
    ) -> float:
        """
        Calibrate confidence score based on response quality indicators.

        Higher confidence for decisions with:
        - Longer, more detailed reasoning chains
        - More supporting evidence
        - Specific (not vague) targets and actions
        """
        base_confidence = 0.5

        # Reasoning depth bonus (up to +0.15)
        chain_bonus = min(len(reasoning_chain) * 0.03, 0.15)

        # Evidence support bonus (up to +0.15)
        evidence_bonus = min(len(evidence_links) * 0.05, 0.15)

        # Specificity bonus
        specificity_bonus = 0.0
        if decision.get("target") and decision["target"] != "unknown":
            specificity_bonus += 0.05
        if decision.get("action") and decision["action"] != "unknown":
            specificity_bonus += 0.05
        if decision.get("thought") and len(decision.get("thought", "")) > 20:
            specificity_bonus += 0.05

        return min(
            base_confidence + chain_bonus + evidence_bonus + specificity_bonus,
            0.95,
        )

    def _decision_to_features(
        self, decision: Dict[str, Any]
    ) -> List[FeatureContribution]:
        """Convert decision fields into feature contribution format."""
        contribs = []

        for key in ["action", "target", "service_name", "thought"]:
            if key in decision and decision[key]:
                value = decision[key] if not isinstance(decision[key], str) else decision[key][:50]
                contribs.append(FeatureContribution(
                    feature_name=key,
                    feature_value=value,
                    contribution=0.1,
                    direction="decision_factor",
                    description=f"LLM decision field: {key}",
                ))

        return contribs
