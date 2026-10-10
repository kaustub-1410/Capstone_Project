"""
Graph RAG Engine — Graph Retrieval-Augmented Generation for cyber reasoning.

Combines knowledge graph structure (Neo4j or in-memory), vector similarity
search, and LLM reasoning to provide context-aware intelligence. Reasons
over hosts, services, credentials, users, connections, vulnerabilities,
telemetry, and MITRE ATT&CK mappings.

Falls back to in-memory graph when Neo4j is unavailable (offline mode).

Part of Phase 3: Graph RAG.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from agent_framework.vector_store import InMemoryVectorStore, TextEmbedder
from llm_orchestration.client import UnifiedLLMClient
from llm_orchestration.context_builder import ContextBuilder
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)


class GraphRAGEngine:
    """
    Graph Retrieval-Augmented Generation engine.

    Combines three information sources for LLM reasoning:
    1. **Graph Structure** — Network topology as a knowledge graph
    2. **Vector Search** — Semantic similarity over past queries/experiences
    3. **LLM Reasoning** — Contextual analysis using structured graph context

    Supports both online (Neo4j) and offline (in-memory) operation.
    """

    def __init__(
        self,
        llm_client: Optional[UnifiedLLMClient] = None,
        embedding_dim: int = 128,
        max_context_tokens: int = 3000,
    ):
        self.llm_client = llm_client or UnifiedLLMClient()
        self.context_builder = ContextBuilder(max_tokens=max_context_tokens)
        self.embedder = TextEmbedder(dimension=embedding_dim)
        self.vector_store = InMemoryVectorStore(dimension=embedding_dim)
        self._query_cache: Dict[str, str] = {}
        self._cache_max = 100
        logger.info("GraphRAGEngine initialized")

    # ------------------------------------------------------------------ #
    #  Core RAG Pipeline
    # ------------------------------------------------------------------ #

    def query(
        self,
        question: str,
        topo: NetworkTopology,
        risk_scores: Optional[Dict[str, float]] = None,
        attack_paths: Optional[List[Dict[str, Any]]] = None,
        recent_alerts: Optional[List[Dict[str, Any]]] = None,
        additional_context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute a Graph RAG query.

        1. Extract relevant subgraph context from topology
        2. Retrieve similar past queries from vector store
        3. Construct an enriched prompt with graph context
        4. Send to LLM for reasoning
        5. Cache the result

        Args:
            question: Natural language query about the network/threat landscape
            topo: Current network topology
            risk_scores: Optional GNN risk scores per host
            attack_paths: Optional computed attack paths
            recent_alerts: Optional recent security alerts
            additional_context: Optional extra context to include

        Returns:
            Dict with keys: answer, context_used, similar_queries, confidence
        """
        # Step 1: Check cache
        cache_key = question.strip().lower()
        if cache_key in self._query_cache:
            logger.debug(f"Cache hit for query: {question[:50]}...")
            return {
                "answer": self._query_cache[cache_key],
                "context_used": "cached",
                "similar_queries": [],
                "confidence": 0.8,
                "cached": True,
            }

        # Step 2: Build graph context
        graph_context = self._build_relevant_context(
            question, topo, risk_scores, attack_paths, recent_alerts
        )

        # Step 3: Retrieve similar past queries
        similar_queries = self._retrieve_similar(question)

        # Step 4: Construct enriched prompt
        prompt = self._build_rag_prompt(
            question, graph_context, similar_queries, additional_context
        )

        # Step 5: LLM reasoning
        system_prompt = (
            "You are an expert cybersecurity analyst with deep knowledge of enterprise "
            "network security, MITRE ATT&CK, vulnerability management, and incident response. "
            "You reason over network graph data, vulnerability intelligence, and telemetry to "
            "provide accurate, actionable security analysis. Base your answers strictly on the "
            "provided graph context. If the context is insufficient, state that clearly."
        )

        try:
            answer = self.llm_client.generate_completion(
                prompt=prompt,
                system_prompt=system_prompt,
                json_mode=False,
            )
        except Exception as e:
            logger.error(f"GraphRAG LLM query failed: {e}")
            answer = f"Analysis unavailable due to LLM error: {str(e)}"

        # Step 6: Cache result and store query embedding
        if len(self._query_cache) >= self._cache_max:
            # Evict oldest entry
            oldest_key = next(iter(self._query_cache))
            del self._query_cache[oldest_key]
        self._query_cache[cache_key] = answer

        # Store query in vector store for future similarity retrieval
        query_vector = self.embedder.embed(question)
        self.vector_store.add(
            id=f"query_{self.vector_store.count()}",
            vector=query_vector,
            metadata={"question": question, "answer": answer[:200]},
        )

        return {
            "answer": answer,
            "context_used": graph_context[:500] + "..." if len(graph_context) > 500 else graph_context,
            "similar_queries": [
                {"question": m.get("question", ""), "similarity": round(s, 3)}
                for _, s, m in similar_queries
            ],
            "confidence": 0.75 if "mock" not in answer.lower() else 0.3,
            "cached": False,
        }

    def query_structured(
        self,
        question: str,
        topo: NetworkTopology,
        risk_scores: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        """
        Execute a Graph RAG query expecting structured JSON output.

        Returns parsed JSON from the LLM or a fallback structure.
        """
        graph_context = self._build_relevant_context(question, topo, risk_scores)

        prompt = f"""Based on the following network graph context, answer the question in valid JSON format.

{graph_context}

Question: {question}

Return a JSON object with these fields:
{{
    "analysis": "Your detailed analysis",
    "findings": ["Finding 1", "Finding 2"],
    "risk_level": "critical|high|medium|low",
    "recommended_actions": ["Action 1", "Action 2"],
    "affected_hosts": ["HOST-ID-1", "HOST-ID-2"],
    "confidence": 0.0 to 1.0
}}"""

        system_prompt = "You are a cybersecurity graph analyst. Output only valid JSON."

        try:
            raw_response = self.llm_client.generate_completion(
                prompt=prompt, system_prompt=system_prompt, json_mode=True
            )
            return json.loads(raw_response)
        except json.JSONDecodeError:
            logger.warning("Failed to parse structured GraphRAG response")
            return {
                "analysis": raw_response if 'raw_response' in dir() else "Parse error",
                "findings": [],
                "risk_level": "unknown",
                "recommended_actions": [],
                "affected_hosts": [],
                "confidence": 0.1,
            }
        except Exception as e:
            logger.error(f"Structured GraphRAG query failed: {e}")
            return {
                "analysis": f"Error: {str(e)}",
                "findings": [],
                "risk_level": "unknown",
                "recommended_actions": [],
                "affected_hosts": [],
                "confidence": 0.0,
            }

    # ------------------------------------------------------------------ #
    #  Specialized Queries
    # ------------------------------------------------------------------ #

    def analyze_attack_path(
        self, source_id: str, target_id: str, topo: NetworkTopology
    ) -> Dict[str, Any]:
        """Analyze attack paths between two hosts using graph context."""
        return self.query(
            question=f"Analyze all possible attack paths from {source_id} to {target_id}. "
                     f"Identify vulnerabilities exploited at each hop, estimate success probability, "
                     f"and recommend defensive measures to block the most critical path.",
            topo=topo,
        )

    def explain_risk_score(
        self,
        host_id: str,
        topo: NetworkTopology,
        risk_scores: Dict[str, float],
    ) -> Dict[str, Any]:
        """Explain why a host has a particular GNN risk score."""
        host_context = self.context_builder.build_host_context(host_id, topo)
        score = risk_scores.get(host_id, 0.0)

        return self.query(
            question=f"Explain why host {host_id} has a GNN risk score of {score:.4f}. "
                     f"What factors contribute to this score? "
                     f"What would reduce the risk?",
            topo=topo,
            risk_scores=risk_scores,
            additional_context=host_context,
        )

    def recommend_defense(
        self, topo: NetworkTopology, recent_alerts: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Generate defensive recommendations based on current threat landscape."""
        return self.query(
            question="Based on the current threat landscape, what are the top 5 defensive "
                     "actions that should be taken immediately? Prioritize by impact and urgency.",
            topo=topo,
            recent_alerts=recent_alerts,
        )

    # ------------------------------------------------------------------ #
    #  Internal Methods
    # ------------------------------------------------------------------ #

    def _build_relevant_context(
        self,
        question: str,
        topo: NetworkTopology,
        risk_scores: Optional[Dict[str, float]] = None,
        attack_paths: Optional[List[Dict[str, Any]]] = None,
        recent_alerts: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Select and build the most relevant context for the question."""
        question_lower = question.lower()

        # Detect question intent to select appropriate context type
        if any(w in question_lower for w in ["attack", "exploit", "path", "compromise", "lateral"]):
            return self.context_builder.build_attack_context(
                topo, risk_scores, attack_paths
            )
        elif any(w in question_lower for w in ["defend", "isolate", "patch", "mitigate", "alert"]):
            return self.context_builder.build_defense_context(topo, recent_alerts)
        elif any(w in question_lower for w in ["host", "server", "workstation"]):
            # Try to extract host ID from question
            for host_id in topo.hosts:
                if host_id.lower() in question_lower:
                    return self.context_builder.build_host_context(host_id, topo)
            return self.context_builder.build_topology_context(topo)
        else:
            # General context
            return self.context_builder.build_topology_context(topo)

    def _retrieve_similar(
        self, question: str, top_k: int = 3
    ) -> List[Tuple[str, float, Dict[str, Any]]]:
        """Retrieve similar past queries from the vector store."""
        if self.vector_store.count() == 0:
            return []

        query_vector = self.embedder.embed(question)
        return self.vector_store.search(query_vector, top_k=top_k)

    def _build_rag_prompt(
        self,
        question: str,
        graph_context: str,
        similar_queries: List[Tuple[str, float, Dict[str, Any]]],
        additional_context: Optional[str] = None,
    ) -> str:
        """Construct the full RAG prompt with all context sources."""
        sections = []

        # Graph context
        sections.append("=== GRAPH CONTEXT ===")
        sections.append(graph_context)

        # Similar past queries (if any)
        if similar_queries:
            sections.append("\n=== SIMILAR PAST ANALYSES ===")
            for _, similarity, metadata in similar_queries:
                if similarity > 0.3:
                    sections.append(
                        f"[Similarity={similarity:.2f}] Q: {metadata.get('question', 'N/A')}\n"
                        f"  A: {metadata.get('answer', 'N/A')}"
                    )

        # Additional context
        if additional_context:
            sections.append("\n=== ADDITIONAL CONTEXT ===")
            sections.append(additional_context)

        # Question
        sections.append(f"\n=== QUESTION ===\n{question}")
        sections.append(
            "\nProvide a detailed, evidence-based analysis. Reference specific hosts, "
            "CVEs, services, and MITRE ATT&CK techniques where applicable."
        )

        return "\n\n".join(sections)

    def clear_cache(self) -> None:
        """Clear the query cache."""
        self._query_cache.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Return engine statistics."""
        return {
            "cached_queries": len(self._query_cache),
            "stored_embeddings": self.vector_store.count(),
            "llm_provider": self.llm_client.provider,
            "embedding_dim": self.embedder.dimension,
        }
