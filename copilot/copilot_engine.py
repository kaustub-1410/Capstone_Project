"""
Security Copilot Module — Core conversational Copilot Engine.
Interacts with the UnifiedLLMClient and GraphRAGEngine to provide natural language answers
and command recommendations to security operations center (SOC) analysts.
"""

import logging
import json
from typing import Dict, Any, Optional, List
from llm_orchestration.client import UnifiedLLMClient
from llm_orchestration.graph_rag import GraphRAGEngine
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)

class CopilotEngine:
    """
    conversational AI copilot for network security posture and incident response.
    """

    def __init__(self, llm_client: Optional[UnifiedLLMClient] = None, graph_rag: Optional[GraphRAGEngine] = None):
        self.llm = llm_client or UnifiedLLMClient()
        self.graph_rag = graph_rag
        
    def ask(self, prompt: str, topo: NetworkTopology) -> Dict[str, Any]:
        """
        Processes a question from a security analyst.
        Resolves topology context via Graph RAG and prompts the LLM for a structured answer.
        """
        logger.info(f"Copilot query received: {prompt}")
        
        # 1. Resolve context
        context = ""
        if self.graph_rag:
            context = self.graph_rag.query_context(prompt, limit=5)
        else:
            compromised = [h.id for h in topo.hosts.values() if h.compromised]
            isolated = [h.id for h in topo.hosts.values() if h.isolated]
            context = f"Active compromised hosts: {compromised}. Active isolated hosts: {isolated}."
            
        system_prompt = "You are AMCDS Security Copilot, a helpful AI Cyber Security Assistant. You output valid JSON."
        
        query_prompt = f"""
        Context:
        {context}
        
        Analyst Question:
        {prompt}
        
        Analyze the question and context. Provide a concise explanation, recommended actions, and confidence score.
        Return valid JSON in this format:
        {{
            "answer": "Concise natural language answer explaining threat context.",
            "recommended_actions": ["Action 1", "Action 2"],
            "confidence": 0.9
        }}
        """
        
        raw_response = self.llm.generate_completion(query_prompt, system_prompt, json_mode=True)
        
        try:
            parsed = json.loads(raw_response)
            # Ensure output schema matches expected Copilot contract
            if "answer" not in parsed:
                parsed = {
                    "answer": parsed.get("thought", "AMCDS Copilot analyzed threat posture: " + raw_response),
                    "recommended_actions": [parsed.get("action", "Audit active network sessions")],
                    "confidence": 0.8
                }
            return parsed
        except Exception as e:
            logger.error(f"Failed to parse Copilot JSON response: {e}. Raw: {raw_response}")
            return {
                "answer": f"Triage complete. Base threat context: {context}",
                "recommended_actions": ["Isolate compromised hosts", "Audit active network sessions"],
                "confidence": 0.5
            }
