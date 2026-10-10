import os
import json
import logging
from typing import Dict, Any, Optional
from shared.config import llm_settings

logger = logging.getLogger(__name__)

class UnifiedLLMClient:
    def __init__(self):
        self.provider = llm_settings.model_provider
        self.model_name = llm_settings.model_name
        self.api_key = None
        self.client = None

        if self.provider == "openai":
            self.api_key = llm_settings.openai_api_key
            if self.api_key:
                from openai import OpenAI
                self.client = OpenAI(api_key=self.api_key)
                logger.info("OpenAI LLM Client configured.")
        elif self.provider == "anthropic":
            self.api_key = llm_settings.anthropic_api_key
            if self.api_key:
                from anthropic import Anthropic
                self.client = Anthropic(api_key=self.api_key)
                logger.info("Anthropic LLM Client configured.")
        elif self.provider == "local":
            from openai import OpenAI
            self.client = OpenAI(api_key="local-key", base_url=llm_settings.local_model_url)
            logger.info(f"Local compatible LLM Client configured at: {llm_settings.local_model_url}")

    def generate_completion(self, prompt: str, system_prompt: Optional[str] = None, json_mode: bool = False) -> str:
        """Invokes the active LLM provider and returns the raw string response."""
        if not self.client or (self.provider != "local" and not self.api_key):
            # Fallback/Mock planner response generator when API keys are absent
            logger.warning(f"No active LLM client or key configured. Generating mock response for prompt: {prompt[:80]}...")
            return self._generate_mock_response(prompt, json_mode)

        try:
            if self.provider == "openai" or self.provider == "local":
                response_format = {"type": "json_object"} if json_mode else None
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})

                chat_completion = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    response_format=response_format,
                    temperature=0.2
                )
                return chat_completion.choices[0].message.content.strip()

            elif self.provider == "anthropic":
                messages = [{"role": "user", "content": prompt}]
                system = system_prompt if system_prompt else ""
                
                message = self.client.messages.create(
                    model=self.model_name,
                    max_tokens=1000,
                    system=system,
                    messages=messages,
                    temperature=0.2
                )
                return message.content[0].text.strip()
                
        except Exception as e:
            logger.error(f"LLM generation failed: {e}", exc_info=True)
            return self._generate_mock_response(prompt, json_mode)

    def _generate_mock_response(self, prompt: str, json_mode: bool) -> str:
        """Returns dummy planned actions based on prompt contents to keep tests runnable."""
        prompt_lower = prompt.lower()
        if json_mode:
            # Map prompts to logical actions
            if "attacker" in prompt_lower or "compromise" in prompt_lower:
                return json.dumps({
                    "thought": "Mock thought: Scanning workstations to find vulnerable SMB ports.",
                    "action": "network_scan",
                    "target": "WS-01",
                    "explanation": "Target workstation 01 shows high GNN risk score."
                })
            elif "defender" in prompt_lower or "isolate" in prompt_lower:
                return json.dumps({
                    "thought": "Mock thought: Isolating suspicious node containing IDS alerts.",
                    "action": "isolate_host",
                    "target": "WS-01",
                    "explanation": "Isolating workstation 01 to prevent lateral spread."
                })
            elif "exploit" in prompt_lower or "cve" in prompt_lower or "service" in prompt_lower:
                return json.dumps({
                    "thought": "Mock thought: Exploiting SMB service.",
                    "service_name": "SMB",
                    "exploit_id": "CVE-2017-0144"
                })
            else:
                return json.dumps({
                    "thought": "Mock thought: General task analysis.",
                    "action": "noop"
                })
        
        return "Thought: I should scan workstation 01. Action: network_scan on WS-01."
