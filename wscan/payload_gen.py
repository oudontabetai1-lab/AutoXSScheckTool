"""
WScan Payload Generator
Generates context-aware payloads using local LLM (Ollama) or Claude API.
Falls back to default payloads when LLM is unavailable.
"""
import json
import re
import httpx
from typing import Optional

from rich.console import Console

console = Console()


class PayloadGenerator:
    """Generates test payloads using LLM or falls back to defaults."""

    def __init__(
        self,
        provider: str = "ollama",
        ollama_model: str = "llama3",
        ollama_url: str = "http://localhost:11434",
        default_payloads: Optional[dict] = None,
        prompt_templates: Optional[dict] = None,
    ):
        self.provider = provider
        self.ollama_model = ollama_model
        self.ollama_url = ollama_url
        self.default_payloads = default_payloads or {}
        self.prompt_templates = prompt_templates or {}
        self._anthropic_client = None
        self._llm_available: Optional[bool] = None

    def _get_anthropic_client(self):
        if self._anthropic_client is None:
            import os
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if api_key:
                try:
                    import anthropic
                    self._anthropic_client = anthropic.Anthropic(api_key=api_key)
                except ImportError:
                    pass
        return self._anthropic_client

    async def _check_llm_available(self) -> bool:
        if self._llm_available is not None:
            return self._llm_available
        if self.provider == "none":
            self._llm_available = False
            return False
        if self.provider == "claude":
            self._llm_available = self._get_anthropic_client() is not None
            return self._llm_available
        # Check Ollama
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(f"{self.ollama_url}/api/tags")
                self._llm_available = resp.status_code == 200
        except Exception:
            self._llm_available = False
        if not self._llm_available:
            console.print("[yellow]LLM not available, using default payloads[/yellow]")
        return self._llm_available

    async def _generate_with_ollama(self, prompt: str) -> Optional[list[str]]:
        """Generate payloads using Ollama."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{self.ollama_url}/api/generate",
                    json={
                        "model": self.ollama_model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {"temperature": 0.7, "num_predict": 500},
                    },
                )
                if resp.status_code == 200:
                    text = resp.json().get("response", "")
                    return self._extract_json_list(text)
        except Exception as e:
            console.print(f"[yellow]Ollama error: {e}[/yellow]")
        return None

    async def _generate_with_claude(self, prompt: str) -> Optional[list[str]]:
        """Generate payloads using Anthropic Claude API."""
        client = self._get_anthropic_client()
        if not client:
            return None
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: client.messages.create(
                    model="claude-haiku-4-5-20251001",
                    max_tokens=500,
                    messages=[{"role": "user", "content": prompt}],
                ),
            )
            text = response.content[0].text
            return self._extract_json_list(text)
        except Exception as e:
            console.print(f"[yellow]Claude API error: {e}[/yellow]")
        return None

    def _extract_json_list(self, text: str) -> Optional[list[str]]:
        """Extract a JSON array from LLM response text."""
        # Find JSON array in the response
        match = re.search(r'\[.*?\]', text, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
                if isinstance(data, list) and all(isinstance(x, str) for x in data):
                    return data
            except json.JSONDecodeError:
                pass
        return None

    async def generate(
        self,
        check_type: str,
        field_name: str,
        url: str,
        custom_payloads: Optional[list[str]] = None,
    ) -> list[str]:
        """
        Generate payloads for a specific check type and field.

        Priority:
        1. Custom payloads (if provided)
        2. LLM-generated payloads
        3. Default payloads from YAML
        """
        # Custom payloads take priority
        if custom_payloads:
            return custom_payloads

        defaults = self.default_payloads.get(check_type, [])

        # Try LLM generation if available
        if self.provider != "none" and await self._check_llm_available():
            template = self.prompt_templates.get(check_type, "")
            if template:
                prompt = template.format(field_name=field_name, url=url)
                if self.provider == "claude":
                    llm_payloads = await self._generate_with_claude(prompt)
                else:
                    llm_payloads = await self._generate_with_ollama(prompt)

                if llm_payloads:
                    console.print(
                        f"[dim]LLM generated {len(llm_payloads)} payloads for {field_name}[/dim]"
                    )
                    # Combine LLM payloads with defaults (LLM first)
                    combined = llm_payloads + [p for p in defaults if p not in llm_payloads]
                    return combined

        return defaults
