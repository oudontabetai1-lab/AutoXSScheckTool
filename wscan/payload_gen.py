"""
WScan Payload Generator
Generates context-aware payloads using local LLM (Ollama) or cloud APIs
(Claude, OpenAI, Gemini). Falls back to default payloads when LLM is unavailable.
"""
import json
import os
import re
import httpx
from contextlib import contextmanager
from typing import Optional

from rich.console import Console

console = Console()


def _format_prompt_template(template: str, *, field_name: str, url: str) -> str:
    """Fill only WScan placeholders, leaving payload syntax such as ${IFS} intact."""
    return (
        template
        .replace("{field_name}", field_name)
        .replace("{url}", url)
    )


class PayloadGenerator:
    """Generates test payloads using LLM or falls back to defaults."""

    def __init__(
        self,
        provider: str = "ollama",
        ollama_model: str = "llama3",
        ollama_url: str = "http://localhost:11434",
        openai_model: str = "gpt-4o-mini",
        gemini_model: str = "gemini-2.0-flash",
        claude_model: str = "claude-haiku-4-5-20251001",
        default_payloads: Optional[dict] = None,
        prompt_templates: Optional[dict] = None,
        role_models: Optional[dict] = None,
        enable_web_browsing: bool = False,
    ):
        self.provider = provider
        self.ollama_model = ollama_model
        self.ollama_url = ollama_url
        self.openai_model = openai_model
        self.gemini_model = gemini_model
        self.claude_model = claude_model
        self.default_payloads = default_payloads or {}
        self.prompt_templates = prompt_templates or {}
        self.role_models = {
            str(k): str(v).strip()
            for k, v in (role_models or {}).items()
            if str(v).strip()
        }
        self.enable_web_browsing = enable_web_browsing
        self._anthropic_client = None
        self._llm_available: Optional[bool] = None

    def get_model(self, role: str = "payload") -> str:
        """Return the configured model for a role, falling back to the provider default."""
        role_model = self.role_models.get(role) or self.role_models.get("default")
        if role_model:
            return role_model
        if self.provider == "claude":
            return self.claude_model
        if self.provider == "openai":
            return self.openai_model
        if self.provider == "gemini":
            return self.gemini_model
        if self.provider == "ollama":
            return self.ollama_model
        return ""

    def role_model_summary(self) -> dict:
        roles = ["planner", "payload", "adaptive", "triage", "report"]
        return {role: self.get_model(role) for role in roles if self.get_model(role)}

    @contextmanager
    def use_role(self, role: str):
        """Temporarily expose a role-specific model through legacy attributes."""
        if self.provider == "none":
            yield
            return
        attr = {
            "claude": "claude_model",
            "openai": "openai_model",
            "gemini": "gemini_model",
            "ollama": "ollama_model",
        }.get(self.provider)
        if not attr:
            yield
            return
        original = getattr(self, attr)
        model = self.get_model(role)
        if model:
            setattr(self, attr, model)
        try:
            yield
        finally:
            setattr(self, attr, original)

    # ------------------------------------------------------------------
    # Client / availability helpers
    # ------------------------------------------------------------------

    def _get_anthropic_client(self):
        if self._anthropic_client is None:
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
        if self.provider == "openai":
            self._llm_available = bool(os.environ.get("OPENAI_API_KEY"))
            if not self._llm_available:
                console.print("[yellow]OPENAI_API_KEY not set, using default payloads[/yellow]")
            return self._llm_available
        if self.provider == "gemini":
            self._llm_available = bool(os.environ.get("GEMINI_API_KEY"))
            if not self._llm_available:
                console.print("[yellow]GEMINI_API_KEY not set, using default payloads[/yellow]")
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

    # ------------------------------------------------------------------
    # Generation backends
    # ------------------------------------------------------------------

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
                    model=self.claude_model,
                    max_tokens=500,
                    messages=[{"role": "user", "content": prompt}],
                ),
            )
            text = response.content[0].text
            return self._extract_json_list(text)
        except Exception as e:
            console.print(f"[yellow]Claude API error: {e}[/yellow]")
        return None

    async def _generate_with_openai(self, prompt: str) -> Optional[list[str]]:
        """Generate payloads using OpenAI API."""
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return None
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}"},
                    json={
                        "model": self.openai_model,
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": 500,
                        "temperature": 0.7,
                    },
                )
                if resp.status_code == 200:
                    text = resp.json()["choices"][0]["message"]["content"]
                    return self._extract_json_list(text)
                console.print(f"[yellow]OpenAI API error {resp.status_code}: {resp.text[:200]}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]OpenAI error: {e}[/yellow]")
        return None

    async def _generate_with_gemini(self, prompt: str) -> Optional[list[str]]:
        """Generate payloads using Google Gemini API."""
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            return None
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                url = (
                    f"https://generativelanguage.googleapis.com/v1beta/models/"
                    f"{self.gemini_model}:generateContent?key={api_key}"
                )
                resp = await client.post(
                    url,
                    json={"contents": [{"parts": [{"text": prompt}]}]},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    text = data["candidates"][0]["content"]["parts"][0]["text"]
                    return self._extract_json_list(text)
                console.print(f"[yellow]Gemini API error {resp.status_code}: {resp.text[:200]}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Gemini error: {e}[/yellow]")
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_json_list(self, text: str) -> Optional[list[str]]:
        """Extract a JSON array from LLM response text."""
        match = re.search(r'\[.*?\]', text, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
                if isinstance(data, list) and all(isinstance(x, str) for x in data):
                    return data
            except json.JSONDecodeError:
                pass
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

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
        2. LLM-generated payloads + auto encoded variants
        3. Default payloads + auto encoded variants
        """
        from wscan.payload_encoder import expand_payloads, ENCODING_EXAMPLES

        if custom_payloads:
            return custom_payloads

        defaults = self.default_payloads.get(check_type, [])

        if self.provider != "none" and await self._check_llm_available():
            template = self.prompt_templates.get(check_type, "")
            if template:
                # エンコード例を LLM プロンプトに注入して Ollama の出力を豊かにする
                encoding_hint = ENCODING_EXAMPLES.get(check_type, "")
                prompt = _format_prompt_template(
                    template, field_name=field_name, url=url
                )
                if encoding_hint:
                    prompt = encoding_hint + "\n" + prompt

                # ── Web intelligence enrichment ──────────────────────────
                if self.enable_web_browsing:
                    from .llm_web_tools import research_vulnerability
                    try:
                        web_ctx = await research_vulnerability(check_type, url)
                        prompt = (
                            f"{web_ctx}\n\n"
                            f"Use the above web intelligence to generate more targeted payloads.\n\n"
                            f"{prompt}"
                        )
                        console.print(
                            f"[dim cyan][Web] Research injected into payload prompt ({check_type})[/dim cyan]"
                        )
                    except Exception:
                        pass

                with self.use_role("payload"):
                    llm_payloads = await self._call_llm(prompt)
                if llm_payloads:
                    console.print(
                        f"[dim]LLM generated {len(llm_payloads)} payloads for {field_name}[/dim]"
                    )
                    # LLM ペイロードをエンコードバリアントで展開
                    expanded = expand_payloads(llm_payloads, check_type, max_variants_per_payload=2)
                    # デフォルトのうち未収録のものを末尾に追加
                    seen = set(expanded)
                    tail = [p for p in defaults if p not in seen]
                    return expanded + tail

        # LLM なし/失敗 → デフォルトペイロードをエンコード展開して返す
        return expand_payloads(defaults, check_type, max_variants_per_payload=1, max_total=40)

    async def _call_llm(self, prompt: str) -> Optional[list[str]]:
        """Route to the appropriate LLM backend."""
        if self.provider == "claude":
            return await self._generate_with_claude(prompt)
        if self.provider == "openai":
            return await self._generate_with_openai(prompt)
        if self.provider == "gemini":
            return await self._generate_with_gemini(prompt)
        return await self._generate_with_ollama(prompt)

    # ------------------------------------------------------------------
    # Screenshot vision analysis
    # ------------------------------------------------------------------

    async def analyze_screenshot_for_vuln(
        self, screenshot_b64: str, page_url: str
    ) -> Optional[str]:
        """
        スクリーンショット画像を LLM ビジョン API で解析し、
        画面上に見えるセキュリティ上の問題を検出する。

        対応プロバイダー: claude, openai
        それ以外 (ollama / gemini / none) の場合は None を返す。

        Parameters
        ----------
        screenshot_b64 : base64 エンコードされた PNG 画像文字列
        page_url       : 画像の元になったページ URL (プロンプトに含める)

        Returns
        -------
        str  : LLM の分析テキスト (100 語以内)
        None : ビジョン未対応 / API キー未設定 / エラー時
        """
        vision_prompt = (
            f"This is a screenshot of the web page at {page_url}.\n"
            "As a web security tester, identify any VISIBLE security issues:\n"
            "- Error messages leaking stack traces, file paths, or DB info\n"
            "- Unescaped HTML or <script> tags rendered in the page\n"
            "- Sensitive data exposure (tokens, keys, PII)\n"
            "- Unusual warning dialogs or unexpected redirects\n"
            "Reply in under 100 words. If no issues visible, reply 'No visible issues'."
        )

        if self.provider == "claude":
            client = self._get_anthropic_client()
            if not client:
                return None
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                msg = await loop.run_in_executor(
                    None,
                    lambda: client.messages.create(
                        model=self.claude_model,
                        max_tokens=300,
                        messages=[{
                            "role": "user",
                            "content": [
                                {
                                    "type": "image",
                                    "source": {
                                        "type": "base64",
                                        "media_type": "image/png",
                                        "data": screenshot_b64,
                                    },
                                },
                                {"type": "text", "text": vision_prompt},
                            ],
                        }],
                    ),
                )
                return msg.content[0].text if msg.content else None
            except Exception as exc:
                console.print(f"[dim yellow]Screenshot analysis error (claude): {exc}[/dim yellow]")
                return None

        elif self.provider == "openai":
            api_key = os.environ.get("OPENAI_API_KEY")
            if not api_key:
                return None
            try:
                async with httpx.AsyncClient(timeout=30.0) as hc:
                    r = await hc.post(
                        "https://api.openai.com/v1/chat/completions",
                        headers={"Authorization": f"Bearer {api_key}"},
                        json={
                            "model": self.openai_model,
                            "max_tokens": 300,
                            "messages": [{
                                "role": "user",
                                "content": [
                                    {
                                        "type": "image_url",
                                        "image_url": {
                                            "url": f"data:image/png;base64,{screenshot_b64}"
                                        },
                                    },
                                    {"type": "text", "text": vision_prompt},
                                ],
                            }],
                        },
                    )
                    r.raise_for_status()
                    return r.json()["choices"][0]["message"]["content"]
            except Exception as exc:
                console.print(f"[dim yellow]Screenshot analysis error (openai): {exc}[/dim yellow]")
                return None

        # ollama / gemini / none: ビジョン未対応
        return None
