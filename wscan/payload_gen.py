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
from contextvars import ContextVar
from typing import Callable, Optional

from rich.console import Console

from .llm_client import complete_text

console = Console()

_active_role: ContextVar[str | None] = ContextVar("pg_active_role", default=None)
# LLM-001: 標準掃射で「決定論 default を先頭寄り」に置く数。first-hit が強い決定論証拠で
# 止まりやすくしつつ、LLM を bulk default より前に残して cap での全滅を防ぐ（比例的）。
_DETERMINISTIC_LEAD = 6


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
        openai_base_url: str = "",
        llm_timeout_seconds: float = 30.0,
        llm_max_retries: int = 2,
    ):
        from . import llm_endpoint
        # このインスタンスが使うベース URL を **構築時にスナップショット** する。
        # グローバル env を呼び出し時に読み直すと、長時間 serve プロセスで別スキャン/
        # リクエストが env を書き換えた際に、進行中スキャンの後続 LLM 呼び出しが
        # 別エンドポイントへ化ける。以降の OpenAI 呼び出しは self.openai_base_url を
        # 明示的に渡し、env に依存しない（元プロバイダ名で公式/互換を判定）。
        self.openai_base_url = llm_endpoint.resolve_instance_base(provider, openai_base_url)
        # API キーも provider の意図でスナップショットする（公式 openai は
        # OPENAI_API_KEY のみ。互換キーを公式へ流用しない）。self.provider は正規化で
        # 公式/互換の区別が消えるため、正規化前の provider で解決しておく。
        self.openai_api_key = llm_endpoint.resolve_api_key(provider)
        # ``openai_compatible``（tsuzumi2 等の外部 OpenAI 互換）は内部的には
        # ``openai`` と同じ経路で処理する。
        self.provider = llm_endpoint.canonical_provider(provider)
        self._ollama_model = ollama_model
        self.ollama_url = ollama_url
        self._openai_model = openai_model
        self._gemini_model = gemini_model
        self._claude_model = claude_model
        self.llm_timeout_seconds = float(llm_timeout_seconds)
        self.llm_max_retries = max(0, int(llm_max_retries))
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

    @property
    def claude_model(self) -> str:
        role = _active_role.get()
        if role:
            model = self.role_models.get(role) or self.role_models.get("default")
            if model:
                return model
        return self._claude_model

    @property
    def openai_model(self) -> str:
        role = _active_role.get()
        if role:
            model = self.role_models.get(role) or self.role_models.get("default")
            if model:
                return model
        return self._openai_model

    @property
    def gemini_model(self) -> str:
        role = _active_role.get()
        if role:
            model = self.role_models.get(role) or self.role_models.get("default")
            if model:
                return model
        return self._gemini_model

    @property
    def ollama_model(self) -> str:
        role = _active_role.get()
        if role:
            model = self.role_models.get(role) or self.role_models.get("default")
            if model:
                return model
        return self._ollama_model

    def get_model(self, role: str = "payload") -> str:
        """Return the configured model for a role, falling back to the provider default."""
        role_model = self.role_models.get(role) or self.role_models.get("default")
        if role_model:
            return role_model
        if self.provider == "claude":
            return self._claude_model
        if self.provider == "openai":
            return self._openai_model
        if self.provider == "gemini":
            return self._gemini_model
        if self.provider == "ollama":
            return self._ollama_model
        return ""

    def role_model_summary(self) -> dict:
        roles = ["planner", "payload", "adaptive", "triage", "report"]
        return {role: self.get_model(role) for role in roles if self.get_model(role)}

    @contextmanager
    def use_role(self, role: str):
        """Expose a role-specific model in the current task context."""
        if self.provider == "none":
            yield
            return
        token = _active_role.set(role)
        try:
            yield
        finally:
            _active_role.reset(token)

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
            self._llm_available = bool(self.openai_api_key)
            if not self._llm_available:
                console.print(
                    "[yellow]LLM API key not set (WSCAN_LLM_API_KEY / OPENAI_API_KEY), "
                    "using default payloads[/yellow]"
                )
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
    # Helpers
    # ------------------------------------------------------------------

    def _extract_json_list(self, text: str) -> Optional[list[str]]:
        """Extract a JSON array of strings from LLM response text (D7 頑健版)。

        素朴な非貪欲 regex は配列内 `]`／前置き／コードフェンス／`<think>` で途中終了し、
        良質 payload を取りこぼしていた。フォールバック連鎖の純粋関数へ委譲する。
        壊れたら None＝呼び出し側は既定 payload へ安全側フォールバック。
        """
        from .llm_output_parser import extract_json_array_of_strings
        return extract_json_array_of_strings(text)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate(
        self,
        check_type: str,
        field_name: str,
        url: str,
        custom_payloads: Optional[list[str]] = None,
        attempt_history: Optional[list] = None,
        learning_summary_provider: "Optional[Callable[[], Optional[str]]]" = None,
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

                # G1: これまで同じフィールドへ投げた payload と結果（status/len/反射/timing/
                # error）をプロンプトへ戻す（evaluator-optimizer ループの復元）。壊れたら
                # 安全側＝履歴節を足さないだけで従来生成に戻す。
                if attempt_history:
                    try:
                        from .attempt_ledger import format_history_for_prompt
                        history_block = format_history_for_prompt(attempt_history)
                        if history_block:
                            prompt = prompt + "\n\n" + history_block
                    except Exception:
                        pass

                # G4: 学習済みで効いた payload の要約をプロンプトへ注入（既存学習データの
                # 再利用）。ここは LLM 生成パス（provider!=none・LLM 可用・template あり・
                # custom 未指定）に入った後なので、要約構築を遅延実行させることで、消費され
                # ないケース（custom/none/template 無し/LLM 不在）での学習履歴の無駄な走査を
                # 避ける。壊れたら安全側＝節を足さないだけ。
                if learning_summary_provider is not None:
                    try:
                        learning_summary = learning_summary_provider()
                        if learning_summary:
                            prompt = prompt + "\n\n" + learning_summary
                    except Exception:
                        pass

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
                    # LLM-001: 決定論 default を先頭寄りにして first-hit が弱い LLM 反射で
                    # 止まるのを防ぐ。LLM は LEAD 個の default の後・残り default の前に置き、
                    # cap で LLM が全滅しないようにする（LLM-only 脆弱性は adaptive も補完）。
                    lead = tail[:_DETERMINISTIC_LEAD]
                    rest = tail[_DETERMINISTIC_LEAD:]
                    return lead + expanded + rest

        # LLM なし/失敗 → デフォルトペイロードをエンコード展開して返す
        return expand_payloads(defaults, check_type, max_variants_per_payload=1, max_total=40)

    async def _call_llm(self, prompt: str) -> Optional[list[str]]:
        """LLM の生テキストからペイロード配列を抽出する。"""
        text = await complete_text(
            self,
            prompt,
            max_tokens=500,
            temperature=0.7,
        )
        if text is None:
            return None
        return self._extract_json_list(text)

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
            from . import llm_endpoint
            api_key = self.openai_api_key
            if not api_key:
                return None
            try:
                async with httpx.AsyncClient(timeout=30.0) as hc:
                    r = await hc.post(
                        llm_endpoint.chat_completions_url(self.openai_base_url),
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
