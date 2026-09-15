"""F08: triage の LLM 分析（散文）を payload 配列パーサへ通さず保持する。

以前は `pg._call_llm`（→`_extract_json_list`）に散文を通して失い、結果欄に文字列 "None" を
出していた。text 完了で生の分析文を保持し、空応答/失敗は空欄で区別することを検証する。
"""
import asyncio
import contextlib
from unittest.mock import AsyncMock, patch

from wscan.triage import TriageEngine, TriageReport


class _FakePG:
    def __init__(self, **kwargs):
        pass

    async def _check_llm_available(self):
        return True

    @contextlib.contextmanager
    def use_role(self, role):
        yield


def _make_engine():
    eng = TriageEngine.__new__(TriageEngine)
    eng.llm_provider = "claude"
    eng.ollama_model = ""
    eng.openai_model = ""
    eng.gemini_model = ""
    eng.claude_model = ""
    eng.openai_base_url = ""
    eng.role_models = {}
    eng.report = TriageReport(target_url="http://t.test/")
    return eng


def _run(complete_text_return):
    eng = _make_engine()
    with patch("wscan.payload_gen.PayloadGenerator", _FakePG), patch(
        "wscan.llm_client.complete_text",
        AsyncMock(return_value=complete_text_return),
    ):
        return asyncio.run(eng._llm_analyse())


def test_prose_is_preserved():
    out = _run("1. Target the login form (SQLi)\n2. Check IDOR on /admin")
    assert "Target the login form" in out
    assert out != "None"


def test_empty_response_is_blank_not_none():
    assert _run("") == ""


def test_failure_none_is_blank_not_none():
    assert _run(None) == ""  # 失敗/空応答は "None" でなく空欄
