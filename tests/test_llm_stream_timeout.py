"""0065: LLM streaming timeout（planner/adaptive）を config/CLI から設定可能にした回帰。"""
import asyncio
import math
import tempfile
from pathlib import Path
from unittest.mock import patch

from wscan.payload_gen import PayloadGenerator
from wscan.attack_planner import AttackPlanner


def test_stream_timeout_default_is_90():
    pg = PayloadGenerator(provider="none")
    assert pg.llm_stream_timeout_seconds == 90.0


def test_stream_timeout_custom_value():
    pg = PayloadGenerator(provider="none", llm_stream_timeout_seconds=45)
    assert pg.llm_stream_timeout_seconds == 45.0


def test_stream_timeout_invalid_falls_back_to_90():
    for bad in (0, -5, float("nan"), float("inf"), "x", None):
        pg = PayloadGenerator(provider="none", llm_stream_timeout_seconds=bad)
        assert pg.llm_stream_timeout_seconds == 90.0, bad


def test_config_reads_stream_timeout_seconds():
    from main import _load_config
    # 既定 config には stream_timeout_seconds: 90 がある。
    assert _load_config()["llm_stream_timeout_seconds"] == 90.0
    # 欠落した最小 config でも既定 90（後方互換）。
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "c.yaml"
        p.write_text("llm:\n  timeout_seconds: 12\n", encoding="utf-8")
        assert _load_config(p)["llm_stream_timeout_seconds"] == 90.0


def test_planner_ollama_uses_stream_timeout():
    # planner の httpx 呼び出しが pg.llm_stream_timeout_seconds を timeout に使う（配線の end-to-end）。
    pg = PayloadGenerator(provider="ollama", llm_stream_timeout_seconds=45)
    planner = AttackPlanner(pg, ["xss"])
    captured = {}

    class _FakeClient:
        def __init__(self, *a, **k):
            captured["timeout"] = k.get("timeout")

        async def __aenter__(self):
            raise RuntimeError("stop after capturing timeout")

        async def __aexit__(self, *a):
            return False

    with patch("httpx.AsyncClient", _FakeClient):
        asyncio.run(planner._call_ollama("prompt"))
    assert captured["timeout"] == 45.0
