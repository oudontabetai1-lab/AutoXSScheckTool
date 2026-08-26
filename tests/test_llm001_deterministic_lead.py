"""LLM-001: 標準掃射で決定論 default を LLM より前に寄せる（ratio:1 交互配置）回帰。

弱い LLM 反射が first-hit で強い決定論確認を先取りしないよう default を先頭寄せしつつ、
小 cap（--max-payloads<=数個）でも LLM が全滅しないよう交互配置する。
"""
import asyncio
from unittest.mock import AsyncMock

from wscan.payload_gen import PayloadGenerator, _order_deterministic_first


def test_interleave_defaults_lead_llm_present_small_cap():
    d = [f"D{i}" for i in range(20)]
    l = ["L0", "L1", "L2"]
    out = _order_deterministic_first(d, l)
    # 先頭は default（強い決定論証拠が first-hit を取りやすい）
    assert out[0].startswith("D")
    # 小 cap(3) でも LLM payload が生き残る
    assert any(x.startswith("L") for x in out[:3])
    # 全 payload 保持（欠落しない）
    assert set(x for x in out if x.startswith("D")) == set(d)
    assert set(x for x in out if x.startswith("L")) == set(l)


def test_generate_orders_deterministic_first():
    pg = PayloadGenerator(provider="claude", claude_model="m")
    pg.default_payloads = {"sqli": [f"D{i}" for i in range(20)]}
    pg.prompt_templates = {"sqli": "inject {field_name} {url}"}
    pg._check_llm_available = AsyncMock(return_value=True)
    pg._call_llm = AsyncMock(return_value=["LLMPAY0", "LLMPAY1"])
    out = asyncio.run(pg.generate("sqli", "q", "http://t/"))
    assert out[0].startswith("D")
    # LLM が典型 cap(40) 内かつ小 cap でも早期に現れる
    first_llm = next(i for i, p in enumerate(out) if p.startswith("LLMPAY"))
    assert first_llm <= 4, (first_llm, out[:6])


def test_empty_llm_returns_defaults_only():
    assert _order_deterministic_first(["D0", "D1"], []) == ["D0", "D1"]
    assert _order_deterministic_first([], ["L0"]) == ["L0"]
