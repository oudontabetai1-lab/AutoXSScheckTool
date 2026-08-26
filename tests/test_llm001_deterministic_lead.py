"""LLM-001: 標準掃射で決定論 default を先頭寄りに置く回帰。

弱い LLM 反射が first-hit で強い決定論確認を先取りしないよう、generate() は
lead 個の default → LLM → 残り default の順に返す（LLM は cap で全滅しないよう bulk 前）。
"""
import asyncio
from unittest.mock import AsyncMock

from wscan.payload_gen import PayloadGenerator, _DETERMINISTIC_LEAD


def _mk_pg(defaults):
    pg = PayloadGenerator(provider="claude", claude_model="m")
    pg.default_payloads = {"sqli": defaults}
    pg.prompt_templates = {"sqli": "inject {field_name} at {url}"}  # LLM 生成パスの条件
    pg._check_llm_available = AsyncMock(return_value=True)
    return pg


def test_deterministic_defaults_lead_then_llm():
    defaults = [f"D{i}" for i in range(20)]
    pg = _mk_pg(defaults)
    # LLM は既定と重複しない payload を返す
    pg._call_llm = AsyncMock(return_value=["L0", "L1", "L2"])

    out = asyncio.run(pg.generate("sqli", "q", "http://t/"))

    # 先頭 LEAD 個は決定論 default（D...）で、その直後に LLM（L...）が来る
    lead = out[:_DETERMINISTIC_LEAD]
    assert all(p.startswith("D") for p in lead), lead
    # LLM payload が lead の直後（bulk default より前）に現れる
    first_llm = next(i for i, p in enumerate(out) if p.startswith("L"))
    assert first_llm == _DETERMINISTIC_LEAD, (first_llm, out[:10])
    # 残りの default も含まれる（欠落しない）
    assert set(p for p in out if p.startswith("D")) == set(defaults)
    assert set(p for p in out if p.startswith("L")) >= {"L0", "L1", "L2"}


def test_llm_before_bulk_defaults_survives_typical_cap():
    # 典型 cap(40) 内で LLM payload が生き残る（lead + llm が cap 前）。
    defaults = [f"D{i}" for i in range(50)]
    pg = _mk_pg(defaults)
    pg._call_llm = AsyncMock(return_value=["L0", "L1"])
    out = asyncio.run(pg.generate("sqli", "q", "http://t/"))
    assert any(p.startswith("L") for p in out[:40])
