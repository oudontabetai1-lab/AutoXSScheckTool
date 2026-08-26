"""LLM-005: LLM 呼び出しの並列度上限 semaphore の回帰。

planner のページ単位 LLM call を asyncio.gather で一括するため、ローカルモデルでは同時多発で
timeout を繰り返す。provider 別既定（ollama/none=1, cloud=3）＋明示上書きで並列度を絞る。
"""
import asyncio
from types import SimpleNamespace

from wscan.engine import ScanEngine, _default_llm_concurrency


def test_default_concurrency_by_provider():
    assert _default_llm_concurrency("ollama") == 1
    assert _default_llm_concurrency("none") == 1
    assert _default_llm_concurrency("") == 1
    for cloud in ("claude", "openai", "gemini", "openai_compatible"):
        assert _default_llm_concurrency(cloud) == 3


def _engine(concurrency, provider):
    e = ScanEngine.__new__(ScanEngine)
    e.llm_concurrency = concurrency
    e._llm_semaphore = None
    e.payload_gen = SimpleNamespace(provider=provider)
    return e


def test_semaphore_uses_auto_and_explicit():
    assert _engine(0, "ollama")._get_llm_semaphore()._value == 1
    assert _engine(0, "claude")._get_llm_semaphore()._value == 3
    assert _engine(5, "ollama")._get_llm_semaphore()._value == 5


def test_semaphore_bounds_concurrent_calls():
    e = _engine(1, "ollama")
    active = [0]
    peak = [0]

    async def task():
        async with e._get_llm_semaphore():
            active[0] += 1
            peak[0] = max(peak[0], active[0])
            await asyncio.sleep(0.005)
            active[0] -= 1

    async def _run():
        await asyncio.gather(*[task() for _ in range(6)])

    asyncio.run(_run())
    assert peak[0] == 1
