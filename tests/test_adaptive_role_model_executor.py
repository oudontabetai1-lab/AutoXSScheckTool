"""_stream_claude が use_role("adaptive") の role model を executor 越しに使う回帰。

ContextVar は run_in_executor のワーカースレッドへ伝播しないため、モデルを async 文脈で
確定してから executor へ渡す必要がある（LLM-004 の ContextVar 化で生じた thread 境界の穴）。
本テストは修正前なら default モデルを送ってしまい fail する。
"""
import asyncio

from wscan.adaptive_payload import AdaptivePayloadEngine
from wscan.payload_gen import PayloadGenerator


class _FakeStream:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    @property
    def text_stream(self):
        return iter(())


class _FakeMessages:
    def __init__(self, sink):
        self._sink = sink

    def stream(self, *, model, **kw):
        self._sink.append(model)
        return _FakeStream()


class _FakeClient:
    def __init__(self, sink):
        self.messages = _FakeMessages(sink)


def test_stream_claude_uses_adaptive_role_model_across_executor():
    used_models = []
    pg = PayloadGenerator(
        provider="claude",
        claude_model="DEFAULT-MODEL",
        role_models={"adaptive": "ADAPTIVE-MODEL"},
    )
    pg._get_anthropic_client = lambda: _FakeClient(used_models)
    engine = AdaptivePayloadEngine(pg)

    async def run():
        with pg.use_role("adaptive"):
            await engine._stream_claude("hi")

    asyncio.run(run())
    assert used_models == ["ADAPTIVE-MODEL"], used_models
