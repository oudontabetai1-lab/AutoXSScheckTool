import asyncio

import pytest

from wscan.payload_gen import PayloadGenerator


def test_use_role_keeps_concurrent_models_task_local():
    generator = PayloadGenerator(
        provider="ollama",
        ollama_model="DEFAULT",
        role_models={"planner": "P", "adaptive": "A", "payload": "D"},
    )

    async def read_role_model(role, expected):
        with generator.use_role(role):
            assert generator.ollama_model == expected
            await asyncio.sleep(0)
            assert generator.ollama_model == expected

    async def run_concurrently():
        await asyncio.gather(
            read_role_model("planner", "P"),
            read_role_model("adaptive", "A"),
        )

    asyncio.run(run_concurrently())
    assert generator.ollama_model == "DEFAULT"


@pytest.mark.parametrize(
    ("provider", "model_kwarg", "model_attribute"),
    [
        ("claude", "claude_model", "claude_model"),
        ("openai", "openai_model", "openai_model"),
        ("gemini", "gemini_model", "gemini_model"),
        ("ollama", "ollama_model", "ollama_model"),
    ],
)
def test_use_role_preserves_single_execution_model_resolution(
    provider, model_kwarg, model_attribute
):
    generator = PayloadGenerator(
        provider=provider,
        role_models={"planner": "PLANNER"},
        **{model_kwarg: "DEFAULT"},
    )

    assert getattr(generator, model_attribute) == "DEFAULT"
    with generator.use_role("planner"):
        assert getattr(generator, model_attribute) == "PLANNER"
    with generator.use_role("unconfigured"):
        assert getattr(generator, model_attribute) == "DEFAULT"
    assert getattr(generator, model_attribute) == "DEFAULT"


def test_use_role_is_noop_for_none_provider():
    generator = PayloadGenerator(provider="none")

    with generator.use_role("planner"):
        assert generator.get_model("planner") == ""
