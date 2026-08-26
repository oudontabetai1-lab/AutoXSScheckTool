"""LLM-008: FAST MODE が LLM/planner/AI を無効化したことを明示する1行の回帰。

--fast は既定と組み合わさると LLM=none・planner off・AI 分析 off にするため、実行前に
何が off になったかを表示して「LLM 無効化が隠れる」のを防ぐ。
"""
import main


def test_fast_note_lists_disabled_features():
    # 実際の --fast 状態（LLM=none・他は強制 off）を明示する。
    n = main._fast_mode_deterministic_note(
        llm="none", no_planner=True, no_ai_analysis=True,
        no_waf_detection=True, no_sitemap_crawl=True,
    )
    assert "LLM=none" in n
    assert "planner=off" in n
    assert "AI分析=off" in n
    # 正確な上書き案内: LLM のみ維持可、他は fast で off。誤った「各個別上書き可」は書かない。
    assert "--llm で維持可" in n
    assert "個別上書き可" not in n


def test_fast_note_llm_override_reachable_state():
    # --fast --llm claude の到達可能状態: LLM=claude だが planner 等は off のまま。
    n = main._fast_mode_deterministic_note(
        llm="claude", no_planner=True, no_ai_analysis=True,
        no_waf_detection=True, no_sitemap_crawl=True,
    )
    assert "LLM=claude" in n
    assert "planner=off" in n


def test_fast_mode_llm_respects_explicit_selection():
    # 明示 --llm は（ollama 含め）維持、既定 provider のみ none 化（LLM-008: 案内を actionable に）。
    assert main._fast_mode_llm("ollama", explicit=True) == "ollama"
    assert main._fast_mode_llm("ollama", explicit=False) == "none"
    assert main._fast_mode_llm("claude", explicit=False) == "claude"
    assert main._fast_mode_llm("claude", explicit=True) == "claude"
    # 既定 provider が config で claude 等でも同様（default 引数で判定）
    assert main._fast_mode_llm("claude", explicit=False, default="claude") == "none"
