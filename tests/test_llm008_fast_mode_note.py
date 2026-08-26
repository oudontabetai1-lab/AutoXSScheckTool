"""LLM-008: FAST MODE が LLM/planner/AI を無効化したことを明示する1行の回帰。

--fast は既定と組み合わさると LLM=none・planner off・AI 分析 off にするため、実行前に
何が off になったかを表示して「LLM 無効化が隠れる」のを防ぐ。
"""
import main


def test_fast_note_lists_disabled_features():
    n = main._fast_mode_deterministic_note(
        llm="none", no_planner=True, no_ai_analysis=True,
        no_waf_detection=True, no_sitemap_crawl=True,
    )
    assert "LLM=none" in n
    assert "planner=off" in n
    assert "AI分析=off" in n
    assert "個別上書き" in n  # 上書き可能であることを案内


def test_fast_note_reflects_overrides_on():
    # 個別フラグで再有効化した場合は on と表示（隠さない）。
    n = main._fast_mode_deterministic_note(
        llm="claude", no_planner=False, no_ai_analysis=False,
        no_waf_detection=False, no_sitemap_crawl=False,
    )
    assert "LLM=claude" in n
    assert "planner=on" in n
    assert "AI分析=on" in n
