"""F01/F02: batch の LLM 設定変換と全失敗時の終了コードの回帰テスト。

- F01: `global.llm` を `llm_provider` へ写像せずそのまま渡すと ScanEngine が
  未知 kwarg で TypeError となり全対象が開始前に失敗する。
- F02: 全対象失敗でも CLI 終了 0・「合計0件」で自動運用が成功と誤認する。
"""
import textwrap

from wscan.batch_runner import BatchRunner, BatchResult, BatchTarget

import main


def test_global_llm_is_mapped_to_llm_provider(tmp_path):
    yaml_path = tmp_path / "batch.yaml"
    yaml_path.write_text(textwrap.dedent("""
        global:
          llm: none
          checks: [sqli]
        targets:
          - url: http://target.test/
    """), encoding="utf-8")

    runner = BatchRunner.load_from_yaml(str(yaml_path))

    # そのまま llm= で渡すと ScanEngine が TypeError → 全対象失敗（F01）。
    assert "llm" not in runner.global_kwargs
    assert runner.global_kwargs.get("llm_provider") == "none"


def test_batch_exit_code_all_and_partial_failures():
    ok = BatchResult(target=BatchTarget(url="http://a/"))
    bad = BatchResult(target=BatchTarget(url="http://b/"), error="boom")

    assert main._batch_exit_code([]) == 0          # 空は 0
    assert main._batch_exit_code([ok, ok]) == 0    # 全成功は 0
    assert main._batch_exit_code([ok, bad]) == 1   # 一部失敗は非0
    assert main._batch_exit_code([bad, bad]) == 1  # 全失敗は非0


def test_summary_text_marks_failures():
    runner = BatchRunner(targets=[], global_kwargs={})
    runner.results = [
        BatchResult(target=BatchTarget(url="http://a/", label="A")),
        BatchResult(target=BatchTarget(url="http://b/", label="B"), error="boom"),
    ]
    text = runner.summary_text()
    assert "失敗" in text and "B" in text
