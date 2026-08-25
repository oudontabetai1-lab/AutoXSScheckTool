"""batch 経路で SPA 自動有効化の opt-out が効くことを検証する（Codex #104 P2）。"""
from __future__ import annotations

import textwrap

from wscan.batch_runner import BatchRunner


def _write_yaml(tmp_path, body: str):
    p = tmp_path / "batch.yaml"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return str(p)


def test_batch_global_forwards_auto_spa_opt_out(tmp_path):
    # global.auto_spa_crawl: false を engine へ転送できないと batch 利用者が
    # 既定 ON の SPA 自動クリックを止められない。
    yaml_path = _write_yaml(
        tmp_path,
        """
        global:
          llm: none
          auto_spa_crawl: false
        targets:
          - url: https://app.example.com
        """,
    )
    runner = BatchRunner.load_from_yaml(yaml_path)
    assert runner.global_kwargs.get("auto_spa_crawl") is False


def test_batch_global_forwards_explicit_spa_crawl(tmp_path):
    yaml_path = _write_yaml(
        tmp_path,
        """
        global:
          llm: none
          spa_crawl: true
        targets:
          - url: https://app.example.com
        """,
    )
    runner = BatchRunner.load_from_yaml(yaml_path)
    assert runner.global_kwargs.get("spa_crawl") is True


def test_batch_omitting_spa_keys_leaves_engine_defaults(tmp_path):
    # 未指定なら global_kwargs に混ぜない（ScanEngine 既定＝auto_spa_crawl True）。
    yaml_path = _write_yaml(
        tmp_path,
        """
        global:
          llm: none
        targets:
          - url: https://app.example.com
        """,
    )
    runner = BatchRunner.load_from_yaml(yaml_path)
    assert "auto_spa_crawl" not in runner.global_kwargs
    assert "spa_crawl" not in runner.global_kwargs
