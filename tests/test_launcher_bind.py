"""launcher._prompt_bind の公開範囲(bind 先)決定ロジックの回帰テスト。

ランチャー起動時の「この端末のみ / LAN 公開」選択と、LAN 公開時の認証トークン
要求、環境変数 WSCAN_HOST 明示時のプロンプト省略を固定する。
"""
import builtins

import pytest

import launcher
import main


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("WSCAN_HOST", raising=False)
    monkeypatch.delenv("WSCAN_AUTH_TOKEN", raising=False)


def _feed_inputs(monkeypatch, responses):
    it = iter(responses)
    monkeypatch.setattr(builtins, "input", lambda *a, **k: next(it))


def test_env_host_skips_prompt(monkeypatch):
    # WSCAN_HOST が明示されていれば対話せずそれを尊重する（input を呼ばない）。
    monkeypatch.setenv("WSCAN_HOST", "0.0.0.0")
    monkeypatch.setenv("WSCAN_AUTH_TOKEN", "tok")

    def _boom(*a, **k):
        raise AssertionError("プロンプトを出してはいけない")

    monkeypatch.setattr(builtins, "input", _boom)
    # env 明示時は insecure を立てない（serve の既定ガードを尊重）。
    assert launcher._prompt_bind() == ("0.0.0.0", "tok", False)


def test_localhost_choice(monkeypatch):
    # 選択肢1 = この端末のみ → loopback、トークンは要求しない、insecure 不要。
    _feed_inputs(monkeypatch, ["1"])
    assert launcher._prompt_bind() == ("127.0.0.1", "", False)


def test_lan_choice_with_token(monkeypatch):
    # 選択肢2 = LAN 公開 → 0.0.0.0、続けてトークンを入力。トークンありなら insecure 不要。
    _feed_inputs(monkeypatch, ["2", "secret"])
    assert launcher._prompt_bind() == ("0.0.0.0", "secret", False)


def test_lan_blank_token_verified_private_no_insecure(monkeypatch):
    # トークン空でも bind が private と確認できれば（社内網）ガードは発火しないので
    # insecure を立てずそのまま無認証公開する。
    monkeypatch.setattr(main, "_bind_is_intranet", lambda h: True)
    _feed_inputs(monkeypatch, ["2", ""])
    assert launcher._prompt_bind() == ("0.0.0.0", "", False)


def test_lan_blank_token_unverified_confirm_sets_insecure(monkeypatch):
    # private と確認できない（オフライン/公開IF）状況で、利用者がリスクを理解して
    # 明示確認した場合のみ insecure=True を返す。
    monkeypatch.setattr(main, "_bind_is_intranet", lambda h: False)
    _feed_inputs(monkeypatch, ["2", "", "2"])  # LAN / 空トークン / 確認=はい
    assert launcher._prompt_bind() == ("0.0.0.0", "", True)


def test_lan_blank_token_unverified_decline_requires_token(monkeypatch):
    # 確認を拒否したらトークンを要求し、insecure は立てない（公開ガードを尊重）。
    monkeypatch.setattr(main, "_bind_is_intranet", lambda h: False)
    _feed_inputs(monkeypatch, ["2", "", "1", "tok"])  # LAN / 空 / 確認=いいえ / トークン
    assert launcher._prompt_bind() == ("0.0.0.0", "tok", False)


def test_lan_choice_uses_env_token(monkeypatch):
    # WSCAN_HOST 未指定でも WSCAN_AUTH_TOKEN があれば LAN 公開時に再入力を求めない。
    monkeypatch.setenv("WSCAN_AUTH_TOKEN", "envtok")
    _feed_inputs(monkeypatch, ["2"])
    assert launcher._prompt_bind() == ("0.0.0.0", "envtok", False)
