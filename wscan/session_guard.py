"""
セッション失効検知（純粋関数）
==============================
長時間スキャン中にログインセッションが切れると、以降のリクエストが全て
ログイン画面/401 に化けて「検出力が静かにゼロになる」。これを検知して
自動再ログインへ繋ぐための判定ロジック。

判定は :mod:`wscan.auth_detect` の純粋関数（``on_login_page`` /
``has_login_form`` / ``has_failure_text``）を再利用し、誤って再ログインを
連発しないよう **強いシグナルが揃ったときだけ** 失効とみなす。

実際の再ログイン副作用（ブラウザ操作・再クロール）は ``engine`` 側が担い、
本モジュールは「失効しているか」の真偽だけを返す（IO 非依存・テスト可能）。
"""
from __future__ import annotations

from typing import Optional

from . import auth_detect

# 認証切れを示す HTTP ステータス。403 は正規の認可拒否（権限不足）でも返るため
# 単独では失効とみなさない（誤再ログイン抑止）。401 のみ強シグナルとして扱う。
_UNAUTHORIZED_STATUSES = {401}


def looks_logged_out(
    *,
    status: Optional[int],
    final_url: str,
    body: str,
    login_url: str = "",
    logged_in_marker: str = "",
) -> bool:
    """応答がログアウト（セッション失効）状態を示すか。

    True を返す条件（いずれか）:
      1. HTTP 401。
      2. ログインページに着地していて、かつログインフォームが残存している
         （＝保護ページから login へリダイレクトされた典型パターン）。
      3. ``logged_in_marker`` 指定時、その印が本文から消え、かつログイン
         フォームが出現している（認証済みページの目印が消えた）。

    誤検知（不要な再ログイン）を避けるため、URL がログインに見えるだけ／
    フォームが在るだけ／403 だけでは失効とみなさない。
    """
    if status in _UNAUTHORIZED_STATUSES:
        return True

    has_form = auth_detect.has_login_form(body or "")

    if has_form and auth_detect.on_login_page(final_url or "", login_url):
        return True

    if logged_in_marker:
        marker_gone = logged_in_marker not in (body or "")
        if marker_gone and has_form:
            return True

    return False
