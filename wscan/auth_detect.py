"""
ログイン成否判定（純粋関数）。

``browser.auto_login`` の成功判定は元々「URL が変わった or ログインページの
パスから外れた」だけで成功としていたため、``/login?error=1`` のような
「ログインページに留まったままの失敗」を成功と誤判定し得た。

本モジュールは判定ロジックを I/O から切り離した純粋関数として提供する:
- ``on_login_page``     … 現在 URL がログインページか（パス一致 + 既知パスの推定）。
- ``has_failure_text``  … 失敗メッセージが本文にあるか（大小文字無視・広めの語彙）。
- ``has_login_form``    … ログインフォーム（パスワード欄＋ユーザ欄/送信/フォーム）が残るか。
- ``login_succeeded``   … 上記を統合した最終判定。

判定方針: 「ログインページから抜け、ログインフォームが残っておらず、失敗文言も
MFA も無い」場合に成功とみなす。URL が変わっただけでは成功と認めない（厳格化）。
"""
from __future__ import annotations

import re
from urllib.parse import urlparse


# 失敗メッセージ（大小文字無視で部分一致）。元実装より語彙を増やした。
_FAILURE_MARKERS = (
    "invalid login",
    "login failed",
    "incorrect password",
    "invalid password",
    "wrong password",
    "incorrect username",
    "invalid username",
    "invalid credentials",
    "incorrect credentials",
    "authentication failed",
    "auth failed",
    "login unsuccessful",
    "could not log",
    "couldn't log",
    "アカウントまたはパスワード",
    "パスワードが正しく",
    "ログインに失敗",
    "認証に失敗",
    "ユーザー名またはパスワード",
)

# 既知のログインパス断片（login_url 未指定時の推定に使う）。
_LOGIN_PATH_HINTS = (
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/account/login",
    "/users/sign_in",
    "/session/new",
)

_PASSWORD_INPUT_RE = re.compile(
    r"<input\b[^>]*\btype\s*=\s*['\"]?password['\"]?", re.IGNORECASE
)
# ログイン特有のユーザ名/メール欄（name/id に user/email/login 等を含む）。
_USERNAME_INPUT_RE = re.compile(
    r"<input\b[^>]*\b(?:name|id)\s*=\s*['\"]?[^'\">]*"
    r"(?:user|email|login|account|mail)[^'\">]*['\"]?",
    re.IGNORECASE,
)
# type=email の入力欄（名前が user 等でなくてもログイン欄とみなす）。
_EMAIL_INPUT_RE = re.compile(
    r"<input\b[^>]*\btype\s*=\s*['\"]?email['\"]?", re.IGNORECASE
)


def _norm(url: str) -> str:
    return (url or "").rstrip("/").lower()


def on_login_page(current_url: str, login_url: str) -> bool:
    """現在 URL がログインページに見えるか。``browser.is_on_login_page`` の純粋版。"""
    current = _norm(current_url)
    if not current:
        return False
    if login_url:
        login = _norm(login_url)
        if current == login:
            return True
        cur_path = urlparse(current).path
        login_path = urlparse(login).path
        if login_path and cur_path == login_path:
            return True
        return False
    cur_path = urlparse(current).path
    for hint in _LOGIN_PATH_HINTS:
        if cur_path == hint or cur_path.endswith(hint):
            return True
    return False


def has_failure_text(body: str) -> bool:
    """本文にログイン失敗を示す語句が含まれるか（大小文字無視）。"""
    if not body:
        return False
    low = body.lower()
    return any(marker in low for marker in _FAILURE_MARKERS)


def has_login_form(body: str) -> bool:
    """本文にログインフォームが残っているか。

    パスワード入力欄に加え、**ログイン特有のユーザ名/メール欄**（name/id に
    user・email・login 等を含む、または type=email）が共存する時にのみ
    「ログインフォーム」とみなす。送信ボタンや ``<form>`` だけでは判定しない
    （パスワード変更/アカウント設定など、ログイン後にパスワード欄を持つ正規
    ページを失敗と誤判定しないため）。
    """
    if not body:
        return False
    if not _PASSWORD_INPUT_RE.search(body):
        return False
    return bool(
        _USERNAME_INPUT_RE.search(body) or _EMAIL_INPUT_RE.search(body)
    )


def login_succeeded(
    *,
    post_url: str,
    login_url: str,
    body: str,
    mfa_present: bool = False,
    success_indicator: str = "",
    auth_cookie_present: bool | None = None,
) -> bool:
    """ログイン後の状態から成功したかを判定する。

    - ``success_indicator`` 指定時は、URL か本文に含まれ、かつ失敗文言が無い時に成功。
    - 未指定時は「失敗文言なし・MFA 未提示・ログインページから離脱・ログイン
      フォーム非残存」を全て満たす時にのみ成功とする。
    - ``auth_cookie_present`` が明示的に ``False`` の場合は成功を否定する
      （URL は遷移したが認証 Cookie が無い＝未認証の疑い）。判定材料が無ければ
      ``None`` を渡せば無視される。
    """
    failed = has_failure_text(body)
    if success_indicator:
        hit = success_indicator in (post_url or "") or success_indicator in (body or "")
        return bool(hit and not failed)

    if failed or mfa_present:
        return False
    if auth_cookie_present is False:
        return False
    if on_login_page(post_url, login_url):
        return False
    if has_login_form(body):
        return False
    return True
