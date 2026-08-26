"""状態変更を伴う注入リクエストの送信可否を判定する純粋関数。

既知の限界（best-effort）: 判定はフォームの宣言メソッド（GET/POST）と action/URL の
静的メタデータに基づく。フォームが GET を宣言しつつボタンハンドラが JS の fetch()/XHR で
POST を発行する SPA 形態は、静的メタデータからは GET に見えるため read-only でも送信され得る。
JS 由来の書き込みを厳密に止めるにはネットワーク層での実リクエスト遮断が必要だが、既存の
CDP/route ヘッダ注入機構との干渉リスクが高いため本実装では扱わない（将来対応）。宣言メソッドが
POST/PUT/PATCH/DELETE のフォーム・XXE の url POST・race の捕捉 POST・検証再送は gate 済み。
"""

from __future__ import annotations

import re


VALID_PROFILES = ("unrestricted", "controlled-write", "read-only")
DESTRUCTIVE_KEYWORDS = (
    "delete",
    "remove",
    "destroy",
    "drop",
    "purchase",
    "checkout",
    "pay",
    "payment",
    "transfer",
    "withdraw",
    "send",
    "logout",
    "deactivate",
    "cancel",
    "unsubscribe",
)

_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# 破壊語の語尾ゆらぎ（複数形/動詞化/名詞化）。identifier をトークン化してから keyword+suffix で照合する。
_KEYWORD_SUFFIXES = ("", "s", "es", "ed", "ing", "ment", "ments", "er", "ers", "d")
# 非英数で区切りつつ camelCase 境界でも分割する（``deleteAccount`` → delete/account）。
_TOKEN_SPLIT_RE = re.compile(r"[^a-zA-Z0-9]+")
_CAMEL_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")


def _tokenize_identifier(text: str) -> list[str]:
    """URL/ラベルを識別子境界（記号・camelCase）で小文字トークンに分割する（純粋）。"""
    tokens: list[str] = []
    for part in _TOKEN_SPLIT_RE.split(text or ""):
        tokens.extend(m.group(0).lower() for m in _CAMEL_RE.finditer(part))
    return tokens


def _token_is_destructive(token: str) -> bool:
    for kw in DESTRUCTIVE_KEYWORDS:
        for suf in _KEYWORD_SUFFIXES:
            if token == kw + suf:
                return True
    return False


def is_state_changing(method: str) -> bool:
    """POST/PUT/PATCH/DELETE を状態変更メソッドとして扱う。"""
    return str(method or "").strip().upper() in _STATE_CHANGING_METHODS


def looks_destructive(*, method: str, action: str = "", labels: str = "") -> bool:
    """状態変更メソッドかつ action/ラベルに破壊語があれば True。"""
    if not is_state_changing(method):
        return False
    for token in _tokenize_identifier(f"{action or ''} {labels or ''}"):
        if _token_is_destructive(token):
            return True
    return False


def may_submit(
    profile: str,
    *,
    method: str,
    action: str = "",
    labels: str = "",
) -> bool:
    """プロファイルに従って送信可否を返す。未知値は互換性優先で許可する。"""
    if profile == "read-only":
        return not is_state_changing(method)
    if profile == "controlled-write":
        return not looks_destructive(method=method, action=action, labels=labels)
    # unrestricted と未知値は既存挙動を維持する。
    return True
