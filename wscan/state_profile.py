"""状態変更を伴う注入リクエストの送信可否を判定する純粋関数。"""

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
