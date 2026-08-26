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
_DESTRUCTIVE_PATTERN = re.compile(
    r"(?:^|[^a-z0-9])(?:" + "|".join(map(re.escape, DESTRUCTIVE_KEYWORDS)) + r")(?:$|[^a-z0-9])",
    re.IGNORECASE,
)


def is_state_changing(method: str) -> bool:
    """POST/PUT/PATCH/DELETE を状態変更メソッドとして扱う。"""
    return str(method or "").strip().upper() in _STATE_CHANGING_METHODS


def looks_destructive(*, method: str, action: str = "", labels: str = "") -> bool:
    """状態変更メソッドかつ action/ラベルに破壊語があれば True。"""
    if not is_state_changing(method):
        return False
    haystack = f"{action or ''} {labels or ''}"
    return bool(_DESTRUCTIVE_PATTERN.search(haystack))


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
