"""認証フォームの入力欄を HTML から検出する、LLM 非依存の純粋関数。"""
from __future__ import annotations

from html.parser import HTMLParser
from itertools import combinations
import re
from typing import Optional

from wscan.mfa import looks_like_mfa_page

_SAFE_VALUE = re.compile(r"[A-Za-z0-9_-]+\Z")
_USER_HINTS = ("user", "email", "login", "account", "userid")
_OTP_HINTS = ("otp", "code", "token", "mfa", "2fa", "totp", "passcode", "pin")
_TEXT_TYPES = {"", "text", "email", "tel"}
_VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input",
              "link", "meta", "param", "source", "track", "wbr"}


class _Inputs(HTMLParser):
    def __init__(self, html: str):
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, dict[str, str]]] = []
        self.inputs: list[dict[str, str]] = []
        self.usable: list[dict[str, str]] = []
        self.stack: list[tuple[str, bool]] = []
        self.feed(html)
        self.close()

    def handle_starttag(self, tag, attrs):
        values: dict[str, str] = {}
        for key, value in attrs:
            values.setdefault(key, value or "")
        style = re.sub(r"\s+", "", values.get("style", "").lower())
        blocked = (
            any(hidden for _, hidden in self.stack)
            or tag in {"template", "noscript"}
            or "hidden" in values or "inert" in values
            or "disabled" in values
            or values.get("aria-hidden", "").lower() == "true"
            or "display:none" in style or "visibility:hidden" in style
        )
        self.elements.append((tag, values))
        if tag == "input":
            self.inputs.append(values)
            if not blocked and "readonly" not in values and _type(values) != "hidden":
                self.usable.append(values)
        if tag not in _VOID_TAGS:
            self.stack.append((tag, blocked))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in _VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break


def name_or_id_selector(value: str) -> str:
    """name/id を CSS 文字列として引用し、設定値を selector 構文にしない。"""
    escaped = "".join(f"\\{ord(ch):x} " if ord(ch) < 32 or ch in '\\"' else ch
                      for ch in str(value))
    return f'input[name="{escaped}"],input[id="{escaped}"]'


def _type(attrs: dict[str, str]) -> str:
    return attrs.get("type", "").lower()


def _matches(attrs: dict[str, str], key: str, value: str) -> bool:
    actual = attrs.get(key)
    # HTML の type は ASCII 大小文字を区別しない。
    return actual is not None and (actual.lower() == value.lower() if key == "type"
                                   else actual == value)


def _selector(doc: _Inputs, target: dict[str, str]) -> Optional[str]:
    for key in ("name", "id"):
        value = target.get(key, "")
        if _SAFE_VALUE.fullmatch(value) and sum(
            attrs.get(key) == value for _, attrs in doc.elements
        ) == 1:
            return f'[{key}="{value}"]'
    parts = [(key, target[key]) for key in ("type", "autocomplete", "inputmode", "maxlength")
             if _SAFE_VALUE.fullmatch(target.get(key, ""))]
    for size in range(1, len(parts) + 1):
        for subset in combinations(parts, size):
            if sum(all(_matches(attrs, k, v) for k, v in subset)
                   for attrs in doc.inputs) == 1:
                return "input" + "".join(f'[{k}="{v}"]' for k, v in subset)
    if "pattern" in target and sum("pattern" in attrs for attrs in doc.inputs) == 1:
        return "input[pattern]"
    if "type" not in target and sum("type" not in attrs for attrs in doc.inputs) == 1:
        return "input:not([type])"
    return None


def _preferred(doc: _Inputs, key: str, value: str) -> tuple[bool, Optional[str]]:
    candidates = [a for a in doc.inputs if _matches(a, key, value)]
    if not candidates:
        return False, None
    if (len(candidates) == 1
            and any(candidates[0] is a for a in doc.usable)
            and _type(candidates[0]) in _TEXT_TYPES | {"number"}):
        return True, f'input[{key}="{value}"]'
    return True, None


def _hinted(attrs: dict[str, str], hints: tuple[str, ...]) -> bool:
    if hints == _OTP_HINTS:
        # shipping/zipcode の部分一致を避け、snake-case・camelCase の語単位で判定。
        for key in ("name", "id"):
            value = re.sub(r"([A-Z])([A-Z][a-z])", r"\1_\2", attrs.get(key, ""))
            value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
            if set(re.split(r"[^a-z0-9]+", value.lower())) & set(hints):
                return True
        return False
    return any(hint in attrs.get(key, "").lower()
               for key in ("name", "id") for hint in hints)


def _single(doc: _Inputs, candidates: list[dict[str, str]]) -> Optional[str]:
    return _selector(doc, candidates[0]) if len(candidates) == 1 else None


def find_password_field(html: str) -> Optional[str]:
    """password input があれば固定 selector を返す（複数欄でも同じ値）。"""
    doc = _Inputs(html)
    return 'input[type="password"]' if any(_type(a) == "password" for a in doc.inputs) else None


def find_username_field(html: str) -> Optional[str]:
    """autocomplete、email 型、password 直前、名前の順に利用者欄を探す。"""
    doc = _Inputs(html)
    for key, value in (("autocomplete", "username"), ("type", "email")):
        found, selector = _preferred(doc, key, value)
        if found:
            return selector
    for index, attrs in enumerate(doc.inputs):
        if _type(attrs) == "password":
            if index:
                previous = doc.inputs[index - 1]
                if _type(previous) in _TEXT_TYPES and any(previous is a for a in doc.usable):
                    return _selector(doc, previous)
            break
    return _single(doc, [a for a in doc.usable
                         if _type(a) in _TEXT_TYPES and _hinted(a, _USER_HINTS)])


def _short_code(attrs: dict[str, str], mfa_context: bool = False) -> bool:
    length = attrs.get("maxlength")
    if length is not None and not re.fullmatch(r"0*[1-8]", length):
        return False
    if attrs.get("inputmode", "").lower() == "numeric" and (length is not None or mfa_context):
        return True
    # 任意の pattern は OTP の根拠にならない。短い数字列だけを許す既知の
    # 形式に限定し、ページ由来の正規表現そのものは実行しない。
    pattern = re.fullmatch(
        r"\^?(?:\[0-9\]|\\d)\{([1-8])(?:,([1-8]))?\}\$?",
        attrs.get("pattern", ""),
    )
    return bool(pattern and (pattern[2] is None or pattern[1] <= pattern[2]))


def find_otp_field(html: str, *, mfa_context: Optional[bool] = None) -> Optional[str]:
    """autocomplete、名前、短い数値欄、MFA の単一可視欄の順に OTP を探す。

    同順位の複数候補や一意に表せない欄は None。可視性は HTML 内の明示的な
    非表示指定のみ判定できるため、呼び出し側でも実 DOM の可視性を確認する。
    """
    doc = _Inputs(html)
    found, selector = _preferred(doc, "autocomplete", "one-time-code")
    if found:
        return selector
    text_inputs = [a for a in doc.usable if _type(a) in {"", "text", "tel", "number"}]
    candidates = [a for a in text_inputs if _hinted(a, _OTP_HINTS)]
    if candidates:
        return _single(doc, candidates)
    if mfa_context is None:
        mfa_context = looks_like_mfa_page(html)
    candidates = [a for a in text_inputs if _short_code(a, mfa_context)]
    if candidates:
        return _single(doc, candidates)
    if mfa_context:
        return _single(doc, [a for a in text_inputs if _type(a) != "number"])
    return None
