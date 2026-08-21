"""JS/JSON 資産から抽出した URL 候補の妥当性判定（LLM 非依存の純粋関数）。

`browser._collect_urls_from_loaded_assets` の `url_re` は `()*+?;=` 等を許容文字に
含むため、minified JS の**正規表現リテラルや式**を `/…` ルートとして誤抽出する
（例: `/(?:` `/16*(a.flipX?-1:1` `/()?;=`）。これらのゴミ URL は (1) 無駄クロール
(2) 高価なプランナー LLM の浪費 (3) 実ルート到達の阻害 を招く（0009 C1）。

ここでは「実在ルートらしさ」を**path 部のコード由来メタ文字**で判定し、誤抽出を
除去する。ブラウザ非依存の純粋関数として分離し、フィクスチャ無しでテスト可能に保つ
（本リポの「検出/判定ロジックは純粋関数へ分離」規約）。除去は保守側に倒し、判断に
迷う候補は**残す**（実ルートの取りこぼし＝到達性低下は C1 の目的に反するため）。
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# URL の path として **RFC 上そもそも不正**な文字（gen-delim/式メタ文字）。実ルートには
# 生では現れず、minified JS の regex リテラルや式片を強く示唆する。
# 除外理由: `* + ( )` は path の sub-delim として**正当**（`/languages/C++`・OData `/Products(1)`・
#   parameterless `/GetDefault()`）なのでここには入れない。regex らしい括弧だけ `_parens_look_like_regex`
#   で別途弾く。`?;=&` はクエリで正当（path から除かれる）。`~ . - _ % @ , ! $ ' :` 等も path で正当。
_STRONG_METACHARS = re.compile(r"[\\|^{}<>`\[\]]")

# path に残る regex 由来シーケンス。`.*`/`.+`（任意文字の量指定）は実 path にまず出ない強い
# 正規表現シグナル。**クエリではなく path** にのみ適用する（実ルートの `?pattern=.*` のような
# クエリ値で誤除去しないため）。
_PATH_REGEX_HINTS = (".*", ".+")


def _parens_look_like_regex(path: str) -> bool:
    """path 中の丸括弧が正規表現片らしいかを返す（純粋）。

    実ルートの括弧（OData `/Products(1)`・parameterless `/GetDefault()/value`）は許容し、
    **regex 特有の形だけ**を弾く: 非キャプチャ/先読み群 `(?` ／ バランス崩れ（切れた regex・
    `/16*(a` や `/(` 等）／ **識別子直後でない `(`**（`/(...)` のように区切り直後で始まる括弧＝
    regex リテラル片。関数呼び出し様の `\\w(` は残す）。
    """
    if "(?" in path:
        return True
    # 関数/コレクション様（識別子・数字・`)` の直後の `(` ）以外の開き括弧は式/regex 片寄り。
    for m in re.finditer(r"\(", path):
        prev = path[m.start() - 1] if m.start() > 0 else ""
        if not (prev.isalnum() or prev in "_)"):
            return True
    depth = 0
    for ch in path:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return True
    return depth != 0


def is_plausible_route_candidate(resolved_url: str) -> bool:
    """解決済み URL が「実在しうるルート/API」の体裁かを返す（純粋）。

    False = JS 由来のゴミ（regex/式片）と判定。判定は「URL として不正な文字」＋「regex 特有の
    形」に絞り、誤って実ルートを落とさないよう保守的（迷ったら True）。OData/関数様の括弧・
    `+`/`*` を含む path・クエリのメタ文字・origin-root は実ルートとして残す。曖昧な候補は残し、
    実在しなければ下流の crawl が 404 で落とす（到達性維持を優先）。
    """
    if not resolved_url:
        return False
    try:
        parsed = urlparse(resolved_url)
    except Exception:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    if not parsed.netloc:
        return False
    path = parsed.path or ""
    # 本丸: path に URL として不正な文字が混ざる候補は regex/式の誤抽出として除去。
    # （origin-root `https://host/` はスコープ内の別オリジン等で実ルートになりうるので残す。）
    if _STRONG_METACHARS.search(path):
        return False
    # 丸括弧は OData/関数様で正当。regex 特有の括弧だけ弾く。
    if _parens_look_like_regex(path):
        return False
    # regex 由来シーケンスは **path にのみ** 適用（クエリ値の `.*` 等で実ルートを落とさない）。
    if any(hint in path for hint in _PATH_REGEX_HINTS):
        return False
    return True


def filter_route_candidates(resolved_urls) -> list[str]:
    """URL 候補列から実在ルートらしいものだけを順序保持で返す（純粋）。"""
    seen: set[str] = set()
    kept: list[str] = []
    for url in resolved_urls or []:
        if url in seen:
            continue
        seen.add(url)
        if is_plausible_route_candidate(url):
            kept.append(url)
    return kept
