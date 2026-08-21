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

# 実 URL の path にはまず生では現れない、正規表現/式の**強い**メタ文字。JS バンドルの
# regex リテラル（`/(?:...)/`）や式片（`16*(a.flipX)`）を強く示唆する。
# 注1: `?`/`;`/`=`/`&` はクエリで正当なので path 判定には使わない（urlparse で path から除かれる）。
# 注2: 丸括弧 `()` は OData の `/Products(1)` 等で**正当**なので一律には弾かず、`_parens_look_like_regex`
#      で「regex らしい括弧」だけを別途判定する。`~ . - _ % @ , ! $ ' :` 等は実 path でも使われうる。
_STRONG_METACHARS = re.compile(r"[*+\\|^{}<>`\[\]]")

# path に残る regex 由来シーケンス（`?:`/`(?` は括弧判定、`[^` は上のメタ文字で拾えるので、
# ここは `.*`/`.+` を主に見る）。**クエリではなく path** にのみ適用する（実ルートの
# `?pattern=.*` のようなクエリ値で誤除去しないため）。
_PATH_REGEX_HINTS = (".*", ".+")


def _parens_look_like_regex(path: str) -> bool:
    """path 中の丸括弧が正規表現片らしいかを返す（純粋）。

    OData の `/Products(1)` のような**バランスした非空の括弧**は実ルートとして許容し、
    非キャプチャ/先読み群 `(?` ・空括弧 `()` ・バランス崩れ（切れた regex／`/(` 等）だけを弾く。
    """
    if "(?" in path or "()" in path:
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

    False = JS 由来のゴミ（regex/式片）と判定。判定は path 部のコードメタ文字を主軸に
    し、誤って実ルートを落とさないよう保守的（迷ったら True）。OData の括弧やクエリの
    メタ文字は実ルートとして残す。
    """
    if not resolved_url:
        return False
    try:
        parsed = urlparse(resolved_url)
    except Exception:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    path = parsed.path or ""
    # path が空/ルート直下だけの候補は資産抽出のゴミ崩壊であることが多く、実ルートは
    # 通常の crawl/リンク収集で拾える。ここでは資産由来のゴミ抑制に集中し候補にしない。
    if not path or path == "/":
        return False
    # 本丸: path に強いコードメタ文字が混ざる候補は regex/式の誤抽出として除去。
    if _STRONG_METACHARS.search(path):
        return False
    # 丸括弧は OData 等で正当。regex らしい括弧（`(?`/空/不均衡）だけ弾く。
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
