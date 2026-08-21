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

# 実 URL の path にはまず生では現れない、正規表現/式のメタ文字。JS バンドルの
# regex リテラル（`/(?:...)/`）や式片（`16*(a.flipX)`）を強く示唆する。
# 注: `?`/`;`/`=`/`&` はクエリで正当なので path 判定には使わない（urlparse で path から
# 除かれる）。`~ . - _ % @ , ! $ ' :` 等は実 path でも使われうるので除外しない。
_CODE_METACHARS = re.compile(r"[()*+\\|^{}<>`\[\]]")

# path から除かれず残る regex 由来シーケンス（保険。多くは上のメタ文字で既に落ちる）。
_REGEX_HINT_SUBSTRINGS = ("?:", "(?", "[^", ".*", ".+")


def is_plausible_route_candidate(resolved_url: str) -> bool:
    """解決済み URL が「実在しうるルート/API」の体裁かを返す（純粋）。

    False = JS 由来のゴミ（regex/式片）と判定。判定は path 部のコードメタ文字を主軸に
    し、誤って実ルートを落とさないよう保守的（迷ったら True）。
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
    # 本丸: path にコード由来メタ文字が混ざる候補は regex/式の誤抽出として除去。
    if _CODE_METACHARS.search(path):
        return False
    # 保険: raw 候補側に残る regex シーケンス（? が path から除かれても検出できるよう
    # 元文字列でも確認）。
    lowered = resolved_url
    if any(hint in lowered for hint in _REGEX_HINT_SUBSTRINGS):
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
