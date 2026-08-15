"""SPA クロールで観測した描画状態と GET 通信を扱う純粋関数。"""
from __future__ import annotations

import html as _html
import re
from urllib.parse import parse_qsl, urlparse


_SPA_MARKERS = (
    "<app-root",
    '<div id="root"',
    "<div id='root'",
    "ng-version",
    "data-reactroot",
    "__next_data__",
)
_STATIC_ASSET_SUFFIXES = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".woff",
    ".woff2",
    ".ico",
    ".map",
)


def looks_like_spa_shell(html: str) -> bool:
    """CSR シェルらしいマーカーと、極端に少ない可視テキストを検出する。"""
    try:
        if not isinstance(html, str) or not html.strip():
            return False

        lowered = html.lower()
        if not any(marker in lowered for marker in _SPA_MARKERS):
            return False

        body_match = re.search(r"<body\b[^>]*>(.*?)</body\s*>", html, re.IGNORECASE | re.DOTALL)
        body = body_match.group(1) if body_match else html
        body = re.sub(
            r"<(script|style|noscript)\b[^>]*>.*?</\1\s*>",
            " ",
            body,
            flags=re.IGNORECASE | re.DOTALL,
        )
        visible_text = re.sub(r"<[^>]+>", " ", body)
        visible_text = " ".join(_html.unescape(visible_text).split())
        return len(visible_text) <= 40
    except Exception:
        return False


def harvest_get_targets(
    pairs: list[dict],
    *,
    base_netlocs,
) -> list[dict]:
    """設定済み攻撃スコープの netloc 群に属する観測済み GET からクエリ注入対象を抽出する。

    ``base_netlocs`` は許可する netloc の集合（str も後方互換で受ける）。SPA が別オリジンの
    API（例: app.example → api.example、両方が攻撃対象）を叩く場合も拾えるよう、現在ページの
    単一 netloc ではなく設定済み攻撃スコープ全体で受ける。最終的な精密スコープ判定は呼び出し側の
    ``_is_attack_target_url`` が担う（analytics 等の外部オリジンはそこで除外）。
    """
    results: list[dict] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()

    try:
        if isinstance(base_netlocs, str):
            base_netlocs = {base_netlocs}
        else:
            try:
                base_netlocs = set(base_netlocs or ())
            except TypeError:
                return results
        if not isinstance(pairs, list) or not base_netlocs:
            return results

        for pair in pairs:
            try:
                if not isinstance(pair, dict):
                    continue
                request = pair.get("request") or {}
                if not isinstance(request, dict):
                    continue
                if str(request.get("method") or "").lower() != "get":
                    continue

                request_url = request.get("url")
                if not isinstance(request_url, str) or not request_url:
                    continue
                parsed = urlparse(request_url)
                if (
                    parsed.scheme.lower() not in {"http", "https"}
                    or not parsed.netloc
                    or parsed.netloc not in base_netlocs
                    or not parsed.query
                ):
                    continue
                if parsed.path.lower().endswith(_STATIC_ASSET_SUFFIXES):
                    continue

                params: list[str] = []
                for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
                    if name and name not in params:
                        params.append(name)
                        if len(params) >= 30:
                            break
                if not params:
                    continue

                endpoint_url = parsed._replace(query="", fragment="").geturl()
                dedup_key = (endpoint_url, tuple(sorted(params)))
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                observed_url = parsed._replace(fragment="").geturl()
                # ``endpoint`` はクエリ値を除いた正規URL。呼び出し側がページ跨ぎで
                # (endpoint, param集合) 単位に大域dedupするためのキーに使う（値違いの
                # 同一エンドポイントを再スキャンしない）。
                results.append({
                    "url": observed_url,
                    "endpoint": endpoint_url,
                    "params": params,
                    "depth_hint": 0,
                })
            except Exception:
                continue
    except Exception:
        return []

    return results
