"""SPA クロールで観測した描画状態と GET 通信を扱う純粋関数。"""
from __future__ import annotations

import html as _html
import json
import re
from urllib.parse import parse_qsl, urlparse

from .injection_point import enumerate_leaf_pointers


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
# replay 時にテンプレートから**落とす**ヘッダ（小文字）。
# - content-length/host: 送信時に再生成されるため残さない。
# - cookie: `auth_headers_for_url` が cookie jar から再同期するため、観測時の stale cookie を残さない。
# - proxy-authorization: プロキシ認証は httpx_client_kwargs 側の設定に委ねる。
# **Authorization / X-Api-Key / X-Auth-Token / X-Access-Token は敢えて残す**：SPA が JS でログイン後に
# localStorage 等から付与する bearer/API トークンは `--header` でも cookie でもないため、落とすと
# `auth_headers_for_url` が再構築できず、認証済み JSON エンドポイントが 401 で未スキャンになる（Codex #90 R3, P1）。
# テンプレは in-memory・非永続で、送信時は merge_template_headers が configured --header を優先し、
# 永続/配信は record_finding=_redact_json_evidence_pair が _CREDENTIAL_HEADERS をマスクする（平文非保存）。
_REPLAY_DROP_HEADERS = frozenset({
    "content-length", "host", "cookie", "proxy-authorization",
    # body 依存/転送エンコーディング系。JSON replay は葉を差し替えて body を再直列化するため、
    # 元 body 用の checksum/encoding を残すと検証するサーバが全プローブを弾く（Codex #90 R6）。
    # 再計算しないので落とす。
    "content-md5", "digest", "content-digest", "content-encoding", "transfer-encoding",
})


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


def harvest_json_body_targets(
    pairs: list[dict],
    *,
    base_netlocs,
    is_in_scope=None,
    max_targets=None,
) -> list[dict]:
    """攻撃スコープ内で観測した JSON body の葉を注入対象として抽出する（純粋）。

    ``is_in_scope`` は呼び出し側（engine）の精密スコープ判定（_is_attack_target_url かつ
    not _is_url_excluded）を url→bool で受け取る述語。body を parse/materialize する**前**に適用し、
    対象外の大きな body を無駄に展開しない（CPU/メモリ保護・Codex #90 R3）。``max_targets`` は
    スコープ通過後の materialize 数の上限。両者を engine から渡すことで、除外パスばかりの観測が
    有効ターゲットを飢餓させず（cap はスコープ後に数える）、かつ untrusted な大量観測でも展開が有界になる。
    """
    results: list[dict] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    seen_raw: set[tuple[str, str, str]] = set()  # pre-parse 生 body dedup
    processed = 0  # スコープ通過＋raw-unique な観測数（parse 作業の上限に使う）

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
        try:
            cap = int(max_targets) if max_targets is not None else None
        except (TypeError, ValueError):
            cap = None

        for pair in pairs:
            try:
                if not isinstance(pair, dict):
                    continue
                request = pair.get("request") or {}
                if not isinstance(request, dict):
                    continue

                method = str(request.get("method") or "").lower()
                if method not in {"post", "put", "patch"}:
                    continue

                request_url = request.get("url")
                if not isinstance(request_url, str) or not request_url:
                    continue
                parsed_url = urlparse(request_url)
                if (
                    parsed_url.scheme.lower() not in {"http", "https"}
                    or not parsed_url.netloc
                    or parsed_url.netloc not in base_netlocs
                    or parsed_url.path.lower().endswith(_STATIC_ASSET_SUFFIXES)
                ):
                    continue

                observed_url = parsed_url._replace(fragment="").geturl()
                # 精密スコープ判定（engine の述語）を body パース**前**に適用し、対象外の
                # 大きな body を parse/展開しない（CPU/メモリ保護・飢餓回避）。
                if is_in_scope is not None:
                    try:
                        if not is_in_scope(observed_url):
                            continue
                    except Exception:
                        continue

                post_data = request.get("post_data")
                if not isinstance(post_data, str):
                    continue
                method_upper = method.upper()
                endpoint_url = parsed_url._replace(query="", fragment="").geturl()
                # pre-parse 生 body dedup: 同一 body の連投(polling/autosave)を json.loads 前に弾く。
                # post-parse dedup だと重複でも毎回 parse+pointer 列挙され CPU を無制限に消費する（#90 R6）。
                raw_key = (method_upper, endpoint_url, post_data)
                if raw_key in seen_raw:
                    continue
                seen_raw.add(raw_key)
                # 処理数（スコープ通過＋raw-unique な観測）を上限に。結果数でなく**処理数**を数えることで、
                # 大量のユニーク body でも parse 作業を有界化する（結果は semantic dedup 後で processed 以下）。
                if cap is not None and processed >= cap:
                    break
                processed += 1
                parsed_body = json.loads(post_data)
                if not isinstance(parsed_body, (dict, list)):
                    continue
                pointers = enumerate_leaf_pointers(parsed_body)
                if not pointers:
                    continue

                request_headers = request.get("headers") or {}
                if not isinstance(request_headers, dict):
                    request_headers = {}
                content_type = "application/json"
                headers: dict = {}
                for name, value in request_headers.items():
                    lowered = str(name).lower()
                    # content-type は content_type へ抽出し、headers には**残さない**。
                    # transport が `{"Content-Type": content_type}` を起点に case-sensitive
                    # マージするため、元の小文字 content-type を残すと大小違いの重複
                    # Content-Type ヘッダになり、重複 singleton を拒否/連結するサーバで
                    # 全 JSON プローブが弾かれる。
                    if lowered == "content-type":
                        if value:
                            content_type = str(value)
                        continue
                    # cookie/proxy-auth/再生成は落とし、Authorization 等の JS 取得トークンは残す。
                    if lowered in _REPLAY_DROP_HEADERS:
                        continue
                    headers[name] = value

                # method_upper/endpoint_url は pre-parse dedup で算出済み。
                # semantic dedup（キー順違いの同一エンドポイントを sorted pointer で1つに）。
                dedup_key = (method_upper, endpoint_url, tuple(sorted(pointers)))
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                results.append({
                    "method": method_upper,
                    "url": observed_url,
                    "endpoint": endpoint_url,
                    "json_body": parsed_body,
                    "content_type": content_type,
                    "headers": headers,
                    "pointers": pointers,
                })
            except Exception:
                continue
    except Exception:
        return []

    return results
