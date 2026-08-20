"""SPA クロールで観測した描画状態と GET 通信を扱う純粋関数。"""
from __future__ import annotations

import hashlib
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
    "content-length", "host", "proxy-authorization",
    # 注: Cookie は落とさず温存する。ブラウザ取得の host/path スコープ Cookie が唯一の有効な
    # 資格情報のことがあり、engine の単一 self.cookies（別ページ URL 同期の可能性）だけに頼ると
    # replay が 401/403 になる。captured Cookie を fallback として温存し、evidence では redact される
    # （cookie は sensitive 集合）。configured Cookie 優先や template URL 向け jar 同期は replay を持つ
    # b2 の領分＝バックログ（#90 R14）。
    # body 依存/転送エンコーディング系。JSON replay は葉を差し替えて body を再直列化するため、
    # 元 body 用の checksum/encoding を残すと検証するサーバが全プローブを弾く（Codex #90 R6）。
    # 再計算しないので落とす。
    "content-md5", "digest", "content-digest", "content-encoding", "transfer-encoding",
    # accept-encoding: Chromium 観測値が br/zstd を広告し得るが、requirements の plain httpx は
    # それらの codec を持たないため、サーバがその codec を選ぶと replay の応答 read が例外→
    # _apply_json_payload が ("",{}) を返し当該 endpoint の全プローブが偽陰性になる。落として
    # httpx が実行時に扱える codec だけを広告させる（#90 R11）。
    "accept-encoding",
    # 注: Idempotency-Key の扱いは **replay 時のプローブ毎の再生成**が正解（削除だと必須キー API で
    # 400/422、温存だと冪等 API でキャッシュ返し）。どちらも b1（present but unfed）では replay しない
    # ため未決定にし、template には温存して b2 の attack replay で fresh key をプローブ毎に生成する
    # （#90 R14・b2 バックログ）。ここでは落とさない。
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


# 1 body の parse/保持サイズ上限（target 支配下の巨大 JSON で CPU/メモリを食わせない・#90 R8）。
_MAX_JSON_BODY_BYTES = 256 * 1024

# 値で operation を多重化する既知の discriminator キー（小文字）。これらの葉の**値**だけを identity に
# 含め、timestamp/id/nonce 等の通常値は無視して同一注入 shape を 1 つに collapse する（#90 R9）。
_OPERATION_DISCRIMINATOR_KEYS = frozenset({
    "method", "operationname", "operation", "action", "op", "command", "cmd", "type",
    # 匿名 GraphQL は operationName を省き、operation を `query` フィールド（クエリ本文）で識別する
    # ため query も discriminator に含める（#90 R10）。
    "query",
    # Apollo persisted query(APQ) は query/operationName を省き extensions.persistedQuery.sha256Hash で
    # operation を識別する。hash を discriminator に含めないと別 operation が collapse し片方が未 probe に
    # なる（#90 R14）。leaf キー名で判定（値は operation ごとに安定なため通常値churn にはならない）。
    "sha256hash",
})


def _collect_discriminators(node, tokens, out, *, depth_cap=None) -> None:
    """full body を**反復 DFS** し operation discriminator の (path, 値) を集める（純粋・pointer cap 非依存）。

    enumerate_leaf_pointers は葉を 200 で打ち切るため、200 葉より後ろにある discriminator
    （例: 大きな body の末尾 method）を pointer 経由で拾うと取りこぼす。ここは parsed_body 全体を
    直接歩いて discriminator を発見する（#90 R14）。**発見数の上限は設けない** ―― 先に現れた
    discriminator 名の葉（nested な type 等）でカットオフすると、その後の operation selector（method）
    を走査せず別 operation を collapse する（#90 R14）。

    深さ上限は設けない（#90 R21b）: injectable な葉が浅くても discriminator（例: JSON-RPC method）が
    8 段より深いと以前の depth_cap=8 で識別子を取りこぼし collapse していた。署名は
    ``tuple(sorted(disc))`` で順序非依存（_injection_signature）なので、明示スタックの反復 DFS で
    全走査してよい。json.loads 済み構造を歩くだけで深いネストでも RecursionError にならず、コストは
    parse 前 body サイズ上限（_MAX_JSON_BODY_BYTES）で有界。depth_cap は後方互換で残すが既定 None。
    """
    stack = [(node, tuple(tokens))]
    while stack:
        cur, path = stack.pop()
        if depth_cap is not None and len(path) > depth_cap:
            continue
        if isinstance(cur, dict):
            for k, v in cur.items():
                key = str(k)
                if key.lower() in _OPERATION_DISCRIMINATOR_KEYS:
                    if isinstance(v, (str, int, float, bool)):
                        # repr で JSON 型を保持（{"action":1} と {"action":"1"} を区別・#90 R13）。
                        out.append((path + (key,), repr(v)))
                    elif isinstance(v, (dict, list)):
                        # discriminator 値が非スカラ（{"type":{"name":"create"}} 等）でも別 operation を
                        # 区別する。正規化 body の hash を署名に含め collapse を防ぐ（#90 FN-F）。
                        out.append((path + (key,), _canon_nonscalar(v)))
                stack.append((v, path + (key,)))
        elif isinstance(cur, list):
            for index, v in enumerate(cur):
                stack.append((v, path + (str(index),)))


def _canon_nonscalar(value) -> str:
    """非スカラ discriminator 値の bounded 正規化ハッシュ（純粋・署名用）。"""
    try:
        s = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    except Exception:
        s = repr(value)
    # ハッシュ前に切り詰めない。SHA1 は任意長を扱え、正規化文字列は既に materialize 済み
    # なので prefix 切り詰めはコスト削減にならず、2048 字以降だけ異なる 2 operation が同一署名へ
    # collapse して一方が未探索になる偽陰性を生む（#90 R21）。全文をハッシュする。
    return "ns:" + hashlib.sha1(s.encode("utf-8")).hexdigest()


# 値ではなく**ヘッダ**で operation を選択する API のヘッダ名（小文字）。body/url が同一でも
# これらの値が違えば別 operation なので、値を signature に含め collapse を防ぐ（#90 FN-E）。
# 例: AWS JSON プロトコル(X-Amz-Target)、SOAP(SOAPAction)、method override、GraphQL operation 名。
_OPERATION_DISPATCH_HEADERS = frozenset({
    "x-amz-target", "soapaction", "x-http-method-override", "x-graphql-operationname",
})


def _dispatch_header_values(headers) -> list:
    """observed ヘッダから operation-dispatch ヘッダの (name, value) を集める（純粋・小文字名）。"""
    if not isinstance(headers, dict):
        return []
    out = []
    for name, value in headers.items():
        lname = str(name).lower()
        if lname in _OPERATION_DISPATCH_HEADERS:
            out.append((lname, str(value)))
    return out


def _injection_signature(parsed_body, pointers, headers=None) -> str:
    """注入 shape の識別子（純粋）。pointer 集合（構造）＋既知 operation discriminator の値
    ＋operation-dispatch ヘッダの値を署名する。JSON-RPC method / GraphQL operationName /
    APQ sha256Hash / X-Amz-Target 等の operation は区別しつつ、timestamp/resource id/CSRF nonce/
    autosave 等の通常値変化は collapse して重複 probe を防ぐ。discriminator は **full body から**収集し、
    200 葉上限を超えた位置の discriminator も拾う（#90 R14）。非スカラ discriminator 値も区別する（#90 FN-F）。"""
    disc: list[tuple] = []
    try:
        _collect_discriminators(parsed_body, [], disc)
    except Exception:
        disc = []
    hdr_disc = _dispatch_header_values(headers)
    payload = repr((tuple(sorted(pointers)), tuple(sorted(disc)), tuple(sorted(hdr_disc))))
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


def _raw_content_type(request_headers) -> str | None:
    """観測ヘッダから content-type の生値を返す（無ければ None）。budget 消費前の JSON 判定用。"""
    if not isinstance(request_headers, dict):
        return None
    for name, value in request_headers.items():
        if str(name).lower() == "content-type":
            return str(value or "")
    return None


def _norm_content_type(ct) -> str:
    """Content-Type を正規化（小文字・パラメータ除去）。operation identity 用（#90 R21c）。

    vendor media type（application/vnd.acme.v1+json vs v2+json）で版/operation を分ける API を、
    同一 method/url/body でも別 operation として identity に反映するため、raw/semantic 双方の
    キーへ含める。charset 等のパラメータは落として無用な分裂を防ぐ。
    """
    if not ct:
        return ""
    return str(ct).split(";", 1)[0].strip().lower()


def _is_jsonish_content_type(ct: str) -> bool:
    """JSON 系 content-type か（application/json / +json / text/json）。"""
    c = (ct or "").lower()
    return "application/json" in c or "+json" in c or "text/json" in c


# 明示的に「非 JSON の構造化 form / バイナリ」な content-type。budget を消費する前に弾く。
# ※ text/plain は含めない ―― fetch() が Content-Type 未指定のとき、および navigator.sendBeacon は
#   JSON 文字列を `text/plain;charset=UTF-8` で送る（CORS simple-request 回避パターン）。これを弾くと
#   modern SPA の JSON API を丸ごと見逃す（偽陰性）。text/plain・content-type 無し・未知の text/* は
#   Phase 2 の json.loads に最終判定を委ねる（#90 FN-A）。
_NON_JSON_BODY_CT_MARKERS = (
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "application/octet-stream",
    "image/", "audio/", "video/", "font/",
    "application/pdf", "application/zip", "application/gzip",
    "application/x-protobuf", "application/grpc",
)


def _is_non_json_body_ct(ct: str) -> bool:
    """content-type が明示的に非 JSON（form/multipart/バイナリ）か。True なら harvest 候補から除外。"""
    c = (ct or "").lower()
    return any(marker in c for marker in _NON_JSON_BODY_CT_MARKERS)


def _extract_replay_headers(request_headers) -> tuple:
    """観測ヘッダから (content_type, replay 用 headers) を抽出する（純粋）。

    content-type は content_type へ分離（headers には残さず transport の重複 Content-Type を防ぐ）、
    cookie/proxy-auth/再生成/body 整合系は落とし、Authorization 等の JS 取得トークンは残す。
    """
    if not isinstance(request_headers, dict):
        return "application/json", {}
    content_type = "application/json"
    headers: dict = {}
    for name, value in request_headers.items():
        lowered = str(name).lower()
        if lowered == "content-type":
            if value:
                content_type = str(value)
            continue
        if lowered in _REPLAY_DROP_HEADERS:
            continue
        headers[name] = value
    return content_type, headers


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
    実 parse 数（グローバル parse 作業）の上限。**endpoint バケツ間 round-robin で parse する**ため、
    1 endpoint の値churn がこの予算を独占して他 endpoint を飢餓させない（#90 R14）。両者を engine から
    渡すことで、除外パスばかりの観測が有効ターゲットを飢餓させず、untrusted な大量観測でも parse が有界になる。
    """
    results: list[dict] = []
    # semantic identity (method, observed_url, body_signature) -> result idx。値まで含む正規化 body で、
    # JSON-RPC/GraphQL のように**値で** operation を多重化する場合も別ターゲットに保つ（#90 R8）。
    seen_index: dict[tuple[str, str, str], int] = {}
    processed = 0  # 実 parse 数（グローバル parse 作業の上限＝max_targets）

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

        # --- Phase 1: フィルタ＋endpoint 単位のバケツ化（parse 前・#90 R14）---
        # pairs を観測順に走査し cheap なフィルタ（method/scope/size/content-type）だけを適用。
        # 同一生 body（method,url,post_data）の連投は 1 entry に潰し、headers は最新観測へ更新する
        # （malformed の連投も生 body dedup で 1 回に潰れる＝負キャッシュ不要）。生き残った候補を
        # (method, observed_url) でバケツ化し順序を保つ。実 parse は Phase 2 で round-robin に行う。
        buckets: dict[str, list] = {}
        raw_first: dict[tuple[str, str, str], dict] = {}
        obs_seq = 0  # 候補観測の通し番号。collapse 時に最新観測（order 最大）だけ template を更新する。
        for pair in pairs:
            try:
                if not isinstance(pair, dict):
                    continue
                request = pair.get("request") or {}
                if not isinstance(request, dict):
                    continue

                method = str(request.get("method") or "").lower()
                # DELETE も body を持てる（bulk-delete: `axios.delete(url,{data:{ids,reason}})`）。
                # body 無し DELETE は下の post_data チェックで自然に落ちる（#90 FN-B）。
                if method not in {"post", "put", "patch", "delete"}:
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
                # C3: 1 body のサイズ上限（parse 前）。巨大 body でメモリ/CPU を食わせない。
                if len(post_data) > _MAX_JSON_BODY_BYTES:
                    continue
                # C4: content-type が**明示的に非 JSON（form/multipart/バイナリ）**なら budget 消費前に skip。
                # content-type 無し・text/plain（fetch 既定/sendBeacon）・未知 text/* は JSON かもしれないので
                # 候補に残し Phase 2 の json.loads に委ねる。text/plain を弾くと modern SPA の JSON API を
                # 丸ごと見逃す（#90 FN-A）。form 大量送信は _is_non_json_body_ct で従来どおり弾く。
                raw_ct = _raw_content_type(request.get("headers"))
                if raw_ct and _is_non_json_body_ct(raw_ct):
                    continue

                method_upper = method.upper()
                endpoint_url = parsed_url._replace(query="", fragment="").geturl()
                request_headers = request.get("headers")
                # 生 body dedup: 同一 (method,url,body) の連投(polling/autosave)は 1 entry に潰し、
                # headers（refresh された Authorization/CSRF）だけ最新観測へ更新する（#90 R7）。
                # ただし operation-dispatch ヘッダ(X-Amz-Target 等)の値まで含める ―― body が同一でも
                # ヘッダで別 operation を選ぶ API を Phase 1 の raw dedup で潰さないため（#90 FN-E）。
                raw_key = (
                    method_upper, observed_url, post_data,
                    tuple(sorted(_dispatch_header_values(request_headers))),
                    # 同一 body でも media type で operation/版を分ける API を区別（#90 R21c）。
                    _norm_content_type(raw_ct),
                )
                obs_seq += 1
                existing = raw_first.get(raw_key)
                if existing is not None:
                    # 同一生 body の再観測: headers を最新に、order も最新観測へ進める（A/B/A で
                    # 古い collapse に上書きされて stale 認証を残さない・#90 R14）。
                    existing["request_headers"] = request_headers
                    existing["order"] = obs_seq
                    continue
                entry = {
                    "method_upper": method_upper,
                    "observed_url": observed_url,
                    "endpoint_url": endpoint_url,
                    "post_data": post_data,
                    "request_headers": request_headers,
                    "order": obs_seq,
                }
                raw_first[raw_key] = entry
                # バケツキーは (method, observed_url)。queryless endpoint で束ねると ?op=create/
                # ?op=delete や別 HTTP method の operation が同一バケツに入り、round-robin 公平配分が
                # それらを区別できず片方を未 parse にする（#90 R14）。値churn は同一 observed_url なので
                # 引き続き 1 バケツに束ねられ、fairness は保たれる。
                buckets.setdefault((method_upper, observed_url), []).append(entry)
            except Exception:
                continue

        # --- Phase 2: バケツ間 round-robin parse（#90 R14）---
        # 各 endpoint バケツから 1 body ずつ順に parse し、global parse 予算(cap)まで繰り返す。
        # これにより 1 endpoint の値churn（多数の distinct body）が予算を独占して他 endpoint を
        # 飢餓させず（fair）、かつ churn endpoint の後続の genuine な新 operation も予算内で parse
        # される（blacklist しない＝#90 R14 で give-up を撤去）。
        bucket_lists = list(buckets.values())
        result_order: dict[int, int] = {}  # result idx -> 採用済み観測の order（最新のみ更新するため）
        depth = 0
        stop = False
        while not stop:
            progressed = False
            for blist in bucket_lists:
                if depth >= len(blist):
                    continue
                progressed = True
                if cap is not None and processed >= cap:
                    stop = True
                    break
                entry = blist[depth]
                processed += 1
                # per-entry 隔離: json.loads の RecursionError（深いネスト）や pointer 列挙の想定外
                # 例外が 1 entry で起きても、それ以前の正常 target を巻き添えにしない（#90 R14）。
                try:
                    parsed_body = json.loads(entry["post_data"])
                    # container を要求しない。top-level スカラ（"term" / 42 / true / null）も valid JSON で、
                    # enumerate_leaf_pointers はそれをルート pointer "" で表し whole-body 置換に対応する。
                    # container 限定にすると検索系など scalar body の endpoint が注入点を得られない（#90 R14）。
                    # 空 container は pointers が空になり下の not pointers で除外される。
                    pointers = enumerate_leaf_pointers(parsed_body)
                    if not pointers:
                        continue
                    content_type, headers = _extract_replay_headers(entry["request_headers"])
                    # 注入 shape の signature を identity に。pointer 集合＋operation discriminator の値
                    # ＋operation-dispatch ヘッダ(X-Amz-Target 等)の値で、JSON-RPC method/GraphQL/AWS JSON 等の
                    # operation は区別しつつ、timestamp/id/nonce 等の通常値変化は collapse する（#90 R9/FN-E）。
                    body_signature = _injection_signature(
                        parsed_body, pointers, entry["request_headers"]
                    )
                    semantic_key = (
                        entry["method_upper"], entry["observed_url"], body_signature,
                        _norm_content_type(content_type),  # media type で版/operation を分ける API を区別（#90 R21c）
                    )
                    if semantic_key in seen_index:
                        # 注入 shape が同じ collapse（キー順違い or 通常値変化）。**最新観測（order 最大）
                        # だけ** headers/content_type/json_body を更新する。round-robin は観測順に並ばない
                        # ため、order で守らないと古い body（stale な CSRF nonce/version/id）で上書きして
                        # replay が 403/409 になる（#90 R10/R14）。pointer 集合は同一なので注入点は不変。
                        idx = seen_index[semantic_key]
                        if entry["order"] >= result_order.get(idx, -1):
                            results[idx]["headers"] = headers
                            results[idx]["content_type"] = content_type
                            results[idx]["json_body"] = parsed_body
                            result_order[idx] = entry["order"]
                        continue
                    results.append({
                        "method": entry["method_upper"],
                        "url": entry["observed_url"],
                        "endpoint": entry["endpoint_url"],
                        "json_body": parsed_body,
                        "content_type": content_type,
                        "headers": headers,
                        "pointers": pointers,
                        "body_signature": body_signature,
                    })
                    seen_index[semantic_key] = len(results) - 1
                    result_order[len(results) - 1] = entry["order"]
                except Exception:
                    continue
            if not progressed:
                break
            depth += 1
    except Exception:
        return []

    return results


def allocate_pointers_round_robin(targets, cap) -> list[tuple[int, str]]:
    """target 間で pointer を **round-robin** に配分する（純粋・#90 R13）。

    ``targets`` は各 dict が ``pointers`` (list) を持つ harvest 結果。``cap`` は配分する
    pointer の総数上限（engine のキュー残容量）。1 pass で各 target から 1 pointer ずつ取り、
    cap に達するまで繰り返す。これにより 1 body が多数の pointer を持っても global キューを
    独占せず、後続 endpoint が最低 1 slot を得られる（greedy だと先頭 target が cap を食い潰す）。

    戻り値は ``(target_index, pointer)`` の配分順リスト。各 target 内の pointer 順は入力順を保つ。
    """
    out: list[tuple[int, str]] = []
    try:
        limit = int(cap) if cap is not None else None
    except (TypeError, ValueError):
        return out
    if limit is not None and limit <= 0:
        return out
    if not isinstance(targets, (list, tuple)):
        return out
    plists = [list((t or {}).get("pointers") or []) for t in targets]
    depth = 0
    while limit is None or len(out) < limit:
        progressed = False
        for ti, plist in enumerate(plists):
            if depth < len(plist):
                out.append((ti, plist[depth]))
                progressed = True
                if limit is not None and len(out) >= limit:
                    return out
        if not progressed:
            break
        depth += 1
    return out
