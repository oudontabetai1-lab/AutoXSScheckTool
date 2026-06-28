"""
API スペック取り込み（OpenAPI / Swagger / Postman）
===================================================
API ファースト検査のための入口。OpenAPI 2.0(Swagger) / 3.x と Postman
Collection v2 を読み込み、:class:`HarSeedData` と同形の
:class:`ApiSeedData` を返す。``engine`` はこれをクロールシード（URL・Cookie・
共通ヘッダ）に流し込み、フォームを辿らずとも API エンドポイントを攻撃面に
できる。

設計方針:
  - 解析は純粋関数（``parse_openapi`` / ``parse_postman``）に切り出し、ネット/
    ブラウザ非依存でテストする。``load`` は薄い IO（ファイル読込＋形式判定）。
  - パスパラメータ（``/users/{id}``）はサンプル値で具体化する（``id`` 系は ``1``、
    それ以外は ``test``）。クエリパラメータはスキーマから既定値を補って、
    既存の URL パラメータ攻撃ループ（``test_url_param``）に乗るようにする。
  - JSON ボディを持つ操作は ``RequestTemplate`` として別途返し、Mass Assignment /
    NoSQL / Prototype Pollution など JSON ボディ系スキャナが利用できるようにする。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlencode, urljoin, urlparse


@dataclass
class RequestTemplate:
    """JSON ボディ等を持つ API 操作のひな型。"""
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    json_body: Optional[dict] = None
    content_type: str = "application/json"


@dataclass
class ApiSeedData:
    """API スペックから抽出したスキャンシード（HarSeedData と同形＋ボディ）。"""
    urls: list[str] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    requests: list[RequestTemplate] = field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"ApiSeedData(urls={len(self.urls)}, requests={len(self.requests)}, "
            f"headers={list(self.headers.keys())})"
        )


# ──────────────────────────────────────────────────────────────────────────
# サンプル値生成
# ──────────────────────────────────────────────────────────────────────────

def _sample_for_name(name: str, schema: Optional[dict] = None) -> Any:
    """パラメータ名/スキーマから無害なサンプル値を作る（純粋）。"""
    schema = schema or {}
    if "default" in schema:
        return schema["default"]
    if "example" in schema:
        return schema["example"]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    typ = schema.get("type", "")
    low = (name or "").lower()
    if typ in ("integer", "number") or low.endswith("id") or low == "id":
        return 1
    if typ == "boolean":
        return True
    if typ == "array":
        return ["test"]
    if typ == "object":
        return {}
    return "test"


def _fill_path(path: str, params: dict) -> str:
    """``/users/{id}`` の ``{id}`` をサンプル値で埋める（純粋）。"""
    out = path
    # パスパラメータ名を収集（{id} 形式）
    import re

    for m in re.findall(r"\{([^}]+)\}", path):
        schema = params.get(m, {})
        val = _sample_for_name(m, schema)
        out = out.replace("{" + m + "}", str(val))
    return out


# ──────────────────────────────────────────────────────────────────────────
# OpenAPI / Swagger
# ──────────────────────────────────────────────────────────────────────────

def _openapi_base_urls(spec: dict, fallback_base: str = "") -> list[str]:
    """servers(3.x) / host+basePath+schemes(2.0) から基底 URL 群を作る（純粋）。"""
    bases: list[str] = []
    # OpenAPI 3.x
    for srv in spec.get("servers", []) or []:
        url = (srv or {}).get("url", "")
        if not url:
            continue
        # サーバ変数（{host} 等）を default で展開。展開しないと netloc が "{host}" の
        # まま生成され、スコープ照合で全て弾かれて API が 1 件も拾えなくなる。
        variables = (srv or {}).get("variables", {}) or {}
        for vname, vdef in variables.items():
            default = (vdef or {}).get("default")
            if default is not None:
                url = url.replace("{" + str(vname) + "}", str(default))
        bases.append(url.rstrip("/"))
    # Swagger 2.0
    if not bases and spec.get("host"):
        schemes = spec.get("schemes") or ["https"]
        base_path = spec.get("basePath", "") or ""
        for scheme in schemes:
            bases.append(f"{scheme}://{spec['host']}{base_path}".rstrip("/"))
    if not bases and fallback_base:
        bases.append(fallback_base.rstrip("/"))
    if not bases:
        bases.append("")
    # 相対 server URL（"/api/v1" 等）は fallback の origin に解決する
    resolved: list[str] = []
    for b in bases:
        if b.startswith(("http://", "https://")) or not b:
            resolved.append(b)
        elif fallback_base:
            origin = "{u.scheme}://{u.netloc}".format(u=urlparse(fallback_base))
            # 相対 server URL が "/" で始まらない場合（"api/v1" 等）でも
            # "https://example.comapi/v1" のような不正ホストにならないよう
            # 区切りスラッシュを補う。
            rel = b if b.startswith("/") else "/" + b
            resolved.append((origin + rel).rstrip("/"))
        else:
            resolved.append(b)
    # 重複除去（順序保持）
    seen: set[str] = set()
    out: list[str] = []
    for b in resolved:
        if b not in seen:
            seen.add(b)
            out.append(b)
    return out


def _resolve_params(params: list, spec: Optional[dict]) -> list:
    """parameters リスト中の ``$ref``（``#/components/parameters/X``）を解決する（純粋）。"""
    out: list = []
    for p in params or []:
        if isinstance(p, dict) and "$ref" in p:
            resolved = _resolve_ref(spec, p["$ref"])
            if isinstance(resolved, dict):
                out.append(resolved)
        elif isinstance(p, dict):
            out.append(p)
    return out


_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head")


def parse_openapi(spec: dict, fallback_base: str = "") -> ApiSeedData:
    """OpenAPI/Swagger dict をシードへ（純粋関数）。

    ``servers``/scheme が複数あるときは **全ベース URL** に対して URL・操作を
    展開する。先頭サーバがスコープ外でも後続にスコープ内サーバがあれば、engine
    のスコープフィルタが拾えるようにする（先頭固定だと API が丸ごと落ちる）。
    """
    seed = ApiSeedData()
    bases = _openapi_base_urls(spec, fallback_base) or [""]
    paths = spec.get("paths", {}) or {}
    seen_urls: set[str] = set()

    for raw_path, item in paths.items():
        if not isinstance(item, dict):
            continue
        # path-level な共通パラメータ
        common_params = item.get("parameters", []) or []
        for method in _HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            params = list(common_params) + list(op.get("parameters", []) or [])
            # parameters が component 参照（{"$ref": "#/components/parameters/X"}）の
            # 場合は解決してから扱う。未解決だと in/name が読めず必須クエリ
            # （api-version/tenant/locale 等）が URL から落ちて 400/404 になる。
            params = _resolve_params(params, spec)

            # path パラメータのスキーマ表を作る
            path_schemas = {
                p.get("name"): (p.get("schema") or p)
                for p in params
                if p.get("in") == "path" and p.get("name")
            }
            concrete_path = _fill_path(raw_path, path_schemas)

            # query パラメータを集める
            query_pairs: list[tuple[str, str]] = []
            # header パラメータ（X-API-Version/tenant/API-key 等）をサンプル値で集める。
            # 落とすと必須ヘッダ欠落で 400/401/404 になり API-first 検査が空振りする。
            header_params: dict[str, str] = {}
            for p in params:
                loc = p.get("in")
                name = p.get("name")
                if not name:
                    continue
                schema = p.get("schema") or p
                if loc == "query":
                    query_pairs.append((name, str(_sample_for_name(name, schema))))
                elif loc == "header" and name.lower() not in (
                    "cookie", "content-length", "host", "content-type", "accept",
                    # 認証系は合成しない。default/example が無いと "test" 等のダミーに
                    # なり、HeaderManager.update が利用者の --header Authorization を
                    # 上書きして API スキャンが未認証になるため。
                    "authorization", "x-api-key", "x-auth-token", "x-access-token",
                    "proxy-authorization",
                ):
                    # default/example がある時のみ採用（合成ダミーは入れない）
                    if "default" in schema or "example" in schema:
                        header_params[name] = str(_sample_for_name(name, schema))
            # クロール/全リクエストに効くよう共通ヘッダへ反映（後勝ち）
            if header_params:
                seed.headers.update(header_params)

            body_schema, body_ctype = _openapi_request_body_schema(op, spec)
            is_body_op = body_schema is not None and method in ("post", "put", "patch")
            example = _example_from_schema(body_schema, spec) if is_body_op else None

            # 全ベース URL に展開（スコープ外は engine 側で除外される）
            for base in bases:
                full = (base + concrete_path) if base else concrete_path
                if query_pairs:
                    full = f"{full}?{urlencode(query_pairs)}"
                # GET 系はクロール URL シードに（URL パラメータ攻撃ループへ）
                if full and full not in seen_urls:
                    seen_urls.add(full)
                    seed.urls.append(full)
                # requestBody(JSON) を持つ操作は RequestTemplate に。
                # 必須クエリパラメータ（api-version/tenant/locale 等）を落とすと
                # 別エンドポイント扱いで 400/404 になり mass_assignment が空振りするため、
                # クエリ込みの URL（full）をそのまま使う。
                if is_body_op:
                    seed.requests.append(
                        RequestTemplate(
                            method=method.upper(),
                            url=full,
                            json_body=example,
                            headers=dict(header_params),
                            content_type=body_ctype or "application/json",
                        )
                    )

    return seed


def _openapi_request_body_schema(
    op: dict, spec: Optional[dict] = None
) -> tuple[Optional[dict], str]:
    """操作の JSON requestBody スキーマと Content-Type を返す（OpenAPI3 / Swagger2 両対応）。

    ``requestBody`` 自体が ``$ref``（``#/components/requestBodies/X``）の component
    参照のことがあるため、先に解決してから ``content`` を見る。解決しないと
    component ベースの spec で RequestTemplate が作られず mass_assignment が
    JSON エンドポイントを取りこぼす。

    戻り値は ``(schema, content_type)``。``application/merge-patch+json`` 等の
    ベンダ/patch JSON メディアタイプはその名前をそのまま返す（既定で
    application/json に潰すと 415 になる API があるため）。スキーマ無しは ``(None, "")``。
    """
    # OpenAPI 3.x
    rb = op.get("requestBody")
    if isinstance(rb, dict):
        if "$ref" in rb:
            rb = _resolve_ref(spec, rb["$ref"]) or {}
        content = rb.get("content", {}) or {}
        for ctype, media in content.items():
            if "json" in (ctype or "").lower():
                return ((media or {}).get("schema") or {}), (ctype or "application/json")
    # Swagger 2.0: parameters[in=body].schema（param 自体が $ref のことがある）
    for p in _resolve_params(op.get("parameters", []) or [], spec):
        if p.get("in") == "body":
            return (p.get("schema") or {}), "application/json"
    return None, ""


def _resolve_ref(spec: Optional[dict], ref: str) -> Optional[dict]:
    """ローカル ``$ref``（``#/components/schemas/X`` / ``#/definitions/X``）を解決する（純粋）。

    外部参照（別ファイル/URL）や解決不能なものは None。
    """
    if not spec or not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node: Any = spec
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")  # JSON Pointer エスケープ
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node if isinstance(node, dict) else None


def _example_from_schema(
    schema: dict,
    spec: Optional[dict] = None,
    _depth: int = 0,
    _seen: Optional[frozenset] = None,
) -> Any:
    """JSON スキーマからサンプルボディを構築する（純粋・浅い再帰）。

    ``$ref``（ローカル component 参照）と ``allOf`` を解決してから組み立てる。
    解決しないと component ベースの spec で本文が ``{}`` になり、mass_assignment が
    必須フィールドを欠いたボディを送って弾かれ、検査を取りこぼす。
    """
    if not isinstance(schema, dict) or _depth > 6:
        return {}
    _seen = _seen or frozenset()

    # $ref を解決（循環参照は打ち切り）
    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in _seen:
            return {}
        resolved = _resolve_ref(spec, ref)
        if resolved is None:
            return {}
        return _example_from_schema(resolved, spec, _depth + 1, _seen | {ref})

    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]

    # allOf: 合成スキーマ → プロパティをマージ
    if "allOf" in schema and isinstance(schema["allOf"], list):
        merged: dict = {}
        for sub in schema["allOf"]:
            if isinstance(sub, dict):
                part = _example_from_schema(sub, spec, _depth + 1, _seen)
                if isinstance(part, dict):
                    merged.update(part)
        # allOf 直下に properties があれば併合
        for name, sub in (schema.get("properties", {}) or {}).items():
            merged[name] = (
                _example_from_schema(sub, spec, _depth + 1, _seen)
                if isinstance(sub, dict) else "test"
            )
        return merged

    typ = schema.get("type")
    if typ == "object" or "properties" in schema:
        out: dict = {}
        for name, sub in (schema.get("properties", {}) or {}).items():
            out[name] = (
                _example_from_schema(sub, spec, _depth + 1, _seen)
                if isinstance(sub, dict) else "test"
            )
        return out
    if typ == "array":
        item = schema.get("items", {})
        return [_example_from_schema(item, spec, _depth + 1, _seen)] if isinstance(item, dict) else []
    if typ in ("integer", "number"):
        return 1
    if typ == "boolean":
        return True
    if typ == "string":
        return "test"
    # 型不明 → 空オブジェクト
    return {}


# ──────────────────────────────────────────────────────────────────────────
# Postman Collection v2
# ──────────────────────────────────────────────────────────────────────────

def parse_postman(collection: dict, fallback_base: str = "") -> ApiSeedData:
    """Postman Collection v2 dict をシードへ（純粋関数）。

    ``{{baseUrl}}`` 等のコレクション変数を解決してから URL を組む。未解決のまま
    だとスコープ判定で非 HTTP として落ち、``--api-spec`` が無言で取りこぼす。
    """
    seed = ApiSeedData()
    seen: set[str] = set()
    varmap = _collection_var_map(collection)

    def _walk(items: list, inherited_auth=None):
        for it in items or []:
            if not isinstance(it, dict):
                continue
            if "item" in it:  # フォルダ → 再帰（フォルダ auth を継承）
                _walk(it.get("item", []), it.get("auth") or inherited_auth)
                continue
            req = it.get("request")
            if not isinstance(req, dict):
                continue
            url = _postman_url(req.get("url"), varmap, fallback_base)
            method = (req.get("method") or "GET").upper()
            # apikey 認証が in:query の場合は URL にキーを付与する（ヘッダ展開だけだと
            # クエリ型 API キーが落ちて未認証になるため）。
            auth_q = _postman_auth_query(req.get("auth") or inherited_auth, varmap)
            if url and auth_q:
                sep = "&" if "?" in url else "?"
                url = f"{url}{sep}{urlencode(auth_q)}"
            if url and url not in seen:
                seen.add(url)
                seed.urls.append(url)
            # リクエストヘッダを収集（値中の {{token}} 等も解決）。auth 系は共通
            # ヘッダ（seed.headers）に、安全な必須ヘッダ（X-API-Version/tenant/routing 等）は
            # RequestTemplate に載せる。欠落すると 400/401/404 で API 検査が空振りする。
            req_headers: dict[str, str] = {}
            body_ctype = "application/json"  # raw JSON body の既定 Content-Type
            # Postman ネイティブ auth ブロック（request → folder/collection 継承）を
            # Authorization/API-key ヘッダへ展開する（明示ヘッダがあれば後段で上書き）。
            auth_block = req.get("auth") or inherited_auth
            for hk, hv in _postman_auth_headers(auth_block, varmap).items():
                req_headers[hk] = hv
                seed.headers[hk] = hv
            for h in req.get("header", []) or []:
                name = (h.get("key") or "").strip()
                if not name or h.get("disabled"):
                    continue
                value = _resolve_postman_vars(h.get("value", ""), varmap, "")
                # 未解決の {{...}}（環境変数など collection 外の値）は採用しない。
                # "Bearer {{token}}" を seed.headers に入れると HeaderManager.update が
                # 利用者の --header の Authorization をリテラル値で上書きしてしまうため。
                if "{{" in value:
                    continue
                low = name.lower()
                if low == "content-type":
                    # raw JSON の宣言メディアタイプ（vendor/patch JSON 含む）を保持し、
                    # RequestTemplate に伝える（application/json 固定で 415 になるのを防ぐ）。
                    if value and "json" in value.lower():
                        body_ctype = value
                    continue
                if low in ("authorization", "x-api-key", "x-auth-token"):
                    seed.headers[name] = value
                    req_headers[name] = value
                elif low not in ("cookie", "content-length", "host",
                                 "content-type", "accept"):
                    req_headers[name] = value
                    # URL-only(GET 等, body 無し)の必須ヘッダ（X-Tenant/X-API-Version 等)も
                    # クロール/全リクエストへ効くよう共通ヘッダに反映する。RequestTemplate は
                    # body 操作にしか作られないため、ここで seed.headers にも載せないと
                    # GET シードが必須ヘッダ無しで叩かれて 400/401/404 になる。
                    seed.headers[name] = value
            # JSON ボディ。collection 変数を json.loads 前に解決する
            # （`{"id": {{userId}}}` は未解決だと不正 JSON で落ち、`{{userEmail}}`
            # はリテラルのまま送られてしまうため）。ボディに origin は補わない。
            body = req.get("body") or {}
            if body.get("mode") == "raw" and url:
                raw = _resolve_postman_vars(body.get("raw", ""), varmap, "")
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        seed.requests.append(
                            RequestTemplate(method=method, url=url, json_body=parsed,
                                            headers=dict(req_headers),
                                            content_type=body_ctype)
                        )
                except (json.JSONDecodeError, TypeError):
                    pass

    _walk(collection.get("item", []), collection.get("auth"))
    return seed


def _postman_auth_headers(auth: Any, varmap: dict) -> dict[str, str]:
    """Postman の auth ブロックを Authorization/API-key ヘッダへ展開する（純粋）。

    bearer / apikey(header) / basic に対応。値の ``{{var}}`` は解決し、未解決のまま
    なら採用しない（利用者の --header を壊さない）。
    """
    if not isinstance(auth, dict):
        return {}
    atype = auth.get("type")
    items = auth.get(atype) if isinstance(auth.get(atype), list) else []
    kv: dict[str, str] = {}
    for it in items:
        if isinstance(it, dict) and it.get("key") is not None:
            kv[str(it["key"])] = _resolve_postman_vars(str(it.get("value", "")), varmap, "")

    def _ok(*vals: str) -> bool:
        return all(v and "{{" not in v for v in vals)

    if atype == "bearer":
        tok = kv.get("token", "")
        if _ok(tok):
            return {"Authorization": f"Bearer {tok}"}
    elif atype == "apikey":
        loc = (kv.get("in") or "header").lower()
        keyname = kv.get("key") or "X-API-Key"
        val = kv.get("value", "")
        if loc == "header" and _ok(keyname, val):
            return {keyname: val}
    elif atype == "basic":
        import base64
        user = kv.get("username", "")
        pw = kv.get("password", "")
        if _ok(user) or _ok(pw):
            if "{{" not in user and "{{" not in pw:
                token = base64.b64encode(f"{user}:{pw}".encode()).decode()
                return {"Authorization": f"Basic {token}"}
    return {}


def _postman_auth_query(auth: Any, varmap: dict) -> dict[str, str]:
    """Postman の apikey(in:query) 認証をクエリ {key: value} へ展開する（純粋）。

    header 型や bearer/basic は ``_postman_auth_headers`` 側で扱う。未解決変数は除外。
    """
    if not isinstance(auth, dict) or auth.get("type") != "apikey":
        return {}
    items = auth.get("apikey") if isinstance(auth.get("apikey"), list) else []
    kv: dict[str, str] = {}
    for it in items:
        if isinstance(it, dict) and it.get("key") is not None:
            kv[str(it["key"])] = _resolve_postman_vars(str(it.get("value", "")), varmap, "")
    if (kv.get("in") or "header").lower() != "query":
        return {}
    keyname = kv.get("key") or "api_key"
    val = kv.get("value", "")
    if keyname and val and "{{" not in keyname and "{{" not in val:
        return {keyname: val}
    return {}


def _collection_var_map(collection: dict) -> dict[str, str]:
    """Postman コレクションの ``variable`` 定義を {key: value} に（純粋）。"""
    out: dict[str, str] = {}
    for v in collection.get("variable", []) or []:
        if isinstance(v, dict) and v.get("key"):
            out[str(v["key"])] = str(v.get("value", ""))
    return out


def _resolve_postman_vars(raw: str, varmap: dict, fallback_base: str) -> str:
    """``{{var}}`` をコレクション変数→fallback の順で解決する（純粋）。"""
    if not raw:
        return raw
    for key, val in (varmap or {}).items():
        if val:
            raw = raw.replace("{{" + key + "}}", val)
    if "{{" in raw and fallback_base:
        origin = "{u.scheme}://{u.netloc}".format(u=urlparse(fallback_base))
        # (A) scheme://<authority に変数を含む>（例: https://{{host}}/users、
        #     {{baseUrl}} を host list で組んだ https://{{baseUrl}}/path）。
        #     authority ごと fallback origin に置換し、"https:///users" 化を防ぐ。
        m = re.match(r"^[a-zA-Z][\w+.\-]*://[^/]*", raw)
        if m and "{{" in m.group(0):
            raw = origin + raw[m.end():]
        # (B) 先頭の変数のみ（scheme 無し。例: {{baseUrl}}/users）→ origin に置換
        raw = re.sub(r"^\{\{[^}]+\}\}", origin, raw)
        # 残るパス中の未解決変数は除去（パス断片のみ残す）
        raw = re.sub(r"\{\{[^}]+\}\}", "", raw)
    return raw


def _postman_url(url_field: Any, varmap: Optional[dict] = None, fallback_base: str = "") -> str:
    """Postman の url（文字列 or {raw,host,path}）を URL 文字列に（純粋）。

    ``{{var}}`` はコレクション変数／fallback_base で解決してから返す。
    """
    varmap = varmap or {}

    def _finalize(u: str) -> str:
        u = _resolve_postman_vars(u, varmap, fallback_base)
        if u and not u.startswith(("http://", "https://")) and fallback_base:
            # ホストの無い相対 URL は scan 対象の origin を補う
            origin = "{u.scheme}://{u.netloc}".format(u=urlparse(fallback_base))
            u = origin.rstrip("/") + "/" + u.lstrip("/")
        return u if u.startswith(("http://", "https://")) else ""

    if isinstance(url_field, str):
        return _finalize(url_field)
    if isinstance(url_field, dict):
        raw = url_field.get("raw")
        if raw:
            resolved = _finalize(raw)
            if resolved:
                return resolved
        host = url_field.get("host")
        path = url_field.get("path")
        if host:
            host_s = ".".join(host) if isinstance(host, list) else str(host)
            path_s = "/".join(str(p) for p in path) if isinstance(path, list) else str(path or "")
            # host 変数を先に解決する。``{{baseUrl}}`` が絶対 URL（https://...）に
            # 解決される場合、``scheme://`` を前置すると "https://https://..." と
            # 壊れてスコープ外になるため、絶対値ならそのまま基底にする。
            host_resolved = _resolve_postman_vars(host_s, varmap, "")
            if host_resolved.startswith(("http://", "https://")):
                base = host_resolved.rstrip("/")
            else:
                scheme = url_field.get("protocol") or "https"
                base = f"{scheme}://{host_resolved}"
            built = f"{base}/{path_s}".rstrip("/")
            # query 配列があれば付与する（raw が無い URL オブジェクトで必須クエリ
            # — api-version/tenant/filter 等 — を落とさない）。
            query = url_field.get("query")
            if isinstance(query, list):
                # 変数は urlencode の前に解決する。先に encode すると {{apiVersion}} が
                # %7B%7B...%7D%7D になり _resolve_postman_vars が見つけられず未解決の
                # まま送られて 400/404 になる。
                pairs = [
                    (
                        _resolve_postman_vars(str(q.get("key")), varmap, ""),
                        _resolve_postman_vars(str(q.get("value", "")), varmap, ""),
                    )
                    for q in query
                    if isinstance(q, dict) and q.get("key") and not q.get("disabled")
                ]
                if pairs:
                    built = f"{built}?{urlencode(pairs)}"
            # 残るパス変数や未解決 authority 変数を fallback origin 等で解決
            built = _resolve_postman_vars(built, varmap, fallback_base)
            if "{{" not in built:
                return built
    return ""


# ──────────────────────────────────────────────────────────────────────────
# 入口
# ──────────────────────────────────────────────────────────────────────────

def _detect_and_parse(data: dict, fallback_base: str = "") -> ApiSeedData:
    """dict の中身から OpenAPI か Postman かを判定して解析する（純粋）。"""
    if "swagger" in data or "openapi" in data or "paths" in data:
        return parse_openapi(data, fallback_base)
    if "item" in data and isinstance(data.get("item"), list):
        return parse_postman(data, fallback_base)
    # info.schema が Postman のことがある
    info = data.get("info", {})
    if isinstance(info, dict) and "postman" in str(info.get("schema", "")).lower():
        return parse_postman(data, fallback_base)
    # 既定は OpenAPI として試す
    return parse_openapi(data, fallback_base)


class ApiSpecImporter:
    """OpenAPI/Swagger/Postman ファイルを解析してシードを生成する。"""

    def load(self, spec_path: str, fallback_base: str = "") -> ApiSeedData:
        p = Path(spec_path)
        if not p.exists():
            raise FileNotFoundError(f"API スペックが見つかりません: {spec_path}")
        text = p.read_text(encoding="utf-8")
        data = _load_structured(text, p.suffix.lower())
        if not isinstance(data, dict):
            raise ValueError("API スペックの形式を解釈できません（dict ではありません）")
        return _detect_and_parse(data, fallback_base)


def _load_structured(text: str, suffix: str) -> Any:
    """JSON / YAML どちらかとして読み込む（YAML 未導入なら JSON のみ）。"""
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore

            return yaml.safe_load(text)
        except ImportError as exc:  # pragma: no cover
            raise ValueError("YAML スペックの読込には PyYAML が必要です") from exc
    # まず JSON、失敗したら YAML を試す
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore

            return yaml.safe_load(text)
        except Exception as exc:
            raise ValueError(f"API スペックの解析に失敗しました: {exc}") from exc
