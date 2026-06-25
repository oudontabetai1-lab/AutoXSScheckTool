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
        if url:
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

            # path パラメータのスキーマ表を作る
            path_schemas = {
                p.get("name"): (p.get("schema") or p)
                for p in params
                if p.get("in") == "path" and p.get("name")
            }
            concrete_path = _fill_path(raw_path, path_schemas)

            # query パラメータを集める
            query_pairs: list[tuple[str, str]] = []
            for p in params:
                if p.get("in") != "query" or not p.get("name"):
                    continue
                schema = p.get("schema") or p
                query_pairs.append((p["name"], str(_sample_for_name(p["name"], schema))))

            body_schema = _openapi_request_body_schema(op, spec)
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
                # requestBody(JSON) を持つ操作は RequestTemplate に
                if is_body_op:
                    url_no_query = (base + concrete_path) if base else concrete_path
                    seed.requests.append(
                        RequestTemplate(
                            method=method.upper(),
                            url=url_no_query,
                            json_body=example,
                        )
                    )

    return seed


def _openapi_request_body_schema(op: dict, spec: Optional[dict] = None) -> Optional[dict]:
    """操作の JSON requestBody スキーマを取り出す（OpenAPI3 / Swagger2 両対応）。

    ``requestBody`` 自体が ``$ref``（``#/components/requestBodies/X``）の component
    参照のことがあるため、先に解決してから ``content`` を見る。解決しないと
    component ベースの spec で RequestTemplate が作られず mass_assignment が
    JSON エンドポイントを取りこぼす。
    """
    # OpenAPI 3.x
    rb = op.get("requestBody")
    if isinstance(rb, dict):
        if "$ref" in rb:
            rb = _resolve_ref(spec, rb["$ref"]) or {}
        content = rb.get("content", {}) or {}
        for ctype, media in content.items():
            if "json" in (ctype or "").lower():
                return (media or {}).get("schema") or {}
    # Swagger 2.0: parameters[in=body].schema
    for p in op.get("parameters", []) or []:
        if p.get("in") == "body":
            return p.get("schema") or {}
    return None


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

    def _walk(items: list):
        for it in items or []:
            if not isinstance(it, dict):
                continue
            if "item" in it:  # フォルダ → 再帰
                _walk(it.get("item", []))
                continue
            req = it.get("request")
            if not isinstance(req, dict):
                continue
            url = _postman_url(req.get("url"), varmap, fallback_base)
            method = (req.get("method") or "GET").upper()
            if url and url not in seen:
                seen.add(url)
                seed.urls.append(url)
            # ヘッダ（Authorization など）
            for h in req.get("header", []) or []:
                name = (h.get("key") or "").strip()
                if name.lower() in ("authorization", "x-api-key", "x-auth-token"):
                    seed.headers[name] = h.get("value", "")
            # JSON ボディ
            body = req.get("body") or {}
            if body.get("mode") == "raw" and url:
                raw = body.get("raw", "")
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        seed.requests.append(
                            RequestTemplate(method=method, url=url, json_body=parsed)
                        )
                except (json.JSONDecodeError, TypeError):
                    pass

    _walk(collection.get("item", []))
    return seed


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
        # 先頭の未解決変数（{{baseUrl}} 等）をスキャン対象の origin に置換
        raw = re.sub(r"^\{\{[^}]+\}\}", origin, raw)
        # 残る未解決変数は除去（パス断片のみ残す）
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
            scheme = url_field.get("protocol") or "https"
            built = f"{scheme}://{host_s}/{path_s}".rstrip("/")
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
