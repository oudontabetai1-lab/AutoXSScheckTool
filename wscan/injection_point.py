"""注入点を表す純粋な内部モデルと JSON Pointer ヘルパー。"""
from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from typing import Any


def unescape_token(token: str) -> str:
    """RFC6901 のトークンをデコードする。"""
    return token.replace("~1", "/").replace("~0", "~")


def escape_token(token: str) -> str:
    """RFC6901 のトークンへエンコードする。"""
    return token.replace("~", "~0").replace("/", "~1")


def parse_pointer(pointer: str) -> list[str]:
    """JSON Pointer 文字列を参照トークン列へ変換する。"""
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise ValueError("JSON Pointer は '/' で始まる必要があります")
    return [unescape_token(token) for token in pointer[1:].split("/")]


def build_pointer(tokens: list[str]) -> str:
    """参照トークン列から JSON Pointer 文字列を構築する。"""
    return "".join(f"/{escape_token(token)}" for token in tokens)


def enumerate_leaf_pointers(
    doc: Any,
    *,
    max_pointers: int = 200,
    max_depth: int = 8,
) -> list[str]:
    """JSON 文書の全スカラ葉への JSON Pointer を**幅優先**で列挙する（純粋）。

    ``max_depth`` はルートからのトークン数で数える。空の dict/list は注入先に
    ならないため列挙せず、上限到達時はそれまでの決定的な順序を保って打ち切る。
    **幅優先**にするのは、深さ優先だと先頭キーが巨大な部分木（例: 250 要素の配列）だと
    pointer_cap を使い切って後続の浅い攻撃対象フィールド（例: 末尾の promo_code）が丸ごと
    列挙されないため（#90 FN-C）。幅優先なら浅い葉が先に確保される。
    """
    pointers: list[str] = []
    try:
        pointer_cap = max(0, int(max_pointers))
        depth_cap = max(0, int(max_depth))
    except (TypeError, ValueError, OverflowError):
        return pointers
    if pointer_cap == 0:
        return pointers

    try:
        from collections import deque
        queue: deque = deque()
        queue.append((doc, []))
        while queue and len(pointers) < pointer_cap:
            node, tokens = queue.popleft()
            if len(tokens) > depth_cap:
                continue
            if isinstance(node, dict):
                for key, value in node.items():
                    queue.append((value, tokens + [str(key)]))
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    queue.append((value, tokens + [str(index)]))
            elif isinstance(node, (str, int, float, bool)) or node is None:
                pointers.append(build_pointer(tokens))
    except Exception:
        # 観測データが JSON 互換でない場合も、harvest 全体へ例外を漏らさない。
        pass
    return pointers


def _list_index(token: str) -> int:
    """配列用トークンを添字へ変換する。"""
    if not token.isdigit():
        raise IndexError(token)
    return int(token)


def pointer_get(doc: Any, pointer: str) -> Any:
    """文書から JSON Pointer が指す値を取得する。"""
    current = doc
    for token in parse_pointer(pointer):
        if isinstance(current, dict):
            current = current[token]
        elif isinstance(current, list):
            current = current[_list_index(token)]
        else:
            raise KeyError(token)
    return current


def pointer_set_copy(doc: Any, pointer: str, value: Any) -> Any:
    """文書を深く複製し、JSON Pointer が指す値だけを置換する。"""
    tokens = parse_pointer(pointer)
    if not tokens:
        return deepcopy(value)

    copied = deepcopy(doc)
    parent = copied
    for token in tokens[:-1]:
        if isinstance(parent, dict):
            parent = parent[token]
        elif isinstance(parent, list):
            parent = parent[_list_index(token)]
        else:
            raise KeyError(token)

    leaf = tokens[-1]
    if isinstance(parent, dict):
        if leaf not in parent:
            raise KeyError(leaf)
        parent[leaf] = deepcopy(value)
    elif isinstance(parent, list):
        parent[_list_index(leaf)] = deepcopy(value)
    else:
        raise KeyError(leaf)
    return copied


def redact_body_except(doc: Any, keep_pointer: str, mask: str = "***") -> Any:
    """注入 pointer の葉だけ残し、他の全ての葉を mask で伏せた複製を返す（純粋）。

    観測テンプレの兄弟フィールド(password/token 等)が Finding.request.post_data として
    report/checkpoint/monitor へ平文で残るのを防ぐ(落とし穴8)。注入した値は自前の payload で
    秘匿ではないため残し、再現時に「どの pointer に何を入れたか」は読めるようにする。
    注入 pointer **以下**(compound payload の子孫含む)は全て残し、それ以外の葉を mask する。
    注入値が dict/list（例 NoSQL の {"$ne": "MARKER"}）でも payload の中身を潰さない。
    """
    keep_tokens = parse_pointer(keep_pointer)
    if not keep_tokens:
        # 空ポインタ=ドキュメント全体が注入 payload（兄弟テンプレは無い）→何も伏せない。
        return deepcopy(doc)

    def _at_or_below_injection(path: list[str]) -> bool:
        # 注入 pointer と一致、またはその子孫（compound payload の中身）なら残す。
        return path[: len(keep_tokens)] == keep_tokens

    def _walk(node: Any, path: list[str]) -> Any:
        if _at_or_below_injection(path):
            return deepcopy(node)
        if isinstance(node, dict):
            return {k: _walk(v, path + [k]) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(v, path + [str(i)]) for i, v in enumerate(node)]
        return mask

    return _walk(deepcopy(doc), [])


def sibling_string_values(doc: Any, keep_pointer: str) -> list[str]:
    """注入 pointer 以外の**文字列**葉の値を列挙する（純粋）。

    エコー系エンドポイントは送信 body をレスポンスに反射することがあり、その本文が
    Finding の response_body_excerpt として checkpoint/report/monitor へ永続/配信される。
    レスポンス証跡から**既知の兄弟秘匿値を伏せる**ために、伏せ対象の値を集める。
    非文字列葉(数値/bool/None)は誤マスク(response 中の "1"/"true" 等)を避けて除外する
    （数値秘匿は低感度かつ過剰マスクの害が大きいため対象外。実配線する PR-b で要否を再検討）。
    空ポインタ=doc 全体が注入 payload なので兄弟は無い（[] を返す）。
    """
    keep_tokens = parse_pointer(keep_pointer)
    if not keep_tokens:
        return []
    out: list[str] = []

    def _at_or_below_injection(path: list[str]) -> bool:
        # 注入 pointer 以下（compound payload の子孫含む）は兄弟ではない。
        return path[: len(keep_tokens)] == keep_tokens

    def _walk(node: Any, path: list[str]) -> None:
        if _at_or_below_injection(path):
            return
        if isinstance(node, dict):
            for k, v in node.items():
                _walk(v, path + [k])
        elif isinstance(node, list):
            for i, v in enumerate(node):
                _walk(v, path + [str(i)])
        else:
            if isinstance(node, str) and node:
                out.append(node)

    _walk(doc, [])
    return out


def _secret_representations(secret: str) -> set[str]:
    """秘匿文字列がレスポンス本文に現れ得る表現を返す（純粋）。

    JSON 直列化は引用符/バックスラッシュ/改行/非ASCII をエスケープするため、生文字列だけを
    置換すると符号化済みの出現（例 `pa\\"ss`、`caf\\u00e9`）を取りこぼす。生形＋
    JSON エスケープ形(ensure_ascii 両方)を候補にする。
    """
    reps = {secret}
    for ensure_ascii in (False, True):
        try:
            reps.add(json.dumps(secret, ensure_ascii=ensure_ascii)[1:-1])
        except (TypeError, ValueError):
            pass
    return {r for r in reps if r}


def redact_known_secrets(text: str, secrets, mask: str = "***") -> str:
    """text 中の既知秘匿値を、符号化違いも含め mask に置換する（純粋）。

    判定は生レスポンス側で済ませ、証跡（永続/配信される本文）側だけを伏せる用途。
    注入した payload marker や SQL エラー等の脆弱性シグナルは兄弟値ではないので消えない。
    各秘匿の生形＋JSON エスケープ形を候補にし、部分被りを避けるため長い順に置換する。
    """
    if not text:
        return text
    reps: set[str] = set()
    for secret in secrets:
        if secret:
            reps |= _secret_representations(secret)
    for rep in sorted(reps, key=len, reverse=True):
        text = text.replace(rep, mask)
    return text


@dataclass(frozen=True)
class InjectionPoint:
    """注入点(endpoint × parameter)の不変記述子。ADR-0008 内部層の第一歩。"""

    location: str
    url: str
    parameter_id: str
    display_name: str = ""
    method: str = ""
    form_index: int = 0
    dom_index: int = -1
    template_id: str = ""
    source: str = ""

    @property
    def submit_index(self) -> int:
        """ブラウザ DOM 参照に渡す実 form index。未指定なら form_index を使う。"""
        return self.dom_index if self.dom_index >= 0 else self.form_index

    def legacy_is_url_param(self) -> bool:
        """form/url_param のみ bool を返す。json_body は例外（form 経路への暗黙落ちを封じる）。"""
        if self.location == "url_param":
            return True
        if self.location == "form":
            return False
        raise ValueError(
            "legacy_is_url_param() は json_body に使えない: "
            f"location={self.location!r}"
        )

    def stable_key_parts(self) -> tuple[str, str, str, str, str]:
        """既存互換の checkpoint キー生成に必要な部品を返す。"""
        norm_url = (self.url or "").rstrip("/")
        field_name = self.display_name or self.parameter_id
        if self.location == "form":
            location_token, pointer = "f", ""
        elif self.location == "url_param":
            location_token, pointer = "u", ""
        else:
            location_token = f"j:{self.method.upper()}"
            pointer = self.parameter_id
        return norm_url, field_name, str(self.form_index), location_token, pointer

    @classmethod
    def for_form(
        cls,
        url: str,
        field_name: str,
        form_index: int = 0,
        source: str = "crawl",
        dom_index: int = -1,
    ) -> "InjectionPoint":
        """従来フォーム用の注入点を作る。"""
        return cls(
            location="form",
            url=url,
            parameter_id=field_name,
            display_name=field_name,
            form_index=form_index,
            dom_index=dom_index,
            source=source,
        )

    @classmethod
    def for_url_param(
        cls,
        url: str,
        param_name: str,
        source: str = "crawl",
    ) -> "InjectionPoint":
        """従来 URL パラメータ用の注入点を作る。"""
        return cls(
            location="url_param",
            url=url,
            parameter_id=param_name,
            display_name=param_name,
            source=source,
        )

    @classmethod
    def for_json_body(
        cls,
        method: str,
        url: str,
        pointer: str,
        *,
        display_name: str = "",
        template_id: str = "",
        source: str = "spa",
    ) -> "InjectionPoint":
        """JSON body 用の注入点を作る。"""
        tokens = parse_pointer(pointer)
        resolved_name = display_name or (tokens[-1] if tokens else pointer)
        return cls(
            location="json_body",
            url=url,
            parameter_id=pointer,
            display_name=resolved_name,
            method=method.upper(),
            template_id=template_id,
            source=source,
        )
