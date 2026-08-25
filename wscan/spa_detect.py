"""
SPA Detector
============
HTML 内のフレームワーク固有マーカーから SPA を保守的に判定する。
"""
from __future__ import annotations

import html as _html
import re
from dataclasses import dataclass, field


@dataclass
class SpaInfo:
    """SPA 判定結果。"""

    is_spa: bool
    framework: str = "unknown"
    confidence: str = "low"
    signals: list[str] = field(default_factory=list)


# 開始タグの属性領域を「引用値を跨がずに」消費するプレフィックス。これが無いと
# <div title="id='__next'"> の属性値内の id='__next' を実属性と誤認する（Codex #104 P2）。
# 素の文字・完全な "…" / '…' のいずれかを非貪欲に繰り返す。
_ATTR_PREFIX = r"""(?:[^>"']|"[^"]*"|'[^']*')*?"""


def _has_id(source: str, element_id: str) -> bool:
    """実際の開始タグ内の id 属性として存在するか調べる。

    - ``\\b`` はハイフンの後にも境界を作るため ``data-id="__next"`` を
      ``id="__next"`` と誤認する。negative lookbehind ``(?<![\\w-])`` で除く。
    - 開始タグ ``<tag … id="…" …>`` の内側に限定し、``<pre>id="__next"</pre>`` の
      ような**表示テキスト**を属性と誤認しない（``[^>]*`` は ``>`` を跨がない）。
    - ``_ATTR_PREFIX`` で引用属性値を跨がず、``<div title="id='__next'">`` の
      属性値内 id を誤認しない（Codex #104 P2）。
    """
    return bool(
        re.search(
            rf"<[a-zA-Z]{_ATTR_PREFIX}(?<![\w-])id\s*=\s*(['\"])\s*{re.escape(element_id)}\s*\1",
            source,
            flags=re.I,
        )
    )


# 本番 SPA シェルの「空マウント要素」を検出する（中身が空白のみ）。
# 例: <div id="root"></div> / <main id="app">  </main>。内容を持つ要素
# （<div id="root">案内</div> 等）は一致しないため静的サイトを誤検出しない。
_EMPTY_MOUNT_RE = re.compile(
    # (?<![\w-]) で data-id="root" 等を、_ATTR_PREFIX で引用値内 id を誤認しない（Codex #104 P2）。
    rf"<(\w+)\b{_ATTR_PREFIX}(?<![\w-])id\s*=\s*(['\"])(root|app|__next|__nuxt)\2[^>]*>\s*</\1\s*>",
    flags=re.I | re.S,
)

# アプリバンドルらしい script src。空マウント fallback で「任意の script」を
# 認めると analytics.js 等でも SPA 誤判定するため（Codex #104 P2）、本番バンドラの
# 典型（ハッシュ付きファイル名 / 既知の SPA アセットディレクトリ / 既知のバンドル語）
# に限定する。
# \bsrc は data-src/async-src（ハイフン付き）にも一致し、遅延プレースホルダ
# <script data-src="…">（未ロード）を実バンドルと誤認する。(?<![\w-]) で実 src 属性に
# 限定する（_has_id と同じ・Codex #104 P2）。
_BUNDLE_SRC_RE = re.compile(
    rf"<script\b{_ATTR_PREFIX}(?<![\w-])src\s*=\s*(['\"])([^'\"]+)\1", flags=re.I
)
_BUNDLE_HINT_RE = re.compile(
    r"(?:/_next/|/_nuxt/|/assets/|/static/js/|/build/|/dist/"
    r"|[.-][0-9a-f]{6,}\.m?js(?:$|[?#])"
    r"|\b(?:bundle|runtime|polyfills|vendor|chunk|webpack|entry)[.\-/])",
    flags=re.I,
)


def _has_bundle_script(source: str) -> bool:
    """本番アプリバンドルらしい外部 script が存在するか（無関係な単発 script を除く）。

    ``type="module"`` 単独では判定しない。インラインの analytics/ユーティリティ
    モジュール（src 無し）や無関係な外部モジュールでも真になり、空 #root/#app の
    静的ページを SPA 誤判定するため（Codex #104 P2）。外部 ``src`` がアプリバンドルの
    痕跡（ハッシュ付きファイル名 / 既知の SPA アセットディレクトリ / 既知のバンドル語）を
    持つ場合のみ真とする。
    """
    for m in _BUNDLE_SRC_RE.finditer(source):
        if _BUNDLE_HINT_RE.search(m.group(2)):
            return True
    return False


# 実行される インライン <script> の本文だけを連結する。JS 式マーカー
# （self.__next_f / window.__NUXT__ / React.createElement 等）を HTML 全体で探すと、
# <code>/<pre> の表示テキストや、type="text/plain"/"application/json" のデータブロックで
# 誤検出する。ブラウザが実行する type だけに限定する（Codex #104 P2）。外部 script
# （<script src=…></script>）は本文が空なので寄与しない。
# 実行可能な script type（未指定は JS 扱い）。text/plain・application/json・importmap・
# speculationrules・application/ld+json 等の非実行データブロックは除外する。
_EXECUTABLE_SCRIPT_TYPES = frozenset({
    "", "text/javascript", "application/javascript",
    "text/ecmascript", "application/ecmascript", "module",
})


def _script_bodies(source: str) -> str:
    """実行される（コメント/inert コンテナの外の）top-level script 本文を連結する。

    ``<!-- <script>…</script> -->`` や ``<template><script>…</script></template>`` の
    script はブラウザが実行しないので除外する（Codex #104 P2）。コメントは飛ばし、inert
    コンテナ（template/noscript 等）は ``_find_inert_end`` でサブツリー丸ごと飛ばして、その中の
    script は収集しない。top-level の実行可能 type の script のみ本文を集める。
    """
    bodies: list[str] = []
    pos = 0
    n = len(source)
    while pos < n:
        tk = _next_tag(source, pos)
        if not tk:
            break
        kind, name, text, s, e = tk
        if kind == "comment":
            pos = e  # コメントは実行されないので飛ばす
            continue
        if kind == "starttag" and name in _INERT_TAGS:
            close_start, close_end = _find_inert_end(source, name, e)
            if name == "script":
                # type は属性を引用を尊重してパースする。data-example='type="…"' の
                # 属性値内 type= を実 type と誤認しない（Codex #104 P2）。
                stype = (_get_attr(text, "type") or "").strip().lower()
                if stype in _EXECUTABLE_SCRIPT_TYPES:
                    bodies.append(source[e:close_start])
            pos = close_end  # inert サブツリー（script 含む）を丸ごと飛ばす
        else:
            pos = e  # 非 inert タグは属性値ごと読み飛ばす（属性内の擬似タグを見ない）
    return "\n".join(bodies)


# markup マーカー（<app-root> / data-reactroot / id="…" / 空マウント / script src 等）を
# 判定する前に、実際にはレンダリングされない inert 領域を無害化する。コメントや
# <template>・<script>・<style> の本文に置かれた例（<!-- <app-root> --> や
# var x="<app-root>"）で SPA 誤判定しないため（Codex #104 P2）。タグ自体は残す（script の
# src/id 属性は markup マーカーとして使うため）。React SSR コメント <!--$--> は別途 raw source で
# 判定するのでここでコメントを消しても影響しない。
_INERT_TAGS = ("template", "script", "style", "noscript", "textarea", "title")
# raw-text 要素は本文がリテラル（最初の </tag> で閉じる。コメント/入れ子タグは効かない）。
_RAWTEXT_TAGS = ("script", "style", "textarea", "title")
_RAWTEXT_OPEN_RE = re.compile(
    r"<(" + "|".join(_RAWTEXT_TAGS) + r")(?![\w-])[^>]*>", flags=re.I
)
# HTML コメント。終端 --> が欠落（truncated/malformed 応答）した場合、コメントは
# EOF まで継続する。未終端でも残り全体を「コメント内容」として扱う（Codex #104 P2）。
_COMMENT_RE = re.compile(r"<!--.*?(?:-->|\Z)", flags=re.S)

_TAG_NAME_RE = re.compile(r"/?([a-zA-Z][\w:-]*)")
_ATTR_RE = re.compile(
    r"""(?<![\w-])([\w:-]+)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""", flags=re.I
)


def _next_tag(source: str, pos: int):
    """``pos`` 以降の最初の「実際のタグ/コメント」を返す（引用属性値を尊重）。

    ``(kind, name, tag_text, start, end)``。kind は "starttag"/"endtag"/"comment"。
    開始タグの終端 ``>`` を探すとき引用属性値内の ``>`` や ``<`` を跨がないので、
    ``<div title="<script>…">`` の属性値内 ``<script>`` を実タグと誤認しない（Codex #104 P2）。
    未終端コメントは EOF まで。タグでない ``<`` は読み飛ばす。見つからなければ None。
    """
    n = len(source)
    while pos < n:
        lt = source.find("<", pos)
        if lt < 0:
            return None
        if source.startswith("<!--", lt):
            end = source.find("-->", lt + 4)
            end = end + 3 if end >= 0 else n
            return ("comment", None, source[lt:end], lt, end)
        m = _TAG_NAME_RE.match(source, lt + 1)
        if not m:
            pos = lt + 1
            continue
        is_end = source[lt + 1] == "/"
        name = m.group(1).lower()
        j = m.end()
        while j < n:
            c = source[j]
            if c in "\"'":
                q = source.find(c, j + 1)
                j = q + 1 if q >= 0 else n
            elif c == ">":
                j += 1
                break
            else:
                j += 1
        return (("endtag" if is_end else "starttag"), name, source[lt:j], lt, j)
    return None


def _get_attr(tag_text: str, name: str):
    """開始タグ文字列から属性値を引用を尊重して取り出す（無ければ None）。"""
    name = name.lower()
    for m in _ATTR_RE.finditer(tag_text):
        if m.group(1).lower() == name:
            v = m.group(2)
            if v and v[0] in "\"'":
                v = v[1:-1]
            return v
    return None


def _find_inert_end(source: str, tag: str, start: int) -> tuple[int, int]:
    """``<tag …>`` 直後 ``start`` から対応する閉じタグ位置 ``(close_start, close_end)`` を返す。

    template/noscript のような**parsed-content**要素では、コメント（``<!-- </template> -->``）や
    入れ子の raw-text 要素（``<script>"</template>"</script>``）の中に現れる ``</tag>`` テキストを
    実 close と誤認しないよう、それらのサブツリーを飛ばして同名タグの深さを数える（Codex #104 P2）。
    raw-text 要素（script/style/textarea/title）自身の本文はリテラルなので、最初の ``</tag>`` が close。
    見つからなければ ``(len, len)``（末尾まで inert 扱い）。
    """
    n = len(source)
    tag_l = tag.lower()
    is_rawtext = tag_l in _RAWTEXT_TAGS
    open_re = re.compile(rf"<{re.escape(tag)}(?![\w-])[^>]*>", flags=re.I)
    close_re = re.compile(rf"</{re.escape(tag)}\s*>", flags=re.I)
    depth = 1
    scan = start
    while depth > 0:
        nc = close_re.search(source, scan)
        if not nc:
            return (n, n)
        events: list[tuple[int, str, "re.Match"]] = [(nc.start(), "close", nc)]
        if not is_rawtext:
            no = open_re.search(source, scan)
            if no:
                events.append((no.start(), "open", no))
            cm = _COMMENT_RE.search(source, scan)
            if cm:
                events.append((cm.start(), "comment", cm))
            rt = _RAWTEXT_OPEN_RE.search(source, scan)
            if rt:
                events.append((rt.start(), "rawtext", rt))
        _, kind, m = min(events, key=lambda e: e[0])
        if kind == "close":
            depth -= 1
            if depth == 0:
                return (m.start(), m.end())
            scan = m.end()
        elif kind == "open":
            depth += 1
            scan = m.end()
        elif kind == "comment":
            scan = m.end()
        else:  # rawtext: 入れ子 raw-text サブツリー丸ごと飛ばす
            rclose = re.compile(
                rf"</{re.escape(m.group(1))}\s*>", flags=re.I
            ).search(source, m.end())
            scan = rclose.end() if rclose else n
    return (n, n)


def _strip_inert_elements(source: str) -> str:
    """inert 要素（template/script/style 等）の本文だけ空にする（コメントは残す）。

    <template> や script 文字列の中にある markup 例（<app-root> や <!--$-->）は
    レンダリングされないので、それらの本文を無害化した版で markup / React SSR マーカーを
    探す（Codex #104 P2）。**ネスト対応**: 同名 inert 要素の深さを数え、外側の閉じタグ
    まで（内側の inert サブツリー丸ごと）を空にする。非貪欲 regex では
    ``<template><template></template><app-root></app-root></template>`` の内側 close で
    止まり <app-root> が残るため、手続き的に走査する（別々の inert ブロック間の実コンテンツは
    保持し、真の SPA マーカーを消さない）。開始/終了タグ自体は残す（外部 script の src/id を
    markup マーカーに使うため）。
    """
    result: list[str] = []
    pos = 0
    n = len(source)
    while pos < n:
        tk = _next_tag(source, pos)
        if not tk:
            result.append(source[pos:])
            break
        kind, name, text, s, e = tk
        result.append(source[pos:s])  # タグ前のテキストは残す
        # コメントはそのまま残す（コメント内の <template> 等を live opener と誤認して
        # 以降を破棄すると後続の実 SPA マーカーを見逃す・Codex #104 P2）。
        if kind == "comment":
            result.append(text)
            pos = e
            continue
        # 非 inert タグ（開始/終了）は属性値ごと丸ごと残す。属性値内の擬似 <template>
        # 等を見ないので、_next_tag が引用を尊重して跨いでいる（Codex #104 P2）。
        if kind != "starttag" or name not in _INERT_TAGS:
            result.append(text)
            pos = e
            continue
        # inert 開始タグ: 開始タグを残し、対応する閉じタグまで（内容）を空にする。
        result.append(text)
        close_start, close_end = _find_inert_end(source, name, e)
        result.append(source[close_start:close_end])  # 閉じタグは残す
        pos = close_end
    return "".join(result)


def _inert_stripped(source: str) -> str:
    # markup マーカー用: inert 要素の本文を空にした上で、コメントも除去する。
    s = _strip_inert_elements(source)
    s = _COMMENT_RE.sub(" ", s)
    return s


def _weak_layout_signals(source: str) -> list[str]:
    """単独では SPA と断定しない、汎用的なページ構成シグナルを返す。"""
    signals: list[str] = []
    if not re.search(r"<form\b", source, flags=re.I):
        signals.append("forms=0")

    external_scripts = len(
        re.findall(r"<script\b[^>]*\bsrc\s*=", source, flags=re.I)
    )
    if external_scripts >= 3:
        signals.append(f"external_scripts={external_scripts}")

    visible = re.sub(
        r"<(?:script|style|template|noscript)\b[^>]*>.*?</(?:script|style|template|noscript)\s*>",
        " ",
        source,
        flags=re.I | re.S,
    )
    visible = re.sub(r"<!--.*?-->|<[^>]+>", " ", visible, flags=re.S)
    visible = re.sub(r"\s+", " ", _html.unescape(visible)).strip()
    if len(visible) <= 80:
        signals.append("visible_text_sparse")
    return signals


def detect_spa(html: str) -> SpaInfo:
    """
    HTML のフレームワークマーカーから SPA を判定する。

    フォーム数・外部 script 数・可視テキスト量は補助シグナルとして返すが、
    誤有効化を避けるため、それらだけで ``is_spa=True`` にはしない。
    """
    source = html or ""
    # JS 式マーカーは表示テキスト誤検出を避けるため script 本文だけで探す。
    scripts = _script_bodies(source)
    # inert 要素（template/script/style 等）の本文を空にした版（コメントは残す）。
    # React SSR コメント <!--$--> は inert 内では無効なのでこの版で探す（Codex #104 P2）。
    noninert = _strip_inert_elements(source)
    # markup マーカーは inert 領域（コメント/<template>/<script>本文等）を無害化した
    # 版で探す。<!-- <app-root> --> や var x="<app-root>" で誤判定しない（Codex #104 P2）。
    markup = _COMMENT_RE.sub(" ", noninert)

    angular_signals: list[str] = []
    # 属性/タグベースのマーカー（markup）は inert 除去済みの markup で探す。
    angular_markup = (
        (r"<app-root\b", "<app-root>"),
        (rf"<[a-zA-Z]{_ATTR_PREFIX}(?<![\w-])ng-app(?:\s*=|\s|>)", "ng-app"),
        (rf"<[a-zA-Z]{_ATTR_PREFIX}(?<![\w-])ng-version\s*=", "ng-version"),
        (rf"<[a-zA-Z]{_ATTR_PREFIX}(?<![\w-])_nghost(?:-[\w-]+)?(?:\s*=|\s|>)", "_nghost"),
        (rf"<[a-zA-Z]{_ATTR_PREFIX}(?<![\w-])_ngcontent(?:-[\w-]+)?(?:\s*=|\s|>)", "_ngcontent"),
    )
    for pattern, label in angular_markup:
        if re.search(pattern, markup, flags=re.I):
            angular_signals.append(label)
    # window.ng は JS 式なので script 本文に限定する（Codex #104 P2）。
    if re.search(r"\bwindow\s*\.\s*ng\b", scripts, flags=re.I):
        angular_signals.append("window.ng")
    if angular_signals:
        return SpaInfo(True, "Angular", "high", angular_signals)

    next_signals: list[str] = []
    # __NEXT_DATA__ は <script id="__NEXT_DATA__" type="application/json"> として
    # 出力される。裸トークン一致だと <code>__NEXT_DATA__</code> の表示テキストで
    # 誤検出するため、script の id 属性に限定する（Codex #104 P2）。
    if re.search(
        rf"<script\b{_ATTR_PREFIX}(?<![\w-])id\s*=\s*(['\"])__NEXT_DATA__\1", markup, flags=re.I
    ):
        next_signals.append("__NEXT_DATA__")
    if _has_id(markup, "__next"):
        next_signals.append('id="__next"')
    # App Router（RSC）は __NEXT_DATA__ も id="__next" も出さず、
    # self.__next_f.push(...) のブートストラップだけを吐くことがある。裸の
    # __next_f トークンや <code>self.__next_f.push(...)</code> の表示テキストで誤検出
    # しないよう、script 本文中の実行式（.push / 代入 / ||）に限定する（Codex #104 P2）。
    if re.search(
        r"\bself\s*\.\s*__next_f\s*(?:\.\s*push\b|=|\|\|)", scripts, flags=re.I
    ):
        next_signals.append("self.__next_f")
    if next_signals:
        return SpaInfo(True, "Next.js", "high", next_signals)

    react_signals: list[str] = []
    if re.search(rf"<[a-zA-Z]{_ATTR_PREFIX}(?<![\w-])data-reactroot(?:\s*=|\s|>)", markup, flags=re.I):
        react_signals.append("data-reactroot")
    # SSR / RSC / Suspense の React 固有コメントマーカー（<!--$-->, <!--/$-->,
    # <!--$?-->, <!--$!-->）。hydration 済みで id="root" に内容がある本番 React
    # （空マウント fallback に載らない）でも、これらは React 特有で誤検出しにくい
    # （Codex #104 P1・SSR/Next の本番 React を拾う）。
    if re.search(r"<!--/?\$[?!]?-->", noninert):
        react_signals.append("react-ssr-marker")
    react_root = _has_id(markup, "root") or _has_id(markup, "app")
    # JS トークンは script 本文で、react バンドルの script src は markup（source）で探す。
    react_trace = re.search(
        r"React\s*\.\s*createElement|__REACT_DEVTOOLS", scripts, flags=re.I
    ) or re.search(
        # (?<![\w-])src で data-src/async-src の誤一致を防ぐ（Codex #104 P2）。
        rf"<script\b{_ATTR_PREFIX}(?<![\w-])src\s*=\s*['\"][^'\"]*react(?:-dom)?[^'\"]*\.js",
        markup,
        flags=re.I,
    )
    if react_root and react_trace:
        react_signals.extend(['id="root/app"', "React trace"])
    if react_signals:
        return SpaInfo(True, "React", "high", react_signals)

    vue_signals: list[str] = []
    nuxt_marker = False
    # Nuxt 2 は window.__NUXT__={...} を吐く。裸トークン一致だと解説記事等の表示
    # テキストで誤検出するため、window.__NUXT__ の実行式に限定する（Codex #104 P2）。
    if re.search(r"\bwindow\s*\.\s*__NUXT__\b", scripts, flags=re.I):
        vue_signals.append("window.__NUXT__")
        nuxt_marker = True
    # Nuxt 3 は <script id="__NUXT_DATA__" type="application/json"> / id="__nuxt" /
    # data-nuxt-data を吐く。__NUXT_DATA__ は script の id 属性に限定する（表示テキスト
    # の誤検出回避・Codex #104 P2）。
    if re.search(
        rf"<script\b{_ATTR_PREFIX}(?<![\w-])id\s*=\s*(['\"])__NUXT_DATA__\1", markup, flags=re.I
    ):
        vue_signals.append("__NUXT_DATA__")
        nuxt_marker = True
    if _has_id(markup, "__nuxt"):
        vue_signals.append('id="__nuxt"')
        nuxt_marker = True
    if re.search(rf"<[a-zA-Z]{_ATTR_PREFIX}(?<![\w-])data-nuxt-data(?:\s*=|\s|>)", markup, flags=re.I):
        vue_signals.append("data-nuxt-data")
        nuxt_marker = True
    if re.search(r"\bwindow\s*\.\s*__VUE__\b", scripts, flags=re.I):
        vue_signals.append("window.__VUE__")
    if re.search(rf"<[a-zA-Z]{_ATTR_PREFIX}(?<![\w-])data-v-[\w-]+(?:\s*=|\s|>)", markup, flags=re.I):
        vue_signals.append("data-v-")
    vue_root = _has_id(markup, "app")
    # JS トークンは script 本文、vue バンドルの script src は markup（source）で探す。
    vue_trace = re.search(
        r"createApp\s*\(|new\s+Vue\b", scripts, flags=re.I
    ) or re.search(
        # (?<![\w-])src で data-src/async-src の誤一致を防ぐ（Codex #104 P2）。
        rf"<script\b{_ATTR_PREFIX}(?<![\w-])src\s*=\s*['\"][^'\"]*vue[^'\"]*\.js",
        markup,
        flags=re.I,
    )
    if vue_root and vue_trace:
        vue_signals.extend(['id="app"', "Vue trace"])
    if vue_signals:
        framework = "Nuxt" if nuxt_marker else "Vue"
        return SpaInfo(True, framework, "high", vue_signals)

    # 本番ビルドの SPA シェル: フレームワーク固有マーカーを一切吐かず、
    # 空のマウント要素（id=root/app/__next/__nuxt）＋ハッシュ付きバンドル
    # script だけを持つ（例: 本番 React=<div id="root"></div> + /assets/index-<hash>.js）。
    # 「空マウント」＝サーバ描画済み HTML が無い＝クライアント描画前提の強い証拠なので、
    # 内容を持つ静的サイトを誤有効化せずに本番 SPA を拾える（保守側の維持）。
    shell = _EMPTY_MOUNT_RE.search(markup)
    if shell and _has_bundle_script(markup):
        mount_id = shell.group(3).lower()
        framework = {
            "root": "React",
            "__next": "Next.js",
            "__nuxt": "Nuxt",
        }.get(mount_id, "SPA")
        return SpaInfo(
            True, framework, "high",
            [f'empty id="{mount_id}"', "bundle script"],
        )

    return SpaInfo(False, "unknown", "low", _weak_layout_signals(source))
