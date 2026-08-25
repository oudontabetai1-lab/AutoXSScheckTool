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


# アプリバンドルらしい script src の痕跡（ハッシュ付きファイル名 / 既知の SPA アセット
# ディレクトリ / 既知のバンドル語）。analytics.js 等の無関係 script を bundle 扱いしない
# （Codex #104 P2）。_scan_markup が実 <script> の src 値に対して用いる。
_BUNDLE_HINT_RE = re.compile(
    r"(?:/_next/|/_nuxt/|/assets/|/static/js/|/build/|/dist/"
    r"|[.-][0-9a-f]{6,}\.m?js(?:$|[?#])"
    r"|\b(?:bundle|runtime|polyfills|vendor|chunk|webpack|entry)[.\-/])",
    flags=re.I,
)


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


def _strip_js_strings_comments(js: str) -> str:
    """JS ソースから文字列リテラルと行/ブロックコメントを空白へ置換する（軽量字句）。

    実行 script の文字列/コメント内に置かれた framework 構文
    （const x = "self.__next_f.push([])" や // self.__next_f…）を実行式と誤認しない
    （Codex #104 P2）。regex リテラルは扱わないが、対象マーカーは識別子/プロパティ
    アクセスなので実害は無い。
    """
    out: list[str] = []
    i, n = 0, len(js)
    while i < n:
        c = js[i]
        if c in "\"'`":
            q = c
            i += 1
            while i < n:
                if js[i] == "\\":
                    i += 2
                    continue
                if js[i] == q:
                    i += 1
                    break
                i += 1
            out.append(" ")
            continue
        if c == "/" and i + 1 < n:
            if js[i + 1] == "/":
                j = js.find("\n", i)
                i = j if j >= 0 else n
                out.append(" ")
                continue
            if js[i + 1] == "*":
                j = js.find("*/", i + 2)
                i = (j + 2) if j >= 0 else n
                out.append(" ")
                continue
        out.append(c)
        i += 1
    return "".join(out)


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
                # 外部 script（src あり）は本文が実行されず外部リソースが走るので、
                # 本文の JS 式マーカーは収集しない（Codex #104 P2）。
                # type は属性を引用を尊重してパースし、MIME の essence（; 以降の
                # パラメータを除いた本体）で比較する。text/javascript; charset=utf-8 の
                # ような実行可能 type を除外しない（Codex #104 P2）。
                stype = (_get_attr(text, "type") or "").split(";", 1)[0].strip().lower()
                # src 属性が「存在」すれば（src="" や bare src も含む）本文は実行されない。
                if not _has_attr(text, "src") and stype in _EXECUTABLE_SCRIPT_TYPES:
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
# iframe の fallback body や xmp/noembed/noframes の本文はブラウザが実行/レンダリング
# せず、中の <script> も実行しない。これらを inert に含めないと _script_bodies が中の
# マーカーを拾い、inert 領域の早期 close にもなる（Codex #104 P2）。
_INERT_TAGS = (
    "template", "script", "style", "noscript", "textarea", "title",
    "iframe", "xmp", "noembed", "noframes",
)
# raw-text 要素は本文がリテラル（最初の </tag> で閉じる。コメント/入れ子タグは効かない）。
_RAWTEXT_TAGS = (
    "script", "style", "textarea", "title", "iframe", "xmp", "noembed", "noframes",
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


def _has_attr(tag_text: str, name: str) -> bool:
    """開始タグに属性 ``name`` が**存在**するか（値の有無に関わらず）。

    ``_get_attr`` は欠落と ``src=""``/bare ``src`` を同じ falsy で返すが、ブラウザは
    ``src`` 属性があれば外部 script として本文を無視する。presence を値と別に判定する
    （Codex #104 P2）。引用属性値を先に除去し、値の中の ``src=`` を誤検出しない。
    """
    stripped = re.sub(r"\"[^\"]*\"|'[^']*'", "", tag_text)
    return re.search(
        rf"(?<![\w-]){re.escape(name)}(?:\s*=|[\s/>]|$)", stripped, flags=re.I
    ) is not None


_MOUNT_IDS = ("root", "app", "__next", "__nuxt")


def _scan_markup(markup: str) -> dict:
    """markup（inert 除去済み）を実開始タグ単位で走査し、タグ/属性ベースの SPA マーカーを
    集める。引用属性値内のタグ形テキスト（<div title='<script id="__NEXT_DATA__">'> 等）を
    実タグ/実属性と誤認しない（Codex #104 P2）。"""
    sig = {
        "app_root": False, "ids": set(), "empty_mount_ids": set(),
        "ng_app": False, "ng_version": False, "nghost": False, "ngcontent": False,
        "data_reactroot": False, "data_nuxt_data": False, "data_v": False,
        "next_data_script": False, "nuxt_data_script": False,
        "bundle_src": False, "react_src": False, "vue_src": False,
    }
    tokens = []
    pos, n = 0, len(markup)
    while pos < n:
        tk = _next_tag(markup, pos)
        if not tk:
            break
        tokens.append(tk)
        pos = tk[4]
    for i, tk in enumerate(tokens):
        kind, name, text, s, e = tk
        if kind != "starttag":
            continue
        if name == "script":
            # script 固有マーカー（id=__NEXT_DATA__/__NUXT_DATA__、bundle/react/vue src）。
            # script の id/data-* は mount マーカーではないので下の汎用処理には回さない。
            sid = (_get_attr(text, "id") or "").strip().lower()
            if sid == "__next_data__":
                sig["next_data_script"] = True
            if sid == "__nuxt_data__":
                sig["nuxt_data_script"] = True
            src = _get_attr(text, "src")
            if src:
                if _BUNDLE_HINT_RE.search(src):
                    sig["bundle_src"] = True
                if re.search(r"react(?:-dom)?[^'\"]*\.js", src, flags=re.I):
                    sig["react_src"] = True
                if re.search(r"vue[^'\"]*\.js", src, flags=re.I):
                    sig["vue_src"] = True
            continue
        if name in _INERT_TAGS:
            # <template>/<noscript>/<style>/<textarea>/<title> の開始タグは
            # レンダリングされる framework 要素ではないので、その id/属性を mount /
            # framework マーカーにしない（<template id="__next"> 等・Codex #104 P2）。
            continue
        # 属性「名」だけを見るため引用属性値を除去（値内の擬似属性を無視）。
        names_only = re.sub(r"\"[^\"]*\"|'[^']*'", "", text)
        if name == "app-root":
            sig["app_root"] = True
        idv = _get_attr(text, "id")
        if idv is not None:
            lid = idv.strip().lower()
            sig["ids"].add(lid)
            if lid in _MOUNT_IDS and i + 1 < len(tokens):
                nk, nn, _, ns, _ = tokens[i + 1]
                if nk == "endtag" and nn == name and markup[e:ns].strip() == "":
                    sig["empty_mount_ids"].add(lid)
        if re.search(r"(?<![\w-])ng-app(?:[\s=/>]|$)", names_only, re.I):
            sig["ng_app"] = True
        if re.search(r"(?<![\w-])ng-version\s*=", names_only, re.I):
            sig["ng_version"] = True
        if re.search(r"(?<![\w-])_nghost(?:-[\w-]+)?(?:[\s=/>]|$)", names_only, re.I):
            sig["nghost"] = True
        if re.search(r"(?<![\w-])_ngcontent(?:-[\w-]+)?(?:[\s=/>]|$)", names_only, re.I):
            sig["ngcontent"] = True
        if re.search(r"(?<![\w-])data-reactroot(?:[\s=/>]|$)", names_only, re.I):
            sig["data_reactroot"] = True
        if re.search(r"(?<![\w-])data-nuxt-data(?:[\s=/>]|$)", names_only, re.I):
            sig["data_nuxt_data"] = True
        if re.search(r"(?<![\w-])data-v-[\w-]+", names_only, re.I):
            sig["data_v"] = True
    return sig




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
    # raw-text 要素は本文がリテラルなので、最初の </tag> が close（引用属性内で誤認する
    # 余地はない・入れ子タグも効かない）。
    if tag_l in _RAWTEXT_TAGS:
        m = re.compile(rf"</{re.escape(tag)}\s*>", flags=re.I).search(source, start)
        return (m.start(), m.end()) if m else (n, n)
    # parsed-content（template/noscript）: 引用尊重の _next_tag で実タグだけを歩き、
    # 引用属性値内の </template> 等を実 close と誤認しない（Codex #104 P2）。コメントは
    # 飛ばし、入れ子 raw-text サブツリーは丸ごと飛ばし、同名タグの深さを数える。
    depth = 1
    pos = start
    while pos < n:
        tk = _next_tag(source, pos)
        if not tk:
            return (n, n)
        kind, name, text, s, e = tk
        if kind == "comment":
            pos = e
        elif kind == "starttag" and name == tag_l:
            depth += 1
            pos = e
        elif kind == "endtag" and name == tag_l:
            depth -= 1
            if depth == 0:
                return (s, e)
            pos = e
        elif kind == "starttag" and name in _RAWTEXT_TAGS:
            _, ce = _find_inert_end(source, name, e)  # 入れ子 raw-text を飛ばす
            pos = ce
        else:
            pos = e
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
    # JS 式マーカーは表示テキスト誤検出を避けるため script 本文だけで探す。さらに JS の
    # 文字列/コメントを除去し、"self.__next_f…" のような文字列/コメント内の構文を
    # 実行式と誤認しない（Codex #104 P2）。
    scripts = _strip_js_strings_comments(_script_bodies(source))
    # inert 要素（template/script/style 等）の本文を空にした版（コメントは残す）。
    # React SSR コメント <!--$--> は inert 内では無効なのでこの版で探す（Codex #104 P2）。
    noninert = _strip_inert_elements(source)
    # markup マーカーは inert 領域（コメント/<template>/<script>本文等）を無害化した
    # 版で探す。<!-- <app-root> --> や var x="<app-root>" で誤判定しない（Codex #104 P2）。
    markup = _COMMENT_RE.sub(" ", noninert)
    # markup のタグ/属性マーカーは実開始タグ単位で評価し、引用属性値内のタグ形テキストを
    # 実タグと誤認しない（Codex #104 P2）。
    tags = _scan_markup(markup)

    angular_signals: list[str] = []
    if tags["app_root"]:
        angular_signals.append("<app-root>")
    if tags["ng_app"]:
        angular_signals.append("ng-app")
    if tags["ng_version"]:
        angular_signals.append("ng-version")
    if tags["nghost"]:
        angular_signals.append("_nghost")
    if tags["ngcontent"]:
        angular_signals.append("_ngcontent")
    # window.ng は JS 式なので script 本文に限定する（Codex #104 P2）。
    if re.search(r"\bwindow\s*\.\s*ng\b", scripts, flags=re.I):
        angular_signals.append("window.ng")
    if angular_signals:
        return SpaInfo(True, "Angular", "high", angular_signals)

    next_signals: list[str] = []
    # __NEXT_DATA__ は <script id="__NEXT_DATA__" type="application/json"> として
    # 出力される。実 <script> の id 属性として照合する（表示テキストや属性値内の
    # タグ形テキストで誤検出しない・Codex #104 P2）。
    if tags["next_data_script"]:
        next_signals.append("__NEXT_DATA__")
    if "__next" in tags["ids"]:
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
    if tags["data_reactroot"]:
        react_signals.append("data-reactroot")
    # SSR / RSC / Suspense の React 固有コメントマーカー（<!--$-->, <!--/$-->,
    # <!--$?-->, <!--$!-->）。hydration 済みで id="root" に内容がある本番 React
    # （空マウント fallback に載らない）でも、これらは React 特有で誤検出しにくい
    # （Codex #104 P1・SSR/Next の本番 React を拾う）。
    if re.search(r"<!--/?\$[?!]?-->", noninert):
        react_signals.append("react-ssr-marker")
    react_root = "root" in tags["ids"] or "app" in tags["ids"]
    # JS トークンは script 本文で、react バンドルの script src は実 <script> の src で照合。
    react_trace = bool(
        re.search(r"React\s*\.\s*createElement|__REACT_DEVTOOLS", scripts, flags=re.I)
        or tags["react_src"]
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
    # data-nuxt-data を吐く。実 <script> の id 属性/実タグで照合する（Codex #104 P2）。
    if tags["nuxt_data_script"]:
        vue_signals.append("__NUXT_DATA__")
        nuxt_marker = True
    if "__nuxt" in tags["ids"]:
        vue_signals.append('id="__nuxt"')
        nuxt_marker = True
    if tags["data_nuxt_data"]:
        vue_signals.append("data-nuxt-data")
        nuxt_marker = True
    if re.search(r"\bwindow\s*\.\s*__VUE__\b", scripts, flags=re.I):
        vue_signals.append("window.__VUE__")
    if tags["data_v"]:
        vue_signals.append("data-v-")
    vue_root = "app" in tags["ids"]
    # JS トークンは script 本文、vue バンドルの script src は実 <script> の src で照合。
    vue_trace = bool(
        re.search(r"createApp\s*\(|new\s+Vue\b", scripts, flags=re.I)
        or tags["vue_src"]
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
    if tags["empty_mount_ids"] and tags["bundle_src"]:
        mount_id = next(
            (m for m in ("__next", "__nuxt", "root", "app") if m in tags["empty_mount_ids"]),
            "app",
        )
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
