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


def _has_id(source: str, element_id: str) -> bool:
    """属性順や引用符に依存せず id の完全一致を調べる。

    ``\\b`` はハイフンの後にも境界を作るため ``data-id="__next"`` を
    ``id="__next"`` と誤認する。ハイフン/英数字が直前に来る属性名（data-id 等）を
    除くため negative lookbehind を使う（Codex #104 P2）。
    """
    return bool(
        re.search(
            rf"(?<![\w-])id\s*=\s*(['\"])\s*{re.escape(element_id)}\s*\1",
            source,
            flags=re.I,
        )
    )


# 本番 SPA シェルの「空マウント要素」を検出する（中身が空白のみ）。
# 例: <div id="root"></div> / <main id="app">  </main>。内容を持つ要素
# （<div id="root">案内</div> 等）は一致しないため静的サイトを誤検出しない。
_EMPTY_MOUNT_RE = re.compile(
    # (?<![\w-]) で data-id="root" 等を id="root" と誤認しない（Codex #104 P2）。
    r"<(\w+)\b[^>]*(?<![\w-])id\s*=\s*(['\"])(root|app|__next|__nuxt)\2[^>]*>\s*</\1\s*>",
    flags=re.I | re.S,
)

# アプリバンドルらしい script src。空マウント fallback で「任意の script」を
# 認めると analytics.js 等でも SPA 誤判定するため（Codex #104 P2）、本番バンドラの
# 典型（ハッシュ付きファイル名 / 既知の SPA アセットディレクトリ / 既知のバンドル語）
# に限定する。
_BUNDLE_SRC_RE = re.compile(r"<script\b[^>]*\bsrc\s*=\s*(['\"])([^'\"]+)\1", flags=re.I)
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

    angular_signals: list[str] = []
    angular_patterns = (
        (r"<app-root\b", "<app-root>"),
        (r"<[^>]+\bng-app(?:\s*=|\s|>)", "ng-app"),
        (r"<[^>]+\bng-version\s*=", "ng-version"),
        (r"<[^>]+\b_nghost(?:-[\w-]+)?(?:\s*=|\s|>)", "_nghost"),
        (r"<[^>]+\b_ngcontent(?:-[\w-]+)?(?:\s*=|\s|>)", "_ngcontent"),
        (r"\bwindow\s*\.\s*ng\b", "window.ng"),
    )
    for pattern, label in angular_patterns:
        if re.search(pattern, source, flags=re.I):
            angular_signals.append(label)
    if angular_signals:
        return SpaInfo(True, "Angular", "high", angular_signals)

    next_signals: list[str] = []
    if re.search(r"\b__NEXT_DATA__\b", source, flags=re.I):
        next_signals.append("__NEXT_DATA__")
    if _has_id(source, "__next"):
        next_signals.append('id="__next"')
    # App Router（RSC）は __NEXT_DATA__ も id="__next" も出さず、
    # self.__next_f.push(...) のブートストラップだけを吐くことがある。裸の
    # __next_f トークン（ドキュメント/エラーページの表示テキスト等）で誤検出しない
    # よう、self.__next_f を用いた実行式（.push / 代入 / ||）に限定する（Codex #104 P2）。
    if re.search(
        r"\bself\s*\.\s*__next_f\s*(?:\.\s*push\b|=|\|\|)", source, flags=re.I
    ):
        next_signals.append("self.__next_f")
    if next_signals:
        return SpaInfo(True, "Next.js", "high", next_signals)

    react_signals: list[str] = []
    if re.search(r"<[^>]+\bdata-reactroot(?:\s*=|\s|>)", source, flags=re.I):
        react_signals.append("data-reactroot")
    # SSR / RSC / Suspense の React 固有コメントマーカー（<!--$-->, <!--/$-->,
    # <!--$?-->, <!--$!-->）。hydration 済みで id="root" に内容がある本番 React
    # （空マウント fallback に載らない）でも、これらは React 特有で誤検出しにくい
    # （Codex #104 P1・SSR/Next の本番 React を拾う）。
    if re.search(r"<!--/?\$[?!]?-->", source):
        react_signals.append("react-ssr-marker")
    react_root = _has_id(source, "root") or _has_id(source, "app")
    react_trace = re.search(
        r"(?:React\s*\.\s*createElement|__REACT_DEVTOOLS|"
        r"<script\b[^>]*\bsrc\s*=\s*['\"][^'\"]*react(?:-dom)?[^'\"]*\.js)",
        source,
        flags=re.I,
    )
    if react_root and react_trace:
        react_signals.extend(['id="root/app"', "React trace"])
    if react_signals:
        return SpaInfo(True, "React", "high", react_signals)

    vue_signals: list[str] = []
    nuxt_marker = False
    if re.search(r"\b__NUXT__\b", source, flags=re.I):
        vue_signals.append("__NUXT__")
        nuxt_marker = True
    # Nuxt 3 は window.__NUXT__ ではなく __NUXT_DATA__ / id="__nuxt" /
    # data-nuxt-data を吐く。__NUXT_DATA__ は \b__NUXT__\b では末尾の
    # 続き（_DATA）が word 文字のため一致しないので、明示的に拾う。
    if re.search(r"\b__NUXT_DATA__\b", source, flags=re.I):
        vue_signals.append("__NUXT_DATA__")
        nuxt_marker = True
    if _has_id(source, "__nuxt"):
        vue_signals.append('id="__nuxt"')
        nuxt_marker = True
    if re.search(r"<[^>]+\bdata-nuxt-data(?:\s*=|\s|>)", source, flags=re.I):
        vue_signals.append("data-nuxt-data")
        nuxt_marker = True
    if re.search(r"\bwindow\s*\.\s*__VUE__\b", source, flags=re.I):
        vue_signals.append("window.__VUE__")
    if re.search(r"<[^>]+\bdata-v-[\w-]+(?:\s*=|\s|>)", source, flags=re.I):
        vue_signals.append("data-v-")
    vue_root = _has_id(source, "app")
    vue_trace = re.search(
        r"(?:createApp\s*\(|new\s+Vue\b|"
        r"<script\b[^>]*\bsrc\s*=\s*['\"][^'\"]*vue[^'\"]*\.js)",
        source,
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
    shell = _EMPTY_MOUNT_RE.search(source)
    if shell and _has_bundle_script(source):
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
