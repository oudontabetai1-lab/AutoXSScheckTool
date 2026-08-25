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
    """属性順や引用符に依存せず id の完全一致を調べる。"""
    return bool(
        re.search(
            rf"\bid\s*=\s*(['\"])\s*{re.escape(element_id)}\s*\1",
            source,
            flags=re.I,
        )
    )


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
    if next_signals:
        return SpaInfo(True, "Next.js", "high", next_signals)

    react_signals: list[str] = []
    if re.search(r"<[^>]+\bdata-reactroot(?:\s*=|\s|>)", source, flags=re.I):
        react_signals.append("data-reactroot")
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
    if re.search(r"\b__NUXT__\b", source, flags=re.I):
        vue_signals.append("__NUXT__")
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
        framework = "Nuxt" if "__NUXT__" in vue_signals else "Vue"
        return SpaInfo(True, framework, "high", vue_signals)

    return SpaInfo(False, "unknown", "low", _weak_layout_signals(source))
