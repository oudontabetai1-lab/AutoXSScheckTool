"""
危険な JavaScript ソースコードの静的評価（DOM XSS の前段階）。

ペイロード投入で実行を確認する ``scanners/dom_xss.py`` の手前で、ページ内の
インライン / 外部 JavaScript を**静的に**読み、危険な DOM シンク（``eval`` /
``innerHTML`` / ``document.write`` 等）と、ユーザ制御の汚染ソース
（``location.hash`` / ``document.cookie`` / ``postMessage`` 等）の
source → sink フローを検出する。

設計方針（CLAUDE.md「検出ロジックは純粋関数に分離」に準拠）:
- ここは I/O を持たない純粋関数群。入力は JS 文字列、出力は ``JsRisk`` のリスト。
- 完全な AST 解析は行わず、正規表現＋軽量な変数汚染追跡で誤検知を抑える。
- 「ソース由来の値がシンクに渡る」フロー（``tainted=True``）を最も重く扱い、
  汚染が辿れない単独の危険シンクは情報レベルに留める。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class JsRisk:
    """1 件の危険箇所。

    - ``sink``     … 危険な出力先（例: ``eval``、``innerHTML``）。
    - ``severity`` … ``critical`` / ``high`` / ``medium`` / ``low``。
    - ``tainted``  … ユーザ制御ソースから値が流れている疑いがあるか。
    - ``source``   … 汚染源の名称（判明した場合）。
    - ``line``     … 1 始まりの行番号。
    - ``snippet``  … 該当行の抜粋（前後の空白を詰めて 160 文字まで）。
    """

    sink: str
    severity: str
    tainted: bool
    line: int
    snippet: str
    source: str = ""
    category: str = "dom_xss"
    evidence: str = ""


# ── 汚染ソース（ユーザ／攻撃者が制御し得る入力） ───────────────────────────
# DOM XSS の "source"。これらの値がシンクへ流れると DOM XSS になり得る。
_SOURCE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("location.hash", re.compile(r"location\s*\.\s*hash")),
    ("location.search", re.compile(r"location\s*\.\s*search")),
    ("location.href", re.compile(r"location\s*\.\s*href")),
    ("location.pathname", re.compile(r"location\s*\.\s*pathname")),
    ("document.URL", re.compile(r"document\s*\.\s*(?:URL|documentURI|baseURI)\b")),
    ("document.referrer", re.compile(r"document\s*\.\s*referrer")),
    ("document.cookie", re.compile(r"document\s*\.\s*cookie")),
    ("window.name", re.compile(r"window\s*\.\s*name")),
    ("document.location", re.compile(r"document\s*\.\s*location")),
    ("postMessage", re.compile(r"\.\s*data\b")),  # message event handler の event.data
    ("URLSearchParams", re.compile(r"URLSearchParams\s*\(")),
    ("storage", re.compile(r"(?:local|session)Storage\s*\.\s*getItem")),
    ("hashchange", re.compile(r"\bnewURL\b")),
]

# message ハンドラ内の event.data は誤検知しやすいので、postMessage 文脈
# （addEventListener('message' か onmessage）が同ソースに有る時だけ source 扱い。
_HAS_MESSAGE_HANDLER = re.compile(
    r"addEventListener\s*\(\s*['\"]message['\"]|onmessage\s*=", re.IGNORECASE
)


# ── 危険シンク ───────────────────────────────────────────────────────────
# 文字列を実行し得るタイマー系シンク。リテラル文字列だけでなく、汚染された
# 非リテラル引数（例: setTimeout(location.hash) / setInterval(userInput,...)）も
# DOM XSS になり得るため広く一致させ、汚染判定で確度を決める（誤検知は、汚染も
# リテラルも無い通常の関数参照 timer を解析ループ側で除外して抑える）。
_TIMER_SINK_NAME = "setTimeout/setInterval"

# 各エントリ: (名前, 正規表現, 汚染なし時 severity, 汚染あり時 severity)
# 正規表現は「シンク呼び出し／代入の開始位置」にマッチさせる。
_SINKS: list[tuple[str, re.Pattern, str, str]] = [
    ("eval", re.compile(r"\beval\s*\("), "medium", "critical"),
    ("Function", re.compile(r"\bnew\s+Function\s*\(|\bFunction\s*\("), "medium", "critical"),
    (
        _TIMER_SINK_NAME,
        re.compile(r"\bset(?:Timeout|Interval)\s*\("),
        "low",
        "high",
    ),
    ("document.write", re.compile(r"document\s*\.\s*write(?:ln)?\s*\("), "medium", "critical"),
    ("innerHTML", re.compile(r"\.\s*innerHTML\s*(?:\+?=)(?!=)"), "medium", "high"),
    ("outerHTML", re.compile(r"\.\s*outerHTML\s*(?:\+?=)(?!=)"), "medium", "high"),
    (
        "insertAdjacentHTML",
        re.compile(r"\.\s*insertAdjacentHTML\s*\("),
        "medium",
        "high",
    ),
    ("srcdoc", re.compile(r"\.\s*srcdoc\s*=(?!=)"), "low", "high"),
    # jQuery 系の HTML 挿入。単独では誤検知が多いので汚染なしは low 据え置き。
    (
        "jQuery.html",
        re.compile(r"\.\s*(?:html|append|prepend|after|before|replaceWith|wrap)\s*\("),
        "low",
        "high",
    ),
    # ナビゲーション系（オープンリダイレクト / javascript: スキーム）
    (
        "location.assign",
        re.compile(r"location\s*\.\s*(?:assign|replace)\s*\("),
        "low",
        "medium",
    ),
    (
        "location=",
        re.compile(r"(?:window\s*\.\s*)?location\s*(?:\.\s*href\s*)?=(?!=)"),
        "low",
        "medium",
    ),
]

# 代入文の左辺変数名を取り出す（汚染伝播の追跡用）。
# 先頭の否定後読みで ``obj.innerHTML = ...`` のようなプロパティ代入を除外し、
# プロパティ名（innerHTML 等）を「汚染変数」と誤認しないようにする。
_ASSIGN_RE = re.compile(
    r"(?<![.\w$])(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)"
)

# 行を取り出すためのヘルパ。
def _line_of(source: str, pos: int) -> int:
    return source.count("\n", 0, pos) + 1


def _snippet_at(source: str, pos: int) -> str:
    start = source.rfind("\n", 0, pos) + 1
    end = source.find("\n", pos)
    if end == -1:
        end = len(source)
    return source[start:end].strip()[:160]


def _find_source(text: str, *, message_ctx: bool) -> str:
    """``text`` 中に現れる最初の汚染ソース名を返す。無ければ空文字。"""
    for name, pat in _SOURCE_PATTERNS:
        if name == "postMessage" and not message_ctx:
            continue
        if pat.search(text):
            return name
    return ""


def _collect_tainted_vars(source: str, message_ctx: bool) -> set[str]:
    """汚染ソース由来の値が代入された変数名の集合を返す（簡易伝播つき）。

    例) ``var p = location.hash`` → ``p`` を汚染。続けて ``var q = p + ''`` の
    ように既汚染変数を参照する代入も汚染へ伝播させる（2 パス）。
    """
    tainted: set[str] = set()
    assignments: list[tuple[str, str]] = []
    for m in _ASSIGN_RE.finditer(source):
        lhs, rhs = m.group(1), m.group(2)
        # 比較演算子（==, ===, <=, >=, !=）の誤マッチを除外。
        if rhs.startswith("=") or m.group(0).count("==") and "=" in rhs[:1]:
            continue
        assignments.append((lhs, rhs))
        if _find_source(rhs, message_ctx=message_ctx):
            tainted.add(lhs)

    # 汚染変数を参照する代入を伝播（収束するまで最大数回）。
    for _ in range(3):
        grew = False
        for lhs, rhs in assignments:
            if lhs in tainted:
                continue
            if _references_var(rhs, tainted):
                tainted.add(lhs)
                grew = True
        if not grew:
            break
    return tainted


_WORD_RE = re.compile(r"[A-Za-z_$][\w$]*")


def _references_var(text: str, names: set[str]) -> bool:
    if not names:
        return False
    for w in _WORD_RE.findall(text):
        if w in names:
            return True
    return False


def _statement_around(source: str, pos: int) -> str:
    """シンク位置を含む「文」を粗く切り出す（直前の ; か { か改行～次の ; ）。"""
    start = max(
        source.rfind(";", 0, pos),
        source.rfind("{", 0, pos),
        source.rfind("\n", 0, pos),
    )
    end_candidates = [e for e in (source.find(";", pos), source.find("\n", pos)) if e != -1]
    end = min(end_candidates) if end_candidates else len(source)
    return source[start + 1 : end]


def analyze_js(source: str, *, origin: str = "") -> list[JsRisk]:
    """JavaScript ソースを静的解析し、危険箇所のリストを返す。

    ``origin`` は由来（ファイル URL / "inline" 等）で、結果には影響しないが
    呼び出し側が evidence を組み立てる際の参考に使う。
    """
    if not source or not source.strip():
        return []

    message_ctx = bool(_HAS_MESSAGE_HANDLER.search(source))
    tainted_vars = _collect_tainted_vars(source, message_ctx)

    risks: list[JsRisk] = []
    seen: set[tuple[str, int]] = set()

    for name, pat, sev_clean, sev_tainted in _SINKS:
        for m in pat.finditer(source):
            line = _line_of(source, m.start())
            key = (name, line)
            if key in seen:
                continue

            stmt = _statement_around(source, m.start())
            src_name = _find_source(stmt, message_ctx=message_ctx)
            tainted = bool(src_name) or _references_var(stmt, tainted_vars)
            if tainted and not src_name:
                src_name = "tainted variable"

            # タイマー系は「文字列リテラル or 汚染」のときだけ報告する。
            # benign な関数参照 timer（例: setTimeout(fn, 100)）は誤検知になるため除外。
            if name == _TIMER_SINK_NAME:
                after = source[m.end():].lstrip()
                is_literal = after[:1] in ("'", '"', "`")
                if not tainted and not is_literal:
                    continue

            severity = sev_tainted if tainted else sev_clean
            seen.add(key)
            risks.append(
                JsRisk(
                    sink=name,
                    severity=severity,
                    tainted=tainted,
                    line=line,
                    snippet=_snippet_at(source, m.start()),
                    source=src_name,
                    evidence=(
                        f"危険な DOM シンク '{name}' を検出"
                        + (
                            f"。汚染ソース '{src_name}' から値が流入する疑い"
                            if tainted
                            else "（ユーザ入力との接続は静的には未確認）"
                        )
                    ),
                )
            )

    # 重大度順 → 行番号順で安定ソート。
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    risks.sort(key=lambda r: (order.get(r.severity, 9), r.line))
    return risks


# ── HTML からの JavaScript 抽出（純粋関数） ─────────────────────────────
_INLINE_SCRIPT_RE = re.compile(
    r"<script\b([^>]*)>(.*?)</script>", re.IGNORECASE | re.DOTALL
)
_SRC_ATTR_RE = re.compile(r"""\bsrc\s*=\s*['"]?([^'"\s>]+)""", re.IGNORECASE)
_TYPE_ATTR_RE = re.compile(r"""\btype\s*=\s*['"]?([^'"\s>]+)""", re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(
    r"<script\b[^>]*\bsrc\s*=\s*['\"]?([^'\"\s>]+)", re.IGNORECASE
)


def extract_external_script_srcs(html: str) -> list[str]:
    """HTML から外部 ``<script src=...>`` の src 値を順序保持・重複除去で返す（純粋関数）。"""
    if not html:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for m in _SCRIPT_SRC_RE.finditer(html):
        src = (m.group(1) or "").strip()
        if not src or src.startswith(("data:", "javascript:", "about:")):
            continue
        if src in seen:
            continue
        seen.add(src)
        out.append(src)
    return out


def extract_inline_scripts(html: str) -> list[str]:
    """HTML から ``src`` を持たない（＝インライン）``<script>`` 本文を返す。"""
    if not html:
        return []
    scripts: list[str] = []
    for m in _INLINE_SCRIPT_RE.finditer(html):
        attrs, body = m.group(1), m.group(2)
        if _SRC_ATTR_RE.search(attrs):
            continue  # 外部参照はここでは対象外
        type_m = _TYPE_ATTR_RE.search(attrs)
        if type_m:
            t = type_m.group(1).lower()
            # JSON や template など JS 実行されない type は除外。
            if t not in ("text/javascript", "application/javascript", "module", "module/javascript"):
                continue
        if body.strip():
            scripts.append(body)
    return scripts


def is_javascript_response(url: str, content_type: str = "") -> bool:
    """URL / Content-Type から JavaScript リソースかどうかを判定する。"""
    ct = (content_type or "").lower()
    if "javascript" in ct or "ecmascript" in ct:
        return True
    path = (url or "").split("?", 1)[0].split("#", 1)[0].lower()
    return path.endswith((".js", ".mjs", ".jsx"))
