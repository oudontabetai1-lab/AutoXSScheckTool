"""文字列結合の等価性に基づく注入検知の汎用プローブ。

入力が ``'...'`` / ``"..."`` のようなリテラル中へ連結されている場合、
**クォートを壊さずに等価な値を組み立てられるか**で注入可否を判定する。

例: マーカーを ``AABB`` とし ``AA`` / ``BB`` に分割したとき

  - ``AA' 'BB``   → SQL 上は ``'AA' 'BB'`` = ``AABB``（隣接リテラル連結 / MySQL・SQLite 等）
  - ``AA'||'BB``  → ``'AA'||'BB'`` = ``AABB``（Oracle / PostgreSQL）
  - ``AA'+'BB``   → ``'AA'+'BB'`` = ``AABB``（MSSQL / JS 文字列）
  - ``AA'BB``     → クォート不整合（破壊系・対照用）

応答本文に「連結後のマーカー ``AABB``」が現れれば、注入したクォートが
データではなく**構文として解釈された**ことを意味する（単に反射しただけなら
``AA' 'BB`` がそのまま現れ ``AABB`` は現れない）。これをエラーメッセージや
WAF に依存せずに確認できるのが利点。SQLi / XSS 双方から再利用する。

本モジュールは HTTP に依存しない純粋ロジック。プローブ値の生成
(``*_probe_set``) と、観測した応答からの判定 (``evaluate``) を提供し、
実際の送信はスキャナ側が担う。
"""
from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field
from typing import Optional

_ALPHABET = string.ascii_lowercase + string.digits


def make_marker() -> tuple[str, str, str]:
    """ランダムな ``(left, right, marker)`` を返す。``marker == left + right``。

    クォートや空白を含まない英数字のみで構成し、ページの既存テキストと
    偶然衝突しないよう十分な長さ・ランダム性を持たせる。
    """
    left = "z" + "".join(secrets.choice(_ALPHABET) for _ in range(5))
    right = "".join(secrets.choice(_ALPHABET) for _ in range(5)) + "q"
    return left, right, left + right


@dataclass(frozen=True)
class Probe:
    """単一のプローブ（フィールドへ投入する値）。"""

    name: str          # 識別子（"baseline" / "adjacent" / "pipe" / "plus" / "broken"）
    value: str         # フィールドへ投入する文字列
    role: str          # "baseline" | "equivalent" | "broken"
    dialect: str = ""  # 参考情報（"ansi" / "oracle" / "mssql" / "js" など）


@dataclass(frozen=True)
class ProbeSet:
    """1 フィールド分のプローブ群。"""

    context: str       # "sql" | "html_attr" | "js_string"
    marker: str        # 連結成功時に応答へ現れるべき文字列（left + right）
    probes: tuple[Probe, ...]

    def by_role(self, role: str) -> list[Probe]:
        return [p for p in self.probes if p.role == role]

    @property
    def baseline(self) -> Optional[Probe]:
        items = self.by_role("baseline")
        return items[0] if items else None


@dataclass(frozen=True)
class ProbeVerdict:
    """判定結果。"""

    injectable: bool
    confidence: float            # 0.0–1.0
    matched_dialect: str         # 連結が成立した方言（例: "ansi"）
    matched_probe: str           # 成立したプローブ名
    rationale: str
    details: dict = field(default_factory=dict)


def _sql_probes(left: str, right: str) -> tuple[Probe, ...]:
    return (
        Probe("baseline", left + right, "baseline", "plain"),
        # シングルクォート文字列コンテキスト
        Probe("adjacent", f"{left}' '{right}", "equivalent", "ansi"),
        Probe("pipe", f"{left}'||'{right}", "equivalent", "oracle"),
        Probe("plus", f"{left}'+'{right}", "equivalent", "mssql"),
        Probe("concat", f"{left}'+CONCAT('{right}')-- -", "equivalent", "mysql_concat"),
        # 破壊系（対照用）: クォート不整合で構文エラー/差分を誘発
        Probe("broken", f"{left}'{right}", "broken", "broken_quote"),
    )


def _html_attr_probes(left: str, right: str) -> tuple[Probe, ...]:
    # value="..." のようなダブルクォート属性からの分割を確認する。
    return (
        Probe("baseline", left + right, "baseline", "plain"),
        Probe("attr_break", f'{left}" "{right}', "equivalent", "dquote_attr"),
        Probe("attr_break_sq", f"{left}' '{right}", "equivalent", "squote_attr"),
        Probe("broken", f'{left}"{right}', "broken", "broken_quote"),
    )


def _js_string_probes(left: str, right: str) -> tuple[Probe, ...]:
    # <script>var x='...'</script> のような JS 文字列からの連結を確認する。
    return (
        Probe("baseline", left + right, "baseline", "plain"),
        Probe("js_plus_sq", f"{left}'+'{right}", "equivalent", "js_sq"),
        Probe("js_plus_dq", f'{left}"+"{right}', "equivalent", "js_dq"),
        Probe("broken", f"{left}'{right}", "broken", "broken_quote"),
    )


def sql_probe_set(marker: Optional[tuple[str, str, str]] = None) -> ProbeSet:
    left, right, m = marker or make_marker()
    return ProbeSet("sql", m, _sql_probes(left, right))


def html_attr_probe_set(marker: Optional[tuple[str, str, str]] = None) -> ProbeSet:
    left, right, m = marker or make_marker()
    return ProbeSet("html_attr", m, _html_attr_probes(left, right))


def js_string_probe_set(marker: Optional[tuple[str, str, str]] = None) -> ProbeSet:
    left, right, m = marker or make_marker()
    return ProbeSet("js_string", m, _js_string_probes(left, right))


def evaluate(probe_set: ProbeSet, responses: dict[str, str]) -> ProbeVerdict:
    """観測した応答本文 ``{probe_name: body}`` から注入可否を判定する。

    判定ロジック:
      1. ベースライン（素のマーカー）が反射しているか確認。反射が無ければ
         この手法は適用不可（``injectable=False`` / confidence 0）。
      2. 等価プローブの応答に「連結後マーカー」が現れ、かつ投入した生の値
         （クォート入り）が現れていなければ、クォートが構文解釈された証拠 →
         注入可能と判定。
      3. 破壊系プローブが「きれいな連結マーカー」を返していなければ
         （= 構文エラー/差分が出ていれば）確度を上げる。
    """
    marker = probe_set.marker
    baseline = probe_set.baseline
    baseline_body = responses.get(baseline.name, "") if baseline else ""

    # 1. 反射が無ければ反射ベースの判定はできない。
    if not baseline_body or marker not in baseline_body:
        return ProbeVerdict(
            injectable=False,
            confidence=0.0,
            matched_dialect="",
            matched_probe="",
            rationale="baseline marker not reflected; reflection-based probe N/A",
        )

    # 2. 等価プローブで連結マーカーが出現したか。
    hits: list[Probe] = []
    for p in probe_set.by_role("equivalent"):
        body = responses.get(p.name, "")
        if not body:
            continue
        # 連結後マーカーが出現し、かつ投入した生の値そのもの（クォート入り）が
        # 反射していない＝クォートはデータではなく構文として消費された。
        if marker in body and p.value not in body:
            hits.append(p)

    if not hits:
        return ProbeVerdict(
            injectable=False,
            confidence=0.0,
            matched_dialect="",
            matched_probe="",
            rationale="no concatenation-equivalence collapse observed",
        )

    # 3. 破壊系（クォート不整合）も「きれいな連結」を返した場合、それは
    #    クォートが構文解釈されたのではなく、入力側で記号/空白を除去する
    #    正規化（サニタイズ系の検索/フィルタ等）が起きている可能性が高い。
    #    この場合は等価変形の collapse も正規化の副作用とみなし、誤検知を
    #    避けるため injectable=False とする（対照テストとしての破壊系が
    #    陽性なら判定を棄却）。
    broken_collapsed = False
    for b in probe_set.by_role("broken"):
        body = responses.get(b.name, "")
        if marker in body and b.value not in body:
            broken_collapsed = True
            break

    if broken_collapsed:
        return ProbeVerdict(
            injectable=False,
            confidence=0.0,
            matched_dialect="",
            matched_probe="",
            rationale=(
                "broken-quote control also collapsed to marker — likely input "
                "normalization (punctuation/whitespace stripping) rather than "
                "quote being interpreted as syntax; rejecting to avoid false positive"
            ),
            details={
                "marker": marker,
                "context": probe_set.context,
                "equivalent_hits": [p.name for p in hits],
                "broken_collapsed": True,
            },
        )

    chosen = hits[0]
    return ProbeVerdict(
        injectable=True,
        confidence=0.9,
        matched_dialect=chosen.dialect,
        matched_probe=chosen.name,
        rationale=(
            f"string-concatenation equivalence collapsed to marker via "
            f"'{chosen.name}' ({chosen.dialect}); broken-quote control did not "
            f"collapse, indicating the quote was interpreted as syntax"
        ),
        details={
            "matched_payload": chosen.value,
            "marker": marker,
            "context": probe_set.context,
            "equivalent_hits": [p.name for p in hits],
        },
    )
