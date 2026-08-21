"""決定論観測（js_analysis の source->sink、context_mutator の反射文脈/生存文字）を
adaptive(LLM) プロンプト用の観測節へ整形する純粋関数（G7）。判定はしない。

観測は2種類に分けて提示する（grounding を偽らないため）:
- **field 固有**（反射文脈・生存文字）: この入力を実際に probe した結果＝この入力に固有。
- **page-level**（JS の DOM sink）: ページ全体の静的解析＝この入力から到達可能とは限らない
  （文脈情報。field 固有の reachability 証拠として提示しない）。
"""
from __future__ import annotations

from typing import Iterable, Optional


def format_deterministic_observations(
    js_risks: Optional[Iterable] = None,
    context: Optional[dict] = None,
    surviving: Optional[set] = None,
    *,
    max_flows: int = 5,
) -> str:
    field_lines: list[str] = []   # この入力に固有（probe 由来）
    page_lines: list[str] = []    # ページ全体（静的解析。到達性は未確認）

    # (page-level) js_analysis の DOM sink。汚染フローが辿れたものを優先し bounded。
    # ただし「この入力から到達可能」とは主張しない（page 全体の静的観測）。
    risks = list(js_risks or [])
    tainted = [r for r in risks if getattr(r, "tainted", False)]
    ranked = tainted or risks
    for r in ranked[:max_flows]:
        try:
            sink = str(getattr(r, "sink", "") or "?")
            line = getattr(r, "line", "")
            if getattr(r, "tainted", False):
                src = str(getattr(r, "source", "") or "user-controlled input")
                page_lines.append(
                    f"- DOM sink {sink} fed by {src} (line {line}) "
                    f"- page-level static flow; reachability from this input not confirmed"
                )
            else:
                page_lines.append(
                    f"- DOM sink {sink} present (line {line}) - source not traced"
                )
        except Exception:
            continue

    # (field 固有) 反射文脈（marker probe 由来）。
    if isinstance(context, dict) and context.get("context"):
        ctx = str(context.get("context"))
        attr = context.get("attribute")
        quote = context.get("quote")
        detail = ""
        if attr:
            detail = f" (attribute '{attr}'" + (f", quote {quote}" if quote else "") + ")"
        field_lines.append(
            f"- Reflection context: injected marker reflected in {ctx}{detail}"
        )

    # (field 固有) フィルタを素通りした特殊文字（生存文字）。
    if surviving:
        specials = "".join(sorted(c for c in surviving if not c.isalnum() and c.strip()))
        specials = specials[:40]
        if specials:
            field_lines.append(
                f"- Characters surviving unescaped (usable for breakout): {specials}"
            )

    sections: list[str] = []
    if field_lines:
        sections.append(
            "## Deterministic observations for this input (grounded - prioritise over guesses)\n"
            + "\n".join(field_lines)
        )
    if page_lines:
        sections.append(
            "## Page-level DOM sinks (context only - not confirmed reachable from this input)\n"
            + "\n".join(page_lines)
        )
    return "\n\n".join(sections)
