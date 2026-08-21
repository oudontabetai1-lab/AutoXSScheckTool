"""決定論観測（js_analysis の source->sink、context_mutator の反射文脈/生存文字）を
adaptive(LLM) プロンプト用の観測節へ整形する純粋関数（G7）。判定はしない。"""
from __future__ import annotations

from typing import Iterable, Optional


def format_deterministic_observations(
    js_risks: Optional[Iterable] = None,
    context: Optional[dict] = None,
    surviving: Optional[set] = None,
    *,
    max_flows: int = 5,
) -> str:
    lines: list[str] = []

    # 1) js_analysis: 汚染された source->sink（DOM XSS 系）を優先し bounded に列挙。
    risks = list(js_risks or [])
    tainted = [r for r in risks if getattr(r, "tainted", False)]
    ranked = tainted or risks  # tainted 無ければ全 risk を控えめに
    for r in ranked[:max_flows]:
        try:
            sink = str(getattr(r, "sink", "") or "?")
            line = getattr(r, "line", "")
            if getattr(r, "tainted", False):
                # 汚染フローが辿れたものだけ source と likelihood を主張する。
                src = str(getattr(r, "source", "") or "user-controlled input")
                lines.append(
                    f"- Static JS analysis: tainted flow {src} -> {sink} "
                    f"(line {line}) - likely DOM XSS"
                )
            else:
                # source 未追跡の単独 sink は、汚染フローを捏造せず「存在」だけ伝える
                # （grounding を偽らない）。
                lines.append(
                    f"- Static JS analysis: DOM sink {sink} present (line {line}) "
                    f"- source not traced; verify reachability"
                )
        except Exception:
            continue

    # 2) context_mutator: 反射文脈（marker probe 由来）。
    if isinstance(context, dict) and context.get("context"):
        ctx = str(context.get("context"))
        attr = context.get("attribute")
        quote = context.get("quote")
        detail = ""
        if attr:
            detail = f" (attribute '{attr}'" + (f", quote {quote}" if quote else "") + ")"
        lines.append(
            f"- Deterministic reflection context: injected marker reflected in {ctx}{detail}"
        )

    # 3) context_mutator: フィルタを素通りした特殊文字（生存文字）。
    if surviving:
        specials = "".join(sorted(c for c in surviving if not c.isalnum() and c.strip()))
        specials = specials[:40]
        if specials:
            lines.append(
                f"- Characters surviving unescaped (usable for breakout): {specials}"
            )

    if not lines:
        return ""
    return (
        "## Deterministic scanner observations (grounded - prioritise over guesses)\n"
        + "\n".join(lines)
    )
