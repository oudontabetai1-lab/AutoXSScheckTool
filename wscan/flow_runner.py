"""
Attack Flow Runner
Executes multi-step attack flows defined by the operator.

A ScanFlow is a named sequence of FlowSteps that the browser executes before
the scanner attacks a target page.  This enables scenarios such as:
  - Login → navigate to protected page → attack
  - Add item to cart → go to checkout → attack checkout form
  - Fill search box → submit → attack result page

Supported step actions
----------------------
navigate  : navigate to ``url``
fill      : fill a form field (``field`` = name/id, ``value`` = content)
submit    : click the submit button (or call form.submit() as fallback)
click     : click an arbitrary CSS selector (``selector``)
wait      : pause for ``timeout`` seconds (useful after AJAX transitions)
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from rich.console import Console

if TYPE_CHECKING:
    from wscan.browser import BrowserManager

console = Console()


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class FlowStep:
    """A single step inside a ScanFlow."""
    action: str          # navigate | fill | submit | click | wait
    url: str = ""        # navigate
    field: str = ""      # fill (name or id attribute)
    value: str = ""      # fill
    selector: str = ""   # click
    timeout: float = 5.0 # wait duration (s) or click timeout (s)

    def to_dict(self) -> dict:
        d: dict = {"action": self.action}
        if self.url:      d["url"]      = self.url
        if self.field:    d["field"]    = self.field
        if self.value:    d["value"]    = self.value
        if self.selector: d["selector"] = self.selector
        if self.action == "wait" or self.action == "click":
            d["timeout"] = self.timeout
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "FlowStep":
        return cls(
            action=d.get("action", "navigate"),
            url=d.get("url", ""),
            field=d.get("field", ""),
            value=d.get("value", ""),
            selector=d.get("selector", ""),
            timeout=float(d.get("timeout", 5.0)),
        )


@dataclass
class ScanFlow:
    """
    A named, ordered sequence of steps executed before attacking a page.

    ``name``  — human-readable label shown in the dashboard and console
    ``steps`` — list of FlowStep objects executed in order
    """
    name: str
    steps: list[FlowStep] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"name": self.name, "steps": [s.to_dict() for s in self.steps]}

    @classmethod
    def from_dict(cls, d: dict) -> "ScanFlow":
        return cls(
            name=d.get("name", "Flow"),
            steps=[FlowStep.from_dict(s) for s in d.get("steps", [])],
        )

    @classmethod
    def list_from_dicts(cls, lst: list[dict]) -> list["ScanFlow"]:
        return [cls.from_dict(d) for d in (lst or [])]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class FlowRunner:
    """
    Executes ScanFlow instances sequentially using a BrowserManager.

    Usage::

        runner = FlowRunner(browser)
        ok = await runner.run(flow)
        # browser is now on the last page of the flow
    """

    def __init__(self, browser: "BrowserManager"):
        self.browser = browser

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self, flow: ScanFlow) -> bool:
        """
        Execute every step of *flow*.
        Returns True on success, False if any step raises an exception.
        """
        console.print(f"  [cyan][Flow][/cyan] {flow.name} ({len(flow.steps)} steps)")
        for i, step in enumerate(flow.steps, 1):
            try:
                await self._execute(step, i, len(flow.steps))
            except Exception as exc:
                console.print(
                    f"  [yellow][Flow] Step {i}/{len(flow.steps)} "
                    f"({step.action}) failed: {exc}[/yellow]"
                )
                return False
        console.print(f"  [green][Flow] Completed:[/green] {flow.name}")
        return True

    # ------------------------------------------------------------------
    # Internal step dispatch
    # ------------------------------------------------------------------

    async def _execute(self, step: FlowStep, num: int, total: int) -> None:
        label = f"[Flow {num}/{total}]"

        if step.action == "navigate":
            console.print(f"  [dim]{label} navigate → {step.url}[/dim]")
            await self.browser.navigate(step.url)

        elif step.action == "fill":
            display_val = step.value if step.field.lower() not in ("password", "pass", "passwd") else "***"
            console.print(f"  [dim]{label} fill [{step.field}] = {display_val[:40]}[/dim]")
            await self.browser.page.evaluate(
                """([f, v]) => {
                    const el = document.querySelector(`[name="${f}"],[id="${f}"]`);
                    if (!el) return;
                    el.value = v;
                    ['input', 'change', 'blur'].forEach(e =>
                        el.dispatchEvent(new Event(e, {bubbles: true}))
                    );
                }""",
                [step.field, step.value],
            )

        elif step.action == "submit":
            console.print(f"  [dim]{label} submit[/dim]")
            clicked = await self.browser.page.evaluate(
                """() => {
                    // Prefer clicking the submit button (handles JS frameworks)
                    const btn = document.querySelector(
                        'button[type="submit"],input[type="submit"]'
                    ) || document.querySelector('[type="submit"]');
                    if (btn) { btn.click(); return true; }
                    const form = document.querySelector('form');
                    if (form) { form.submit(); return true; }
                    return false;
                }"""
            )
            if clicked:
                try:
                    await self.browser.page.wait_for_load_state(
                        "domcontentloaded", timeout=15_000
                    )
                except Exception:
                    pass

        elif step.action == "click":
            sel = step.selector or step.field
            console.print(f"  [dim]{label} click [{sel}][/dim]")
            await self.browser.page.click(sel, timeout=int(step.timeout * 1000))
            try:
                await self.browser.page.wait_for_load_state(
                    "domcontentloaded", timeout=10_000
                )
            except Exception:
                pass

        elif step.action == "wait":
            console.print(f"  [dim]{label} wait {step.timeout}s[/dim]")
            await asyncio.sleep(step.timeout)

        else:
            console.print(f"  [yellow]{label} unknown action '{step.action}' — skipped[/yellow]")
