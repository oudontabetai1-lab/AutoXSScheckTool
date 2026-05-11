"""
Flow Recorder / Replayer
========================
Playwright のナビゲーション・フォーム送信を JSON ステップとして記録し、
記録した手順を再生してペイロードを注入する。

シナリオ記録/再生により、ログイン後や複数画面にまたがる操作を再利用する。

記録コマンド:
    python main.py record --output flows/login_flow.json http://example.com/login

再生 (エンジン内部から呼び出し):
    from wscan.flow_recorder import FlowRecorder
    recorder = FlowRecorder()
    html, pair = await recorder.replay_with_payloads(steps, "bio", "<script>alert(1)</script>", browser)

ステップ形式 (JSON):
    [
      {"action": "navigate", "url": "http://example.com/login"},
      {"action": "fill",     "selector": "#username", "value": "admin"},
      {"action": "fill",     "selector": "#password", "value": "password"},
      {"action": "click",    "selector": "button[type=submit]"},
      {"action": "fill_inject", "selector": "#bio", "field_name": "bio"}
    ]

"fill_inject" ステップが payload 注入ポイント。
"""
from __future__ import annotations

import asyncio
import json
import secrets
import time
from pathlib import Path
from typing import Optional


class FlowRecorder:
    """Playwright 操作を JSON ステップとして記録・再生する。"""

    def __init__(self):
        self._steps: list[dict] = []

    # ──────────────────────────────────────────────────────────────────────────
    # Recording
    # ──────────────────────────────────────────────────────────────────────────

    async def record_interactive(
        self,
        start_url: str,
        output_path: str,
        headless: bool = False,
    ) -> list[dict]:
        """
        非ヘッドレスで Playwright を起動し、ユーザー操作を記録する。
        Ctrl+C で記録終了 → JSON 保存。

        Returns
        -------
        記録されたステップのリスト
        """
        from playwright.async_api import async_playwright

        print(f"[FlowRecorder] 記録開始: {start_url}")
        print("[FlowRecorder] 操作を行い、終了したら Ctrl+C を押してください。")
        steps: list[dict] = [{"action": "navigate", "url": start_url}]

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=headless)
            page = await browser.new_page()

            # ナビゲーション追跡
            def on_navigate(frame):
                if frame == page.main_frame:
                    url = frame.url
                    if url and url != "about:blank" and url != start_url:
                        steps.append({"action": "navigate", "url": url})

            page.on("framenavigated", on_navigate)

            # フォーム送信の追跡 (input change)
            # Use random token in function names so malicious page JS cannot
            # inject fake steps by calling the predictable global names.
            _tok = secrets.token_hex(12)
            _fn_fill = f"__wscan_fill_{_tok}__"
            _fn_click = f"__wscan_click_{_tok}__"

            await page.expose_function(_fn_fill, lambda selector, value: steps.append(
                {"action": "fill", "selector": selector, "value": value}
            ))
            await page.expose_function(_fn_click, lambda selector: steps.append(
                {"action": "click", "selector": selector}
            ))

            # ページに監視スクリプト注入
            await page.add_init_script(f"""
                document.addEventListener('change', function(e) {{
                    const el = e.target;
                    if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT') {{
                        const sel = el.id ? '#' + el.id : (el.name ? '[name="' + el.name + '"]' : el.tagName.toLowerCase());
                        if (typeof window['{_fn_fill}'] === 'function') {{
                            window['{_fn_fill}'](sel, el.value);
                        }}
                    }}
                }}, true);
                document.addEventListener('click', function(e) {{
                    const el = e.target;
                    if (el.tagName === 'BUTTON' || el.type === 'submit' || el.tagName === 'A') {{
                        const sel = el.id ? '#' + el.id : (el.type === 'submit' ? 'button[type=submit]' : el.tagName.toLowerCase());
                        if (typeof window['{_fn_click}'] === 'function') {{
                            window['{_fn_click}'](sel);
                        }}
                    }}
                }}, true);
            """)

            await page.goto(start_url)

            try:
                # ユーザーが Ctrl+C するまで待機
                while True:
                    await asyncio.sleep(1)
            except (KeyboardInterrupt, asyncio.CancelledError):
                pass
            finally:
                await browser.close()

        # 保存
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(steps, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[FlowRecorder] {len(steps)} ステップを保存: {output_path}")
        self._steps = steps
        return steps

    # ──────────────────────────────────────────────────────────────────────────
    # Loading / saving
    # ──────────────────────────────────────────────────────────────────────────

    def load(self, path: str) -> list[dict]:
        """JSON ファイルからステップを読み込む。"""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Flow file not found: {path}")
        steps = json.loads(p.read_text(encoding="utf-8"))
        self._steps = steps
        return steps

    # ──────────────────────────────────────────────────────────────────────────
    # Replay
    # ──────────────────────────────────────────────────────────────────────────

    async def replay_with_payloads(
        self,
        steps: list[dict],
        inject_field: str,
        payload: str,
        browser,
    ) -> tuple[str, dict]:
        """
        記録されたステップを再生し、inject_field の fill/fill_inject を payload に差し替える。

        Parameters
        ----------
        steps        : load() で得たステップリスト
        inject_field : ペイロードを注入するフィールド名 (field_name) または CSS セレクタ
        payload      : 注入するペイロード文字列
        browser      : BrowserManager インスタンス

        Returns
        -------
        (html_after_replay, request_response_pair)
        """
        html = ""
        pair: dict = {"request": {}, "response": {}}

        for step in steps:
            action = step.get("action", "")

            if action == "navigate":
                url = step.get("url", "")
                if url:
                    await browser.navigate(url)
                    await asyncio.sleep(0.3)

            elif action == "fill":
                selector = step.get("selector", "")
                value = step.get("value", "")
                if selector:
                    try:
                        await browser.page.fill(selector, value, timeout=5000)
                    except Exception:
                        pass

            elif action == "fill_inject":
                # ペイロード注入ポイント — field_name または selector でマッチ
                selector = step.get("selector", "")
                field_name = step.get("field_name", "")
                if field_name == inject_field or selector == inject_field:
                    if selector:
                        try:
                            await browser.page.fill(selector, payload, timeout=5000)
                        except Exception:
                            pass
                else:
                    # 他のフィールドはデフォルト値をそのまま入力
                    default_val = step.get("value", "")
                    if selector and default_val:
                        try:
                            await browser.page.fill(selector, default_val, timeout=5000)
                        except Exception:
                            pass

            elif action == "click":
                selector = step.get("selector", "")
                if selector:
                    try:
                        req_ts = time.time()
                        await browser.page.click(selector, timeout=5000)
                        await asyncio.sleep(0.5)
                        resp_ts = time.time()
                        html = await browser.page.content()
                        pair = {
                            "request": {"timestamp": req_ts, "url": browser.page.url},
                            "response": {"timestamp": resp_ts, "body": html, "status": 200},
                        }
                    except Exception:
                        pass

            elif action == "wait":
                ms = step.get("ms", 500)
                await asyncio.sleep(ms / 1000)

        # 最終状態の HTML
        try:
            html = await browser.page.content()
        except Exception:
            pass

        return html, pair

    # ──────────────────────────────────────────────────────────────────────────
    # Helper: inject_fields discovery
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def get_inject_fields(steps: list[dict]) -> list[str]:
        """
        ステップリストから fill_inject ステップの field_name を収集する。
        スキャンエンジンがどのフィールドにペイロードを注入すべきか確認する際に使用。
        """
        return [
            s.get("field_name") or s.get("selector", "")
            for s in steps
            if s.get("action") == "fill_inject"
        ]
