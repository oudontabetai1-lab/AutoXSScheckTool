"""
DOM-based XSS Scanner (S-1)
Detects client-side XSS by hooking dangerous DOM sinks via Playwright's
page.add_init_script(). A unique marker is injected into each field; the
monitoring script captures any write to innerHTML, document.write, eval,
location.href etc. that contains the marker, confirming DOM-based XSS.
"""
import asyncio
import re
import uuid
from typing import TYPE_CHECKING

from wscan.injection_point import InjectionPoint

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# JavaScript injected before page load — patches dangerous DOM sinks.
# Any call whose argument contains the unique marker is recorded in
# window.__wscan_domxss_log as {sink, data}.
_HOOK_SCRIPT = r"""
(function() {
    window.__wscan_domxss_log = [];
    var _marker = '__WSCAN_DOMXSS__';

    function _record(sink, data) {
        if (typeof data === 'string' && data.indexOf(_marker) !== -1) {
            window.__wscan_domxss_log.push({sink: sink, data: data.slice(0, 200)});
        }
    }

    // innerHTML / outerHTML
    var _descInner = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (_descInner && _descInner.set) {
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(v) { _record('innerHTML', v); _descInner.set.call(this, v); },
            get: _descInner.get,
            configurable: true,
        });
    }
    var _descOuter = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (_descOuter && _descOuter.set) {
        Object.defineProperty(Element.prototype, 'outerHTML', {
            set: function(v) { _record('outerHTML', v); _descOuter.set.call(this, v); },
            get: _descOuter.get,
            configurable: true,
        });
    }

    // document.write / writeln
    var _origWrite = document.write.bind(document);
    document.write = function() {
        for (var i = 0; i < arguments.length; i++) _record('document.write', String(arguments[i]));
        return _origWrite.apply(document, arguments);
    };
    var _origWriteln = document.writeln.bind(document);
    document.writeln = function() {
        for (var i = 0; i < arguments.length; i++) _record('document.writeln', String(arguments[i]));
        return _origWriteln.apply(document, arguments);
    };

    // eval
    var _origEval = window.eval;
    window.eval = function(code) {
        _record('eval', String(code));
        return _origEval.call(window, code);
    };

    // setTimeout / setInterval with string arg
    var _origSTO = window.setTimeout;
    window.setTimeout = function(fn) {
        if (typeof fn === 'string') _record('setTimeout', fn);
        return _origSTO.apply(window, arguments);
    };
    var _origSI = window.setInterval;
    window.setInterval = function(fn) {
        if (typeof fn === 'string') _record('setInterval', fn);
        return _origSI.apply(window, arguments);
    };

    // location.href / location.assign / location.replace
    var _descHref = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
    if (_descHref && _descHref.set) {
        Object.defineProperty(Location.prototype, 'href', {
            set: function(v) { _record('location.href', v); _descHref.set.call(this, v); },
            get: _descHref.get,
            configurable: true,
        });
    }

    // insertAdjacentHTML
    var _origIAH = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(pos, html) {
        _record('insertAdjacentHTML', html);
        return _origIAH.call(this, pos, html);
    };
})();
"""

# Payload template — marker is embedded so the sink hook recognises it
_DOM_XSS_PAYLOAD = "__WSCAN_DOMXSS__{uid}<img src=x onerror=alert(1)>"


class DOMXSSScanner(BaseScanner):
    """DOM-based XSS scanner — hooks client-side sinks via Playwright."""

    CHECK_TYPE = "dom_xss"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.FIELD_INJECTION}),
        capabilities=(
            CarrierCapability(
                carrier=Carrier.QUERY, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.DOM, TransportKind.PLAYWRIGHT}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
                browser_required=True,
            ),
            CarrierCapability(
                carrier=Carrier.FORM, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.DOM, TransportKind.PLAYWRIGHT}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
                browser_required=True,
            ),
            CarrierCapability(
                carrier=Carrier.JSON, state=CapabilityState.PLANNED,
                reason="DOM 実行を伴う JSON body 経路は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.XML, state=CapabilityState.PLANNED,
                reason="DOM XSS の carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.MULTIPART, state=CapabilityState.PLANNED,
                reason="DOM XSS の carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.HEADER, state=CapabilityState.PLANNED,
                reason="DOM XSS の carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.COOKIE, state=CapabilityState.PLANNED,
                reason="DOM XSS の carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.PATH, state=CapabilityState.PLANNED,
                reason="DOM XSS の carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.GRAPHQL, state=CapabilityState.PLANNED,
                reason="DOM XSS の carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.WEBSOCKET, state=CapabilityState.PLANNED,
                reason="DOM XSS の carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
        ),
        prerequisites=frozenset({Prerequisite.BROWSER}),
        cost=CostClass.HIGH,
    )

    SEVERITY = "critical"
    SUPPORTS_JSON_BODY = False

    async def _ensure_hook(self) -> None:
        """シンクフックを「各ページに対して一度だけ」登録する。

        ``page.add_init_script`` は呼ぶたびに別個のスクリプトとして蓄積され、
        以降の全ナビゲーションで多重実行される。フィールドごとに呼ぶと
        innerHTML 等の setter が何重にもラップされ、ログ重複・性能劣化・
        他スキャナのページ遷移への波及を招く。

        並列ワーカーは ContextVar で ``browser.page`` を差し替えるため、単一属性
        では「ページ単位 1 回」を保証できない。登録済みページを ``WeakSet`` で
        管理し、ページごとに 1 回だけ登録する（GC されたページは自動で外れる）。
        """
        from weakref import WeakSet

        page = self.browser.page
        hooked = getattr(self, "_hooked_pages", None)
        if hooked is None:
            hooked = self._hooked_pages = WeakSet()
        if page in hooked:
            return
        await page.add_init_script(_HOOK_SCRIPT)
        hooked.add(page)

    async def scan_injection_point(
        self,
        ip: InjectionPoint,
        field: dict,
    ) -> list[Finding]:
        # DOM sink/dialog 実行に依存するため、ブラウザ遷移しない JSON 注入は扱わない。
        if ip.location == "json_body":
            return []

        findings = []
        field_name = ip.parameter_id

        if self.monitor:
            await self.monitor.emit_status(
                f"DOM-XSS testing: {field_name} on {ip.url}"
            )

        uid = uuid.uuid4().hex[:8]
        payload = _DOM_XSS_PAYLOAD.replace("{uid}", uid)
        marker = f"__WSCAN_DOMXSS__{uid}"

        await self.log_payload_test(field_name, payload, "dom_xss", ip.url)

        try:
            # Install DOM hook before the page loads (once per page)
            await self._ensure_hook()

            source, pair = await self._apply_payload(
                ip.url, ip.parameter_id, payload,
                ip.submit_index, ip.legacy_is_url_param(),
            )
            # DOMXSS は独自シグネチャの _apply_payload 直送で _apply_ip を通らないため、
            # ここで試行台帳へ記録する（adaptive 履歴の欠落防止）。
            self._record_attempt(ip, payload, source, pair)

            await asyncio.sleep(2.0 * self.sleep_factor)  # Allow JS to settle

            # インタラクション必須ハンドラ（onmouseover 等）や javascript: URL は
            # 自動発火しないため、能動的に発火させてから sink ログ／dialog を読む。
            if not self.browser.dialog_fired:
                try:
                    if await self.browser.trigger_injected_handlers(payload):
                        await asyncio.sleep(0.3 * self.sleep_factor)
                except Exception:
                    pass

            # Read what the sink hooks captured
            log = await self.browser.page.evaluate(
                "() => window.__wscan_domxss_log || []"
            )
        except Exception:
            return []

        for entry in log:
            sink = entry.get("sink", "unknown")
            data = entry.get("data", "")
            if marker in data:
                finding = await self.record_finding(
                    url=ip.url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        f"DOM-based XSS: payload marker reached sink '{sink}'. "
                        f"Data excerpt: {data[:120]}"
                    ),
                    pair=pair,
                    severity="critical",
                    confidence="confirmed",
                    evidence_type="dom_xss_sink",
                    evidence_details={
                        "sink": sink,
                        "marker": marker,
                        "data_excerpt": data[:200],
                    },
                    reproduction_steps=[
                        f"Open {ip.url}",
                        f"Inject the payload into field '{field_name}'.",
                        f"Observe that the marker reaches DOM sink '{sink}'.",
                    ],
                    injection_point=ip,
                )
                findings.append(finding)
                break  # One sink is enough evidence

        # Also check if alert fired (extra confirmation)
        if not findings and self.browser.dialog_fired and marker in self.browser.dialog_message:
            finding = await self.record_finding(
                url=ip.url,
                field_name=field_name,
                payload=payload,
                evidence=f"DOM-based XSS confirmed: alert() fired with marker in dialog",
                pair=pair,
                severity="critical",
                dialog_confirmed=True,
                dialog_message=self.browser.dialog_message,
                confidence="confirmed",
                evidence_type="dom_xss_dialog",
                evidence_details={
                    "marker": marker,
                    "dialog_message": self.browser.dialog_message,
                },
                reproduction_steps=[
                    f"Open {ip.url}",
                    f"Inject the payload into field '{field_name}'.",
                    "Observe the browser JavaScript dialog.",
                ],
                injection_point=ip,
            )
            findings.append(finding)

        if not findings:
            extra_payloads = await self.evolved_payloads(
                ip.url,
                ip.form_index,
                ip.parameter_id,
                ip.legacy_is_url_param(),
                dom_index=ip.submit_index,
            )
            for raw_payload in extra_payloads:
                payload = marker + raw_payload
                await self.log_payload_test(
                    field_name, payload, "dom_xss_evolved", ip.url
                )
                try:
                    self.browser.reset_dialog()
                    await self.browser.page.add_init_script(_HOOK_SCRIPT)
                    source, pair = await self._apply_payload(
                        ip.url, ip.parameter_id, payload,
                        ip.submit_index, ip.legacy_is_url_param(),
                    )
                    self._record_attempt(ip, payload, source, pair)
                    await asyncio.sleep(2.0 * self.sleep_factor)
                    log = await self.browser.page.evaluate(
                        "() => window.__wscan_domxss_log || []"
                    )
                except Exception:
                    continue

                for entry in log or []:
                    sink = entry.get("sink", "unknown")
                    data = entry.get("data", "")
                    if marker in data:
                        finding = await self.record_finding(
                            url=ip.url,
                            field_name=field_name,
                            payload=payload,
                            evidence=(
                                f"DOM-based XSS: payload marker reached sink '{sink}'. "
                                f"Data excerpt: {data[:120]}"
                            ),
                            pair=pair,
                            severity="critical",
                            confidence="confirmed",
                            evidence_type="dom_xss_sink",
                            evidence_details={
                                "sink": sink,
                                "marker": marker,
                                "data_excerpt": data[:200],
                            },
                            reproduction_steps=[
                                f"Open {ip.url}",
                                f"Inject the payload into field '{field_name}'.",
                                f"Observe that the marker reaches DOM sink '{sink}'.",
                            ],
                            injection_point=ip,
                        )
                        findings.append(finding)
                        break
                if findings:
                    break

        return findings

    async def _evolution_probe(
        self,
        url: str,
        form_index: int,
        field_name: str,
        is_url_param: bool,
        *,
        dom_index: int | None = None,
    ) -> tuple[str, set[str], dict]:
        """文脈 probe の判定を保ち、非標準 3 引数 transport で送信する。"""
        try:
            from wscan import context_mutator

            marker = context_mutator.make_marker()
            probe = context_mutator.make_char_probe(marker)
            await self.log_payload_test(
                field_name,
                probe,
                f"{self.CHECK_TYPE}_evolution_probe",
                url,
            )
            source, pair = await self._apply_payload(
                url,
                field_name,
                probe,
                form_index if dom_index is None else dom_index,
                is_url_param,
            )
            response_source = (
                (pair.get("response", {}) or {}).get("body") or source or ""
            )
            surviving = context_mutator.surviving_chars(response_source, marker)
            detected_context = context_mutator.detect_context(response_source, marker)
            detected_context["marker"] = marker
            return response_source, surviving, detected_context
        except Exception as exc:
            self._note_wave_degradation("evolution_probe", exc)
            return "", set(), {}

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """従来 API を InjectionPoint 駆動へ接続する互換 wrapper。"""
        name = field.get("name", "unknown")
        ip = (
            InjectionPoint.for_url_param(url, name)
            if is_url_param
            else InjectionPoint.for_form(url, name, form_index)
        )
        return await self.scan_injection_point(ip, field)

    async def verify_finding(self, finding: Finding) -> bool | None:
        if finding.evidence_type not in {"dom_xss_sink", "dom_xss_dialog"}:
            return None

        marker = self._marker_for_finding(finding)
        if not marker:
            return None

        # 注入点種別は provenance(injection_location) を優先し、無い旧 Finding のみ
        # URL クエリ推測へ fallback（旧 verify と同じ推測）。scan と同じ明示種別で再送する。
        from urllib.parse import parse_qs, urlparse

        if finding.injection_location:
            is_url_param = finding.injection_location == "url_param"
        else:
            is_url_param = finding.field_name in parse_qs(
                urlparse(finding.url).query, keep_blank_values=True
            )
        try:
            self.browser.reset_dialog()
            await self._ensure_hook()
            await self.log_payload_test(
                finding.field_name, finding.payload, "dom_xss_verify", finding.url
            )
            # provenance に dom_index があれば実 DOM 位置で再送する（未指定は form_index に
            # フォールバック＝submit_index と同じ意味論）。これが無いと入力欄なしフォーム先行時に
            # 別 DOM フォームへ再送し、本物の DOM-XSS を「未再現」と誤判定する。
            _dom = getattr(finding, "injection_dom_index", -1)
            _submit_index = _dom if _dom >= 0 else finding.injection_form_index
            await self._apply_payload(
                finding.url, finding.field_name, finding.payload,
                _submit_index, is_url_param,
            )
            await asyncio.sleep(0.5 * self.sleep_factor)
            log = await self.browser.page.evaluate(
                "() => window.__wscan_domxss_log || []"
            )
        except Exception:
            return None

        for entry in log or []:
            if marker in (entry.get("data", "") or ""):
                return True

        if self.browser.dialog_fired and marker in self.browser.dialog_message:
            return True

        return False

    async def _apply_payload(
        self,
        url: str,
        field_name: str,
        payload: str,
        form_index: int = 0,
        is_url_param: bool = False,
    ):
        # **明示の注入点種別**で dispatch する（URL クエリからの推測はしない）。旧 scan 本体は
        # engine の is_url_param を直接使っていたため、form フィールド名がたまたま URL クエリと
        # 同名（例 /search?q=old の form field q）でも form へ送っていた。ここで URL 推測に戻すと
        # test_url_param へ誤経路し form-only DOM XSS を取りこぼす/provenance が url_param になる。
        if is_url_param:
            return await self.browser.test_url_param(url, field_name, payload)

        # 選択された form_index を使う（複数フォームのページで別フォームを潰さない）。
        await self.browser.navigate(url)
        return await self.browser.fill_and_submit_form(form_index, field_name, payload)

    def _marker_for_finding(self, finding: Finding) -> str:
        details = getattr(finding, "evidence_details", {}) or {}
        marker = details.get("marker")
        if marker:
            return str(marker)

        match = re.search(r"__WSCAN_DOMXSS__[0-9a-fA-F]+", finding.payload or "")
        return match.group(0) if match else ""
