"""
DOM-based XSS Scanner (S-1)
Detects client-side XSS by hooking dangerous DOM sinks via Playwright's
page.add_init_script(). A unique marker is injected into each field; the
monitoring script captures any write to innerHTML, document.write, eval,
location.href etc. that contains the marker, confirming DOM-based XSS.
"""
import asyncio
import uuid
from typing import TYPE_CHECKING

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
    SEVERITY = "critical"

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        findings = []
        field_name = field.get("name", "unknown")

        if self.monitor:
            await self.monitor.emit_status(f"DOM-XSS testing: {field_name} on {url}")

        uid = uuid.uuid4().hex[:8]
        payload = _DOM_XSS_PAYLOAD.replace("{uid}", uid)
        marker = f"__WSCAN_DOMXSS__{uid}"

        if self.monitor:
            await self.monitor.emit_payload_test(field_name, payload, "dom_xss")

        try:
            # Install DOM hook before the page loads
            await self.browser.page.add_init_script(_HOOK_SCRIPT)

            if is_url_param:
                source, pair = await self.browser.test_url_param(url, field_name, payload)
            else:
                await self.browser.navigate(url)
                source, pair = await self.browser.fill_and_submit_form(
                    form_index, field_name, payload
                )

            await asyncio.sleep(0.8)  # Allow JS to settle

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
                    url=url,
                    field_name=field_name,
                    payload=payload,
                    evidence=(
                        f"DOM-based XSS: payload marker reached sink '{sink}'. "
                        f"Data excerpt: {data[:120]}"
                    ),
                    pair=pair,
                    severity="critical",
                )
                findings.append(finding)
                break  # One sink is enough evidence

        # Also check if alert fired (extra confirmation)
        if not findings and self.browser.dialog_fired and marker in self.browser.dialog_message:
            finding = await self.record_finding(
                url=url,
                field_name=field_name,
                payload=payload,
                evidence=f"DOM-based XSS confirmed: alert() fired with marker in dialog",
                pair=pair,
                severity="critical",
                dialog_confirmed=True,
                dialog_message=self.browser.dialog_message,
            )
            findings.append(finding)

        return findings
