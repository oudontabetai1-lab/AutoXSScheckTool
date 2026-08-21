"""WAFDetector が follow_redirects の最終到達 origin を記録することの検証。

planner fingerprint（G5）で WAF を「実際に probe した origin」にだけ帰属させるため、
detect() は pre-redirect の target ではなく landed origin を _detected_origin に残す。
"""
import asyncio

import httpx

from wscan.waf_detector import WAFDetector


def _run(coro):
    return asyncio.run(coro)


def test_records_final_redirect_origin():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "a.test":
            return httpx.Response(302, headers={"Location": "https://b.test/"})
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)
    det = WAFDetector(
        tls_options_provider=lambda: {"verify": False, "transport": transport}
    )
    _run(det.detect("http://a.test/"))
    # pre-redirect(target)=http://a.test ではなく、landed=https://b.test を記録する。
    assert det._detected_origin == "https://b.test"


def test_records_origin_without_redirect_and_strips_default_port():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)
    det = WAFDetector(
        tls_options_provider=lambda: {"verify": False, "transport": transport}
    )
    _run(det.detect("https://c.test:443/x"))
    assert det._detected_origin == "https://c.test"
