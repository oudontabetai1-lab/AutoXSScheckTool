"""WAFDetector が「署名が一致した応答」の最終到達 origin を記録することの検証。

detect() は normal(resp) と anomaly probe(resp2) を送る。両者が別 origin に到達し得るため、
planner fingerprint（G5）で WAF を正しい origin に帰属させるには、当たった側の origin を記録する。
"""
import asyncio

import httpx

from wscan.waf_detector import WAFDetector


def _run(coro):
    return asyncio.run(coro)


def _detector(handler, record_status=None):
    transport = httpx.MockTransport(handler)
    return WAFDetector(
        tls_options_provider=lambda: {"verify": False, "transport": transport},
        record_status=record_status,
    )


def test_probe_match_records_probe_origin_after_redirect():
    # normal は origin B(200/無署名)へ、probe は origin A で WAF 署名(cf-ray)に当たる。
    def handler(request: httpx.Request) -> httpx.Response:
        is_probe = "wscan=" in (request.url.query.decode() if isinstance(request.url.query, bytes) else str(request.url.query))
        if request.url.host == "start.test":
            # normal はB、probeはAへ振り分け（probe だけ WAF に intercept される想定）
            dest = "https://a.test/" if is_probe else "https://b.test/"
            return httpx.Response(302, headers={"Location": dest})
        if request.url.host == "a.test":
            return httpx.Response(200, headers={"cf-ray": "abc-LAX"}, text="blocked")
        return httpx.Response(200, text="ok")

    det = _detector(handler)
    name = _run(det.detect("http://start.test/"))
    assert name == "Cloudflare"
    # 当たったのは probe(=origin A)なので A を記録する（normal の B ではない）。
    assert det._detected_origin == "https://a.test"


def test_normal_match_records_normal_origin():
    # normal 応答自体が WAF 署名を持つ場合は normal の origin を記録。
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"cf-ray": "xyz"}, text="ok")

    det = _detector(handler)
    name = _run(det.detect("https://c.test:443/x"))
    assert name == "Cloudflare"
    assert det._detected_origin == "https://c.test"


def test_normal_and_anomaly_statuses_are_recorded():
    recorded = []

    def handler(request: httpx.Request) -> httpx.Response:
        query = request.url.query
        is_probe = "wscan=" in (
            query.decode() if isinstance(query, bytes) else str(query)
        )
        if request.url.host == "status.test":
            location = (
                "https://external.test/rate-limit"
                if is_probe
                else "https://normal.test/final"
            )
            return httpx.Response(302, headers={"Location": location})
        return httpx.Response(
            429 if request.url.host == "external.test" else 200,
            text="ok",
        )

    det = _detector(
        handler,
        record_status=lambda status, url: recorded.append((status, str(url))),
    )

    assert _run(det.detect("https://status.test/")) is None
    assert recorded == [
        (200, "https://normal.test/final"),
        (429, "https://external.test/rate-limit"),
    ]
