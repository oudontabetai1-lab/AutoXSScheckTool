"""Attempt.req_url（応答/リクエスト URL）の抽出と serialization round-trip（G6）。

WAF フィードバックの origin 帰属は、静的予測でなく台帳が実際に記録した応答 origin で行う。
"""
from wscan.attempt_ledger import AttemptLedger, Attempt, attempt_from_pair


def test_non_redirect_uses_request_url():
    # 非リダイレクト（request.url と最終 response.url が同一エンドポイント）は request.url。
    pair = {"response": {"status": 403, "url": "https://a.test/post", "body": ""},
            "request": {"url": "https://a.test/post"}}
    a = attempt_from_pair("p", "", pair)
    assert a.req_url == "https://a.test/post"
    assert a.status == 403


def test_non_redirect_default_port_spelling_kept():
    # 既定ポート表記の差（:443）だけで実体は同一エンドポイント → 非リダイレクト扱いで request.url。
    pair = {"response": {"status": 403, "url": "https://a.test/post"},
            "request": {"url": "https://a.test:443/post"}}
    a = attempt_from_pair("p", "", pair)
    assert a.req_url == "https://a.test:443/post"


def test_same_origin_redirect_marks_url_unknown():
    # 同一 origin でも path が変わる 301/302/303。最終 status は payload を運んだ req のもので
    # ないため unknown（None）。
    pair = {"response": {"status": 403, "url": "https://a.test/final"},
            "request": {"url": "https://a.test/post"}}
    a = attempt_from_pair("p", "", pair)
    assert a.req_url is None
    assert a.status == 403


def test_cross_origin_redirect_marks_url_unknown():
    pair = {"response": {"status": 403, "url": "https://b.test/final"},
            "request": {"url": "https://a.test/post"}}
    a = attempt_from_pair("p", "", pair)
    assert a.req_url is None


def test_attempt_from_pair_falls_back_to_response_url_when_no_request_url():
    pair = {"response": {"status": 200, "url": "https://a.test/x", "body": "p"}, "request": {}}
    a = attempt_from_pair("p", "", pair)
    assert a.req_url == "https://a.test/x"


def test_attempt_from_pair_empty_pair_has_no_url():
    a = attempt_from_pair("p", "", {})
    assert a.req_url is None and a.error is True


def test_req_url_round_trips_through_serialization():
    led = AttemptLedger()
    key = ("http://x", "q", "0", "f", "")
    led.record(key, "xss", Attempt(payload="p", status=403, req_url="https://b.test/api"))
    restored = AttemptLedger.from_dict(led.to_dict())
    hist = restored.history(key, "xss")
    assert hist and hist[0].req_url == "https://b.test/api"


if __name__ == "__main__":
    import unittest
    unittest.main()
