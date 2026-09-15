"""F03: JWT ページ検査で cookies_str が未初期化になり検査が脱落する回帰テスト。

通常 ScanEngine は `auth_headers` を持つため scan_page は `if hasattr(engine,'auth_headers')`
の真ブランチを通る。以前は `cookies_str` を else 節でのみ代入していたため、後段の
session cookie からの JWT 抽出（`if cookies_str:`）で NameError となり、JWT の有無を
確かめる前に検査が丸ごと脱落していた。auth_headers 経路でも scan_page が例外なく
完了することを検証する。
"""
import asyncio
from unittest.mock import patch

import httpx

from wscan.scanners.jwt_scanner import JWTScanner, _build_jwt


class _AuthEngine:
    """auth_headers を持つ（=通常 ScanEngine と同じ）最小エンジンダブル。"""

    def __init__(self, cookies=""):
        self.browser = None
        self.monitor = None
        self.payload_gen = None
        self._finding_dedup = set()
        self.all_findings = []
        self.checks = []
        self.cookies = cookies
        self.timeout = 5

    def auth_headers(self, extra=None, include_cookie=True):
        return dict(extra or {})


def _fake_client_returning(body: str):
    class _Resp:
        status_code = 200
        url = "http://fixture.test/jwt"

        def __init__(self):
            self.text = body
            self.headers = httpx.Headers([])

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            return _Resp()

    return _Client


def _run_scan_page(engine, body):
    scanner = JWTScanner(engine)
    with patch("wscan.scanners.jwt_scanner.httpx.AsyncClient",
               _fake_client_returning(body)):
        return asyncio.run(scanner.scan_page("http://fixture.test/jwt"))


def test_scan_page_auth_headers_path_does_not_raise():
    # 以前はこの経路で cookies_str 未束縛 → NameError。修正後は空応答で [] を返す。
    result = _run_scan_page(_AuthEngine(cookies=""), body="")
    assert result == []


def test_scan_page_collects_jwt_from_session_cookie():
    # session cookie（engine.cookies）中の JWT も auth_headers 経路で拾えること。
    token = _build_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "admin"}, "secret")
    result = _run_scan_page(_AuthEngine(cookies=f"session={token}"), body="")
    # 未初期化バグがあればここへ到達する前に NameError。到達＝バグ解消。
    assert isinstance(result, list)
