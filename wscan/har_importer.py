"""
HAR File Importer
=================
HTTP Archive (HAR) ファイルを読み込み、スキャンのシードデータを生成する。

ブラウザの DevTools「ネットワーク → HAR としてエクスポート」や
Burp Suite の「Save items」機能で取得した HAR を利用し、
発見済みエンドポイント・Cookie・Authorization ヘッダを
スキャンに引き渡す。

使い方:
    from wscan.har_importer import HarImporter
    seed = HarImporter().load("captured.har")
    # seed.urls      — 発見されたエンドポイント URL リスト
    # seed.cookies   — Playwright 形式の Cookie リスト
    # seed.headers   — Authorization などの共通ヘッダ
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse, urlencode


@dataclass
class HarSeedData:
    """HAR から抽出したスキャンシードデータ。"""
    urls: list[str] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)   # Playwright 形式
    headers: dict[str, str] = field(default_factory=dict)  # Authorization など

    def __repr__(self) -> str:
        return (
            f"HarSeedData(urls={len(self.urls)}, "
            f"cookies={len(self.cookies)}, "
            f"headers={list(self.headers.keys())})"
        )


class HarImporter:
    """HAR ファイルを解析してスキャンシードデータを生成する。"""

    # 静的アセットは URL として収集しない
    _SKIP_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot",
        ".css", ".map",
        ".mp4", ".webm", ".ogg",
    }

    # これらの Content-Type は動的コンテンツとみなす
    _DYNAMIC_CONTENT_TYPES = {
        "text/html", "application/json", "application/xml",
        "text/xml", "text/plain",
        "application/x-www-form-urlencoded", "multipart/form-data",
    }

    def load(self, har_path: str) -> HarSeedData:
        """
        HAR ファイルを読み込んで HarSeedData を返す。

        Parameters
        ----------
        har_path : HAR ファイルのパス

        Returns
        -------
        HarSeedData
        """
        p = Path(har_path)
        if not p.exists():
            raise FileNotFoundError(f"HAR ファイルが見つかりません: {har_path}")

        # HAR は cp932/Shift-JIS で保存されたり gzip 圧縮で渡されることがあるため、
        # 生の UTF-8 読み込みではなく耐性のあるデコーダを使う（byte 0x8b 対策）。
        from .textio import read_text_resilient

        try:
            har = json.loads(read_text_resilient(p))
        except json.JSONDecodeError as exc:
            raise ValueError(f"HAR ファイルの JSON 解析に失敗しました: {exc}") from exc

        entries: list[dict] = har.get("log", {}).get("entries", [])
        if not entries:
            return HarSeedData()

        urls: list[str] = []
        all_cookies: list[dict] = []
        common_headers: dict[str, str] = {}
        seen_urls: set[str] = set()

        for entry in entries:
            req = entry.get("request", {})
            resp = entry.get("response", {})

            url = req.get("url", "")
            method = req.get("method", "GET").upper()

            # スキップ判定
            if not url or not url.startswith(("http://", "https://")):
                continue
            if self._should_skip(url, resp):
                continue

            # URL 正規化 (POST の場合もクエリパラメータを含めたベース URL を保持)
            normalized = self._normalize_url(url)
            if normalized not in seen_urls:
                seen_urls.add(normalized)
                urls.append(url)

            # Cookie 収集 (Set-Cookie ヘッダから)
            for hdr in resp.get("headers", []):
                if hdr.get("name", "").lower() == "set-cookie":
                    cookie = self._parse_set_cookie(hdr.get("value", ""), url)
                    if cookie:
                        all_cookies.append(cookie)

            # Cookie ヘッダから既存セッション Cookie を収集
            for hdr in req.get("headers", []):
                name = hdr.get("name", "").lower()
                value = hdr.get("value", "")
                if name == "cookie":
                    for cookie in self._parse_cookie_header(value, url):
                        all_cookies.append(cookie)
                # Authorization / API キーなどの共通ヘッダを抽出
                elif name in ("authorization", "x-api-key", "x-auth-token",
                               "x-access-token", "bearer"):
                    common_headers[hdr.get("name", name)] = value

        # Cookie の重複除去 (name + domain で一意化、後勝ち)
        deduped_cookies = self._dedup_cookies(all_cookies)

        return HarSeedData(
            urls=urls,
            cookies=deduped_cookies,
            headers=common_headers,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _should_skip(self, url: str, response: dict) -> bool:
        """静的アセットや無関係なリクエストをスキップするか判定する。"""
        # 拡張子チェック
        parsed = urlparse(url)
        path = parsed.path.lower()
        _, ext = path.rsplit(".", 1) if "." in path.split("/")[-1] else (path, "")
        if f".{ext}" in self._SKIP_EXTENSIONS:
            return True

        # ステータスコードチェック (リダイレクトや 4xx/5xx を除外しない — 脆弱なレスポンスの可能性)
        status = response.get("status", 200)
        if status in (301, 302, 303, 307, 308):
            return False  # リダイレクトも収集する

        return False

    @staticmethod
    def _normalize_url(url: str) -> str:
        """URL を正規化してクエリパラメータ名のみ保持した形式にする。"""
        try:
            p = urlparse(url)
            # クエリパラメータの値を除いてキーのみ正規化 (同一パターンの URL 重複防止)
            if p.query:
                params = [kv.split("=")[0] for kv in p.query.split("&") if kv]
                normalized_query = "&".join(sorted(params))
                return f"{p.scheme}://{p.netloc}{p.path}?{normalized_query}"
            return f"{p.scheme}://{p.netloc}{p.path}"
        except Exception:
            return url

    @staticmethod
    def _parse_set_cookie(header_value: str, request_url: str) -> dict | None:
        """Set-Cookie ヘッダ値を Playwright 形式の Cookie dict に変換する。"""
        if not header_value:
            return None
        parts = [p.strip() for p in header_value.split(";")]
        if not parts:
            return None
        name_value = parts[0]
        if "=" not in name_value:
            return None
        name, _, value = name_value.partition("=")

        parsed_url = urlparse(request_url)
        domain = parsed_url.hostname or ""
        path = "/"
        secure = False
        http_only = False
        same_site = "Lax"
        expires = -1

        for part in parts[1:]:
            lower = part.lower()
            if lower.startswith("domain="):
                domain = part[7:].lstrip(".")
            elif lower.startswith("path="):
                path = part[5:]
            elif lower == "secure":
                secure = True
            elif lower == "httponly":
                http_only = True
            elif lower.startswith("samesite="):
                same_site = part[9:].capitalize()
            elif lower.startswith("expires="):
                pass  # expires は無視 (セッション Cookie として扱う)
            elif lower.startswith("max-age="):
                try:
                    age = int(part[8:])
                    if age <= 0:
                        return None  # 削除 Cookie は無視
                except ValueError:
                    pass

        return {
            "name":     name.strip(),
            "value":    value.strip(),
            "domain":   domain,
            "path":     path,
            "secure":   secure,
            "httpOnly": http_only,
            "sameSite": same_site,
            "expires":  expires,
        }

    @staticmethod
    def _parse_cookie_header(header_value: str, request_url: str) -> list[dict]:
        """Cookie リクエストヘッダを Playwright 形式の Cookie リストに変換する。"""
        cookies: list[dict] = []
        parsed_url = urlparse(request_url)
        domain = parsed_url.hostname or ""
        for pair in header_value.split(";"):
            pair = pair.strip()
            if "=" not in pair:
                continue
            name, _, value = pair.partition("=")
            cookies.append({
                "name":     name.strip(),
                "value":    value.strip(),
                "domain":   domain,
                "path":     "/",
                "secure":   parsed_url.scheme == "https",
                "httpOnly": False,
                "sameSite": "Lax",
                "expires":  -1,
            })
        return cookies

    @staticmethod
    def _dedup_cookies(cookies: list[dict]) -> list[dict]:
        """name + domain の組み合わせで重複を除去 (後勝ち)。"""
        seen: dict[tuple, dict] = {}
        for c in cookies:
            key = (c.get("name", ""), c.get("domain", ""))
            seen[key] = c
        return list(seen.values())
