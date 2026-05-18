"""
CMS Scanner
===========
CMS 固有の脆弱性・設定ミスを検出するスキャナー。
cms_detect.py で CMS が判定された後に実行される。

対応:
  - WordPress: xmlrpc.php 有効、wp-config.php.bak、debug.log 露出
  - Django: DEBUG=True 露出、/admin/ 認証なし
  - Laravel: .env 露出、APP_DEBUG=True
  - Drupal: CHANGELOG.txt 露出、install.php 残存
  - Joomla: /administrator/ 列挙
  - Magento: /downloader/ 露出
  - 汎用: backup ファイル、robots.txt 内の機密パス
"""
from __future__ import annotations

from .base import BaseScanner, Finding


class CmsScanner(BaseScanner):
    CHECK_TYPE = "cms"
    SEVERITY = "medium"

    # (path, description, severity)
    _GENERIC_PATHS = [
        ("/robots.txt",          "robots.txt",                  "info"),
        ("/.env",                ".env ファイル露出",           "critical"),
        ("/.env.local",          ".env.local ファイル露出",     "critical"),
        ("/.env.production",     ".env.production 露出",        "critical"),
        ("/config.php.bak",      "config.php バックアップ露出", "high"),
        ("/config.bak",          "config.bak 露出",             "high"),
        ("/backup.zip",          "backup.zip 露出",             "high"),
        ("/database.sql",        "database.sql 露出",           "critical"),
        ("/db.sql",              "db.sql 露出",                 "critical"),
    ]

    _WP_PATHS = [
        ("/xmlrpc.php",                       "WordPress xmlrpc.php 有効",           "medium"),
        ("/wp-config.php.bak",                "wp-config.php.bak 露出",              "critical"),
        ("/wp-config.php~",                   "wp-config.php~ 露出",                 "critical"),
        ("/wp-content/debug.log",             "WordPress debug.log 露出",            "high"),
        ("/wp-json/wp/v2/users",              "WordPress ユーザー列挙 API",           "medium"),
        ("/wp-content/uploads/",              "WordPress uploads ディレクトリ一覧",   "info"),
    ]

    _DRUPAL_PATHS = [
        ("/CHANGELOG.txt",   "Drupal CHANGELOG.txt 露出",  "medium"),
        ("/install.php",     "Drupal install.php 残存",    "high"),
        ("/update.php",      "Drupal update.php 残存",     "high"),
        ("/README.txt",      "Drupal README.txt 露出",     "info"),
    ]

    _DJANGO_PATHS = [
        ("/admin/",          "Django /admin/ アクセス確認",   "info"),
    ]

    _LARAVEL_PATHS = [
        ("/.env",            ".env ファイル露出",             "critical"),
        ("/storage/logs/laravel.log", "Laravel ログ露出",     "high"),
        ("/phpinfo.php",     "phpinfo.php 露出",              "high"),
    ]

    _JOOMLA_PATHS = [
        ("/administrator/",          "Joomla 管理画面アクセス確認",    "info"),
        ("/configuration.php.bak",   "configuration.php.bak 露出",      "critical"),
    ]

    _MAGENTO_PATHS = [
        ("/downloader/",             "Magento downloader 露出",          "medium"),
        ("/app/etc/local.xml",       "Magento local.xml 露出",           "critical"),
    ]

    async def scan_field(self, url, form_index, field, is_url_param=False):
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        """CMS 検出後に既知の脆弱パスを探索する。"""
        import time
        import httpx
        from urllib.parse import urlparse

        detected_cms = getattr(self.engine, "detected_cms", None)
        findings: list[Finding] = []

        # ベース URL の取得 (scheme + netloc)
        parsed = urlparse(self.engine.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # CMS 固有のパスリスト選択
        cms_name = detected_cms.name if detected_cms else "unknown"
        paths = list(self._GENERIC_PATHS)
        if cms_name == "wordpress":
            paths += self._WP_PATHS
        elif cms_name == "drupal":
            paths += self._DRUPAL_PATHS
        elif cms_name == "django":
            paths += self._DJANGO_PATHS
        elif cms_name == "laravel":
            paths += self._LARAVEL_PATHS
        elif cms_name == "joomla":
            paths += self._JOOMLA_PATHS
        elif cms_name == "magento":
            paths += self._MAGENTO_PATHS

        # セッション Cookie を引き継ぐ
        cookies_str = getattr(self.engine, "cookies", "") or ""
        cookies_dict: dict = {}
        if cookies_str:
            for part in cookies_str.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies_dict[k.strip()] = v.strip()

        proxy = getattr(self.engine, "proxy", "") or None
        client_kwargs: dict = {"timeout": 10.0, "follow_redirects": True}
        if proxy:
            client_kwargs["proxy"] = proxy
        if hasattr(self.engine, "auth_headers"):
            # Strip Cookie from auth_headers because we already pass it via
            # the ``cookies`` kwarg below; httpx would otherwise duplicate it.
            client_kwargs["headers"] = {
                k: v for k, v in self.engine.auth_headers().items()
                if k.lower() != "cookie"
            }

        async with httpx.AsyncClient(**client_kwargs) as client:
            for path, desc, severity in paths:
                target_url = base + path
                try:
                    req_ts = time.time()
                    resp = await client.get(target_url, cookies=cookies_dict)
                    resp_ts = time.time()
                    status = resp.status_code
                    body = resp.text[:2000]
                    pair = {
                        "request": {"url": target_url, "method": "GET", "timestamp": req_ts},
                        "response": {"status": status, "body": body, "timestamp": resp_ts},
                    }
                except Exception:
                    continue

                # 200 → 検出
                if status == 200:
                    # .env ファイルの中身チェック
                    if path.endswith(".env") and (
                        "APP_KEY" in body or "DB_PASSWORD" in body or "SECRET" in body.upper()
                    ):
                        severity = "critical"
                        desc += " (機密情報を含む)"

                    # robots.txt は情報として記録するだけ (通常は公開ファイル)
                    if path == "/robots.txt":
                        continue

                    f = await self.record_finding(
                        url=target_url,
                        field_name="(page)",
                        payload=path,
                        evidence=f"{desc}: HTTP {status}",
                        pair=pair,
                        severity=severity,
                    )
                    if f:
                        findings.append(f)

                elif status == 405 and path == "/xmlrpc.php":
                    # xmlrpc.php は 405 でも有効 (POST が必要)
                    f = await self.record_finding(
                        url=target_url,
                        field_name="(page)",
                        payload=path,
                        evidence=f"{desc}: HTTP {status} (POST必要、xmlrpc有効)",
                        pair=pair,
                        severity=severity,
                    )
                    if f:
                        findings.append(f)

        return findings
