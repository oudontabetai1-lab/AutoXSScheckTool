"""
Information Disclosure / Sensitive File Exposure Scanner (V-3)
Checks for:
  1. Accessible sensitive files/directories (.env, .git, phpinfo, backup files, etc.)
  2. Technology stack leakage in HTTP response headers (Server, X-Powered-By, etc.)
  3. Verbose error page patterns that reveal framework/DB details
"""
import re
import httpx
from urllib.parse import urljoin, urlparse
from typing import TYPE_CHECKING

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# Paths that should never be publicly accessible
_SENSITIVE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/.DS_Store",
    "/web.config",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.sql",
    "/db.sql",
    "/dump.sql",
    "/database.sql",
    "/wp-config.php.bak",
    "/config.php.bak",
    "/application.log",
    "/error.log",
    "/debug.log",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/mappings",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v2/api-docs",
    "/.well-known/security.txt",
    "/crossdomain.xml",
    "/elmah.axd",
    "/trace.axd",
    "/server-status",
    "/server-info",
    # 忘れ物 artifact（バージョン管理内部・秘密・バックアップ）。各パスは下の
    # _ARTIFACT_PATTERNS または（署名の無いもののみ）soft-404 ベースライン比較付きの
    # 非 HTML fallback で「実際に配信された」ことを確認してから報告する（0017）。
    # 既に上に含まれるパス（/.env・/.git/* 等）は重複登録しない。
    "/.hg/requires",
    "/.env.bak",
    "/.htpasswd",
    "/.npmrc",
    "/.aws/credentials",
    "/id_rsa",
    "/web.config.bak",
]

# Patterns that confirm a sensitive file was actually served (not a 404 page)
_CONTENT_PATTERNS: dict[str, str] = {
    r"DB_PASSWORD|DB_HOST|APP_KEY|SECRET_KEY|AWS_SECRET":       ".env file content",
    r"\[core\]\s*repositoryformatversion":                      ".git config content",
    r"<title>phpinfo\(\)</title>":                              "phpinfo() output",
    r"root:.*:/bin/(?:bash|sh)":                                "/etc/passwd content",
    r"(?i)fatal\s+error.*on\s+line\s+\d+":                     "PHP fatal error with stack trace",
    r"(?i)at\s+[\w\.]+\([\w\.]+\.java:\d+\)":                  "Java stack trace",
    r"(?i)Traceback \(most recent call last\)":                 "Python traceback",
    r"(?i)microsoft.*ole.*db.*provider.*error":                 "MSSQL OLE DB error",
    r"(?i)syntax error.*near.*line \d+":                        "SQL syntax error",
    r"(?i)(mysql|postgresql|sqlite|oracle)\s+error":            "Database error",
}

# 忘れ物 artifact（実際に配信されたファイル）の確定シグネチャ（0017）。これらは
# _check_sensitive_files でのみ使う。_check_error_page（通常ページ HTML の監査）には
# 混ぜない——SQL DDL やアーカイブ断片は正常ページにも現れ得て誤検知になるため。
_ARTIFACT_PATTERNS: dict[str, str] = {
    r"ref:\s*refs/":                                            ".git/HEAD content",
    r"(?:dir\n\d+\n|svn://|\.svn/)":                            ".svn metadata",
    r"^revlogv1|^store\b":                                      ".hg metadata",
    r":\$(?:apr1|2[aby]|6)\$|:\{SHA\}":                         ".htpasswd hashes",
    r"_authToken=|//registry\.":                                ".npmrc registry token",
    r"aws_access_key_id\s*=|aws_secret_access_key\s*=":         ".aws credentials",
    r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----":  "private key file",
    # 実 .DS_Store は先頭 4 バイト(00 00 00 01)＋"Bud1"。^Bud1 では復号本文に一致しない。
    r"\x00\x00\x00\x01Bud1":                                    ".DS_Store metadata",
    r"(?i)(?:INSERT INTO|CREATE TABLE|DROP TABLE IF EXISTS)":   "SQL dump content",
    r"^PK\x03\x04":                                             "ZIP archive (possible backup)",
}

# 署名種別 → その本文に秘匿情報が含まれるため、レポートには本文を平文で保存しない
# （マスクする）。0017。.env も秘密（DB_PASSWORD 等）を含むため対象。
_SECRET_ARTIFACT_LABELS = frozenset({
    ".htpasswd hashes", ".npmrc registry token", ".aws credentials",
    "private key file", ".env file content",
})

# ラベル → そのシグネチャが適用可能なパス断片（小文字・部分一致のいずれか）。
# 署名内容が一致しても、パスが不適合なら採用しない。これで (a) 別ファイル用の署名を
# 誤ったラベルで選ばない（例: /.aws/credentials を「.env file content」にしない）、
# (b) soft-404 の catch-all ページ（例 CREATE TABLE を含む SQL 解説）を全パスの
# 「機密ファイル」に化けさせない、を同時に防ぐ（Codex #156 P1）。パス非依存の
# エラー/漏えい署名（phpinfo・stack trace 等）はマップに載せず常に適用可とする。
_LABEL_PATHS: dict[str, tuple[str, ...]] = {
    ".env file content":            (".env",),
    ".git config content":          ("/.git/",),
    ".git/HEAD content":            ("/.git/",),
    ".svn metadata":                ("/.svn/",),
    ".hg metadata":                 ("/.hg/",),
    ".htpasswd hashes":             (".htpasswd",),
    ".npmrc registry token":        (".npmrc",),
    ".aws credentials":             ("/.aws/",),
    "private key file":             ("id_rsa", "id_dsa", "id_ecdsa", ".key", ".pem"),
    ".DS_Store metadata":           (".ds_store",),
    "SQL dump content":             (".sql",),
    "ZIP archive (possible backup)": (".zip", ".tar.gz", ".tgz"),
}

# 本文に秘密を含みうるパス（ラベル判定に依らず本文をマスクする保険）。
_SECRET_PATH_MARKERS = (
    ".env", ".htpasswd", ".npmrc", "/.aws/", "id_rsa", "id_dsa", "id_ecdsa",
    ".key", ".pem", "config.php.bak", "wp-config", "web.config",
)


def _label_applies(label: str, path: str) -> bool:
    """ラベルが当該パスに適用可能か（マップ外のラベルは常に True＝パス非依存）。"""
    markers = _LABEL_PATHS.get(label)
    if not markers:
        return True
    p = (path or "").lower()
    return any(mk in p for mk in markers)


def _is_secret_path(path: str) -> bool:
    p = (path or "").lower()
    return any(mk in p for mk in _SECRET_PATH_MARKERS)

# ディレクトリリスティング（autoindex）の確定シグネチャ。
_DIR_LISTING_PATTERNS = (
    re.compile(r"<title>\s*Index of /", re.IGNORECASE),
    re.compile(r"<h1>\s*Index of /", re.IGNORECASE),
    re.compile(r'\[To Parent Directory\]', re.IGNORECASE),  # IIS
    re.compile(r'<a href="\?C=N;O=D">Name</a>', re.IGNORECASE),  # Apache autoindex
)

# ディレクトリリスティングを試すよくある公開ディレクトリ。
_LISTING_DIRS = (
    "/", "/uploads/", "/files/", "/images/", "/assets/", "/backup/",
    "/backups/", "/download/", "/downloads/", "/tmp/", "/static/", "/media/",
)


# 単独で autoindex を確定できる強いマーカー（サーバ生成に固有）。
_DIR_LISTING_STRONG = (
    re.compile(r'\[To Parent Directory\]', re.IGNORECASE),          # IIS
    re.compile(r'<a href="\?C=N;O=D">Name</a>', re.IGNORECASE),     # Apache autoindex ソートリンク
)
# タイトル/見出しの "Index of /"（単独では弱い＝別途 補強証拠が要る）。
_DIR_LISTING_TITLE = (
    re.compile(r"<title>\s*Index of /", re.IGNORECASE),
    re.compile(r"<h1>\s*Index of /", re.IGNORECASE),
)
# autoindex を補強する構造的証拠（親ディレクトリリンク・ファイル行）。
_DIR_LISTING_CORROBORATION = (
    re.compile(r'(?i)>\s*(?:Parent Directory|\.\.)\s*<'),           # 親ディレクトリ行
    re.compile(r'(?i)<a href="[^"?][^"]*">[^<]+</a>\s*'
               r'\d{1,2}-\w{3}-\d{4}'),                             # Apache のファイル行（名前+日付）
)


def detect_directory_listing(body: str) -> bool:
    """レスポンス本文が autoindex（ディレクトリリスティング）かを判定する（純粋）。

    誤検知を抑えるため、(1) サーバ生成に固有の強いマーカー1つ、または
    (2) "Index of /" タイトル/見出し＋親ディレクトリ/ファイル行の補強証拠、のいずれかを要求する。
    タイトル文字列だけの一致では確定しない（"Index of / ..." を含む通常ページを拾わない）。
    """
    if not body:
        return False
    if any(p.search(body) for p in _DIR_LISTING_STRONG):
        return True
    if any(p.search(body) for p in _DIR_LISTING_TITLE):
        return any(p.search(body) for p in _DIR_LISTING_CORROBORATION)
    return False


# soft-404（存在しないパスにも 200 を返すサーバ）判定のため、まず「まず存在しない」パスを
# 引いて基準本文を得る。基準が 200 の非 HTML/一定本文なら、その origin では非 HTML fallback を
# 信頼せず「署名一致のみ」で報告する（0017 のリーク物検査は soft-404 で誤検知しやすいため）。
_SOFT404_PROBE = "/wscan-nonexistent-probe-8f3a1c9e2b.zzz"


def _redact_sensitive(body: str, limit: int = 300) -> str:
    """秘匿ファイル本文をレポート保存用にマスクする（純粋）。

    key=value / key: value の値、および秘密鍵ブロックを伏字化し、先頭 ``limit`` 文字に切る。
    レポートには「何が露出したか」の証跡は残しつつ、秘密の実値は残さない。
    """
    if not body:
        return ""
    text = body[:limit]
    # 秘密鍵ブロックはヘッダだけ残して本体を伏字化。
    text = re.sub(
        r"(-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----).*",
        r"\1 [REDACTED]", text, flags=re.DOTALL,
    )
    # aws_secret_access_key=..., _authToken=..., password: ... 等の値を伏字化
    # （行頭とは限らない: npmrc は `//registry...:_authToken=` の形を取る）。
    text = re.sub(
        r"(?i)([\w.\-]*(?:key|token|secret|password|passwd|pwd)[\w.\-]*\s*[:=]\s*)\S+",
        r"\1[REDACTED]", text,
    )
    # htpasswd のハッシュ（user:$apr1$...）を伏字化。
    text = re.sub(r"(:\$(?:apr1|2[aby]|6)\$)\S+", r"\1[REDACTED]", text)
    return text

# Headers that reveal technology stack
_TECH_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-joomla-cache",
]


class InfoDisclosureScanner(BaseScanner):
    """Sensitive file exposure and information disclosure scanner."""

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "info_disclosure"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.PAGE_ANALYSIS}),
        capabilities=(
            CarrierCapability(
                carrier=Carrier.QUERY, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.FORM, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.JSON, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.XML, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.MULTIPART, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.HEADER, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.COOKIE, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                # scan_page→_check_sensitive_files() が _SENSITIVE_PATHS 各エントリを
                # HTTPX GET し露出ファイルを検出するため supported。
                carrier=Carrier.PATH, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                carrier=Carrier.GRAPHQL, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.WEBSOCKET, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
        ),
        state_change=StateChangeClass.READ_ONLY,
        cost=CostClass.LOW,
    )

    SEVERITY = "medium"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_origins: set[str] = set()

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        """Run all disclosure checks once per origin."""
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        if origin in self._checked_origins:
            return await self._check_error_page(url)
        self._checked_origins.add(origin)

        findings = []
        findings += await self._check_sensitive_files(origin)
        findings += await self._check_directory_listing(origin)
        findings += await self._check_tech_headers(url)
        findings += await self._check_error_page(url)
        return findings

    async def _check_directory_listing(self, origin: str) -> list[Finding]:
        """よくある公開ディレクトリで autoindex（ディレクトリリスティング）が有効かを検出する（0017）。"""
        findings: list[Finding] = []
        proxy = getattr(self.engine, "proxy", "") or None
        timeout = getattr(self.engine, "timeout", 15)
        kwargs: dict = {"timeout": timeout, "follow_redirects": False}
        if hasattr(self.engine, "httpx_client_kwargs"):
            kwargs = self.engine.httpx_client_kwargs(**kwargs)
        elif proxy:
            kwargs["proxy"] = proxy
        if hasattr(self.engine, "auth_headers"):
            kwargs["headers"] = self.auth_headers_for_url(origin)

        try:
            async with httpx.AsyncClient(**kwargs) as client:
                for path in _LISTING_DIRS:
                    target = urljoin(origin, path)
                    try:
                        r = await client.get(target)
                        self._record_probe_status(r)
                    except Exception:
                        self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:dir_listing")
                        continue
                    if r.status_code not in (200, 206):
                        continue
                    if not detect_directory_listing(r.text[:4000]):
                        continue
                    pair = {
                        "request": {"url": target},
                        "response": {"status": r.status_code,
                                     "headers": dict(r.headers), "body": r.text[:2000]},
                    }
                    findings.append(await self.record_finding(
                        url=target,
                        field_name="(directory listing)",
                        payload="(GET request — no payload)",
                        evidence=(
                            f"Directory listing (autoindex) enabled: {path} → HTTP {r.status_code}. "
                            "ファイル一覧が露出し、意図しないファイルの発見に悪用され得ます。"
                        ),
                        pair=pair,
                        severity="medium",
                        confidence="confirmed",
                        evidence_type="info_directory_listing",
                        evidence_details={"path": path},
                        reproduction_steps=[
                            f"Request {target}",
                            "Confirm the response is an autoindex directory listing (\"Index of /\").",
                            "Disable directory indexing (e.g. Apache: Options -Indexes).",
                        ],
                    ))
        except Exception:
            self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:dir_listing_client")
        return findings

    # ------------------------------------------------------------------

    async def _check_sensitive_files(self, origin: str) -> list[Finding]:
        """Probe well-known sensitive paths on the server origin."""
        findings = []
        proxy = getattr(self.engine, "proxy", "") or None
        timeout = getattr(self.engine, "timeout", 15)

        kwargs: dict = {
            "timeout": timeout,
            "follow_redirects": False,
        }
        if hasattr(self.engine, "httpx_client_kwargs"):
            kwargs = self.engine.httpx_client_kwargs(**kwargs)
        elif proxy:
            kwargs["proxy"] = proxy
        if hasattr(self.engine, "auth_headers"):
            kwargs["headers"] = self.auth_headers_for_url(origin)

        if self.monitor:
            await self.monitor.emit_status(
                f"Info disclosure: probing sensitive files on {origin}"
            )

        async with httpx.AsyncClient(**kwargs) as client:
            # soft-404 判定: まず存在しないパスを引く。200/206 が返る（＝存在しないのに
            # 応答する）サーバでは、非 HTML fallback を信頼せず「署名一致のみ」で報告する。
            soft404 = False
            try:
                probe = await client.get(urljoin(origin, _SOFT404_PROBE))
                self._record_probe_status(probe)
                soft404 = probe.status_code in (200, 206)
            except Exception as exc:
                self._record_scan_note(
                    f"probe_error:{self.CHECK_TYPE}:soft404_baseline:{type(exc).__name__}"
                )

            for path in _SENSITIVE_PATHS:
                target = urljoin(origin, path)
                try:
                    r = await client.get(target)
                    self._record_probe_status(r)
                    if r.status_code not in (200, 206):
                        continue
                    body = r.text[:4000]

                    # 確定は「ファイル内容の署名一致」を最優先。エラー系署名と artifact 署名の両方を見る。
                    # ただし署名は当該パスに適用可能なものだけ採用する（誤ラベル選択・soft-404 catch-all を防ぐ）。
                    matched_label = None
                    for pattern, label in {**_CONTENT_PATTERNS, **_ARTIFACT_PATTERNS}.items():
                        if not _label_applies(label, path):
                            continue
                        if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                            matched_label = label
                            break

                    # Fallback: Content-Type が非 HTML で本文が非空なら疑う。ただし soft-404 の
                    # origin ではこの一般 fallback を使わない（署名の無い 200 は誤検知になるため）。
                    ct = r.headers.get("content-type", "")
                    if (matched_label is None and not soft404
                            and "html" not in ct and len(body.strip()) > 20):
                        matched_label = "non-HTML content (possible sensitive file)"

                    if matched_label is None:
                        continue

                    severity = "critical" if ".env" in path or ".git" in path else "high"
                    # 秘匿情報を含むファイルはレポートに本文を平文で残さない（マスク）。
                    # ラベル判定に加えパスでも判断する（誤ラベル時の取りこぼしを防ぐ保険）。
                    stored_body = (
                        _redact_sensitive(body)
                        if (matched_label in _SECRET_ARTIFACT_LABELS or _is_secret_path(path))
                        else body
                    )
                    pair = {
                        "request": {"url": target},
                        "response": {
                            "status": r.status_code,
                            "headers": dict(r.headers),
                            "body": stored_body,
                        },
                    }
                    finding = await self.record_finding(
                        url=target,
                        field_name="(sensitive file/directory)",
                        payload="(GET request — no payload)",
                        evidence=(
                            f"Sensitive resource accessible: {path} "
                            f"→ HTTP {r.status_code} — {matched_label}"
                        ),
                        pair=pair,
                        severity=severity,
                        confidence="confirmed",
                        evidence_type="info_sensitive_resource",
                        evidence_details={
                            "path": path,
                            "matched_label": matched_label,
                            "status": r.status_code,
                            "content_type": ct,
                        },
                    )
                    findings.append(finding)

                except Exception as exc:
                    self._record_scan_note(
                        f"probe_error:{self.CHECK_TYPE}:{type(exc).__name__}"
                    )
                    continue

        return findings

    async def _check_tech_headers(self, url: str) -> list[Finding]:
        """Check response headers for technology version disclosure."""
        pair = self.current_page_pair(url)
        resp_headers = {
            k.lower(): v
            for k, v in pair.get("response", {}).get("headers", {}).items()
        }

        exposed = []
        for header in _TECH_HEADERS:
            value = resp_headers.get(header, "")
            if value:
                exposed.append(f"{header}: {value}")

        if not exposed:
            return []

        finding = await self.record_finding(
            url=url,
            field_name="(HTTP response headers)",
            payload="(no payload — header analysis)",
            evidence=(
                "Technology stack disclosed via HTTP headers: "
                + "; ".join(exposed)
            ),
            pair=pair,
            severity="low",
            confidence="likely",
            evidence_type="info_tech_headers",
            evidence_details={"headers": exposed},
        )
        return [finding]

    async def _check_error_page(self, url: str) -> list[Finding]:
        """Check current page HTML for verbose error / stack trace patterns."""
        try:
            source = await self.browser.page.content()
        except Exception:
            return []

        for pattern, label in _CONTENT_PATTERNS.items():
            if re.search(pattern, source, re.IGNORECASE | re.DOTALL):
                pair = self.current_page_pair(url)
                finding = await self.record_finding(
                    url=url,
                    field_name="(page HTML)",
                    payload="(no payload — page content analysis)",
                    evidence=f"Sensitive information in page: {label}",
                    pair=pair,
                    severity="medium",
                    confidence="likely",
                    evidence_type="info_error_pattern",
                    evidence_details={"matched_label": label, "pattern": pattern},
                )
                return [finding]

        return []

    async def verify_finding(self, finding: Finding) -> bool | None:
        if finding.evidence_type == "info_sensitive_resource":
            try:
                r = await self._get(finding.url, follow_redirects=False)
            except Exception:
                return None
            if r.status_code not in (200, 206):
                return False
            return self._classify_sensitive_body(
                r.text[:4000],
                r.headers.get("content-type", ""),
            ) is not None

        if finding.evidence_type == "info_tech_headers":
            try:
                r = await self._get(finding.url, follow_redirects=True)
            except Exception:
                return None
            headers = {k.lower(): v for k, v in r.headers.items()}
            expected = (getattr(finding, "evidence_details", {}) or {}).get("headers", [])
            if expected:
                return all(
                    ":" in item and headers.get(item.split(":", 1)[0].strip().lower(), "")
                    for item in expected
                )
            return any(headers.get(header) for header in _TECH_HEADERS)

        if finding.evidence_type == "info_error_pattern":
            try:
                r = await self._get(finding.url, follow_redirects=True)
            except Exception:
                return None
            return self._classify_error_body(r.text[:8000]) is not None

        if finding.evidence_type == "info_directory_listing":
            # GET し直して autoindex を再判定する（verify 分岐が無いと汎用 fallback が
            # _apply_payload を呼んで失敗→assumed へ格下げされ confirmed 集計から漏れる・Codex #156）。
            try:
                r = await self._get(finding.url, follow_redirects=False)
            except Exception:
                return None
            if r.status_code not in (200, 206):
                return False
            return detect_directory_listing(r.text[:4000])

        return None

    async def _get(self, url: str, follow_redirects: bool):
        proxy = getattr(self.engine, "proxy", "") or None
        timeout = getattr(self.engine, "timeout", 15)
        kwargs: dict = {"timeout": timeout, "follow_redirects": follow_redirects}
        if hasattr(self.engine, "httpx_client_kwargs"):
            kwargs = self.engine.httpx_client_kwargs(**kwargs)
        elif proxy:
            kwargs["proxy"] = proxy
        if hasattr(self.engine, "auth_headers"):
            kwargs["headers"] = self.auth_headers_for_url(url)
        async with httpx.AsyncClient(**kwargs) as client:
            response = await client.get(url)
            self._record_probe_status(response)
        return response

    def _classify_sensitive_body(self, body: str, content_type: str) -> str | None:
        for pattern, label in {**_CONTENT_PATTERNS, **_ARTIFACT_PATTERNS}.items():
            if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                return label
        if "html" not in content_type and len((body or "").strip()) > 20:
            return "non-HTML content (possible sensitive file)"
        return None

    def _classify_error_body(self, body: str) -> str | None:
        for pattern, label in _CONTENT_PATTERNS.items():
            if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                return label
        return None
