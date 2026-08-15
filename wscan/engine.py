"""
WScan Scan Engine — 4-Phase Pipeline
=====================================
Phase 1: Crawl    — BFS crawl, collect page info. No payload injection.
Phase 2: Plan     — Build per-page attack plans (LLM or heuristic).
                    Cross-page XSS/stored-injection awareness.
                    User confirms before attack begins.
Phase 3: Attack   — Execute attacks guided by the plan.
  Phase 3a:         Standard payload sweep (default list + plan extras).
                    LLM adaptively re-ranks remaining pages on new findings.
  Phase 3b:         Adaptive AI round — after each field, LLM observes the
                    application's filtering behavior in the page HTML and
                    generates creative bypass payloads (encoding tricks,
                    WAF evasion, context-aware injection, polyglots).
  Phase 3c:         Chain detection — inject distinctive probes into content
                    fields, then check ALL pages for stored/second-order
                    execution (Stored XSS, HTML injection → XSS, SSTI chain).
  Phase 3d:         Multi-parameter simultaneous injection — fill all form
                    fields with their respective payloads at once to catch
                    cross-parameter interactions and WAF bypasses.
Phase 4: Report   — Save evidence JSON and generate HTML report.
"""
import asyncio
import datetime
import fnmatch
import json
import os
import re
import xml.etree.ElementTree as _ET
from collections import deque
from contextvars import ContextVar
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urljoin, parse_qs

# ---------------------------------------------------------------------------
# Per-worker browser context variable
# ---------------------------------------------------------------------------
# When concurrent scanning is enabled, each asyncio Task that handles a page
# sets this variable to its dedicated WorkerBrowser instance.  The engine's
# ``browser`` property reads it so that scanners transparently use the
# worker's isolated page without any code changes.
_CURRENT_WORKER: ContextVar = ContextVar("wscan_worker", default=None)
# Per-task payload override: maps check_type → list[str].  Set for the duration
# of a single scan_field call so parallel workers never clobber each other.
_FIELD_PAYLOAD_OVERRIDES: ContextVar = ContextVar("wscan_payload_overrides", default=None)


def _coerce_header_scope_enforce(value, default: bool = True) -> bool:
    """設定値/env を bool 化する。明示的な false 値だけが逃げ道を有効にする。"""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if normalized in {"0", "false", "no", "off"}:
        return False
    if normalized in {"1", "true", "yes", "on"}:
        return True
    return default


def _coerce_popup_header_intercept(value, default: bool = False) -> bool:
    """DevTools ポートを開く明示 opt-in 値だけを bool 化する。"""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if normalized in {"1", "true"}:
        return True
    if normalized in {"0", "false"}:
        return False
    return default


# 検査名と一致／前置しない別 check_type を出すスキャナのエイリアス。
# resume 時の Finding 絞り込み（_check_type_in_scope）で使う。
# 例: cache_poisoning スキャナは cache_deception も出す。
_CHECK_EXTRA_TYPES: dict[str, tuple[str, ...]] = {
    "cache_poisoning": ("cache_deception",),
}

# crawl 中／構築時に条件付きで自動有効化されるスキャナ（cms は CMS 検出時、privesc は
# Cookie 認証時）。resume の Finding 復元（_init_checkpoint）は crawl の cms 自動追加より
# 前に走るため、これらを常に in-scope 扱いにしないと既出 cms Finding を取りこぼす。
_AUTO_ENABLED_CHECKS: frozenset[str] = frozenset({"cms", "privesc"})

# API スペック由来テンプレート（api_seed_requests）でのみ動くスキャナ。通常の
# page-level ループからは除外し、checkpoint を刻む _run_api_template_checks に一本化
# する（状態変更系プローブの二重送信・resume 重複を防ぐ）。
_API_TEMPLATE_ONLY_CHECKS: frozenset[str] = frozenset({"mass_assignment"})

def _page_check_cp_url(check_name: str, url: str) -> str:
    """page-level チェックポイントの url 成分を返す（exact URL）。

    以前は graphql を origin スコープで刻んでいたが、それだと API スペック等が
    同一オリジンの **別 URL**（例: 先に ``/users``、後に非標準の ``/gql``）を持つとき、
    先行 URL で origin を「済み」にした時点で後続の ``/gql`` が丸ごと飛ばされ、
    ``GraphQLScanner.scan_page`` の exact-URL プローブが走らなくなる。チェック
    ポイントは exact URL で刻む。標準パスの origin 単位掃引は scanner 内部の
    ``_tested_endpoints``/``_tested_urls`` ガードが run 内で重複を防ぐため、
    intrusive な再送は起きない（resume 跨ぎの標準パス再掃引は冪等な introspection）。
    """
    return url


def _reset_scanner_url_guard(scanner, url: str) -> None:
    """scanner の per-URL/per-origin 重複ガードから ``url`` を外す（純粋・副作用最小）。

    再ログイン後の再試行で scan_page(url) を確実に再実行させるため、各スキャナが
    使う既知のガード集合（``_checked_urls`` / ``_tested_urls`` / ``_tested_endpoints``）
    から該当エントリを取り除く。
    """
    for attr in ("_checked_urls", "_tested_urls"):
        s = getattr(scanner, attr, None)
        if isinstance(s, set):
            s.discard(url)
    origins = getattr(scanner, "_tested_endpoints", None)
    if isinstance(origins, set):
        try:
            from urllib.parse import urlparse as _up
            p = _up(url)
            origins.discard(f"{p.scheme}://{p.netloc}")
        except Exception:
            pass


def _cookie_path_matches(request_path: str, cookie_path: str) -> bool:
    """RFC 6265 の path-match（純粋関数）。

    Cookie の ``Path`` 属性が要求パスにマッチするか。``cookie_path`` が要求パスの
    プレフィックス（境界はスラッシュ）であれば送出してよい。
    """
    req = request_path or "/"
    cp = cookie_path or "/"
    if cp == req:
        return True
    if not req.startswith(cp):
        return False
    # 境界が "/" であること（/admin が /administrator に誤マッチしないように）
    return cp.endswith("/") or req[len(cp):len(cp) + 1] == "/"

import yaml
from rich.console import Console
from rich.rule import Rule
from rich.table import Table
from rich import box as rbox

from .attack_planner import AttackPlanner, FieldAttackPlan, PageAttackPlan
from .adaptive_payload import AdaptivePayloadEngine
from .browser import BrowserManager
from .header_scope import allowed_header_origins, headers_allowed_for_url
from .tls_config import TLSConfig
from .chain_scanner import ChainScanner, ChainFinding
from .ctf_flag_finder import FlagFinder
from .intervention import ScanController, AbortScan, SkipField, SkipPage
from .monitor import MonitorServer
from .payload_gen import PayloadGenerator
from .scanners.base import Finding, finding_dedup_key_for
from .scanners.sqli import SQLiScanner, SQL_ERROR_PATTERNS
from .scanners.xss import XSSScanner
from .scanners.os_injection import OSInjectionScanner
from .scanners.ssti import SSTIScanner
from .scanners.path_traversal import PathTraversalScanner
from .scanners.csrf import CSRFScanner
from .scanners.header_injection import HeaderInjectionScanner
from .scanners.mail_header import MailHeaderInjectionScanner
from .scanners.open_redirect import OpenRedirectScanner
from .scanners.clickjacking import ClickjackingScanner
from .scanners.session import SessionScanner
from .scanners.privesc import PrivEscScanner
from .scanners.dom_xss import DOMXSSScanner
from .scanners.stored_xss import StoredXSSScanner
from .scanners.cors import CORSScanner
from .scanners.info_disclosure import InfoDisclosureScanner
from .scanners.host_header import HostHeaderScanner
from .scanners.security_headers import SecurityHeadersScanner
from .scanners.nosql_injection import NoSQLInjectionScanner
from .scanners.deserialization import DeserializationScanner
from .scanners.request_smuggling import RequestSmugglingScanner
from .scanners.ssrf import SSRFScanner
from .scanners.graphql import GraphQLScanner
from .scanners.jwt_scanner import JWTScanner
from .scanners.cms import CmsScanner
from .waf_detector import WAFDetector
from .payload_learning import PayloadLearner
from .flow_runner import ScanFlow, FlowRunner
from .oob_email import OOBEmailConfig, EmailSink, make_oob_token, oob_address

console = Console()

CONFIG_DIR = Path(__file__).parent.parent / "config"
OUTPUT_BASE = Path(__file__).parent.parent / "output"


def _interleave_payloads(
    primary: list, secondary: list, *, primary_run: int = 2
) -> list:
    """primary を primary_run 個ごとに secondary を1個挟んで連結する。

    curated(既定) を優先しつつ community を分散配置することで、下流の件数 cap
    （`payload_gen` の no-LLM 経路は `max_total` で先頭のみ展開）を越えても
    community ペイロードが必ず代表される。各列内の相対順序は保つ。
    """
    out: list = []
    i = j = 0
    while i < len(primary) or j < len(secondary):
        for _ in range(primary_run):
            if i < len(primary):
                out.append(primary[i])
                i += 1
        if j < len(secondary):
            out.append(secondary[j])
            j += 1
    return out


def merge_community_payloads(default_payloads: dict, community_payloads: dict) -> dict:
    """既定(curated)を優先しつつ、未収録の community を 2:1 でインターリーブする。

    単純な末尾追記だと、curated だけで `payload_gen` の no-LLM 件数 cap を
    使い切る check_type（xss/sqli/os 等）で community が一切使われない。
    インターリーブにより cap 内にも community を行き渡らせる。
    """
    merged: dict = {
        key: list(value) if isinstance(value, list) else value
        for key, value in (default_payloads or {}).items()
    }
    for check_type, payloads in (community_payloads or {}).items():
        if not isinstance(payloads, list):
            continue
        community_items = [p for p in payloads if isinstance(p, str)]
        if not community_items:
            continue
        if check_type in merged and not isinstance(merged.get(check_type), list):
            continue
        curated = merged.get(check_type, [])
        seen = set(curated)
        new_items = []
        new_seen = set()
        for payload in community_items:
            if payload in seen or payload in new_seen:
                continue
            new_seen.add(payload)
            new_items.append(payload)
        merged[check_type] = _interleave_payloads(curated, new_items, primary_run=2)
    return merged


def _community_payloads_enabled_by_config(path: Path | None = None) -> bool:
    """config/wscan.yaml の features.community_payloads を読む。"""
    config_path = path or (CONFIG_DIR / "wscan.yaml")
    try:
        with open(config_path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        features = raw.get("features", {}) or {}
        return bool(features.get("community_payloads", True))
    except Exception:
        return True


def _payload_evolution_enabled_by_config(path: Path | None = None) -> bool:
    """config/wscan.yaml の features.payload_evolution を読む。"""
    config_path = path or (CONFIG_DIR / "wscan.yaml")
    try:
        with open(config_path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        features = raw.get("features", {}) or {}
        return bool(features.get("payload_evolution", True))
    except Exception:
        return True


def _payload_mutation_enabled_by_config(path: Path | None = None) -> bool:
    """config/wscan.yaml の features.payload_mutation を読む。"""
    config_path = path or (CONFIG_DIR / "wscan.yaml")
    try:
        with open(config_path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        features = raw.get("features", {}) or {}
        return bool(features.get("payload_mutation", True))
    except Exception:
        return True


# ---------------------------------------------------------------------------
# Registration page / form detection
# ---------------------------------------------------------------------------

# URL path patterns that strongly suggest a new-account registration page
_REGISTRATION_URL_RE = re.compile(
    r"/(register|signup|sign[_-]up|new[_-]?account|create[_-]?account|join|enroll"
    r"|account/new|user/new|users/new|member/new|members/new"
    r"|新規登録|会員登録|ユーザー登録|アカウント登録|メンバー登録)",
    re.IGNORECASE,
)

# Field name / id patterns that only appear in registration (confirm-password) forms
_REGISTRATION_FIELD_RE = re.compile(
    r"^(confirm[_-]?pass(word)?|pass(word)?[_-]?confirm"
    r"|pass(word)?[_-]?(2|two|again|repeat|retry|check|verify|verification)"
    r"|re[_-]?pass(word)?|re[_-]?enter[_-]?pass(word)?"
    r"|password_?confirmation|passwordConfirmation"
    r"|repeat_?password|new_?password_?confirm"
    r"|パスワード確認|確認用パスワード)$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Data class for crawled pages
# ---------------------------------------------------------------------------

@dataclass
class CrawledPage:
    """Page data collected during Phase 1 crawl (no payload injection)."""
    url: str
    html: str
    forms: list
    url_params: list
    depth: int
    # クロール時点で捕捉した外部スクリプト本文 {絶対URL: body}。
    # 攻撃フェーズでは navigate() が network 捕捉をクリアするため、ここに
    # スナップショットしておくと js_static が別ページに遷移後でも外部 JS を
    # 正しく解析できる。
    external_scripts: dict = dc_field(default_factory=dict)


def _crawl_review_wants_recrawl(command: str) -> bool:
    """検査前レビューの応答が「再巡回」要求かを判定する純粋関数。

    「検査開始(continue)」では再巡回しない＝レビューを再表示するループを防ぐ。
    追加URL/手動巡回JSONはユーザーが明示的に「再巡回」を選んだときだけ反映する
    （以前は continue でも追加URL/手動ファイルがあると再巡回に入り、設定の手動巡回
    ファイルが自動補完されると無限にレビューが出続けてしまっていた）。
    """
    return (command or "").strip().lower() == "recrawl"


_ADAPTIVE_PAGE_LEVEL_CHECKS = frozenset({"csrf", "session", "clickjacking"})


def _adaptive_checkpoint_check(check_name: str) -> str:
    """adaptive の完了単位を check_type ごとに生成する。"""
    return f"(adaptive:{check_name})"


# ---------------------------------------------------------------------------
# Scan Engine
# ---------------------------------------------------------------------------

class ScanEngine:
    """Main scanning engine — 4-phase pipeline."""

    def __init__(
        self,
        url: str,
        monitor: Optional[MonitorServer] = None,
        payloads_file: Optional[str] = None,
        depth: int = 2,
        headless: bool = False,
        llm_provider: str = "ollama",
        ollama_model: str = "llama3",
        openai_model: str = "gpt-4o-mini",
        gemini_model: str = "gemini-2.0-flash",
        claude_model: str = "claude-haiku-4-5-20251001",
        openai_base_url: str = "",
        role_models: Optional[dict] = None,
        llm_timeout_seconds: float = 30.0,
        llm_max_retries: int = 2,
        checks: Optional[list] = None,
        output_dir: Optional[str] = None,
        timeout: int = 30,
        max_forms: int = 50,
        exclude_fields: Optional[list] = None,
        exclude_urls: Optional[list] = None,
        ctf_mode: bool = False,
        ctf_flag_pattern: str = "",
        cookies: str = "",
        cookie_list: Optional[list] = None,
        low_priv_cookies: str = "",
        low_priv_cookie_list: Optional[list] = None,
        auth_user: str = "",
        auth_pass: str = "",
        use_planner: bool = True,
        interactive_plan: bool = False,
        interactive_crawl_review: bool = False,
        skip_registration: bool = True,
        open_report: bool = True,
        proxy: str = "",
        login_url: str = "",
        login_user_field: str = "username",
        login_pass_field: str = "password",
        login_success_indicator: str = "",
        mfa_type: Optional[str] = None,
        mfa_field: str = "",
        mfa_totp_secret: str = "",
        mfa_totp_uri: str = "",
        mfa_totp_qr: str = "",
        mfa_totp_digits: int = 0,
        mfa_totp_period: int = 0,
        mfa_totp_algorithm: str = "",
        mfa_email_account: str = "",
        mfa_email_imap: Optional[dict] = None,
        learning_file: Optional[str] = None,
        # Feature flags (from config/wscan.yaml via main.py)
        enable_ai_analysis: bool = True,
        enable_waf_detection: bool = True,
        enable_payload_learning: bool = True,
        enable_community_payloads: Optional[bool] = None,
        enable_payload_evolution: Optional[bool] = None,
        enable_payload_mutation: Optional[bool] = None,
        enable_adaptive_payloads: bool = True,
        enable_sitemap_crawl: bool = True,
        enable_llm_web_browsing: bool = False,
        # Concurrent scanning
        concurrency: int = 1,
        # Multi-step attack flows
        flows: Optional[list] = None,
        # Fast mode
        max_payloads: int = 0,   # 0 = no limit; fast mode default: 12
        fast_mode: bool = False,  # sets sleep_factor=0
        # A: Multi-account privilege escalation
        accounts: Optional[list] = None,      # list of {"username":, "password":, "role":}
        auto_register: bool = False,          # auto-create accounts via registration forms
        auto_register_count: int = 2,         # how many accounts to auto-register
        # Opt-in for intrusive, potentially state-changing probes (e.g. privesc
        # verb tampering with POST/PUT/PATCH). Off by default for safety.
        allow_state_changing_probes: bool = False,
        # ①: SPA crawl enhancement
        spa_crawl: bool = False,
        # ハイブリッドモード: Agent偵察で発見したURLをクロールのシードに使う
        seed_urls: Optional[list] = None,
        # Scope: URLs that are attacked vs. URLs that may be visited only
        target_urls: Optional[list] = None,
        access_urls: Optional[list] = None,
        # I: 差分スキャン — 前回出力ディレクトリのパス
        previous_scan_dir: Optional[str] = None,
        # N: リクエスト間の待機秒数 (0 = 無制限)
        request_delay: float = 0.5,
        navigation_retries: int = 2,
        # K: SARIF 出力を有効にするか
        sarif: bool = True,
        # L: Webhook/Slack 通知
        webhook_url: str = "",
        notify_min_severity: str = "high",
        # O: HAR ファイルインポート
        har_path: str = "",
        # 手動巡回ファイルインポート
        manual_crawl_path: str = "",
        # Custom HTTP headers + periodic refresh (Authorization rotation, etc.)
        headers: Optional[dict] = None,
        header_refresh_cmd: str = "",
        header_refresh_interval: float = 0.0,
        header_scope_enforce: bool = True,
        popup_header_intercept: Optional[bool] = None,
        tls_client_cert: str = "",
        tls_client_key: str = "",
        tls_client_pfx: str = "",
        tls_client_cert_password: str = "",
        tls_ca_cert: str = "",
        tls_verify: bool = False,
        # API ファースト検査: OpenAPI/Swagger/Postman スペックのパス
        api_spec_path: str = "",
        # 再開可能スキャン: 直前スキャンの出力ディレクトリ（checkpoint.json を読む）
        resume_dir: str = "",
        enable_checkpoint: bool = True,
        # 検査時間帯ゲート（"09:00-18:00" / "Mon-Fri 22:00-06:00" 等のリスト）
        allowed_hours: Optional[list] = None,
        forbidden_hours: Optional[list] = None,
        # セッション失効時の自動再ログイン
        relogin_on_expiry: bool = True,
        logged_in_marker: str = "",
        # Hybrid の Agent Finding。決定論検証の完了後、レポート直前に併記する
        additional_report_findings: Optional[list[Finding]] = None,
    ):
        # ユーザーが指定した URL は末尾スラッシュも含めてそのまま保持する。
        # 以前は url.rstrip("/") で末尾の "/" を一律に除去していたが、
        # http://example.com/app/ と /app は別リソースになりうるため、
        # 指定どおりにリクエストする。スコープ判定側 (_normalize_scope_urls /
        # _url_matches_scope など) は両辺を rstrip("/") して比較するので、
        # 末尾スラッシュを保持しても突合は崩れない。
        self.target_url = url.strip()
        self.monitor = monitor
        self.depth = depth
        self.checks = list(checks or ["sqli", "xss", "os"])
        self.timeout = timeout
        self.max_forms = max_forms
        self.ctf_mode = ctf_mode
        self.max_payloads = max_payloads
        self.fast_mode = fast_mode
        # sleep_factor: fast=0.0 (no delays), ctf=0.5, normal=1.0
        if fast_mode:
            self.sleep_factor = 0.0
        elif ctf_mode:
            self.sleep_factor = 0.5
        else:
            self.sleep_factor = 1.0
        # N: effective delay = request_delay * sleep_factor
        # fast_mode forces 0; ctf_mode halves the delay
        self._effective_delay: float = request_delay * self.sleep_factor
        self.navigation_retries: int = max(0, int(navigation_retries))
        self.cookies = cookies
        self.cookie_list: list = list(cookie_list or [])
        # Normalise low-privilege cookies: prefer list form when both are given
        self.low_priv_cookies: str = low_priv_cookies
        self.low_priv_cookie_list: list = list(low_priv_cookie_list or [])
        # Convert low_priv_cookie_list → cookie-string for httpx usage
        if self.low_priv_cookie_list and not self.low_priv_cookies:
            self.low_priv_cookies = "; ".join(
                f"{c['name']}={c['value']}"
                for c in self.low_priv_cookie_list
                if c.get("name") and c.get("value") is not None
            )
        # A: Multi-account settings
        self.accounts: list = list(accounts or [])
        self.auto_register = auto_register
        self.auto_register_count = auto_register_count
        self.allow_state_changing_probes = allow_state_changing_probes
        # account_sessions: resolved at run time — list of {"username":, "cookies":, "role":}
        self.account_sessions: list = []
        # ①: SPA crawl
        self.spa_crawl = spa_crawl
        # ハイブリッドモード用シード URL (Agent偵察で発見したURL)
        self.seed_urls: list = list(seed_urls or [])
        self.additional_report_findings: list[Finding] = list(
            additional_report_findings or []
        )
        primary_origin = self._origin_for(self.target_url)
        self.additional_target_urls: list[str] = self._normalize_scope_urls(list(target_urls or []))
        self.target_urls: list[str] = self._normalize_scope_urls(
            [primary_origin] + self.additional_target_urls
        )
        self.access_urls: list[str] = self._normalize_scope_urls(
            list(access_urls or []) + ([login_url] if login_url else [])
        )
        # I: 差分スキャン
        self.previous_scan_dir: Optional[str] = previous_scan_dir
        # K: SARIF 出力フラグ
        self.sarif: bool = sarif
        # O: HAR インポートパス
        self.har_path: str = har_path
        # 手動巡回インポートパス
        self.manual_crawl_path: str = manual_crawl_path
        # API ファースト検査: スペック取り込みパスと、取り込んだ JSON 操作群
        # （mass_assignment 等が利用する RequestTemplate のリスト）
        self.api_spec_path: str = api_spec_path
        self.api_seed_requests: list = []
        # API スペック由来 URL の集合（GraphQL の具体 URL probe を API/GraphQL 系のみへ
        # 限定するために参照。全クロールページへ probe を撒かないためのゲート）。
        self.api_seed_urls: set = set()
        # API テンプレート検査中に認証失効（401/login）を観測したときに立つフラグ。
        # mass_assignment 等がベースライン応答で検知し、_run_api_template_checks が
        # 「済み」記録を抑止して resume での恒久スキップを防ぐ。
        self._api_auth_failed: bool = False
        # 再開可能スキャン
        self.resume_dir: str = resume_dir
        self.enable_checkpoint: bool = enable_checkpoint
        self.checkpoint = None  # CheckpointState（run() で初期化）
        # セッション失効時の自動再ログイン
        self.relogin_on_expiry: bool = relogin_on_expiry
        # 認証済みの目印（指定が無ければログイン成功判定文字列を流用）
        self.logged_in_marker: str = logged_in_marker or login_success_indicator
        self._relogin_count: int = 0
        # L: Webhook/Slack 通知マネージャー
        if webhook_url:
            from wscan.notification import NotificationManager
            self._notifier = NotificationManager(
                webhook_url=webhook_url,
                min_severity=notify_min_severity,
            )
        else:
            self._notifier = None
        # C: CMS 検出結果 (crawl時に設定)
        self.detected_cms = None

        self.use_planner = use_planner
        self.interactive_plan = interactive_plan
        self.interactive_crawl_review = interactive_crawl_review
        self.skip_registration = skip_registration
        self.open_report = open_report
        self.proxy = proxy
        self.tls_config = TLSConfig.from_values(
            client_cert=tls_client_cert,
            client_key=tls_client_key,
            client_pfx=tls_client_pfx,
            client_cert_password=tls_client_cert_password,
            ca_cert=tls_ca_cert,
            verify_tls=tls_verify,
        )
        tls_errors = self.tls_config.validate_paths()
        if tls_errors:
            raise ValueError("; ".join(tls_errors))
        self.login_url = login_url
        self.login_user_field = login_user_field
        self.login_pass_field = login_pass_field
        self.login_success_indicator = login_success_indicator
        # Feature on/off
        self.enable_ai_analysis = enable_ai_analysis
        self.enable_waf_detection = enable_waf_detection
        self.enable_payload_learning = enable_payload_learning
        # 明示指定(True/False)を最優先し、None のときだけ config を既定として読む
        # （CLI/API の明示値が config:false で握り潰されないようにする）。
        self.enable_payload_mutation = (
            _payload_mutation_enabled_by_config()
            if enable_payload_mutation is None
            else enable_payload_mutation
        )
        self.enable_payload_evolution = (
            _payload_evolution_enabled_by_config()
            if enable_payload_evolution is None
            else enable_payload_evolution
        )
        self.enable_community_payloads = (
            _community_payloads_enabled_by_config()
            if enable_community_payloads is None
            else enable_community_payloads
        )
        self.enable_adaptive_payloads = enable_adaptive_payloads
        self.enable_sitemap_crawl = enable_sitemap_crawl
        self.enable_llm_web_browsing = enable_llm_web_browsing
        self.concurrency = max(1, concurrency)
        # Multi-step attack flows (list[ScanFlow])
        self.flows: list[ScanFlow] = ScanFlow.list_from_dicts(flows or [])
        if ctf_mode and "ssti" not in self.checks:
            self.checks.append("ssti")

        # CTF flag finder
        self.flag_finder: Optional[FlagFinder] = FlagFinder(ctf_flag_pattern) if ctf_mode else None
        self.ctf_found_flags: list = []   # [(flag_str, source_url)]

        # Output directory
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = Path(output_dir) if output_dir else OUTPUT_BASE / ts
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "screenshots").mkdir(exist_ok=True)
        # リクエスト/ペイロードの監査ログ。送信した全 HTTP リクエスト
        # (http_requests.jsonl) と投入ペイロード (payloads.jsonl) を保存する。
        from .request_logger import (
            RequestLogger,
            clear_sensitive_headers,
            register_sensitive_headers,
        )
        self.request_logger = RequestLogger(self.output_dir)
        if self.monitor is not None:
            self.monitor.request_logger = self.request_logger
        # Let the monitor/portal map the running scan to its artifact folder.
        # Only when the output folder is under OUTPUT_BASE (the portal serves
        # reports from there); a custom output_dir elsewhere is not listed.
        if self.monitor is not None:
            try:
                self.output_dir.resolve().relative_to(OUTPUT_BASE.resolve())
                self.monitor.current_scan_id = self.output_dir.name
            except ValueError:
                self.monitor.current_scan_id = ""
            except Exception:
                pass

        # Payloads
        default_payloads_path = CONFIG_DIR / "default_payloads.yaml"
        payloads_data = self._load_yaml(payloads_file or str(default_payloads_path))
        using_default_payloads = not payloads_file or payloads_file == str(default_payloads_path)
        if using_default_payloads and self.enable_community_payloads:
            community_payloads_path = CONFIG_DIR / "community_payloads.yaml"
            if community_payloads_path.exists():
                community_payloads = self._load_yaml(str(community_payloads_path))
                payloads_data = merge_community_payloads(payloads_data, community_payloads)
        self.default_payloads = payloads_data
        self.custom_payloads: dict = {}
        if payloads_file and payloads_file != str(default_payloads_path):
            custom = self._load_yaml(payloads_file)
            for ct in ["sqli", "xss", "os", "ssti", "path_traversal", "header_injection", "open_redirect"]:
                if ct in custom:
                    self.custom_payloads[ct] = custom[ct]

        prompt_templates = payloads_data.get("llm_prompts", {})

        # Header manager — single source of truth for custom HTTP headers
        # (Authorization, X-API-Key, etc.). Browser context AND every httpx call
        # site pull from here so rotating tokens take effect immediately.
        from .header_manager import HeaderManager
        self.header_manager = HeaderManager(
            headers=headers or {},
            refresh_cmd=header_refresh_cmd or "",
            refresh_interval=float(header_refresh_interval or 0.0),
        )
        # Runtime redaction names are process-global, so reset them at each scan
        # boundary. serve runs only one scan at a time; concurrent scans would
        # require context-local redaction state instead of this simple reset.
        clear_sensitive_headers()
        register_sensitive_headers(self.header_manager.current().keys())
        # MFA（2FA）ソルバ: ネイティブ TOTP または外部 MCP からコードを取得。
        # 種別/欄は env（WSCAN_MFA_*）が既定。UI/CLI/config が明示的に値を渡した
        # ときはそれを優先する。mfa_type=None は「未指定→env に委ねる」、空文字 ""
        # は「明示的に無効」を意味し、env に WSCAN_MFA_TYPE があっても上書き無効化する。
        from .mfa import MFAConfig, MFASolver
        _mfa_overrides: dict = {}
        if mfa_type is not None:
            _mfa_overrides["type"] = mfa_type or "none"
        if mfa_field:
            _mfa_overrides["field"] = mfa_field
        if mfa_totp_secret:
            _mfa_overrides["totp_secret"] = mfa_totp_secret
        if mfa_totp_uri:
            _mfa_overrides["totp_uri"] = mfa_totp_uri
        if mfa_totp_qr:
            _mfa_overrides["totp_qr"] = mfa_totp_qr
        if mfa_totp_digits:
            _mfa_overrides["totp_digits"] = mfa_totp_digits
        if mfa_totp_period:
            _mfa_overrides["totp_period"] = mfa_totp_period
        if mfa_totp_algorithm:
            _mfa_overrides["totp_algorithm"] = mfa_totp_algorithm
        # MFA メールのアカウント名（通常はメールアドレス）。CLI/UI/config で
        # 自由に指定でき、空なら WSCAN_MFA_EMAIL_ACCOUNT env にフォールバック
        # （既存設定をそのまま利用可能）。
        if mfa_email_account:
            _mfa_overrides["email_account"] = mfa_email_account
        # 動的 IMAP 認証情報（ツールから直接渡す）。host を含めると、サーバ側に
        # 事前登録の無い任意アドレスでも mcp-email-server へ env 注入して受信する。
        _imap = mfa_email_imap or {}
        for _src, _dst in (
            ("address", "email_address"),
            ("user", "email_user"),
            ("password", "email_password"),
            ("host", "email_imap_host"),
            ("port", "email_imap_port"),
        ):
            _v = _imap.get(_src)
            if _v:
                _mfa_overrides[_dst] = _v
        if _imap.get("ssl") is not None:
            _mfa_overrides["email_imap_ssl"] = _imap["ssl"]
        if _imap.get("server_env"):
            _mfa_overrides["email_server_env"] = _imap["server_env"]
        self._mfa_config = MFAConfig.from_env(overrides=_mfa_overrides)
        self._mfa_solver = MFASolver(self._mfa_config) if self._mfa_config.enabled else None

        configured_header_scope = _coerce_header_scope_enforce(
            header_scope_enforce
        )
        env_header_scope = os.environ.get("WSCAN_HEADER_SCOPE_ENFORCE")
        self.header_scope_enforce = _coerce_header_scope_enforce(
            env_header_scope,
            default=configured_header_scope,
        )
        if popup_header_intercept is None:
            self.popup_header_intercept = _coerce_popup_header_intercept(
                os.environ.get("WSCAN_POPUP_HEADER_INTERCEPT"),
                default=False,
            )
        else:
            # main.py 側で CLI > env > config を解決済み。明示値を env で
            # 上書きせず、そのまま BrowserManager へ渡す。
            self.popup_header_intercept = _coerce_popup_header_intercept(
                popup_header_intercept,
                default=False,
            )
        self._header_scope_origins = allowed_header_origins(
            self.target_url,
            self.target_urls,
            self.access_urls,
            self.login_url,
        )

        # Components
        self._browser = BrowserManager(
            headless=headless, timeout=timeout, monitor=monitor,
            auth_user=auth_user, auth_pass=auth_pass,
            proxy=proxy,
            sleep_factor=self.sleep_factor,
            extra_headers=self.header_manager.current(),
            tls_config=self.tls_config,
            target_url=self.target_url,
            header_scope_origins=self._header_scope_origins,
            header_scope_enforce=self.header_scope_enforce,
            expect_late_headers=bool(header_refresh_cmd),
            popup_header_intercept=self.popup_header_intercept,
            request_logger=self.request_logger,
            mfa_solver=self._mfa_solver,
        )
        # When the refresh task fetches a new token, push it into the browser
        # context so crawled pages immediately use the rotated header.
        async def _propagate_headers(new_headers: dict):
            register_sensitive_headers(new_headers.keys())
            try:
                await self._browser.update_extra_headers(new_headers)
            except Exception:
                pass
            # If the refresh command emitted a fresh ``Cookie:`` header, treat it
            # as a session refresh: update the engine cookie string AND the
            # browser cookie jar so subsequent navigations carry it.
            cookie_value = ""
            for k, v in new_headers.items():
                if k.lower() == "cookie":
                    cookie_value = v
                    break
            if cookie_value and cookie_value != self.cookies:
                self.cookies = cookie_value
                try:
                    await self._browser.set_cookies(cookie_value, self.target_url)
                except Exception:
                    pass
        self.header_manager._on_change = _propagate_headers
        self.payload_gen = PayloadGenerator(
            provider=llm_provider,
            ollama_model=ollama_model,
            openai_model=openai_model,
            gemini_model=gemini_model,
            claude_model=claude_model,
            openai_base_url=openai_base_url,
            role_models=role_models,
            llm_timeout_seconds=llm_timeout_seconds,
            llm_max_retries=llm_max_retries,
            default_payloads=payloads_data,
            prompt_templates=prompt_templates,
            enable_web_browsing=enable_llm_web_browsing,
        )

        # Central registry lives in wscan/scanners/__init__.py
        from .scanners import SCANNERS as _SCANNERS
        self.scanners = {n: cls(self) for n, cls in _SCANNERS.items() if n in self.checks}

        # Always enable privilege-escalation scanner when auth cookies are provided,
        # even if the user didn't explicitly list "privesc" in --checks.
        if "privesc" not in self.scanners and (self.cookies or self.cookie_list or self.low_priv_cookies):
            self.scanners["privesc"] = PrivEscScanner(self)

        self.attack_planner = AttackPlanner(
            payload_gen=self.payload_gen,
            enabled_checks=self.checks,
        )

        self.exclude_fields: set = {f.lower() for f in (exclude_fields or [])}
        self.exclude_urls: set = set(exclude_urls or [])

        # A-2: WAF detection — feed custom headers through so authenticated
        # endpoints respond honestly during the probe.
        self.waf_detector = WAFDetector(
            payload_gen=self.payload_gen,
            proxy=proxy,
            headers_provider=lambda url="": self.auth_headers(url=url),
            tls_options_provider=lambda: self.tls_config.httpx_options(),
        )
        # A-3: Payload continuous learning
        self.payload_learner = PayloadLearner(learning_file=learning_file)

        # Adaptive AI payload refinement — runs a second pass per field
        # using LLM analysis of the page's filtering behavior
        self.adaptive_engine = AdaptivePayloadEngine(self.payload_gen)
        self.adaptive_enabled = enable_adaptive_payloads and llm_provider != "none"
        # provider の恒久的な不達は scan 中に一度だけ判定する。並列 field が
        # 同時に初回 adaptive へ到達しても probe を重複させない。
        self._adaptive_llm_available: Optional[bool] = None
        self._adaptive_llm_availability_lock = asyncio.Lock()

        # OOB（帯域外）メール受信シンク。環境変数（WSCAN_OOB_*）から構築し、
        # 設定が揃っているときだけ EmailSink を有効化する（未設定なら None）。
        # メールヘッダインジェクション等「アプリがメールを送って初めて確証できる」
        # 検査が、注入した一意 Bcc 宛にメールが届いたかをポーリングするために使う。
        # 認証情報はコードに埋めず env 経由（CLAUDE.md の不変条件）。
        self.oob_config = OOBEmailConfig.from_env()
        self.oob_sink: Optional[EmailSink] = (
            EmailSink(self.oob_config) if self.oob_config.configured else None
        )

        # Chain / stored vulnerability scanner (Phase 3c)
        self.chain_scanner = ChainScanner(
            browser=self._browser,
            sleep_factor=self.sleep_factor,
            exclude_fields=self.exclude_fields,
            enabled_checks=self.checks,
        )

        # State
        self.all_findings: list = []
        self.wave_errors: list = []                  # 検出力低下事象の観測ログ（base から共有）
        self._finding_dedup: set[tuple] = set()     # (url, field_name, check_type) — prevent duplicates
        self.attack_plans: list = []
        self.visited_urls: set = set()
        self.scanned_forms: set = set()
        self._scanned_forms_lock = asyncio.Lock()   # guards scanned_forms in concurrent mode
        self.completed_fields: int = 0
        self.total_fields: int = 0
        self.scan_matrix: list[dict] = []
        # page_graph: {url: {"parent": parent_url|None, "screenshot_b64": str, "depth": int}}
        self.page_graph: dict = {}
        # transition_via: {child_url: {"text","selector","rect","viewport"}} — records
        # which element on the parent page led to each discovered URL (for the diagram).
        self._transition_via: dict = {}
        # Scan controller (intervention system)
        self.controller = ScanController()
        # 検査時間帯ゲートをコントローラへ設定（空なら常時許可）
        self.allowed_hours: list = list(allowed_hours or [])
        self.forbidden_hours: list = list(forbidden_hours or [])
        if self.allowed_hours or self.forbidden_hours:
            self.controller.set_time_windows(self.allowed_hours, self.forbidden_hours)
        # SQLi auth-bypass signal: set by signal_auth_bypass() when a scanner detects bypass
        self.auth_bypass_detected: bool = False
        self.auth_bypass_login_url: str = ""
        self.auth_bypass_post_url: str = ""
        # Auto-login landing page. Seeded into the normal crawl so authenticated
        # pages are not missed when the scan target itself is the login URL.
        self.auth_landing_url: str = ""

    def new_oob_address(self) -> Optional[tuple[str, str]]:
        """OOB 受信用の一意トークンとメールアドレスを返す。

        OOB シンクが未設定、または catch-all ドメイン未設定なら ``None``。
        戻り値は ``(token, address)`` で、address を Cc/Bcc に注入し、token で
        受信箱を検索する。スキャン ID（出力ディレクトリ名）をトークンに含め、
        並行スキャン間の取り違えを避ける。
        """
        if not self.oob_sink or not self.oob_config.domain:
            return None
        scan_id = getattr(self, "output_dir", None)
        token = make_oob_token(scan_id.name if scan_id else "")
        return token, oob_address(token, self.oob_config.domain)

    def httpx_client_kwargs(self, **overrides) -> dict:
        """Return httpx kwargs with scanner-wide proxy/TLS settings applied."""
        kwargs = self.tls_config.httpx_options()
        if self.proxy and "proxy" not in overrides:
            kwargs["proxy"] = self.proxy
        kwargs.update(overrides)
        return kwargs

    @staticmethod
    def _origin_for(url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
        return url.rstrip("/")

    @classmethod
    def _normalize_scope_urls(cls, urls: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for raw in urls:
            value = str(raw or "").strip().rstrip("/")
            if not value:
                continue
            if value not in seen:
                seen.add(value)
                normalized.append(value)
        return normalized

    def _url_matches_scope(self, url: str, scopes: list[str]) -> bool:
        candidate = url.rstrip("/")
        parsed = urlparse(candidate)
        for scope in scopes:
            if scope.startswith(("http://", "https://")):
                if candidate == scope or candidate.startswith(scope + "/"):
                    return True
                continue
            if parsed.path == scope or parsed.path.startswith(scope.rstrip("/") + "/"):
                return True
        return False

    def _is_attack_target_url(self, url: str) -> bool:
        return self._url_matches_scope(url, self.target_urls)

    def _is_access_allowed_url(self, url: str) -> bool:
        return self._is_attack_target_url(url) or self._url_matches_scope(url, self.access_urls)

    def _is_login_target_url(self, url: str) -> bool:
        """Return True when *url* itself is the configured login page.

        Used to distinguish a *deliberate* visit to the login page (so the login
        form can be crawled and attacked) from an *unexpected* redirect to it
        (genuine session expiry). Without this, ``is_on_login_page`` would treat
        every login-page visit as expiry, re-authenticate, and navigate away —
        leaving the login form itself never inspected.
        """
        if not self.login_url or not url:
            return False
        current = urlparse(url.rstrip("/").lower())
        target = urlparse(self.login_url.rstrip("/").lower())
        # The host AND path must match: a different origin that merely shares the
        # /login path (e.g. an external IdP) is not our target login page.
        if (current.netloc, current.path) != (target.netloc, target.path):
            return False
        # When the login route is encoded in the query string
        # (e.g. /index.php?route=account/login), that query is significant — a
        # protected page like /index.php?route=checkout shares the path but is
        # NOT the login page, so require the configured query params to match.
        # When the login URL has no query, ignore the candidate's query so
        # redirect params such as ?next=… still match.
        if not target.query:
            return True
        target_params = parse_qs(target.query)
        current_params = parse_qs(current.query)
        return all(current_params.get(k) == v for k, v in target_params.items())

    def _record_scan_matrix(
        self,
        url: str,
        field_name: str,
        check_name: str,
        status: str,
        location: str = "",
        severity: str = "",
        finding_count: int = 0,
        note: str = "",
    ) -> None:
        """Record per-target scan execution for checklist-style reports."""
        self.scan_matrix.append({
            "url": url,
            "field_name": field_name,
            "check": check_name,
            "status": status,
            "location": location,
            "severity": severity,
            "finding_count": finding_count,
            "note": note,
        })

    def _navigation_failure_note(self) -> str:
        """Return the most recent browser navigation failure in report-friendly form."""
        br = self.browser
        status = getattr(br, "last_navigation_status", None)
        error = getattr(br, "last_navigation_error", "") or ""
        if status is not None and error:
            return f"Navigation failed after retries ({error}, last status HTTP {status})."
        if status is not None:
            return f"Navigation failed after retries (last status HTTP {status})."
        if error:
            return f"Navigation failed after retries ({error})."
        return "Navigation failed after retries."

    def _record_unscannable_url(self, url: str, *, field_name: str = "(page)", note: str = "") -> None:
        """Record a URL/input that could not be tested so reports show scan gaps."""
        note = note or self._navigation_failure_note()
        self._record_scan_matrix(
            url=url,
            field_name=field_name,
            check_name="access",
            status="error",
            location="navigation",
            note=note,
        )
        if self.monitor:
            try:
                asyncio.get_running_loop().create_task(
                    self.monitor.emit_scan_gap(
                        url=url,
                        field_name=field_name,
                        check="access",
                        location="navigation",
                        note=note,
                    )
                )
            except RuntimeError:
                pass

    # =========================================================================
    # browser property — transparently returns the current worker's browser
    # =========================================================================

    def headers_for_url(self, url: str) -> dict:
        """Return current custom headers only when ``url`` is in header scope.

        An explicitly disabled scope, an unknown scope, and headerless scans
        preserve the legacy behavior.  The returned snapshot can be safely
        merged underneath scanner defaults without removing headers such as
        User-Agent or Content-Type.
        """
        headers = self.header_manager.current()
        if (
            not self.header_scope_enforce
            or not headers
            or not self._header_scope_origins
        ):
            return headers
        if headers_allowed_for_url(url, self._header_scope_origins):
            return headers
        return {}

    def auth_headers(
        self,
        extra: Optional[dict] = None,
        *,
        include_cookie: bool = True,
        url: str = "",
    ) -> dict:
        """
        Central source of HTTP headers for direct httpx calls.

        Merges (in order, later overrides earlier):
          * Custom headers from --header / --header-file / refresh command
          * The current Cookie string (engine.cookies) unless ``include_cookie=False``
            and the user hasn't already supplied a Cookie header
          * Caller-supplied ``extra``

        When ``url`` is supplied, custom HeaderManager keys are included only
        for an allowed origin.  An omitted URL intentionally preserves legacy
        behavior for callers whose destination is not yet known.
        """
        headers: dict = (
            self.headers_for_url(url)
            if url
            else self.header_manager.current()
        )
        if include_cookie and self.cookies:
            # Don't clobber an explicit Cookie header from --header.
            if not any(k.lower() == "cookie" for k in headers):
                headers["Cookie"] = self.cookies
        if extra:
            for k, v in extra.items():
                if v is None:
                    continue
                headers[k] = v
        return headers

    @property
    def browser(self):
        """
        Returns the current concurrent worker's WorkerBrowser when called from
        inside a worker task, otherwise returns the main BrowserManager.
        This makes all scanners work correctly in both serial and concurrent modes
        without any changes to scanner code.
        """
        worker = _CURRENT_WORKER.get(None)
        return worker if worker is not None else self._browser

    # =========================================================================
    # Checkpoint / resume
    # =========================================================================

    def _init_checkpoint(self) -> None:
        """チェックポイントを初期化する。``resume_dir`` 指定時は進捗を復元する。"""
        if not self.enable_checkpoint:
            return
        from wscan import checkpoint as cp

        state = None
        if self.resume_dir:
            loaded = cp.load_checkpoint(self.resume_dir)
            if loaded is None:
                console.print(
                    f"  [yellow][Resume] checkpoint が見つかりません: {self.resume_dir}"
                    f" — 最初から実行します。[/yellow]"
                )
            elif not loaded.is_compatible_with(self.target_url, self.checks):
                console.print(
                    "  [yellow][Resume] checkpoint のターゲット/チェックが今回と"
                    "整合しないため破棄します（最初から実行）。[/yellow]"
                )
            else:
                state = loaded
                # 既出 Finding をレポートへ復元（重複防止のため dedup へも登録）。
                # ただし今回要求されたチェックに属する Finding のみ復元する
                # （xss sqli の結果を --checks xss で再開したとき、SQLi の古い
                # Finding をレポートへ持ち込まないため）。
                restored = 0
                for fd in state.findings:
                    try:
                        f = Finding.from_dict(fd)
                    except Exception:
                        continue
                    if not self._check_type_in_scope(f.check_type):
                        continue
                    key = finding_dedup_key_for(f)
                    if key not in self._finding_dedup:
                        self._finding_dedup.add(key)
                        self.all_findings.append(f)
                        restored += 1
                console.print(
                    f"  [green][Resume] {len(state.completed_units)} 済み単位 / "
                    f"{restored} 件の既出 Finding を復元しました。[/green]"
                )

        if state is None:
            state = cp.CheckpointState(target_url=self.target_url, checks=list(self.checks))
        self.checkpoint = state
        self._save_checkpoint()

    def _save_checkpoint(self) -> None:
        """現在の進捗（済み単位 + Finding スナップショット）を書き出す。"""
        if not self.enable_checkpoint or self.checkpoint is None:
            return
        from wscan import checkpoint as cp

        try:
            # Finding は all_findings から都度スナップショット（最新を保存）
            self.checkpoint.findings = [f.to_dict() for f in self.all_findings]
            cp.save_checkpoint(self.output_dir, self.checkpoint)
        except Exception as exc:
            self.wave_errors.append(f"checkpoint_save: {type(exc).__name__}: {exc}")

    async def _run_api_template_checks(self) -> None:
        """API スペック由来の JSON 操作（``api_seed_requests``）を、クロール結果に
        依存せず検査する。

        JSON API は GET がページ化されない（404/405）ことが多く、その場合 page-level の
        ``scan_page`` がそれらの URL に対して一度も呼ばれない。``mass_assignment`` は
        テンプレートを直接回すが、``prototype_pollution``/``cache_poisoning``/``graphql``
        のような URL 起点の page-level 検査も取りこぼす。ここでテンプレートの URL 群に
        対して全 page-level スキャナの ``scan_page`` を明示的に起動する（各スキャナの
        ``_checked_urls``/``_done`` ガードで二重実行は無害）。
        """
        if not self.api_seed_requests:
            return
        # 検査対象 URL: 各テンプレートの URL（重複除去）＋ターゲット（mass_assignment 用）。
        urls: list[str] = []
        seen: set[str] = set()
        for tmpl in self.api_seed_requests:
            u = getattr(tmpl, "url", "") or ""
            if u and u not in seen:
                seen.add(u)
                urls.append(u)
        if self.target_url not in seen:
            urls.append(self.target_url)

        for url in urls:
            # 時間帯ゲート/一時停止/スキップ/Abort を尊重する。クロール無しの API
            # スキャンではここが最初の攻撃になり得るため controller を必ず通す。
            try:
                await self.controller.checkpoint()
            except SkipField:
                continue
            except SkipPage:
                continue
            # これから叩く URL でセッション失効を検知して再ログインする。target が
            # 公開ページで API テンプレートだけ保護されている場合、target_url だけ
            # 見ても失効を検知できず、httpx 検査が 401 を Finding 0 で「済み」記録し
            # resume が恒久スキップしてしまうため、URL 単位で確認・cookie 更新する。
            await self._maybe_relogin_for_page(url)
            # 再ログインが起きなくても、ブラウザが既に保持する当該ホストの Cookie を
            # self.cookies へ写す。マルチスコープ（別サブドメインの API/ログイン）で
            # 初期ログインが API ホストに着地済みでも httpx 検査が認証されるようにする。
            try:
                await self._sync_cookies_from_browser(self.browser, for_url=url)
            except Exception:
                pass
            # httpx ベースのセッション確認。ブラウザの GET プレフライトが見逃す API の
            # 401/login を、scanner が使うのと同じ Cookie で検出する。mass_assignment 以外
            # （graphql/cache/proto）は 401 でも空 Finding を返すだけなので、ここで失効を
            # 捉えて再ログインしないと未認証の空振りを「済み」記録→resume 恒久スキップになる。
            url_auth_failed = False
            if await self._api_session_looks_expired(url):
                if not await self._force_relogin(for_url=url):
                    url_auth_failed = True  # 復旧不能 → この URL の単位は済みにしない
            for check_name, scanner in self.scanners.items():
                # 再開: 済みの API テンプレート単位は飛ばす（合成フィールド名で記録）。
                # exact URL で刻む。graphql を origin で刻むと、先行テンプレ URL の後に
                # 続く非標準 GraphQL エンドポイント（/gql 等）が丸ごと飛ばされるため。
                cp_url = _page_check_cp_url(check_name, url)
                if self._checkpoint_is_done(cp_url, "(api-template)", 0, check_name):
                    continue
                # page-level 攻撃（_attack_one_page）はこの API テンプレ pass より前に
                # 走り、proto/cache/graphql 等の非テンプレ専用検査を crawl 済み URL に
                # 対して scan_page 済みにしている。page 攻撃後・本 pass 前にクラッシュ/
                # Abort して resume すると、(page) 単位は済みでも (api-template) は未済の
                # ため scan_page を再送してしまう（proto の JSON POST 等、状態変更を伴う）。
                # API テンプレ専用でない検査は (page) 単位の完了も尊重して二重送信を防ぐ。
                if (
                    check_name not in _API_TEMPLATE_ONLY_CHECKS
                    and self._checkpoint_is_done(cp_url, "(page)", 0, check_name)
                ):
                    continue
                try:
                    self._api_auth_failed = url_auth_failed
                    findings = await scanner.scan_page(url)
                    # 実テンプレ要求で認証失効を観測したら、再ログイン+1回だけ再試行。
                    # GET プレフライトでは検知できないメソッド限定保護(POST=401)を救済。
                    # 失効は既知なので _force_relogin（検知を介さず直接 auto_login）を使う。
                    if self._api_auth_failed:
                        relogged = await self._force_relogin(for_url=url)
                        if relogged:
                            self._api_auth_failed = False
                            # scanner は初回で url を per-URL ガード（_checked_urls 等）に
                            # 登録済みのことがあり、そのまま再実行すると [] を返す。
                            # 再試行が実際に走るようガードからこの url を外す。
                            _reset_scanner_url_guard(scanner, url)
                            findings = await scanner.scan_page(url)
                    for f in (findings or []):
                        self._record_finding(f, source="api-spec")
                except AbortScan:
                    # 中断前に、ここまでの Finding と進捗を必ず永続化してから伝播する
                    # （resume が状態変更系テンプレートを再実行しないように）。
                    self._save_checkpoint()
                    raise
                except Exception as e:
                    console.print(
                        f"  [yellow]API template check ({check_name}) on {url}: {e}[/yellow]"
                    )
                else:
                    # 認証失効が解消しないまま空振りした単位は「済み」にしない
                    # （resume が再試行できるようにする）。
                    if not self._api_auth_failed:
                        self._checkpoint_mark_done(cp_url, "(api-template)", 0, check_name)
            # URL 単位で進捗＋Finding スナップショットを保存（クラッシュ耐性）。
            self._save_checkpoint()

    def _check_type_in_scope(self, check_type: str) -> bool:
        """Finding の check_type が今回有効なチェック集合に属するか。

        スキャナの ``CHECK_TYPE`` は実際の検査名と一致するもの（``xss``/``sqli``）と、
        サブタイプを持つもの（``graphql_introspection``/``jwt_alg_none``/``privesc_*``）
        がある。完全一致・``"<check>_"`` 前置・エイリアス表で判定する。

        判定対象は ``self.checks`` ではなく **実際に有効なスキャナ**（``self.scanners``）。
        Cookie 認証時に自動追加される ``privesc``/``cms`` 等は ``checks`` には入らないが
        スキャナは動く。``checks`` だけで絞ると、それらの完了単位は honor される一方で
        既出 ``privesc_*`` Finding が復元されず、レポートから消えてしまう。
        """
        ct = check_type or ""
        effective = set(self.checks) | set(getattr(self, "scanners", {}).keys())
        # crawl 中に条件付きで自動有効化される検査（cms/privesc）は、復元時点では
        # まだ scanners に無いことがあるため常に in-scope 扱いで既出 Finding を保つ。
        effective |= _AUTO_ENABLED_CHECKS
        for check in effective:
            if ct == check or ct.startswith(check + "_"):
                return True
            if ct in _CHECK_EXTRA_TYPES.get(check, ()):
                return True
        return False

    def _check_type_requested(self, check_type: str) -> bool:
        """Agent Finding 用の**厳格**な check_type 判定。

        ``_check_type_in_scope`` は resume 用で、Cookie 認証/CMS 検出で自動有効化される
        ``privesc``/``cms`` 等（``_AUTO_ENABLED_CHECKS``）や実行中スキャナも in-scope 扱い
        する。しかし Agent は任意の ``Type:`` を出力できるため、それを流用すると
        ``--checks xss`` でも Agent 由来の ``privesc_*``/``cms_*`` がレポートに混入する。
        ここでは**演算子が明示的に要求した ``self.checks`` のみ**（サブタイプ前置・
        エイリアスは許可）で判定し、自動有効化ぶんは含めない。
        """
        ct = check_type or ""
        for check in self.checks:
            if ct == check or ct.startswith(check + "_"):
                return True
            if ct in _CHECK_EXTRA_TYPES.get(check, ()):
                return True
        return False

    def _checkpoint_is_done(
        self, url: str, field_name: str, form_index: int, check: str,
        is_url_param: bool = False,
    ) -> bool:
        if not self.enable_checkpoint or self.checkpoint is None:
            return False
        return self.checkpoint.is_done(url, field_name, form_index, check, is_url_param)

    def _checkpoint_mark_done(
        self, url: str, field_name: str, form_index: int, check: str,
        is_url_param: bool = False,
    ) -> None:
        if not self.enable_checkpoint or self.checkpoint is None:
            return
        self.checkpoint.mark_done(url, field_name, form_index, check, is_url_param)

    # =========================================================================
    # Session expiry / auto re-login
    # =========================================================================

    async def _relogin_if_needed(
        self, browser, *, status=None, final_url: str = "", body: str = "", for_url: str = ""
    ) -> bool:
        """応答がセッション失効を示す場合に ``browser`` 上で自動再ログインする。

        再ログインに成功したら True。失効していない／再ログイン不可なら False。
        誤った連続再ログインを避けるため :mod:`wscan.session_guard` の厳しめの
        判定（401 か「ログインフォーム残存」）を通った場合だけ実行する。

        ``browser`` は呼び出し側が渡す文脈対応ブラウザ（並列時は worker、直列時は
        メイン）。worker 自身のコンテキストで再ログインすることで、別 worker が
        攻撃中のメインページを動かす副作用を避ける。
        """
        if not self.relogin_on_expiry:
            return False
        if not (self.login_url and getattr(browser, "auth_user", "")
                and getattr(browser, "auth_pass", "")):
            return False
        if not hasattr(browser, "auto_login"):
            return False
        from wscan import session_guard

        if not session_guard.looks_logged_out(
            status=status,
            final_url=final_url,
            body=body,
            login_url=self.login_url,
            logged_in_marker=self.logged_in_marker,
        ):
            return False

        self._relogin_count += 1
        console.print(
            f"  [bold yellow][Auth] セッション失効を検知 — 自動再ログインを試みます "
            f"(#{self._relogin_count})[/bold yellow]"
        )
        if self.monitor:
            try:
                await self.monitor.emit_status("セッション失効を検知 — 自動再ログイン中", "running")
            except Exception:
                pass
        try:
            success = await browser.auto_login(
                self.login_url,
                user_field=self.login_user_field,
                pass_field=self.login_pass_field,
                success_indicator=self.login_success_indicator,
            )
        except Exception as exc:
            console.print(f"  [yellow][Auth] 再ログイン失敗: {exc}[/yellow]")
            return False
        if success:
            console.print("  [green][Auth] 再ログイン成功 — セッションを更新しました。[/green]")
            # 新しい Cookie を httpx 系（auth_headers）にも反映する。これを怠ると
            # mass_assignment/graphql/cache_poisoning/server-side proto などの直接
            # httpx 検査が失効 Cookie を送り続けて認証 API を取りこぼす。これから叩く
            # ホスト（for_url）の Cookie を採るため for_url を渡す。
            await self._sync_cookies_from_browser(browser, for_url=for_url or final_url)
        else:
            console.print("  [yellow][Auth] 再ログインできませんでした。[/yellow]")
        return bool(success)

    async def _sync_cookies_from_browser(self, browser, for_url: str = "") -> None:
        """ブラウザコンテキストの Cookie を ``self.cookies`` 文字列へ反映する。

        ``auth_headers()`` は ``self.cookies`` を Cookie ヘッダに使うため、再ログイン
        後にここを更新しないと httpx ベースの検査が古い Cookie を送ってしまう。
        ``for_url`` のホスト（未指定なら target_url）宛に送られる Cookie のみ採用する。
        マルチスコープ（www とは別サブドメインの API/ログイン）では、これから叩く
        ホストを渡さないと host-only Cookie が落ちて API 検査が未認証になる。
        """
        try:
            from urllib.parse import urlparse as _up
            page = getattr(browser, "page", None)
            if page is None:
                return
            cookies = await page.context.cookies()
        except Exception:
            return
        if not cookies:
            # jar が空（ログアウトで消去 / Bearer・localStorage 認証など）。stale な
            # Cookie を送り続けないようクリアする。なお page 取得不能・例外時は判定
            # できないため上の except/None 経路では据え置く（無闇に消さない）。
            self.cookies = ""
            return
        _parsed = _up(for_url or self.target_url)
        target_host = (_parsed.hostname or "").lower()
        req_path = _parsed.path or "/"
        # (path, "name=value") を集めてから RFC 6265 §5.4 の並びへ整える。
        matched: list[tuple[str, str]] = []
        for c in cookies:
            name = c.get("name")
            if not name:
                continue
            raw_dom = str(c.get("domain", ""))
            # 先頭ドットの有無で host-only か domain-scoped かを判別する
            # （Playwright: ドメイン Cookie は ".example.com"、host-only は "example.com"）。
            is_domain_cookie = raw_dom.startswith(".")
            dom = raw_dom.lstrip(".").lower()
            # ブラウザの送出規則に合わせて採用する:
            #  - 完全一致は常に可
            #  - サブドメインへの suffix 一致は **domain-scoped Cookie のときだけ** 可
            #    （host-only な example.com の Cookie を api.example.com へ送らない）。
            if dom and target_host and not (
                target_host == dom
                or (is_domain_cookie and target_host.endswith("." + dom))
            ):
                continue
            cpath = str(c.get("path", "/") or "/")
            # path スコープも照合（Path=/admin の Cookie を /api へ送らない）。
            if not _cookie_path_matches(req_path, cpath):
                continue
            matched.append((cpath, f"{name}={c.get('value', '')}"))
        # RFC 6265 §5.4: path の長いものを先に送る（同名 Cookie が / と /admin に
        # ある場合、より具体的な /admin を先頭に）。最初の値を使うフレームワークで
        # 誤ったセッション（root cookie）で検査するのを防ぐ。stable sort なので同じ
        # path 長は元の順序（概ね生成順）を保つ。
        matched.sort(key=lambda pv: len(pv[0]), reverse=True)
        # マッチ集合で**常に置換**する（空でも）。per-URL 同期では、前の URL で
        # 別ホスト用に設定した self.cookies が残ると、当該ホストに無関係な Cookie を
        # 送って別セッションで検査してしまう。一致が無ければクリアして未認証で送る。
        self.cookies = "; ".join(pv[1] for pv in matched)

    async def _maybe_relogin_for_page(self, url: str) -> None:
        """攻撃対象ページの状態を見てセッション失効なら再ログインする。

        並列時に別ワーカーのメインページを動かさないよう、文脈対応の
        ``self.browser``（worker 実行中は worker、直列時はメイン）を使う。worker は
        これから ``url`` を攻撃するので、ここでの遷移は自分自身のページに対する
        無害なものになる。``auto_login`` を持たないブラウザなら no-op。
        """
        if not self.relogin_on_expiry:
            return
        # ログインページ自体を攻撃対象にしている場合は再ログインしない。
        # ここで auto_login するとログインフォームが認証後画面に化け、ログイン
        # サーフェスへの SQLi/XSS 検査が空振りになる（_scan_login_form_preauth が
        # この経路を通るため）。
        if self._is_login_target_url(url):
            return
        browser = self.browser  # 文脈対応（worker or main）
        if not (self.login_url and getattr(browser, "auth_user", "")
                and getattr(browser, "auth_pass", "")):
            return
        if not hasattr(browser, "auto_login"):
            return
        try:
            # navigate() は >=400 応答で False を返すが、401 は失効の最強シグナル
            # なので bool で早期 return せず、ステータス/本文を見て判定する。
            await browser.navigate(url, retries=self.navigation_retries)
            body = await browser.page.content()
            final_url = browser.page.url
        except Exception:
            body = ""
            final_url = url
        status = None
        try:
            network = getattr(browser, "network", None)
            pair = network.latest_for_url(url, match_query=False) if network else None
            if pair:
                status = (pair.get("response", {}) or {}).get("status")
        except Exception:
            status = None
        # 判定材料が全く得られなければ何もしない
        if not body and status is None:
            return False
        relogged = await self._relogin_if_needed(
            browser, status=status, final_url=final_url, body=body, for_url=url
        )
        if relogged:
            # 認証済みコンテンツを攻撃で見るため、対象ページへ再遷移する。
            try:
                await browser.navigate(url, retries=self.navigation_retries)
            except Exception:
                pass
        return bool(relogged)

    async def _force_relogin(self, for_url: str = "") -> bool:
        """検知を介さず直接再ログインする（失効が既知のとき用）。成功で True。

        実テンプレ要求(POST 等)で 401 を観測済みの場合、GET プレフライトでは
        失効を再検知できない（メソッド限定保護で 404/405）。そのときは検知を
        飛ばして直接 auto_login し、``for_url`` のホスト宛 Cookie を同期する。
        """
        if not self.relogin_on_expiry:
            return False
        browser = self.browser
        if not (self.login_url and getattr(browser, "auth_user", "")
                and getattr(browser, "auth_pass", "")):
            return False
        if not hasattr(browser, "auto_login"):
            return False
        try:
            success = await browser.auto_login(
                self.login_url,
                user_field=self.login_user_field,
                pass_field=self.login_pass_field,
                success_indicator=self.login_success_indicator,
            )
        except Exception as exc:
            console.print(f"  [yellow][Auth] 再ログイン失敗: {exc}[/yellow]")
            return False
        if success:
            self._relogin_count += 1
            await self._sync_cookies_from_browser(browser, for_url=for_url)
        return bool(success)

    async def _api_session_looks_expired(self, url: str) -> bool:
        """``url`` への **非破壊 GET**（scanner と同じ auth_headers）で失効を判定する。

        ブラウザ GET プレフライトと異なり、httpx ベース検査が実際に送る Cookie/ヘッダで
        確認する。状態変更を避けるため必ず GET のみ（POST/PUT/PATCH テンプレを
        プレフライトで実行すると create 等が二重実行され state を壊す）。POST 専用
        エンドポイント（GET=404/405 だが実 POST=401）の失効は、実際に POST する
        mass_assignment / prototype_pollution が ``_api_auth_failed`` を立てて救済する。
        再ログイン未設定なら常に False。判定不能（例外）も False。
        """
        if not (self.relogin_on_expiry and self.login_url):
            return False
        import httpx
        from wscan import session_guard

        kwargs: dict = {"timeout": getattr(self, "timeout", 15), "follow_redirects": True}
        if hasattr(self, "httpx_client_kwargs"):
            kwargs = self.httpx_client_kwargs(**kwargs)
        elif getattr(self, "proxy", ""):
            kwargs["proxy"] = self.proxy
        headers = self.auth_headers(url=url) if hasattr(self, "auth_headers") else {}
        try:
            async with httpx.AsyncClient(**kwargs) as client:
                r = await client.get(url, headers=headers)
        except Exception:
            return False
        return session_guard.looks_logged_out(
            status=r.status_code,
            final_url=str(r.url),
            body=r.text,
            login_url=self.login_url,
            logged_in_marker=self.logged_in_marker,
        )

    # =========================================================================
    # Public entry point
    # =========================================================================

    async def run(self):
        """4-phase scan pipeline."""
        if self.monitor:
            await self.monitor.emit_status(f"Starting scan of {self.target_url}", "running")
            await self.monitor.emit_scan_config(
                url=self.target_url,
                checks=self.checks,
                depth=self.depth,
                concurrency=self.concurrency,
                timeout=self.timeout,
                fast_mode=self.fast_mode,
            )

        loop = asyncio.get_event_loop()
        self.controller.start(loop, monitor=self.monitor)

        # 再開可能スキャン: チェックポイントを初期化（resume 指定時は復元）
        self._init_checkpoint()

        # U-3: Start manual payload listener if monitor active
        if self.monitor:
            asyncio.run_coroutine_threadsafe(self._manual_payload_listener(), loop)

        # Periodic header refresh (rotating Bearer tokens etc.). Safe no-op if
        # no refresh command / interval was configured.
        self.header_manager.start_background_refresh()

        try:
            await self._browser.init()
            if self.cookies:
                await self._browser.set_cookies(self.cookies, self.target_url)
            if self.cookie_list:
                await self._browser.set_cookies_from_list(self.cookie_list, self.target_url)

            # pre-auth ログインフォーム検査〜attack までの停止(abort)を単一の捕捉点で
            # 扱う。controller は既に _active のため、pre-auth 検査中の停止でも
            # per-payload の AbortScan が飛ぶ。AbortScan は BaseException で外側の
            # except Exception では捕まらず、ここで受けないと run() を抜けて serve
            # ループごと落ちる（crawl 由来と同じ経路）。crawl-review の cancel も同様。
            scan_aborted = False
            try:
                # Auth-1: Auto-login if login URL provided
                if self.login_url and self._browser.auth_user and self._browser.auth_pass:
                    # Inspect the login form FIRST, while still logged out. Apps that
                    # redirect authenticated users away from /login would otherwise
                    # hide the form, leaving this attack surface untested.
                    await self._scan_login_form_preauth()
                    console.print(
                        f"  [cyan][Auth] Auto-login:[/cyan] {self.login_url}"
                    )
                    if self._mfa_solver is not None:
                        console.print(
                            f"  [cyan][Auth] MFA enabled:[/cyan] type={self._mfa_config.type} "
                            f"(external MCP)"
                        )
                    success = await self._browser.auto_login(
                        self.login_url,
                        user_field=self.login_user_field,
                        pass_field=self.login_pass_field,
                        success_indicator=self.login_success_indicator,
                    )
                    if success:
                        self.auth_landing_url = getattr(self._browser, "last_login_url", "") or self._browser.page.url
                        console.print("  [green][Auth] Login successful — session cookies captured.[/green]")
                        # httpx 系検査も認証されるよう、初回ログイン直後に Cookie を同期する。
                        await self._sync_cookies_from_browser(self._browser)
                        if self.auth_landing_url:
                            console.print(f"  [dim][Auth] Authenticated landing:[/dim] {self.auth_landing_url}")
                    else:
                        console.print("  [yellow][Auth] Login may have failed — continuing anyway.[/yellow]")

                # A: Set up multi-account sessions (if --accounts supplied)
                if self.accounts and self.login_url:
                    await self._setup_account_sessions()

                # A-2: Detect WAF before crawling (if enabled)
                if self.enable_waf_detection:
                    waf_name = await self.waf_detector.detect(self.target_url, timeout=float(self.timeout))
                    if waf_name:
                        console.print(f"  [bold yellow][WAF][/bold yellow] Detected: {waf_name}")
                        bypass_hints = self.waf_detector.get_bypass_hints(waf_name)
                        console.print(f"  [dim yellow]Bypass hints: {'; '.join(bypass_hints[:3])}[/dim yellow]")
                        if self.monitor:
                            await self.monitor.emit("waf_detected", {"waf": waf_name, "hints": bypass_hints})
                    else:
                        console.print("  [dim]No WAF detected.[/dim]")
                else:
                    console.print("  [dim]WAF detection disabled.[/dim]")

                # ── Phase 1: Crawl ───────────────────────────────────────
                if self.monitor: await self.monitor.emit_phase("crawl")
                crawled_pages = await self._phase_crawl()

                # ── Phase 1b: Crawl Review (AeyeScan-style) ──────────────
                if self.interactive_crawl_review and self.monitor:
                    crawled_pages = await self._phase_crawl_review(crawled_pages)

                # A: Auto-register accounts via registration forms (after crawl)
                if self.auto_register and self.login_url:
                    await self._auto_register_accounts(crawled_pages)
                    if self.account_sessions:
                        console.print(
                            f"  [green][A] {len(self.account_sessions)} account session(s) ready "
                            f"for privilege escalation testing.[/green]"
                        )

                # ── Phase 2: Plan ────────────────────────────────────────
                if self.monitor: await self.monitor.emit_phase("plan")
                plans = await self._phase_plan(crawled_pages)

                # ── Phase 3: Attack ──────────────────────────────────────
                if self.monitor: await self.monitor.emit_phase("attack")
                await self._phase_attack(crawled_pages, plans)
            except AbortScan:
                scan_aborted = True
                # 中断時点の Finding と進捗を必ず永続化してから続行する。payload 単位の
                # 即時停止は _scan_field 末尾の _save_checkpoint より前に抜けるため、
                # ここで保存しないと中断フィールドで既に記録した Finding が checkpoint
                # に載らず、部分レポート（in-memory）と resume（snapshot 復元）が食い違う。
                self._save_checkpoint()
                console.print(
                    "\n[bold red][Intervention] Scan aborted by operator.[/bold red] "
                    "Generating partial report …"
                )

            # ── Phase 3b: API スペック由来の本文検査（クロール非依存）──────
            # JSON API は GET に 404/405 を返してページ化されないことが多く、
            # その場合 page-level の scan_page が一度も呼ばれず mass_assignment 等が
            # 空振りする。クロール結果に依存せず api_seed_requests を直接検査する。
            # 既に Abort 済みなら、状態変更系（POST/PUT/PATCH）を新たに送らないため
            # この後続フェーズは実行しない（abort 制御の信頼性を保つ）。
            if not scan_aborted:
                try:
                    await self._run_api_template_checks()
                except AbortScan:
                    scan_aborted = True

            # ── Phase 3c: Post-Auth Crawl + Attack (if SQLi bypass detected) ──
            if not scan_aborted and self.auth_bypass_detected:
                console.print(
                    "\n[bold red][Auth Bypass][/bold red] "
                    "SQL injection bypass confirmed — "
                    "re-crawling and attacking authenticated surface …"
                )
                # post-auth の crawl/plan/attack を通して停止(abort)を捕捉する。
                # post-auth crawl も独自 BFS ループを持ち wait_if_paused_or_abort を
                # 通すため、ここで受けないと crawl 由来の AbortScan が run() を抜ける。
                try:
                    new_pages = await self._phase_crawl_postauth()
                    if new_pages:
                        new_plans = await self._phase_plan(new_pages)
                        console.print(
                            Rule(
                                "[bold red] Post-Auth Attack [/bold red]",
                                style="red",
                            )
                        )
                        await self._phase_attack(new_pages, new_plans)
                    else:
                        console.print(
                            "  [dim]No new pages discovered in post-auth crawl.[/dim]"
                        )
                except AbortScan:
                    scan_aborted = True
                    # 中断時点の Finding/進捗を永続化（resume と部分レポートの整合）。
                    self._save_checkpoint()

        except Exception as _run_exc:
            console.print(f"\n[bold red]Scan error:[/bold red] {_run_exc}")
            if self.monitor:
                await self.monitor.emit_status(f"Scan error: {_run_exc}", "error")
            raise

        finally:
            self.controller.stop()

            # ── Phase 4.5: Verification ──────────────────────────────────
            # Keep the header refresh task alive through verification: scanner
            # verify_finding() paths still make authenticated httpx calls via
            # auth_headers(), and stopping refresh here would freeze the token
            # snapshot — verifiers near token expiry would 401 and mark real
            # findings unconfirmed.
            try:
                await self._phase_verify()
            finally:
                try:
                    await self.header_manager.stop_background_refresh()
                except Exception:
                    pass
                await self._browser.close()

            # Agent Finding は認可済みスコープ内だけ、決定論 Finding の生成・検証を
            # 変えずに追加する。source の異なる同一 Finding は意図的に併記する。
            self._merge_additional_report_findings()

            # ── Phase 4: Report ──────────────────────────────────────────
            if self.monitor: await self.monitor.emit_phase("report")
            await self._phase_report_async()

            if self.monitor:
                self.monitor.api_findings = [f.to_dict() for f in self.all_findings]
                self.monitor.api_scan_status = "done"
                # Only expose a portal-servable scan id when the output folder
                # lives under OUTPUT_BASE; the /reports endpoint resolves ids
                # there, so a custom output_dir elsewhere would 404.
                served_scan_id = ""
                try:
                    self.output_dir.resolve().relative_to(OUTPUT_BASE.resolve())
                    served_scan_id = self.output_dir.name
                except ValueError:
                    served_scan_id = ""
                await self.monitor.emit("scan_complete", {
                    "total_findings": len(self.all_findings),
                    "report_path": str(self.output_dir / "report.html"),
                    "scan_id": served_scan_id,
                    "findings": self.monitor.api_findings,
                })

    # =========================================================================
    # Phase 1: Crawl
    # =========================================================================

    async def _fetch_sitemap_urls(self) -> list[str]:
        """C-3: Fetch and parse sitemap.xml and robots.txt for additional seed URLs."""
        import httpx
        discovered: list[str] = []
        base = self.target_url.rstrip("/")

        async with httpx.AsyncClient(
            **self.httpx_client_kwargs(
                timeout=10.0,
                follow_redirects=True,
            )
        ) as client:
            # robots.txt
            try:
                robots_url = f"{base}/robots.txt"
                r = await client.get(
                    robots_url,
                    headers=self.auth_headers(url=robots_url),
                )
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("sitemap:"):
                            sitemap_url = line.split(":", 1)[1].strip()
                            discovered += await self._parse_sitemap(client, sitemap_url)
                        elif line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/":
                                full = urljoin(base + "/", path.lstrip("/"))
                                discovered.append(full)
            except Exception:
                pass

            # sitemap.xml (try directly if not found via robots)
            try:
                sitemap_url = f"{base}/sitemap.xml"
                r = await client.get(
                    sitemap_url,
                    headers=self.auth_headers(url=sitemap_url),
                )
                if r.status_code == 200:
                    discovered += self._extract_sitemap_locs(r.text)
            except Exception:
                pass

        # Filter to same domain
        base_parsed = urlparse(base)
        return [
            u for u in discovered
            if urlparse(u).netloc == base_parsed.netloc and u not in self.visited_urls
        ]

    async def _parse_sitemap(self, client, sitemap_url: str) -> list[str]:
        """Fetch and parse a sitemap URL (supports sitemap index)."""
        try:
            r = await client.get(
                sitemap_url,
                timeout=10.0,
                headers=self.auth_headers(url=sitemap_url),
            )
            if r.status_code == 200:
                return self._extract_sitemap_locs(r.text)
        except Exception:
            pass
        return []

    @staticmethod
    def _page_fingerprint(html: str, url: str = "") -> str:
        """
        A: HTML の構造的フィンガープリント。
        テキスト・通常属性値を除いたタグ列に、フォームの method/action/name を加える。
        同じレイアウトでも別 action のフォームや別 URL 入力面は検査対象として残す。
        """
        import hashlib
        html_l = html.lower()
        tags = re.findall(r'<\w+', html_l)
        form_sigs: list[str] = []
        for form_html in re.findall(r'<form\b[^>]*>.*?</form>', html_l, flags=re.S):
            open_tag = form_html.split(">", 1)[0]
            method = re.search(r'\bmethod=["\']?([^"\'\s>]+)', open_tag)
            action = re.search(r'\baction=["\']?([^"\'\s>]+)', open_tag)
            names = re.findall(r'\bname=["\']?([^"\'\s>]+)', form_html)
            form_sigs.append(
                "form:"
                + (method.group(1) if method else "get")
                + ":"
                + (action.group(1) if action else "")
                + ":"
                + ",".join(sorted(names[:20]))
            )
        route_sig = ""
        if url:
            parsed = urlparse(url)
            route_sig = f"route:{parsed.path or '/'}"
            query_names = sorted(
                {
                    part.split("=", 1)[0]
                    for part in parsed.query.split("&")
                    if part.split("=", 1)[0]
                }
            )
            if query_names:
                route_sig += f"?{','.join(query_names[:20])}"
        material = "".join(tags[:50]) + "|".join(sorted(form_sigs)) + route_sig
        return hashlib.md5(material.encode()).hexdigest()[:12]

    @staticmethod
    def _merge_url_params(current_params: list[str], queued_url: str) -> list[str]:
        """
        Preserve query inputs from the queued URL even if navigation redirects.

        Open redirect and post-login redirect endpoints often immediately move
        the browser away from the vulnerable URL.  Browser-side
        window.location.search then describes the destination page, not the
        original URL that should be attacked.
        """
        merged: list[str] = []
        seen: set[str] = set()
        parsed = urlparse(queued_url)
        queued_params = [
            part.split("=", 1)[0]
            for part in parsed.query.split("&")
            if part.split("=", 1)[0]
        ]
        for name in [*(current_params or []), *queued_params]:
            if name and name not in seen:
                seen.add(name)
                merged.append(name)
        return merged

    def _extract_sitemap_locs(self, xml_text: str) -> list[str]:
        """Extract <loc> URLs from a sitemap XML string."""
        urls: list[str] = []
        try:
            root = _ET.fromstring(xml_text)
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            for loc in root.iter():
                if loc.tag.endswith("}loc") or loc.tag == "loc":
                    text = (loc.text or "").strip()
                    if text.startswith("http"):
                        urls.append(text)
        except Exception:
            pass
        return urls

    async def _phase_crawl(self) -> list:
        """BFS crawl — navigate every reachable page, collect forms/HTML. No payloads."""
        console.print(Rule("[bold blue] Phase 1 / 4  ·  Crawl [/bold blue]", style="blue"))
        console.print(f"  Target: [cyan]{self.target_url}[/cyan]  depth={self.depth}")
        if len(self.target_urls) > 1 or self.access_urls:
            console.print(
                f"  Scope : [cyan]{len(self.target_urls)}[/cyan] attack scope(s), "
                f"[cyan]{len(self.access_urls)}[/cyan] access-only scope(s)\n"
            )
        else:
            console.print()

        pages: list = []
        queue: deque = deque([(self.target_url, 0, None)])  # (url, depth, parent_url)
        self.visited_urls.add(self.target_url)
        for scope_url in self.additional_target_urls:
            if (
                scope_url.startswith(("http://", "https://"))
                and scope_url not in self.visited_urls
                and not self._is_url_excluded(scope_url)
            ):
                self.visited_urls.add(scope_url)
                queue.append((scope_url, 0, self.target_url))
        # A: DOM構造フィンガープリントで類似ページを検出
        self._seen_page_fingerprints: set[str] = set()
        _first_page = True  # CMS 検出は最初のページのみ

        # 認証後の到達ページを通常クロールにも戻す。ログイン URL を起点にした診断では、
        # ここを入れないとログイン後画面を巡回しないまま攻撃フェーズへ進んでしまう。
        if self.auth_landing_url:
            try:
                if (
                    self.auth_landing_url not in self.visited_urls
                    and self._is_access_allowed_url(self.auth_landing_url)
                    and not self._is_url_excluded(self.auth_landing_url)
                ):
                    self.visited_urls.add(self.auth_landing_url)
                    queue.append((self.auth_landing_url, 0, self.target_url))
                    console.print(
                        f"  [dim cyan][Auth][/dim cyan] "
                        f"ログイン後ページをクロールキューに追加: {self.auth_landing_url}"
                    )
            except Exception:
                pass

        # ログインページ自体を必ずクロール対象に含める。認証後はログインへの
        # リンクが消えるアプリが多く、シードしないとログインフォームが
        # 攻撃対象から漏れてしまう。
        if self.login_url and self._is_attack_target_url(self.login_url):
            login_seed = self.login_url.rstrip("/")
            if (
                login_seed not in self.visited_urls
                and not self._is_url_excluded(login_seed)
            ):
                self.visited_urls.add(login_seed)
                queue.append((login_seed, 0, self.target_url))
                console.print(
                    f"  [dim cyan][Auth][/dim cyan] "
                    f"ログインページをクロールキューに追加: {login_seed}"
                )

        # O: HAR ファイルインポート — URL シードと Cookie を注入
        if self.har_path:
            try:
                from wscan.har_importer import HarImporter
                har_seed = HarImporter().load(self.har_path)
                console.print(
                    f"  [dim cyan][O-HAR][/dim cyan] {len(har_seed.urls)} URL, "
                    f"{len(har_seed.cookies)} Cookie を読み込みました: {self.har_path}"
                )
                for _hurl in har_seed.urls:
                    if (
                        _hurl not in self.visited_urls
                        and self._is_access_allowed_url(_hurl)
                        and not self._is_url_excluded(_hurl)
                    ):
                        self.visited_urls.add(_hurl)
                        queue.append((_hurl, 0, self.target_url))
                if har_seed.cookies:
                    await self.browser.page.context.add_cookies(har_seed.cookies)
                # Pick up Authorization / X-API-Key headers captured in the HAR
                # so the scanner sends them on every subsequent request.
                if getattr(har_seed, "headers", None):
                    har_hdrs = {
                        k: v for k, v in har_seed.headers.items()
                        if k.lower() not in ("cookie", "content-length", "host")
                    }
                    if har_hdrs:
                        await self.header_manager.update(har_hdrs)
            except Exception as _har_err:
                console.print(f"  [yellow][O-HAR] HAR 読み込み失敗: {_har_err}[/yellow]")

        # 手動巡回インポート — 操作者が実際に辿った画面をクロールシードにする
        if self.manual_crawl_path:
            try:
                from wscan.manual_crawl import load_manual_crawl_seed
                manual_seed = load_manual_crawl_seed(
                    self.manual_crawl_path,
                    self.target_url,
                    allowed_scopes=[*self.target_urls, *self.access_urls],
                )
                console.print(
                    f"  [dim cyan][Manual Crawl][/dim cyan] {len(manual_seed.urls)} URL, "
                    f"{len(manual_seed.cookies)} Cookie を読み込みました: {self.manual_crawl_path}"
                )
                for _murl in manual_seed.urls:
                    if (
                        _murl not in self.visited_urls
                        and self._is_access_allowed_url(_murl)
                        and not self._is_url_excluded(_murl)
                    ):
                        self.visited_urls.add(_murl)
                        queue.append((_murl, 0, self.target_url))
                if manual_seed.cookies:
                    await self.browser.page.context.add_cookies(manual_seed.cookies)
            except Exception as _manual_err:
                console.print(f"  [yellow][Manual Crawl] 読み込み失敗: {_manual_err}[/yellow]")

        # API ファースト検査 — OpenAPI/Swagger/Postman スペックからエンドポイント・
        # 共通ヘッダ・JSON 操作（mass_assignment 等が使う）をシードする。
        if self.api_spec_path:
            try:
                from wscan.api_spec_importer import ApiSpecImporter
                api_seed = ApiSpecImporter().load(self.api_spec_path, self.target_url)
                console.print(
                    f"  [dim cyan][API][/dim cyan] {len(api_seed.urls)} URL, "
                    f"{len(api_seed.requests)} JSON 操作を読み込みました: {self.api_spec_path}"
                )
                for _aurl in api_seed.urls:
                    if (
                        _aurl not in self.visited_urls
                        and self._is_access_allowed_url(_aurl)
                        and not self._is_url_excluded(_aurl)
                    ):
                        self.visited_urls.add(_aurl)
                        queue.append((_aurl, 0, self.target_url))
                # JSON ボディ操作はスコープ内のものだけ mass_assignment へ渡す
                self.api_seed_requests = [
                    r for r in api_seed.requests
                    if self._is_attack_target_url(r.url) and not self._is_url_excluded(r.url)
                ]
                # スペック由来 URL（GET 含む全操作）を記録（graphql の具体 URL probe ゲート用）
                self.api_seed_urls = {
                    u for u in (api_seed.urls or [])
                    if not self._is_url_excluded(u)
                } | {r.url for r in self.api_seed_requests}
                if getattr(api_seed, "headers", None):
                    # 利用者が --header で明示した値は seed（スペックの default/example、
                    # 例えば API キーのプレースホルダ）で上書きしない。has() で既存を尊重。
                    api_hdrs = {
                        k: v for k, v in api_seed.headers.items()
                        if k.lower() not in ("cookie", "content-length", "host")
                        and not self.header_manager.has(k)
                    }
                    if api_hdrs:
                        await self.header_manager.update(api_hdrs)
            except Exception as _api_err:
                console.print(f"  [yellow][API] スペック読み込み失敗: {_api_err}[/yellow]")

        # C-3: Seed crawl queue from sitemap.xml / robots.txt (if enabled)
        sitemap_urls = await self._fetch_sitemap_urls() if self.enable_sitemap_crawl else []
        if sitemap_urls:
            console.print(
                f"  [dim cyan][C-3] Sitemap/robots.txt:[/dim cyan] "
                f"{len(sitemap_urls)} additional URL(s) discovered"
            )
            for su in sitemap_urls[:30]:  # cap at 30 seed URLs
                if (
                    su not in self.visited_urls
                    and self._is_access_allowed_url(su)
                    and not self._is_url_excluded(su)
                ):
                    self.visited_urls.add(su)
                    queue.append((su, 0, self.target_url))  # depth=0: treat as root-level

        # ハイブリッドモード: Agent偵察で発見したURLをシードとして追加
        if self.seed_urls:
            added = 0
            for su in self.seed_urls:
                if (
                    su not in self.visited_urls
                    and self._is_access_allowed_url(su)
                    and not self._is_url_excluded(su)
                ):
                    self.visited_urls.add(su)
                    queue.append((su, 0, self.target_url))
                    added += 1
            if added:
                console.print(
                    f"  [dim cyan][Hybrid] Agent偵察シード:[/dim cyan] "
                    f"{added} URL をクロールキューに追加"
                )

        _spa_cap_warned = False
        while queue:
            # 停止(abort)/一時停止(pause)をクロール中も尊重する。従来はこのループが
            # チェックポイントを一切通さず、停止要求が attack フェーズ開始まで
            # 無視されていた（深い/広いサイトほど「止まらない」体感になる）。
            await self.controller.wait_if_paused_or_abort()

            url, depth, parent_url = queue.popleft()

            # Skip excluded URLs (exact match or prefix match)
            if self._is_url_excluded(url):
                console.print(f"  [dim yellow]Skip (excluded URL):[/dim yellow] {url}")
                continue
            if not self._is_access_allowed_url(url):
                console.print(f"  [dim yellow]Skip (out of scope):[/dim yellow] {url}")
                continue

            console.print(f"  [dim]Crawling[/dim] ({depth + 1}/{self.depth}): {url}")
            if self.monitor:
                await self.monitor.emit_page_start(url)

            success = await self.browser.navigate(url, retries=self.navigation_retries)
            if not success:
                console.print(f"  [yellow]  ✘ could not load[/yellow]")
                self._record_unscannable_url(url)
                continue

            if self.spa_crawl:
                try:
                    await self.browser.settle_spa()
                except Exception:
                    pass

            # Detect session expiry: if we've been redirected to the login page,
            # re-authenticate before collecting forms from this page.
            # Skip when we deliberately navigated to the login page itself — the
            # login form is a valid attack surface and must be crawled/attacked
            # rather than mistaken for an expired session.
            if (
                self.login_url
                and self.relogin_on_expiry
                and self._browser.is_on_login_page(self.login_url)
                and not self._is_login_target_url(url)
            ):
                console.print(
                    "  [yellow][Auth] Session expired during crawl — re-authenticating...[/yellow]"
                )
                ok = await self._browser.auto_login(
                    self.login_url,
                    user_field=self.login_user_field,
                    pass_field=self.login_pass_field,
                    success_indicator=self.login_success_indicator,
                )
                if ok:
                    console.print("  [green][Auth] Re-login successful — resuming crawl.[/green]")
                    await self._sync_cookies_from_browser(self._browser)
                    # Navigate back to the intended page after re-login
                    success = await self.browser.navigate(url, retries=self.navigation_retries)
                    if not success:
                        console.print(f"  [yellow]  ✘ could not re-load after login[/yellow]")
                        self._record_unscannable_url(
                            url,
                            note="Navigation failed after successful re-login: "
                            + self._navigation_failure_note(),
                        )
                        continue
                    if self.spa_crawl:
                        try:
                            await self.browser.settle_spa()
                        except Exception:
                            pass
                else:
                    console.print(
                        "  [yellow][Auth] Re-login may have failed — skipping page.[/yellow]"
                    )
                    continue

            try:
                html = await self.browser.page.content()
            except Exception:
                html = ""

            # A: 重複ページスキップ (DOM構造フィンガープリント)
            if html:
                if self.flag_finder:
                    self._check_page_for_flags(html, url)
                fp = self._page_fingerprint(html, url)
                if fp in self._seen_page_fingerprints:
                    console.print(f"  [dim]重複ページスキップ: {url} (同一構造を検出)[/dim]")
                    # リンクは抽出するが、スキャン対象には追加しない
                    if depth + 1 < self.depth:
                        try:
                            link_entries = await self.browser.collect_links_rich(url, same_domain=False)
                            for entry in link_entries:
                                link = entry["url"]
                                clean = link.split("#")[0]
                                if (
                                    clean not in self.visited_urls
                                    and self._is_access_allowed_url(clean)
                                    and not self._is_url_excluded(clean)
                                ):
                                    self.visited_urls.add(clean)
                                    self._transition_via.setdefault(clean, {
                                        "text": entry.get("text", ""),
                                        "selector": entry.get("selector", ""),
                                        "rect": entry.get("rect"),
                                        "viewport": entry.get("viewport"),
                                    })
                                    queue.append((link, depth + 1, url))
                        except Exception:
                            pass
                    continue
                self._seen_page_fingerprints.add(fp)

            # C: CMS 検出 (最初のページのみ)
            if _first_page:
                _first_page = False
                try:
                    from wscan.cms_detect import detect_cms
                    # HTTP ヘッダはブラウザ経由では取得困難なため空辞書で渡す
                    self.detected_cms = detect_cms(html, {}, url)
                    if self.detected_cms.is_known:
                        console.print(
                            f"  [cyan][CMS] 検出:[/cyan] {self.detected_cms.name}"
                            + (f" v{self.detected_cms.version}" if self.detected_cms.version else "")
                            + f" (信頼度: {self.detected_cms.confidence})"
                        )
                        # CMS スキャナーを自動有効化
                        if "cms" not in self.scanners:
                            from wscan.scanners.cms import CmsScanner
                            self.scanners["cms"] = CmsScanner(self)
                except Exception:
                    pass

            forms = await self.browser.find_forms()
            # 遷移後 URL がキュー URL と別パスなら（リダイレクトで別ページへ移動）、
            # ここで収集した form は遷移先のもの。元 URL に紐付けると別ページの脆弱性を
            # 元 URL へ誤帰属する（例: open_redirect 安全ツインで遷移先の反射 XSS が
            # 元 URL の finding として出る）。form は遷移先 URL へ寄せ（未訪問かつ
            # スコープ内なら巡回キューへ積み）、URL パラメータはリダイレクト系
            # エンドポイント自体の検査用に元 URL へ残す（_merge_url_params の方針）。
            if forms:
                try:
                    landed = (self.browser.page.url or "").split("#")[0]
                except Exception:
                    landed = ""
                # scheme/host/path で比較する。パスだけだと、同一パスで別オリジンへ飛ぶ
                # リダイレクト（例: 社内 /login → 外部 SSO /login）を「同一ページ」と誤認し、
                # 外部ページの form を元 URL に残してしまう（Codex 指摘）。
                def _origin_path(u: str) -> tuple:
                    p = urlparse(u)
                    return (p.scheme, p.netloc, p.path.rstrip("/"))

                if landed and _origin_path(landed) != _origin_path(url):
                    if (
                        landed not in self.visited_urls
                        and self._is_access_allowed_url(landed)
                        and not self._is_url_excluded(landed)
                    ):
                        self.visited_urls.add(landed)
                        queue.append((landed, depth, parent_url))
                    forms = []
            url_params = self._merge_url_params(await self.browser.get_url_params(), url)
            screenshot_b64 = await self.browser.screenshot_b64(f"Crawl: {url}")

            # Record in page_graph for the transition diagram
            via = self._transition_via.get(url.split("#")[0])
            self.page_graph[url] = {
                "parent": parent_url,
                "screenshot_b64": screenshot_b64,
                "depth": depth,
                "via": via,
            }

            # CTF: scan page HTML for flags even during crawl
            if self.flag_finder and not html:
                self._check_page_for_flags(html, url)

            # Count and flag registration forms during crawl (informational only;
            # actual skipping happens in _attack_page)
            reg_form_count = 0
            if self.skip_registration:
                reg_form_count = sum(
                    1 for f in forms
                    if self._is_registration_form(f)
                )
                if self._is_registration_url(url):
                    reg_form_count = len(forms)  # whole page will be skipped

            input_count = sum(len(f.get("inputs", [])) for f in forms) + len(url_params)
            # Persist counts so the offline report's diagram can show them too.
            self.page_graph[url].update(
                {"forms": len(forms), "inputs": input_count, "params": len(url_params)}
            )
            if self.monitor:
                await self.monitor.emit_page_graph_update(
                    url=url,
                    parent=parent_url,
                    depth=depth,
                    forms=len(forms),
                    inputs=input_count,
                    params=len(url_params),
                    status="done",
                    via=via,
                    screenshot_b64=screenshot_b64,
                )
            reg_note = (
                f"  [dim yellow]({reg_form_count} registration form(s) will be skipped)[/dim yellow]"
                if reg_form_count else ""
            )
            console.print(
                f"    [dim]forms:[/dim] {len(forms)}  "
                f"[dim]url params:[/dim] {len(url_params)}  "
                f"[dim]inputs:[/dim] {input_count}"
                + (f"\n    {reg_note}" if reg_note else "")
            )

            is_attack_target = self._is_attack_target_url(url)
            if is_attack_target:
                pages.append(CrawledPage(
                    url=url, html=html, forms=forms,
                    url_params=url_params, depth=depth,
                    external_scripts=self._snapshot_external_scripts(html, url),
                ))
            else:
                console.print(
                    f"    [dim cyan]access-only scope: forms and parameters were collected "
                    f"for navigation context but will not be attacked[/dim cyan]"
                )

            # SPA が描画中に呼び出した GET API を既存 URL パラメータ経路へ載せる。
            if self.spa_crawl:
                try:
                    from . import spa_harvest

                    base_netloc = urlparse(self.target_url).netloc
                    url_cap = max(200, self.depth * 50)
                    harvested_count = 0
                    for target in spa_harvest.harvest_get_targets(
                        self.browser.network.pairs,
                        base_netloc=base_netloc,
                    ):
                        clean = target["url"]
                        if (
                            clean not in self.visited_urls
                            and self._is_access_allowed_url(clean)
                            and not self._is_url_excluded(clean)
                        ):
                            if len(self.visited_urls) >= url_cap:
                                if not _spa_cap_warned:
                                    console.print(
                                        f"  [yellow]Crawl URL cap ({url_cap}) reached — "
                                        f"some pages may have been skipped.[/yellow]"
                                    )
                                    _spa_cap_warned = True
                                break
                            self.visited_urls.add(clean)
                            pages.append(CrawledPage(
                                url=target["url"],
                                html="",
                                forms=[],
                                url_params=target["params"],
                                depth=depth + 1,
                            ))
                            harvested_count += 1
                    if harvested_count:
                        console.print(
                            f"  [dim cyan][SPA][/dim cyan] "
                            f"{harvested_count} 個の API エンドポイントを対象化"
                        )
                except Exception:
                    pass

            # ① SPA crawl: discover dynamically-rendered routes via click interaction
            if self.spa_crawl:
                try:
                    spa_links = await self._browser.explore_spa_interactions(
                        self._browser.page, url, max_clicks=20
                    )
                    for spa_link in spa_links:
                        clean_spa = spa_link.split("#")[0]
                        if (
                            clean_spa not in self.visited_urls
                            and self._is_access_allowed_url(clean_spa)
                            and not self._is_url_excluded(clean_spa)
                        ):
                            self.visited_urls.add(clean_spa)
                            queue.append((spa_link, depth + 1, url))
                except Exception:
                    pass

            if depth + 1 < self.depth:
                link_entries = await self.browser.collect_links_rich(url, same_domain=False)
                url_cap = max(200, self.depth * 50)
                _cap_warned = False
                for entry in link_entries:
                    link = entry["url"]
                    clean = link.split("#")[0]
                    if len(self.visited_urls) >= url_cap:
                        if not _cap_warned:
                            console.print(
                                f"  [yellow]Crawl URL cap ({url_cap}) reached — "
                                f"some pages may have been skipped.[/yellow]"
                            )
                            _cap_warned = True
                        break
                    if (clean not in self.visited_urls
                            and self._is_access_allowed_url(clean)
                            and not self._is_url_excluded(clean)):
                        self.visited_urls.add(clean)
                        self._transition_via.setdefault(clean, {
                            "text": entry.get("text", ""),
                            "selector": entry.get("selector", ""),
                            "rect": entry.get("rect"),
                            "viewport": entry.get("viewport"),
                        })
                        queue.append((link, depth + 1, url))

        total_inputs = sum(
            sum(len(f.get("inputs", [])) for f in p.forms) + len(p.url_params)
            for p in pages
        )
        console.print(
            f"\n  [bold green]Crawl complete[/bold green]  "
            f"[cyan]{len(pages)}[/cyan] page(s) · "
            f"[cyan]{total_inputs}[/cyan] input(s) discovered"
        )
        return pages

    # =========================================================================
    # Phase 2: Plan
    # =========================================================================

    async def _phase_plan(self, pages: list) -> dict:
        """Build per-page attack plans with cross-page awareness, then confirm with user."""
        console.print(Rule("[bold cyan] Phase 2 / 4  ·  Attack Planning [/bold cyan]", style="cyan"))

        plans: dict = {}

        if not self.use_planner:
            if self.interactive_plan:
                # Manual planning mode: generate heuristic base plans so the user
                # has something to start from, then open the interactive editor.
                console.print(
                    "  [bold yellow]手動プラン作成モード[/bold yellow]  "
                    "(AIプランナー無効 — ヒューリスティック分析から開始)\n"
                )
                plans = self._generate_heuristic_plans_for_pages(pages)
                if plans:
                    self.attack_plans = list(plans.values())
                    self._print_all_plans(plans)
                    console.print()
                    if self.monitor:
                        # Dashboard mode: send plans to web UI for review
                        console.print(
                            "  [bold cyan][Web Dashboard][/bold cyan] "
                            "プラン確認モーダルが開きます。ダッシュボードで確認後に攻撃を開始してください。"
                        )
                        plans_data = self._serialize_plans(plans)
                        await self.monitor.emit_plan_review(plans_data)
                        edits = await self.monitor.wait_for_plan_confirm()
                        if edits:
                            self._apply_plan_edits(plans, edits)
                            console.print("  [dim]プラン編集が適用されました。[/dim]")
                    else:
                        # Terminal fallback: interactive CUI editor
                        self._interactive_plan_editor(plans)
                        console.print(
                            "[bold]  手動プランが完成しました。[/bold] "
                            "[green]Enter[/green] で攻撃開始、[red]Ctrl+C[/red] で中断。"
                        )
                        try:
                            await asyncio.get_event_loop().run_in_executor(None, input, "  → ")
                        except (KeyboardInterrupt, EOFError):
                            raise SystemExit("\nAborted by user.")
            else:
                console.print("  [dim]Planner disabled — all checks will run on every field.[/dim]")
            return plans

        # Build a site map string so LLM can reason about cross-page flows
        # (e.g., stored XSS: input on /post, reflected on /feed)
        site_map_lines = []
        for i, p in enumerate(pages):
            inp_count = sum(len(f.get("inputs", [])) for f in p.forms) + len(p.url_params)
            site_map_lines.append(
                f"  [{i+1}] {p.url}  ({len(p.forms)} form(s), {len(p.url_params)} URL param(s), "
                f"{inp_count} input(s) total)"
            )
        site_map = "\n".join(site_map_lines)

        console.print(f"  Site map ({len(pages)} page(s)):")
        console.print(f"[dim]{site_map}[/dim]\n")

        pages_with_inputs = [p for p in pages if p.forms or p.url_params]
        pages_no_inputs   = [p for p in pages if not p.forms and not p.url_params]
        for p in pages_no_inputs:
            console.print(f"  [dim]No inputs on {p.url}, skipping[/dim]")

        async def _plan_one(page):
            console.print(f"  [dim cyan]Planning:[/dim cyan] {page.url}")
            plan = await self.attack_planner.analyze_page(
                url=page.url,
                page_html=page.html,
                forms=page.forms[:self.max_forms],
                url_params=page.url_params,
                site_map=site_map,
            )
            if self.monitor:
                await self.monitor.emit_status(f"Plan: {plan.page_purpose[:60]}")
            return page.url, plan

        results = await asyncio.gather(
            *[_plan_one(p) for p in pages_with_inputs],
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, Exception):
                console.print(f"  [yellow]Planning error: {r}[/yellow]")
                continue
            page_url, plan = r
            plans[page_url] = plan
            self.attack_plans.append(plan)

        # Print all plans summary (terminal log)
        if plans:
            self._print_all_plans(plans)

        # ── Confirm / edit plans ─────────────────────────────────────
        # When the web dashboard is active, send plans there and wait for
        # the operator to click "Start Attack" (edits are applied below).
        # Without a dashboard, fall back to the terminal interactive editor.
        if self.monitor:
            if plans:
                console.print(
                    "\n  [bold cyan][Web Dashboard][/bold cyan] "
                    "プラン確認モーダルが開きます。ダッシュボードで確認・修正後に攻撃を開始してください。"
                )
                plans_data = self._serialize_plans(plans)
                await self.monitor.emit_plan_review(plans_data)
                edits = await self.monitor.wait_for_plan_confirm()
                if edits:
                    self._apply_plan_edits(plans, edits)
                    console.print("  [dim]プラン編集が適用されました。[/dim]")
            else:
                # Empty plans on a dashboard run: nothing to confirm.
                # Never block on input() — the WebUI has no way to respond.
                await self.monitor.emit_status(
                    "攻撃プランが生成できませんでした (入力フィールド無し)。次フェーズに進みます。"
                )
                console.print(
                    "  [dim]No plans to review — continuing without confirmation.[/dim]"
                )
        elif self.interactive_plan:
            # Terminal fallback: show interactive editor then wait for Enter
            if plans:
                self._interactive_plan_editor(plans)
            console.print()
            console.print(
                "[bold]  Plans are ready.[/bold] "
                "Press [green]Enter[/green] to start the attack, or [red]Ctrl+C[/red] to abort."
            )
            try:
                await asyncio.get_event_loop().run_in_executor(None, input, "  → ")
            except (KeyboardInterrupt, EOFError):
                raise SystemExit("\nAborted by user.")
        elif plans:
            console.print("  [dim]Plan review skipped — non-interactive scan continues.[/dim]")

        return plans

    def _print_all_plans(self, plans: dict):
        """Print a summary table of all page attack plans."""
        t = Table(
            title="Attack Plan Summary",
            show_header=True,
            header_style="bold magenta",
            box=rbox.ROUNDED,
        )
        t.add_column("#",           justify="right",  style="dim")
        t.add_column("Page",        style="cyan",      no_wrap=False, max_width=40)
        t.add_column("Purpose",     style="white",     max_width=30)
        t.add_column("Fields",      justify="center")
        t.add_column("Top risk",    justify="center",  style="bold")
        t.add_column("Planned by",  style="dim")

        for i, (url, plan) in enumerate(plans.items(), 1):
            top = max((fp.risk_score for fp in plan.fields), default=0)
            risk_color = "red" if top >= 8 else ("yellow" if top >= 5 else "green")
            t.add_row(
                str(i),
                url[-40:] if len(url) > 40 else url,
                plan.page_purpose[:30],
                str(len(plan.fields)),
                f"[{risk_color}]{top}[/{risk_color}]",
                plan.planned_by,
            )
        console.print(t)

    # =========================================================================
    # Plan serialisation / deserialisation (web dashboard ↔ engine)
    # =========================================================================

    def _serialize_plans(self, plans: dict) -> list:
        """Convert plans dict → JSON-serialisable list for the web dashboard."""
        result = []
        for url, plan in plans.items():
            fields = []
            for fp in plan.fields:
                fields.append({
                    "name": fp.name,
                    "risk_score": fp.risk_score,
                    "priority_checks": fp.priority_checks,
                    "rationale": fp.rationale or "",
                    "is_url_param": fp.is_url_param,
                    "form_index": fp.form_index,
                    "custom_payloads": fp.custom_payloads or {},
                    "skip": False,
                })
            result.append({
                "url": url,
                "page_purpose": plan.page_purpose,
                "planned_by": plan.planned_by,
                "fields": fields,
            })
        return result

    def _apply_plan_edits(self, plans: dict, edits: dict) -> None:
        """
        Apply edits from the web dashboard back into the plan objects.

        edits format:
          {url: {field_name: {risk_score, priority_checks, custom_payloads, skip}}}
        """
        for url, field_edits in edits.items():
            plan = plans.get(url)
            if not plan:
                continue
            for fp in plan.fields:
                fe = field_edits.get(fp.name)
                if not fe:
                    continue
                if "risk_score" in fe:
                    fp.risk_score = int(fe["risk_score"])
                if "priority_checks" in fe:
                    fp.priority_checks = list(fe["priority_checks"])
                if "custom_payloads" in fe:
                    fp.custom_payloads = dict(fe["custom_payloads"])
                if fe.get("skip"):
                    fp.risk_score = 0   # score=0 causes field to be skipped

    # =========================================================================
    # Interactive Plan Editor (terminal fallback)
    # =========================================================================

    def _interactive_plan_editor(self, plans: dict) -> None:
        """
        Per-field interactive attack plan editor.
        Runs after LLM/heuristic planning, before the attack phase.
        Lets the user review, adjust, or override every field's plan.
        """
        console.print(Rule("[bold yellow] 手動プラン編集モード [/bold yellow]", style="yellow"))
        console.print(
            "  各フィールドのリスク・検査項目・カスタムペイロードを設定できます。\n"
            "  [dim]操作: [Enter] 確定  [番号] フィールド編集  [s] ページスキップ  [a] 全ページ確定[/dim]"
        )

        page_list = list(plans.items())
        for page_idx, (url, plan) in enumerate(page_list):
            if not plan.fields:
                continue

            while True:
                console.print(f"\n  [bold cyan]ページ {page_idx + 1}/{len(page_list)}:[/bold cyan] {url}")
                console.print(f"  [dim]目的:[/dim] {plan.page_purpose}  [dim]計画:[/dim] {plan.planned_by}")
                self._print_editable_fields(plan)

                try:
                    raw = input(
                        "\n  操作 → [Enter]=確定  [番号]=編集  [s]=スキップ  [a]=全確定: "
                    ).strip().lower()
                except (KeyboardInterrupt, EOFError):
                    raise SystemExit("\nAborted.")

                if raw == "a":
                    console.print("  [green]全ページを確定しました。[/green]")
                    return
                if raw == "s":
                    for fp in plan.fields:
                        fp.priority_checks = []
                        fp.risk_score = 0
                    console.print(f"  [yellow]  ページをスキップします。[/yellow]")
                    break
                if raw == "":
                    break
                if raw.isdigit():
                    idx = int(raw) - 1
                    sorted_fields = plan.sorted_fields()
                    if 0 <= idx < len(sorted_fields):
                        self._edit_field(sorted_fields[idx])
                    else:
                        console.print(f"  [red]  1〜{len(sorted_fields)} の番号を入力してください。[/red]")

    def _print_editable_fields(self, plan) -> None:
        """Print a numbered table of fields for interactive editing."""
        t = Table(show_header=True, header_style="bold", box=rbox.SIMPLE, padding=(0, 1))
        t.add_column("#",         justify="right", style="dim", width=3)
        t.add_column("フィールド",  style="cyan",   no_wrap=True, max_width=20)
        t.add_column("種別",       style="dim",    width=8)
        t.add_column("Risk",       justify="center", width=5)
        t.add_column("検査項目",   style="green",  max_width=30)
        t.add_column("PL",         justify="right", style="dim", width=4)

        for i, fp in enumerate(plan.sorted_fields(), 1):
            if fp.risk_score == 0:
                risk_disp = "[dim]SKIP[/dim]"
            else:
                rc = "red" if fp.risk_score >= 8 else ("yellow" if fp.risk_score >= 5 else "green")
                risk_disp = f"[{rc}]{fp.risk_score}[/{rc}]"
            kind = "URL param" if fp.is_url_param else "form"
            pl_count = sum(len(v) for v in fp.custom_payloads.values()) if fp.custom_payloads else 0
            checks_str = " · ".join(fp.priority_checks[:4]) if fp.priority_checks else "[dim]—[/dim]"
            t.add_row(str(i), fp.name, kind, risk_disp, checks_str, str(pl_count) if pl_count else "-")
        console.print(t)

    def _edit_field(self, fp) -> None:
        """Interactive editor for a single FieldAttackPlan."""
        console.print(f"\n  [bold]編集中:[/bold] [cyan]{fp.name}[/cyan]"
                      f"  [dim](現在: risk={fp.risk_score}, checks={' '.join(fp.priority_checks)})[/dim]")

        # ── Risk score ───────────────────────────────────────────────
        try:
            r = input(f"  リスクスコア (1-10) [{fp.risk_score}]: ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        if r.isdigit():
            fp.risk_score = max(1, min(10, int(r)))

        # ── Checks ───────────────────────────────────────────────────
        console.print("  実施する検査:")
        for i, c in enumerate(self.checks, 1):
            mark = "[green]●[/green]" if c in fp.priority_checks else "[dim]○[/dim]"
            console.print(f"    [{i:>2}] {mark} {c}")

        try:
            c_raw = input(
                f"  番号 (スペース区切り) / 'all' / 'none'  [現在: {' '.join(fp.priority_checks) or '—'}] [Enter=変更なし]: "
            ).strip().lower()
        except (KeyboardInterrupt, EOFError):
            c_raw = ""

        if c_raw == "all":
            fp.priority_checks = list(self.checks)
        elif c_raw == "none":
            fp.priority_checks = []
            fp.risk_score = 0
            console.print("  [yellow]  スキップに設定しました。[/yellow]")
            return
        elif c_raw:
            selected = []
            for token in c_raw.split():
                if token.isdigit() and 1 <= int(token) <= len(self.checks):
                    selected.append(self.checks[int(token) - 1])
                elif token in self.checks:
                    selected.append(token)
            if selected:
                fp.priority_checks = selected

        # ── Custom payloads ──────────────────────────────────────────
        try:
            add_pl = input("  カスタムペイロードを追加しますか? (y/N): ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            add_pl = ""

        if add_pl in ("y", "yes") and fp.priority_checks:
            # Choose check type
            console.print("  どの検査用ペイロードを追加しますか?")
            for i, c in enumerate(fp.priority_checks, 1):
                console.print(f"    [{i}] {c}")
            try:
                ct_raw = input(f"  番号 [{fp.priority_checks[0]}]: ").strip()
            except (KeyboardInterrupt, EOFError):
                ct_raw = ""
            check_type = fp.priority_checks[0]
            if ct_raw.isdigit() and 1 <= int(ct_raw) <= len(fp.priority_checks):
                check_type = fp.priority_checks[int(ct_raw) - 1]
            elif ct_raw in self.checks:
                check_type = ct_raw

            console.print(f"  [dim]{check_type} 用ペイロードを1行ずつ入力 (空行で終了)[/dim]")
            new_payloads: list = []
            while True:
                try:
                    p = input("    > ").strip()
                except (KeyboardInterrupt, EOFError):
                    break
                if not p:
                    break
                new_payloads.append(p)

            if new_payloads:
                existing = fp.custom_payloads.get(check_type, [])
                fp.custom_payloads[check_type] = existing + new_payloads
                console.print(f"  [green]  ✔ {len(new_payloads)} 件のペイロードを追加しました[/green]")

        # ── Summary ──────────────────────────────────────────────────
        pl_total = sum(len(v) for v in fp.custom_payloads.values())
        console.print(
            f"  [green]  ✔ 更新:[/green] risk={fp.risk_score}  "
            f"checks={' · '.join(fp.priority_checks) or '—'}  "
            f"custom_payloads={pl_total}件"
        )

    # =========================================================================
    # Phase 3: Attack
    # =========================================================================

    def _snapshot_external_scripts(self, html: str, base_url: str) -> dict:
        """クロール時点の network 捕捉から、このページが参照する外部スクリプト
        本文を ``{絶対URL: body}`` で抜き出す。

        攻撃フェーズでは ``navigate()`` が network をクリアするため、ここで本文を
        確保しておくと js_static が別ページ遷移後でも外部 JS を解析できる。
        失敗・未捕捉は単に空のまま（best-effort）。
        """
        from urllib.parse import urljoin
        from wscan import js_analysis

        network = getattr(self.browser, "network", None)
        if not network or not hasattr(network, "latest_for_url"):
            return {}
        out: dict = {}
        for src in js_analysis.extract_external_script_srcs(html or ""):
            abs_url = urljoin(base_url, src)
            if abs_url in out:
                continue
            try:
                # 完全一致（クエリ込み）を優先。キャッシュバスター付きで同一パス
                # 別クエリ（/app.js?v=public と ?v=admin）の取り違えを防ぐ。
                pair = network.latest_for_url(abs_url, match_query=True)
                if not pair:
                    pair = network.latest_for_url(abs_url, match_query=False)
            except Exception:
                pair = None
            body = (pair or {}).get("response", {}).get("body", "") if pair else ""
            if body and body.strip():
                out[abs_url] = body
        return out

    async def _phase_attack(self, pages: list, plans: dict):
        """
        Execute attacks guided by the plan.

        Serial mode (concurrency=1):  same sequential flow as before.
        Concurrent mode (concurrency>1): worker pool — each worker holds its
        own Playwright page (WorkerBrowser) and processes pages in parallel.
        Within a single page, fields are still tested sequentially so that
        form state is consistent.
        """
        console.print(Rule("[bold red] Phase 3 / 4  ·  Attack [/bold red]", style="red"))

        if self.concurrency > 1:
            console.print(
                f"  [bold cyan][Concurrent][/bold cyan] "
                f"{self.concurrency} parallel worker(s)"
            )
            await self._phase_attack_concurrent(pages, plans)
        else:
            await self._phase_attack_serial(pages, plans)

        # Phase 3c: chain / stored vulnerability detection (runs after ALL pages attacked)
        chain_findings = await self.chain_scanner.run(
            source_pages=[p for p in pages if p.forms],
            observation_pages=pages,
            attack_plans=plans,
            max_forms=self.max_forms,
        )
        for cf in chain_findings:
            self._record_finding(cf.finding, source=f"chain:{cf.source_url}→{cf.trigger_url}")

    # ── Serial attack (original flow) ─────────────────────────────────────

    async def _phase_attack_serial(self, pages: list, plans: dict):
        # Reset progress counters at the start of each attack phase
        self.completed_fields = 0
        self.total_fields = 0
        attacked_urls: set = set()

        for page in pages:
            try:
                await self.controller.checkpoint()
            except SkipPage:
                console.print(f"  [yellow][Intervention] Skipping page: {page.url}[/yellow]")
                continue

            attacked_urls.add(page.url)
            findings_before = len(self.all_findings)
            if self.monitor:
                await self.monitor.emit_url_start(page.url, len(pages))
            await self._attack_one_page(page, plans)
            if self.monitor:
                await self.monitor.emit_url_complete(page.url)

            new_findings = self.all_findings[findings_before:]
            if new_findings and self.use_planner:
                remaining = [p for p in pages if p.url not in attacked_urls]
                if remaining:
                    self._adaptive_rerank(new_findings, remaining, plans)

    # ── Concurrent attack ─────────────────────────────────────────────────

    async def _phase_attack_concurrent(self, pages: list, plans: dict):
        """
        Distribute pages across N WorkerBrowser instances.
        Reset progress counters so dashboard starts from 0 each time.

        Concurrency model:
        - N worker coroutines run as asyncio Tasks (N = self.concurrency).
        - Each worker picks a page from the queue, sets _CURRENT_WORKER
          in its task-local ContextVar, runs _attack_one_page(), then
          returns the worker to the pool.
        - Since asyncio is cooperative (not preemptive) and each page-attack
          is a single sequential coroutine, there are no data races on
          per-worker browser state.
        - The shared findings list and scanned_forms set are guarded by
          asyncio Locks at yield points.
        """
        # Reset progress counters at the start of each attack phase
        self.completed_fields = 0
        self.total_fields = 0
        # Create (concurrency-1) additional worker pages; worker[0] = main page.
        extra_workers = []
        for i in range(self.concurrency - 1):
            try:
                w = await self._browser.create_worker()
                extra_workers.append(w)
                console.print(f"  [dim]Worker {i + 2} page created[/dim]")
            except Exception as e:
                console.print(f"  [yellow]Could not create worker {i + 2}: {e}[/yellow]")

        # Worker pool queue: None = use main browser, WorkerBrowser = use worker
        worker_pool: asyncio.Queue = asyncio.Queue()
        await worker_pool.put(None)          # slot 0 → main _browser
        for w in extra_workers:
            await worker_pool.put(w)

        page_queue: asyncio.Queue = asyncio.Queue()
        for p in pages:
            await page_queue.put(p)

        # Shared abort signal — any worker that catches AbortScan sets this
        # so that other workers stop starting new pages.
        _abort_event = asyncio.Event()
        tasks: list = []  # populated below; referenced inside worker_loop

        async def worker_loop():
            while True:
                if _abort_event.is_set():
                    return
                try:
                    page = page_queue.get_nowait()
                except asyncio.QueueEmpty:
                    return

                worker_browser = await worker_pool.get()
                token = _CURRENT_WORKER.set(worker_browser)
                skip_this_page = False
                try:
                    try:
                        await self.controller.checkpoint()
                    except SkipPage:
                        console.print(
                            f"  [yellow][Intervention] Skipping page: {page.url}[/yellow]"
                        )
                        skip_this_page = True
                    if not skip_this_page:
                        if self.monitor:
                            await self.monitor.emit_url_start(page.url, page_queue.qsize() + 1)
                        await self._attack_one_page(page, plans)
                        if self.monitor:
                            await self.monitor.emit_url_complete(page.url)
                except AbortScan:
                    _abort_event.set()
                    raise
                except Exception as exc:
                    console.print(f"  [yellow][Worker] Error on {page.url}: {exc}[/yellow]")
                finally:
                    _CURRENT_WORKER.reset(token)
                    await worker_pool.put(worker_browser)
                    page_queue.task_done()

        n_slots = 1 + len(extra_workers)
        tasks[:] = [asyncio.create_task(worker_loop()) for _ in range(n_slots)]
        try:
            # return_exceptions=True so one AbortScan doesn't cancel other tasks mid-page;
            # they will exit cleanly at the top-of-loop _abort_event check.
            results = await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            # Even if gather() propagates a cancellation, try to close every
            # worker so their browser contexts don't leak. Exceptions from one
            # worker must not prevent the next one from closing.
            for w in extra_workers:
                try:
                    await w.close()
                except Exception as _close_exc:
                    console.print(
                        f"  [yellow][Worker cleanup] close() failed: {_close_exc}[/yellow]"
                    )

        # Propagate AbortScan to the caller (_phase_attack → run)
        if _abort_event.is_set():
            raise AbortScan()

    # ── SQLi auth-bypass signal ───────────────────────────────────────────

    def signal_auth_bypass(self, login_url: str, payload: str, post_url: str) -> None:
        """
        Called by SQLiScanner when a payload successfully bypasses authentication.
        Records the bypass event and schedules a post-authentication re-crawl
        (executed after Phase 3 completes).
        """
        if not self.auth_bypass_detected:
            self.auth_bypass_detected = True
            self.auth_bypass_login_url = login_url
            self.auth_bypass_post_url = post_url
            console.print(
                f"\n  [bold red][SQLi Auth Bypass][/bold red] "
                f"Login bypassed at [cyan]{login_url}[/cyan] "
                f"with payload [yellow]{payload!r}[/yellow]\n"
                f"  Redirected to: [green]{post_url}[/green]\n"
                f"  → Post-authentication re-crawl scheduled for after Phase 3."
            )
            # Monitor notification is done lazily at async context (see _phase_crawl_postauth)

    # ── Crawl review (interactive pause between crawl and plan) ───────────

    async def _phase_crawl_review(self, pages: list) -> list:
        """
        Pause between crawl and plan phases so the operator can review the
        discovered pages on the screen-transition diagram (dashboard 巡回マップ),
        request a re-crawl, add manually-recorded URLs, or proceed to the attack
        phase.  Only an explicit "recrawl" command loops back to crawl; "continue"
        always proceeds (so the review never re-appears after the operator starts
        the scan).  Repeats until the operator clicks "continue" / "cancel" (or the
        review times out).
        """
        current = list(pages)
        # Track scenarios already merged so re-crawl loops do not duplicate them.
        applied_flow_sigs: set[str] = set()
        while True:
            pages_data = [
                {
                    "url": p.url,
                    "depth": p.depth,
                    "forms": len(p.forms or []),
                    "params": len(p.url_params or []),
                    # Rich detail for the manual scenario builder: form actions and
                    # their input fields so the operator can compose steps visually.
                    "param_names": list(p.url_params or []),
                    "form_details": [
                        {
                            "action": (f.get("action") or p.url),
                            "method": (f.get("method") or "get"),
                            "fields": [
                                {
                                    "name": (inp.get("name") or inp.get("id") or ""),
                                    "type": (inp.get("type") or "text"),
                                }
                                for inp in (f.get("inputs") or [])
                                if (inp.get("name") or inp.get("id"))
                            ],
                        }
                        for f in (p.forms or [])
                    ],
                }
                for p in current
            ]
            console.print(
                f"\n  [bold cyan][Crawl Review][/bold cyan] "
                f"{len(current)} 画面を巡回しました。ダッシュボードで確認してください。"
            )
            await self.monitor.emit_status(
                f"巡回完了: {len(current)} 画面。ダッシュボードで確認してください。",
                "running",
            )
            await self.monitor.emit_crawl_review(pages_data)
            action = await self.monitor.wait_for_crawl_review()
            command = (action.get("command") or "continue").lower()

            extra_urls = [
                u.strip() for u in (action.get("extra_urls") or [])
                if isinstance(u, str) and u.strip().startswith(("http://", "https://"))
            ]
            # 追加URLは除外パターンに合致するものを除いてシードに登録
            extra_urls = [
                u for u in extra_urls
                if self._is_access_allowed_url(u) and not self._is_url_excluded(u)
            ]
            for eu in extra_urls:
                if eu not in self.visited_urls:
                    self.visited_urls.add(eu)

            manual_file = (action.get("manual_crawl_file") or "").strip()
            if manual_file:
                self.manual_crawl_path = manual_file

            # Manual attack scenarios composed in the dashboard builder. Merge any
            # newly-defined scenarios into the flows executed before each attack,
            # deduplicating so re-crawl iterations do not register them twice.
            for raw_flow in (action.get("flows") or []):
                try:
                    sig = json.dumps(raw_flow, sort_keys=True, ensure_ascii=False)
                except (TypeError, ValueError):
                    continue
                if sig in applied_flow_sigs:
                    continue
                applied_flow_sigs.add(sig)
                try:
                    self.flows.append(ScanFlow.from_dict(raw_flow))
                    console.print(
                        f"  [cyan][Crawl Review][/cyan] 手動シナリオを追加: "
                        f"{raw_flow.get('name', 'scenario')} "
                        f"({len(raw_flow.get('steps') or [])} ステップ)"
                    )
                except Exception as exc:
                    console.print(f"  [yellow][Crawl Review] シナリオ取り込み失敗: {exc}[/yellow]")

            if _crawl_review_wants_recrawl(command):
                console.print(
                    f"  [cyan][Crawl Review][/cyan] 再巡回を実行 "
                    f"(+{len(extra_urls)} URL, manual={'on' if manual_file else 'off'})"
                )
                await self.monitor.emit_status("再巡回中...", "running")
                # Seed the new crawl with the user-supplied URLs so they are
                # actually visited even if the previous crawl already enqueued
                # the application root.
                prev_seed = list(self.seed_urls)
                if extra_urls:
                    self.seed_urls = list({*prev_seed, *extra_urls})
                try:
                    additional = await self._phase_crawl()
                finally:
                    self.seed_urls = prev_seed
                # Merge new pages, deduplicating by URL.
                seen = {p.url for p in current}
                for p in additional:
                    if p.url not in seen:
                        current.append(p)
                        seen.add(p.url)
                continue

            if command == "cancel":
                console.print("  [yellow][Crawl Review][/yellow] 操作者が検査を中断しました。")
                raise AbortScan("crawl review cancelled")

            return current

    # ── Post-authentication re-crawl ──────────────────────────────────────

    async def _phase_crawl_postauth(self) -> list:
        """
        Re-crawl the application with the authenticated session gained via SQL
        injection auth bypass.

        Key difference from the initial crawl: we re-visit ALL pages regardless of
        whether they were visited before authentication.  Pages that previously just
        returned the login redirect may now show actual authenticated content (forms,
        data) that must be scanned.

        Deduplication is only within this crawl pass (auth_visited), NOT against
        self.visited_urls.  A page whose content changed after authentication is
        treated as new and re-added to new_pages for attack.
        """
        console.print(Rule(
            "[bold red] Phase 3c  ·  Post-Auth Crawl (SQLi Bypass) [/bold red]",
            style="red"
        ))
        console.print(
            "  [bold red]Session obtained via SQL injection authentication bypass.[/bold red]\n"
            f"  Re-crawling authenticated surface from "
            f"[cyan]{self.target_url}[/cyan]  depth={self.depth}\n"
        )
        if self.monitor:
            await self.monitor.emit_status(
                "Post-auth crawl: re-crawling authenticated surface (SQLi bypass)", "running"
            )

        # Navigate to target URL with authenticated session to find the landing page
        # (e.g., target is /login but authenticated session redirects to /dashboard)
        await self._browser.navigate(self.target_url, retries=self.navigation_retries)
        landing_url = self._browser.page.url.rstrip("/")

        # If we landed on the login page, session may have expired — try to re-login.
        # Unless the target itself is the login page (then staying on it is expected).
        if (
            self.relogin_on_expiry
            and self._browser.is_on_login_page(self.login_url)
            and not self._is_login_target_url(self.target_url)
        ):
            console.print("  [yellow][Post-Auth] Session appears expired — re-authenticating …[/yellow]")
            if self.login_url and self._browser.auth_user:
                ok = await self._browser.auto_login(
                    self.login_url,
                    user_field=self.login_user_field,
                    pass_field=self.login_pass_field,
                    success_indicator=self.login_success_indicator,
                )
                if not ok:
                    console.print(
                        "  [red][Post-Auth] Re-authentication failed — cannot crawl authenticated surface.[/red]"
                    )
                    return []
                await self._sync_cookies_from_browser(self._browser)
                landing_url = self._browser.page.url.rstrip("/")

        new_pages: list = []
        # auth_visited: only prevents re-queueing within THIS crawl (not against pre-auth crawl)
        auth_visited: set = set()
        queue: deque = deque()

        for seed in {landing_url, self.target_url}:
            if seed and seed not in auth_visited and not self._is_url_excluded(seed):
                auth_visited.add(seed)
                queue.append((seed, 0, None))

        while queue:
            # 初回 crawl と同様、post-auth 再クロール中も停止(abort)/一時停止を尊重する。
            await self.controller.wait_if_paused_or_abort()

            url, depth, parent_url = queue.popleft()

            if self._is_url_excluded(url):
                continue

            console.print(
                f"  [dim][Post-Auth][/dim] Crawling ({depth + 1}/{self.depth}): {url}"
            )
            if self.monitor:
                await self.monitor.emit_page_start(url)

            success = await self._browser.navigate(url, retries=self.navigation_retries)
            if not success:
                console.print(f"  [yellow]  ✘ could not load[/yellow]")
                self._record_unscannable_url(url)
                continue

            # Check actual URL after navigation (may redirect)
            actual_url = self._browser.page.url.rstrip("/")

            # If redirected to login, session expired mid-crawl — unless this URL
            # is the login page itself, which is a legitimate page to crawl.
            if (
                self._browser.is_on_login_page(self.login_url)
                and not self._is_login_target_url(url)
            ):
                console.print(
                    "  [yellow][Post-Auth] Redirected to login — session expired.[/yellow]"
                )
                break

            try:
                html = await self._browser.page.content()
            except Exception:
                html = ""

            forms = await self._browser.find_forms()
            url_params = self._merge_url_params(await self._browser.get_url_params(), url)
            screenshot_b64 = await self._browser.screenshot_b64(
                f"Post-Auth Crawl: {actual_url}"
            )

            was_known = url in self.visited_urls or actual_url in self.visited_urls

            via = self._transition_via.get(actual_url.split("#")[0]) or \
                self._transition_via.get(url.split("#")[0])
            self.page_graph[actual_url] = {
                "parent": parent_url,
                "screenshot_b64": screenshot_b64,
                "depth": depth,
                "via": via,
            }
            # Mark as visited so the main scanner doesn't double-count
            self.visited_urls.add(actual_url)

            input_count = (
                sum(len(f.get("inputs", [])) for f in forms) + len(url_params)
            )
            self.page_graph[actual_url].update(
                {"forms": len(forms), "inputs": input_count, "params": len(url_params)}
            )
            label = "[dim](re-crawled with auth)[/dim]" if was_known else "[green][NEW][/green]"
            console.print(
                f"    {label} "
                f"forms: {len(forms)}  "
                f"url params: {len(url_params)}  "
                f"inputs: {input_count}"
            )

            # Always add to new_pages — authenticated content may differ completely
            # from what was seen pre-auth (login form vs real page content)
            new_pages.append(
                CrawledPage(url=actual_url, html=html, forms=forms,
                            url_params=url_params, depth=depth,
                            external_scripts=self._snapshot_external_scripts(html, actual_url))
            )

            # If actual_url differs from queued url (redirect), also mark in auth_visited
            if actual_url != url.rstrip("/") and actual_url not in auth_visited:
                auth_visited.add(actual_url)

            if self.monitor:
                await self.monitor.emit_page_graph_update(
                    url=actual_url,
                    parent=parent_url,
                    depth=depth,
                    forms=len(forms),
                    inputs=input_count,
                    params=len(url_params),
                    status="done",
                    via=via,
                    screenshot_b64=screenshot_b64,
                )

            # BFS: collect links from actual page
            if depth + 1 < self.depth:
                try:
                    link_entries = await self._browser.collect_links_rich(actual_url, same_domain=True)
                except Exception:
                    link_entries = []
                url_cap = max(200, self.depth * 50)
                for entry in link_entries:
                    link = entry["url"]
                    clean = link.split("#")[0].split("?")[0]
                    if len(auth_visited) >= url_cap:
                        break
                    if clean not in auth_visited and not self._is_url_excluded(clean):
                        auth_visited.add(clean)
                        self._transition_via.setdefault(clean, {
                            "text": entry.get("text", ""),
                            "selector": entry.get("selector", ""),
                            "rect": entry.get("rect"),
                            "viewport": entry.get("viewport"),
                        })
                        queue.append((clean, depth + 1, actual_url))

        total_inputs = sum(
            sum(len(f.get("inputs", [])) for f in p.forms) + len(p.url_params)
            for p in new_pages
        )
        console.print(
            f"\n  [bold green]Post-Auth Crawl complete[/bold green]  "
            f"[cyan]{len(new_pages)}[/cyan] page(s) · "
            f"[cyan]{total_inputs}[/cyan] input(s) discovered\n"
        )
        return new_pages

    # ── Single-page attack (shared by serial and concurrent modes) ────────

    async def _ensure_authenticated(self, intended_url: str = "") -> bool:
        """
        Detect session expiry (redirect to login page) and re-authenticate.
        Called before attacking each page.  Returns True if session is valid
        (or if no auto-login is configured).

        When *intended_url* is the login page itself we are deliberately about to
        attack the login form, so a re-login (which would navigate away) is
        suppressed.
        """
        br = self.browser  # context-aware: returns worker in concurrent mode
        if not self.login_url and not br.auth_user:
            return True
        # --no-relogin（relogin_on_expiry=False）のときは、セッション失効を検知しても
        # 自動再ログインしない。利用者が保とうとした対象状態を勝手に変えないため、
        # 新フラグをこの既存パスでも尊重する。
        if not self.relogin_on_expiry:
            return True
        if self._is_login_target_url(intended_url):
            return True
        if br.is_on_login_page(self.login_url):
            console.print(
                "  [yellow][Auth] Session expired — re-authenticating...[/yellow]"
            )
            if self.monitor:
                await self.monitor.emit_status("Session expired — re-authenticating", "running")
            success = await br.auto_login(
                self.login_url,
                user_field=self.login_user_field,
                pass_field=self.login_pass_field,
                success_indicator=self.login_success_indicator,
            )
            if success:
                console.print("  [green][Auth] Re-login successful.[/green]")
                await self._sync_cookies_from_browser(br)
            else:
                console.print("  [yellow][Auth] Re-login may have failed — continuing.[/yellow]")
            return success
        return True

    async def _scan_login_form_preauth(self) -> None:
        """Capture and attack the login form while still unauthenticated.

        Runs BEFORE auto-login. Apps that redirect authenticated users away from
        the login page would otherwise hide the form entirely, so the login form
        (reflected XSS in the username/error message, SQLi auth bypass, etc.)
        must be observed and tested in a logged-out context. Marks the login URL
        as visited so the authenticated crawl does not re-record post-login
        content under it.
        """
        if not (self.login_url and self._is_attack_target_url(self.login_url)):
            return
        login_seed = self.login_url.rstrip("/")
        if self._is_url_excluded(login_seed):
            return

        console.print(
            Rule(
                "[bold magenta] Pre-Auth · Login Form Inspection [/bold magenta]",
                style="magenta",
            )
        )
        console.print(
            f"  [dim]未認証コンテキストでログインフォームを検査:[/dim] {login_seed}"
        )

        if not await self._browser.navigate(login_seed, retries=self.navigation_retries):
            console.print("  [yellow]  ✘ ログインページを読み込めませんでした[/yellow]")
            self._record_unscannable_url(
                login_seed,
                note="Pre-auth login page load failed: "
                + self._navigation_failure_note(),
            )
            return

        try:
            html = await self._browser.page.content()
        except Exception:
            html = ""
        forms = await self._browser.find_forms()
        url_params = self._merge_url_params(
            await self._browser.get_url_params(), login_seed
        )

        if not forms and not url_params:
            console.print(
                "  [dim]ログインページに入力フォームが見つかりませんでした。[/dim]"
            )
            return

        console.print(
            f"  [cyan]{len(forms)}[/cyan] form(s) · "
            f"[cyan]{len(url_params)}[/cyan] URL param(s) を検出"
        )
        page = CrawledPage(
            url=login_seed, html=html, forms=forms, url_params=url_params, depth=0,
            external_scripts=self._snapshot_external_scripts(html, login_seed),
        )
        self.page_graph.setdefault(
            login_seed, {"parent": None, "screenshot_b64": "", "depth": 0}
        )

        await self._attack_one_page(page, {})

        # Prevent the authenticated crawl/attack from re-visiting the login page
        # (which, on redirect-on-auth apps, would only capture post-login content).
        self.visited_urls.add(login_seed)

    async def _attack_one_page(self, page: CrawledPage, plans: dict):
        """
        Run all checks on a single crawled page.
        Uses ``self.browser`` which transparently returns the worker's browser
        when called from inside a concurrent worker task.
        """
        # ── セッション失効チェック（全検査の前に一度）────────────────────
        # 長時間スキャンでセッションが切れると以降が全てログイン画面/401 に化け、
        # 検出力が静かにゼロになる。ページ単位検査（graphql/cache/proto/mass 等）も
        # 失効レスポンスに当ててしまわないよう、page-level・field 双方の前に実行する。
        await self._maybe_relogin_for_page(page.url)
        # 再ログインが起きなくても、この page.url 宛に送られる Cookie を self.cookies へ
        # 同期する。domain/path フィルタにより target_url 同期では Path=/admin の
        # セッション Cookie が落ちるため、graphql/cache/proto の httpx 検査が認証 Cookie
        # 無しで /admin を叩かないよう、ページ毎にそのパス宛 Cookie を採り直す。
        # ただし self.cookies はエンジン共有なので、並列(--concurrency>1)では別ワーカーの
        # 検査中に書き換える競合になる。直列時のみ行う（並列は既存の共有 cookie 前提）。
        if (getattr(self, "concurrency", 1) or 1) <= 1:
            try:
                await self._sync_cookies_from_browser(self.browser, for_url=page.url)
            except Exception:
                pass

        # ── Page-level checks (header inspection, clickjacking, session, etc.) ──
        for check_name, scanner in self.scanners.items():
            # API テンプレート専用スキャナ（mass_assignment）はここで動かさない。
            # body-operation の URL は crawl キューにも入るため、GET 可能なら本ループと
            # _run_api_template_checks の両方で状態変更系プローブを二重送信し、resume も
            # 重複する。これらは checkpoint を刻む _run_api_template_checks に一本化する。
            if check_name in _API_TEMPLATE_ONLY_CHECKS:
                continue
            # 再開: 済みの page-level 単位 (url,"(page)",check) は飛ばす。intrusive な
            # page-level プローブ（proto の JSON POST、graphql コスト探索）を resume で
            # 再送しないため。exact URL で刻む（origin だと別 URL を取りこぼす）。
            cp_url = _page_check_cp_url(check_name, page.url)
            if self._checkpoint_is_done(cp_url, "(page)", 0, check_name):
                continue
            page_errored = False
            try:
                if hasattr(scanner, "scan_page_context"):
                    page_findings = await scanner.scan_page_context(page)
                else:
                    page_findings = await scanner.scan_page(page.url)
                for f in (page_findings or []):
                    self._record_finding(f, source="page-level")
            except Exception as e:
                page_errored = True
                console.print(f"  [yellow]Page-level ({check_name}): {e}[/yellow]")
            if not page_errored:
                self._checkpoint_mark_done(cp_url, "(page)", 0, check_name)
        # page-level のみのページ（フォーム/URLパラメータ無し）でも進捗を永続化する。
        self._save_checkpoint()

        if not page.forms and not page.url_params:
            return

        # ── Run multi-step attack flows that target this page ─────────────
        matched_flow = None
        for flow in self.flows:
            if flow.steps:
                # The last step action=navigate|attack defines the target URL
                last_nav = next(
                    (s for s in reversed(flow.steps) if s.action == "navigate"),
                    None,
                )
                if last_nav and last_nav.url.rstrip("/") == page.url.rstrip("/"):
                    matched_flow = flow
                    break
        if matched_flow:
            console.print(
                f"\n  [cyan][Flow] Pre-attack flow:[/cyan] {matched_flow.name}"
            )
            # Use context-aware browser (worker in concurrent mode)
            await FlowRunner(self.browser).run(matched_flow)
            # Verify the browser ended on the intended target page.
            # A failed step in the flow may leave the browser on the wrong URL.
            try:
                actual_url = self.browser.page.url.rstrip("/")
                if actual_url != page.url.rstrip("/"):
                    console.print(
                        f"  [yellow][Flow] Ended on {actual_url}, "
                        f"re-navigating to {page.url}[/yellow]"
                    )
                    if not await self.browser.navigate(page.url, retries=self.navigation_retries):
                        self._record_unscannable_url(
                            page.url,
                            note="Pre-attack flow ended on a different URL and re-navigation failed: "
                            + self._navigation_failure_note(),
                        )
                        return
            except Exception:
                if not await self.browser.navigate(page.url, retries=self.navigation_retries):
                    self._record_unscannable_url(
                        page.url,
                        note="Pre-attack flow recovery navigation failed: "
                        + self._navigation_failure_note(),
                    )
                    return
        else:
            # ── Re-authenticate if session expired ───────────────────────
            await self._ensure_authenticated(page.url)
            # Navigate back to page for form interaction
            success = await self.browser.navigate(page.url, retries=self.navigation_retries)
            if not success:
                self._record_unscannable_url(
                    page.url,
                    note="Attack phase could not load page: " + self._navigation_failure_note(),
                )
                return

        # CTF: re-check page after navigating (dynamic content may differ from crawl)
        if self.flag_finder:
            try:
                attack_html = await self.browser.page.content()
                self._check_page_for_flags(attack_html, page.url)
            except Exception:
                pass

        console.print(f"\n  [bold]Attacking:[/bold] {page.url}")
        plan = plans.get(page.url)

        # Phase 3a + 3b: individual field scan + adaptive AI
        await self._attack_page(page, plan)

        # Phase 3d: multi-parameter simultaneous injection
        await self._phase_multi_param(page, plan)

    async def _attack_page(self, page: CrawledPage, plan: Optional[PageAttackPlan]):
        """Run all scanners on all fields of a single page."""
        # 除外URLが page.url の場合は丸ごとスキップ（防御的: 通常は crawl で
        # 弾かれるが、HAR/手動巡回/シードから直接到達した場合への保険）
        if self._is_url_excluded(page.url):
            console.print(
                f"  [dim yellow]Skip (excluded URL):[/dim yellow] {page.url}"
            )
            return
        all_forms = page.forms[:self.max_forms]

        # ── Registration form exclusion ───────────────────────────────
        if self.skip_registration:
            # Also skip the whole page if its URL looks like a registration page
            if self._is_registration_url(page.url):
                console.print(
                    f"  [dim yellow]Skip (registration page):[/dim yellow] {page.url}"
                )
                return
            forms = []
            for form in all_forms:
                if self._is_registration_form(form):
                    action_hint = urlparse(form.get("action", "")).path or page.url
                    console.print(
                        f"  [dim yellow]Skip (registration form):[/dim yellow] "
                        f"action={action_hint}"
                    )
                else:
                    forms.append(form)
        else:
            forms = all_forms

        # ── Exclude forms whose action URL matches exclude_urls ───────
        # action="/logout" 等の破壊系エンドポイントを攻撃しないための保険。
        if self.exclude_urls:
            kept = []
            for form in forms:
                action_url = self._form_action_url(form, page.url)
                if self._is_url_excluded(action_url):
                    console.print(
                        f"  [dim yellow]Skip (excluded action):[/dim yellow] {action_url}"
                    )
                    continue
                kept.append(form)
            forms = kept

        # Build ordered field list
        field_queue: list = []
        for fi, form in enumerate(forms):
            for inp in form.get("inputs", []):
                field_queue.append((fi, inp, False))
        for param in page.url_params:
            field_queue.append((0, {"name": param, "type": "text"}, True))

        # Sort by risk score from the plan
        if plan:
            def _sort_key(item):
                fi, inp, is_url = item
                fp = plan.get_field_plan(inp.get("name", ""), fi, is_url)
                return -(fp.risk_score if fp else 5)
            field_queue.sort(key=_sort_key)

        skipped = sum(
            1 for _, inp, _ in field_queue
            if inp.get("name", "").lower() in self.exclude_fields
        )
        console.print(
            f"  [cyan]{len(forms)}[/cyan] form(s) · "
            f"[cyan]{len(page.url_params)}[/cyan] URL param(s)"
            + (f" · [yellow]{skipped} excluded[/yellow]" if skipped else "")
        )
        # NOTE: total_fields is incremented inside the scanned_forms lock below,
        # so it only counts fields that are actually going to be scanned.
        # This prevents overcounting when multiple concurrent workers process
        # pages with overlapping URL params.

        for fi, field, is_url_param in field_queue:
            field_name = field.get("name", f"field_{fi}")
            key = (f"{page.url}||url_param||{field_name}" if is_url_param
                   else f"{page.url}||{fi}||{field_name}")
            # Guard scanned_forms with a lock so concurrent workers don't
            # both pick up the same field simultaneously.
            async with self._scanned_forms_lock:
                if key in self.scanned_forms:
                    continue
                self.scanned_forms.add(key)
                self.total_fields += 1  # Only count fields we'll actually scan

            if field_name.lower() in self.exclude_fields:
                console.print(f"  [dim]Skip excluded: {field_name}[/dim]")
                continue

            # Intervention checkpoint — allows skip-field / skip-page / abort
            try:
                await self.controller.checkpoint()
            except SkipField:
                console.print(f"  [yellow][Intervention] Skipping field: {field_name}[/yellow]")
                continue
            except SkipPage:
                console.print(f"  [yellow][Intervention] Skipping rest of page: {page.url}[/yellow]")
                return
            # AbortScan propagates up

            field_plan = plan.get_field_plan(field_name, fi, is_url_param) if plan else None
            try:
                await self._scan_field(page.url, fi, field, is_url_param, field_plan)
            except (AbortScan, SkipPage):
                raise
            except Exception as e:
                console.print(f"  [dim red]Field scan error ({field_name}): {e}[/dim red]")
                continue

            if not is_url_param:
                if not await self.browser.navigate(page.url, retries=self.navigation_retries):
                    self._record_unscannable_url(
                        page.url,
                        field_name=field_name,
                        note="Could not restore page after field scan: "
                        + self._navigation_failure_note(),
                    )

    # =========================================================================
    # Phase 3d: Multi-parameter simultaneous injection
    # =========================================================================

    async def _phase_multi_param(self, page: CrawledPage, plan: Optional[PageAttackPlan]):
        """
        Fill ALL relevant fields in each form simultaneously with their
        respective check-type payloads and test the combined submission.

        Catches:
        - Cross-parameter WAF bypasses (each field clean alone, dangerous together)
        - Vulnerabilities that need valid companion field values to trigger
        - Concatenated rendering (multiple fields appear together on another page)
        """
        if not page.forms:
            return

        # Only run when there are forms with 2+ testable fields
        forms_to_test = [
            (fi, form) for fi, form in enumerate(page.forms[:self.max_forms])
            if len([
                inp for inp in form.get("inputs", [])
                if inp.get("name", "").lower() not in self.exclude_fields
            ]) >= 2
        ]
        if not forms_to_test:
            return

        console.print(
            f"\n  [bold magenta][MultiParam][/bold magenta] "
            f"Multi-parameter attack on {page.url}  "
            f"({len(forms_to_test)} form(s) with 2+ fields)"
        )

        xss_scanner = self.scanners.get("xss")
        sqli_scanner = self.scanners.get("sqli")

        for fi, form in forms_to_test:
            inputs = [
                inp for inp in form.get("inputs", [])
                if inp.get("name", "").lower() not in self.exclude_fields
            ]

            # Build a per-field payload map for each relevant check type
            for check_name in [c for c in ("xss", "sqli", "ssti") if c in self.scanners]:
                field_payloads: dict = {}

                for inp in inputs:
                    fname = inp.get("name", "")
                    if not fname:
                        continue

                    fp = plan.get_field_plan(fname, fi, False) if plan else None
                    # Use check if: explicitly planned OR field name heuristically relevant
                    if fp and fp.priority_checks and check_name not in fp.priority_checks:
                        continue

                    plan_payloads = (fp.custom_payloads.get(check_name) if fp else None) or []
                    defaults = self.payload_gen.default_payloads.get(check_name, [])
                    candidates = plan_payloads + [p for p in defaults if p not in plan_payloads]
                    if candidates:
                        field_payloads[fname] = candidates[0]  # pick first/best payload

                if len(field_payloads) < 2:
                    continue  # skip if only 1 field would be filled — that's already tested

                console.print(
                    f"  [dim magenta]  {check_name.upper()} × "
                    f"{len(field_payloads)} fields: "
                    f"{', '.join(field_payloads)}[/dim magenta]"
                )

                # multi-param は fill_and_submit_form_multi で直接送信し log_payload_test を
                # 通さないため、per-payload の abort フックが効かない。送信直前にここで
                # 停止(abort)/一時停止を尊重し、残りの結合 payload を送り続けないようにする。
                await self.controller.wait_if_paused_or_abort()

                ok = await self.browser.navigate(page.url, retries=self.navigation_retries)
                if not ok:
                    self._record_unscannable_url(
                        page.url,
                        field_name=f"multi[{','.join(field_payloads)}]",
                        note="Multi-parameter scan could not load page: "
                        + self._navigation_failure_note(),
                    )
                    continue
                self.browser.reset_dialog()

                source, pair = await self.browser.fill_and_submit_form_multi(fi, field_payloads)
                await asyncio.sleep(self._effective_delay)

                # CTF flag check on combined result
                if self.flag_finder and source:
                    self._check_page_for_flags(source, page.url)

                # ── XSS detection ──────────────────────────────────────
                if check_name == "xss" and xss_scanner:
                    if self.browser.dialog_fired:
                        f = await xss_scanner.record_finding(
                            url=page.url,
                            field_name=f"multi[{','.join(field_payloads)}]",
                            payload=str(field_payloads),
                            evidence=(
                                f"[MultiParam] XSS dialog triggered with simultaneous "
                                f"multi-field injection: '{self.browser.dialog_message}'"
                            ),
                            pair=pair,
                            severity="critical",
                            dialog_confirmed=True,
                            dialog_message=self.browser.dialog_message,
                        )
                        self._record_finding(f, source="multi-param")
                    elif source:
                        for fname, p in field_payloads.items():
                            reflected = xss_scanner._check_reflected(source, p)
                            if reflected:
                                f = await xss_scanner.record_finding(
                                    url=page.url,
                                    field_name=f"multi[{','.join(field_payloads)}]",
                                    payload=str(field_payloads),
                                    evidence=(
                                        f"[MultiParam] XSS reflected in combined submission "
                                        f"(field '{fname}'): '{reflected[:80]}'"
                                    ),
                                    pair=pair,
                                    severity="high",
                                )
                                self._record_finding(f, source="multi-param")
                                break

                # ── SQLi detection ─────────────────────────────────────
                elif check_name == "sqli" and sqli_scanner and source:
                    sqli_patterns = [
                        r"SQL syntax.*MySQL", r"Warning.*mysql_",
                        r"PostgreSQL.*ERROR", r"ORA-\d{5}",
                        r"SQLite.*Exception", r"ODBC.*Driver",
                        r"Microsoft.*ODBC.*SQL Server",
                        r"syntax error.*sqlite",
                        r"Unclosed quotation mark",
                    ]
                    matched = sqli_scanner.check_response_for_patterns(source, sqli_patterns)
                    if matched:
                        f = await sqli_scanner.record_finding(
                            url=page.url,
                            field_name=f"multi[{','.join(field_payloads)}]",
                            payload=str(field_payloads),
                            evidence=(
                                f"[MultiParam] SQLi error in combined submission: "
                                f"'{matched[:120]}'"
                            ),
                            pair=pair,
                            severity="high",
                        )
                        self._record_finding(f, source="multi-param")

    def _adaptive_rerank(self, new_findings: list, remaining_pages: list, plans: dict):
        """
        Elevate risk scores on remaining pages for fields matching the newly found
        vulnerability types. This allows the attack to prioritise similar targets.
        """
        affected_checks = {f.check_type for f in new_findings}
        elevated = 0
        for page in remaining_pages:
            plan = plans.get(page.url)
            if not plan:
                continue
            for fp in plan.fields:
                if any(c in affected_checks for c in fp.priority_checks):
                    old = fp.risk_score
                    fp.risk_score = min(10, fp.risk_score + 2)
                    if fp.risk_score != old:
                        elevated += 1
        if elevated:
            checks_str = ", ".join(affected_checks)
            console.print(
                f"\n  [bold yellow][Adaptive Replan][/bold yellow] "
                f"New findings ({checks_str}) → "
                f"elevated risk on [cyan]{elevated}[/cyan] field(s) in remaining pages"
            )

    async def _scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
        field_plan: Optional[FieldAttackPlan] = None,
    ):
        """Run enabled scanners on a single field, guided by the attack plan."""
        field_name = field.get("name", "unknown")
        location = "URL param" if is_url_param else "form field"

        if field_plan and field_plan.priority_checks:
            planned = [c for c in field_plan.priority_checks if c in self.scanners]
            rest = [c for c in self.scanners if c not in set(planned)]
            ordered_checks = planned + rest
            risk_label = f"risk={field_plan.risk_score}/10"
        else:
            ordered_checks = list(self.scanners.keys())
            risk_label = "risk=?"

        console.print(
            f"  [dim]Testing {location}:[/dim] [green]{field_name}[/green] "
            f"[dim]({risk_label})[/dim]"
        )
        if field_plan and field_plan.rationale:
            console.print(f"    [dim cyan]Plan:[/dim cyan] [dim]{field_plan.rationale[:100]}[/dim]")

        # 実際に実行した（resume でスキップしなかった）チェック数と、resume で
        # 完了済みとして飛ばしたチェック数。両方 0＝このフィールドに in-scope な
        # チェックが無い（＝adaptive も走らせない）。adaptive の要否は下部で
        # 「(adaptive) 完了マーカー」と併せて判定する（abort 中断時の再開網羅性のため）。
        checks_executed = 0
        checks_skipped_done = 0
        for check_name in ordered_checks:
            scanner = self.scanners.get(check_name)
            if scanner is None:
                continue

            # 再開可能スキャン: 既に完了した (url, field, location, check) 単位は飛ばす
            if self._checkpoint_is_done(url, field_name, form_index, check_name, is_url_param):
                self._record_scan_matrix(
                    url=url,
                    field_name=field_name,
                    check_name=check_name,
                    status="skipped",
                    location=location,
                    note="Skipped — already completed in a previous run (resume).",
                )
                checks_skipped_done += 1
                continue

            # 注意: 以前はこのフィールドで critical finding が確定すると残りの
            # チェックをスキップしていた。しかし critical が過検知（false positive）
            # の場合、他の本物の脆弱性を取りこぼしてしまう。過検知の可能性がある以上、
            # 「脆弱性が見つかったから」といって他チェックを飛ばさず、全チェック種別を
            # 常に実行する（重複証跡は record_finding の dedup が抑止する）。

            # Merge plan payloads with defaults (LLM extras come first, defaults appended)
            # Use a per-task ContextVar so parallel workers never contaminate each other.
            plan_payloads = field_plan.custom_payloads.get(check_name) if field_plan else None
            _override_token = None
            if plan_payloads:
                defaults = self.payload_gen.default_payloads.get(check_name, [])
                merged = plan_payloads + [p for p in defaults if p not in plan_payloads]
                current_overrides = _FIELD_PAYLOAD_OVERRIDES.get() or {}
                _override_token = _FIELD_PAYLOAD_OVERRIDES.set({**current_overrides, check_name: merged})

            check_errored = False
            checks_executed += 1
            try:
                before_count = len(self.all_findings)
                findings = await scanner.scan_field(url, form_index, field, is_url_param)
                for f in (findings or []):
                    if f is None:
                        continue
                    self._record_finding(f, source=field_name)
                new_findings = [
                    f for f in self.all_findings[before_count:]
                    if f.url == url and f.field_name == field_name and f.check_type == check_name
                ]
                self._record_scan_matrix(
                    url=url,
                    field_name=field_name,
                    check_name=check_name,
                    status="finding" if new_findings else "tested",
                    location=location,
                    severity=max((f.severity for f in new_findings), default=""),
                    finding_count=len(new_findings),
                )
            except AbortScan:
                # payload 単位の即時停止でこの check は途中終了した。「済み」に
                # しないことで resume が未完の payload を取りこぼさない（finally の
                # mark_done を抑止するため check_errored を立ててから伝播する）。
                check_errored = True
                raise
            except Exception as e:
                check_errored = True
                self._record_scan_matrix(
                    url=url,
                    field_name=field_name,
                    check_name=check_name,
                    status="error",
                    location=location,
                    note=str(e)[:240],
                )
                console.print(f"    [yellow]Scanner error ({check_name}): {e}[/yellow]")
            finally:
                if _override_token is not None:
                    _FIELD_PAYLOAD_OVERRIDES.reset(_override_token)
                # この (url, field, check) 単位を完了として記録（再開時に飛ばす）。
                # ただし例外で終わった単位は「未完了」のまま残し、再開時に再試行する
                # （一時的なブラウザ/ネットワーク障害で取りこぼした検査を resume が
                # 飛ばしてしまわないようにする — 再開の網羅性を守る）。
                if not check_errored:
                    self._checkpoint_mark_done(url, field_name, form_index, check_name, is_url_param)

        # CTF: check page source after all scanners ran on this field
        if self.flag_finder:
            try:
                post_html = await self.browser.page.content()
                self._check_page_for_flags(post_html, url)
            except Exception:
                pass

        # ── Adaptive AI round ────────────────────────────────────────────
        # 以前は critical finding があると adaptive パスをスキップしていたが、過検知で
        # ある可能性を踏まえ「見つかったからスキップ」はしない。
        #
        # adaptive は field×check_type の独立単位として管理する。一部 check が失敗しても
        # 成功済み check の完了記録を残し、resume では失敗分だけを再試行する。
        # 旧 checkpoint の field 単位 "(adaptive)" marker は「全 check 完了」として尊重し、
        # 読み込み互換と完了済みフィールドへの再送防止を維持する。
        legacy_adaptive_done = self._checkpoint_is_done(
            url, field_name, form_index, "(adaptive)", is_url_param
        )
        adaptive_checks = [
            check_name for check_name in ordered_checks
            if check_name in self.scanners
            and check_name not in _ADAPTIVE_PAGE_LEVEL_CHECKS
        ]
        adaptive_pending = any(
            not self._checkpoint_is_done(
                url,
                field_name,
                form_index,
                _adaptive_checkpoint_check(check_name),
                is_url_param,
            )
            for check_name in adaptive_checks
        )
        # checks_skipped_done>0 は first-pass 完了後・adaptive 実行前に中断した resume を
        # 拾う。個々の済み判定は _adaptive_attack_field 側でも行い、再攻撃を防ぐ。
        if (
            self.adaptive_enabled
            and not legacy_adaptive_done
            and adaptive_pending
            and (checks_executed > 0 or checks_skipped_done > 0)
        ):
            adaptive_payloads = await self._adaptive_attack_field(
                url, form_index, field, is_url_param, ordered_checks, field_plan
            )
            # None はいずれかの check が未完、list は今回対象がすべて完了。
            # 完了記録自体は check_type ごとに _adaptive_attack_field が行う。
            if adaptive_payloads is not None:
                if self.monitor:
                    await self.monitor.emit_status(
                        f"adaptive payloads generated: {len(adaptive_payloads)}件"
                    )

        self.completed_fields += 1
        # フィールド完了ごとに進捗を永続化（中断しても次回ここから再開できる）
        self._save_checkpoint()
        if self.monitor and self.total_fields > 0:
            await self.monitor.emit_progress(
                current=self.completed_fields,
                total=self.total_fields,
                message=f"{field_name} ({url})",
            )

    async def _adaptive_attack_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool,
        check_names: list,
        field_plan: Optional[FieldAttackPlan],
    ) -> Optional[list[str]]:
        """
        Phase 3b: Adaptive AI round.
        For each check type, get current page HTML, ask LLM to generate
        context-aware bypass payloads, then run the scanner again with those payloads.
        """
        field_name = field.get("name", "unknown")

        # provider 自体が使えない場合はフォールバック完了として収束させる。
        # 個別 generate() の一時失敗とは分離し、可用性 probe は scan 中に一度だけ行う。
        if self._adaptive_llm_available is None:
            async with self._adaptive_llm_availability_lock:
                if self._adaptive_llm_available is None:
                    self._adaptive_llm_available = (
                        await self.payload_gen._check_llm_available()
                    )
                    if self.monitor:
                        availability = "利用可能" if self._adaptive_llm_available else "利用不可"
                        await self.monitor.emit_status(
                            f"Adaptive LLM 可用性: {availability}"
                        )

        if not self._adaptive_llm_available:
            checkpoint_updated = False
            for check_name in check_names:
                if (
                    check_name not in self.scanners
                    or check_name in _ADAPTIVE_PAGE_LEVEL_CHECKS
                ):
                    continue
                adaptive_checkpoint_check = _adaptive_checkpoint_check(check_name)
                if self._checkpoint_is_done(
                    url,
                    field_name,
                    form_index,
                    adaptive_checkpoint_check,
                    is_url_param,
                ):
                    continue
                self._checkpoint_mark_done(
                    url,
                    field_name,
                    form_index,
                    adaptive_checkpoint_check,
                    is_url_param,
                )
                checkpoint_updated = True
            if checkpoint_updated:
                self._save_checkpoint()
            return []

        # Get current page HTML as probe context
        try:
            page_html = await self.browser.page.content()
        except Exception:
            return None

        generated_payloads: list[str] = []
        generation_failed = False
        for check_name in check_names:
            scanner = self.scanners.get(check_name)
            if scanner is None:
                continue

            # Don't bother adaptive pass on page-level-only scanners
            if check_name in _ADAPTIVE_PAGE_LEVEL_CHECKS:
                continue

            adaptive_checkpoint_check = _adaptive_checkpoint_check(check_name)
            if self._checkpoint_is_done(
                url,
                field_name,
                form_index,
                adaptive_checkpoint_check,
                is_url_param,
            ):
                continue

            # 別 field/check の恒久失敗で可用性キャッシュが倒れた場合も、以降は
            # LLM を呼ばずフォールバック完了として収束させる。
            if self._adaptive_llm_available is False:
                self._checkpoint_mark_done(
                    url,
                    field_name,
                    form_index,
                    adaptive_checkpoint_check,
                    is_url_param,
                )
                self._save_checkpoint()
                continue

            # Standard payloads that were tried in the first pass
            plan_payloads = field_plan.custom_payloads.get(check_name, []) if field_plan else []
            defaults = self.payload_gen.default_payloads.get(check_name, [])
            tried = plan_payloads + [p for p in defaults if p not in plan_payloads]

            # Ask LLM for bypass payloads (include detected WAF for targeted evasion)
            adaptive_payloads, generation_status = await self.adaptive_engine.generate(
                check_type=check_name,
                field_name=field_name,
                url=url,
                payloads_tried=tried,
                page_html=page_html,
                waf_name=self.waf_detector._detected,
                return_status=True,
            )

            # API キー・モデル・URL 等の恒久不備が判明したら scan 内キャッシュを倒す。
            # 後続 field/check は上の可用性ゲートで収束し、同じ失敗呼び出しを繰り返さない。
            # empty/transient は resume での再試行と recall を維持するため倒さない。
            if generation_status in {"permanent", "unavailable"}:
                self._adaptive_llm_available = False

            if adaptive_payloads is None:
                generation_failed = True
                continue

            generated_payloads.extend(adaptive_payloads)
            if not adaptive_payloads:
                self._checkpoint_mark_done(
                    url,
                    field_name,
                    form_index,
                    adaptive_checkpoint_check,
                    is_url_param,
                )
                self._save_checkpoint()
                continue

            # Run scanner again with adaptive payloads — isolated via ContextVar
            current_overrides = _FIELD_PAYLOAD_OVERRIDES.get() or {}
            _adaptive_token = _FIELD_PAYLOAD_OVERRIDES.set({**current_overrides, check_name: adaptive_payloads})

            try:
                findings = await scanner.scan_field(url, form_index, field, is_url_param)
                for f in (findings or []):
                    if f is None:
                        continue
                    # Tag adaptive findings so they're identifiable
                    f.evidence = f"[AdaptiveAI] {f.evidence}"
                    self._record_finding(f, source=f"{field_name}[adaptive]")
                # 過検知の可能性があるため、critical が出ても残りのチェック種別の
                # adaptive パスを打ち切らない（見つかったからスキップしない）。
            except Exception as e:
                # payload 生成だけでなく実スキャンも adaptive 作業単位の一部。
                # 一時的なブラウザ/スキャン障害を完了扱いにせず resume で回収する。
                generation_failed = True
                console.print(f"    [yellow]Adaptive scanner error ({check_name}): {e}[/yellow]")
            else:
                self._checkpoint_mark_done(
                    url,
                    field_name,
                    form_index,
                    adaptive_checkpoint_check,
                    is_url_param,
                )
                # 後続 check の失敗やプロセス中断でも部分成功を保持する。
                self._save_checkpoint()
            finally:
                _FIELD_PAYLOAD_OVERRIDES.reset(_adaptive_token)

            # CTF: scan page again after adaptive probe
            if self.flag_finder:
                try:
                    post_html = await self.browser.page.content()
                    self._check_page_for_flags(post_html, url)
                except Exception:
                    pass

        # 一部のチェックだけ成功した場合も、失敗分を resume で回収できるよう未完とする。
        return None if generation_failed else generated_payloads

    def _generate_heuristic_plans_for_pages(self, pages: list) -> dict:
        """
        Generate heuristic attack plans for all pages without calling the LLM.
        Used as a starting point for manual (interactive) plan editing.
        """
        plans: dict = {}
        for page in pages:
            if not page.forms and not page.url_params:
                continue
            plan = self.attack_planner._heuristic_plan(
                url=page.url,
                forms=page.forms[:self.max_forms],
                url_params=page.url_params,
            )
            plans[page.url] = plan
            console.print(
                f"  [dim cyan][HeuristicPlan][/dim cyan] {page.url}  "
                f"→ {len(plan.fields)} field(s)"
            )
        return plans

    def _is_url_excluded(self, url: str) -> bool:
        """Return True if *url* matches any entry in the exclude_urls set.

        Matching rules:
          - Full URL exact match
          - Full URL prefix match (e.g. 'https://host/admin' excludes /admin/*)
          - Path-only patterns starting with '/' (e.g. '/logout', '/admin/')
            match against the URL's path on any host. Useful for excluding
            destructive endpoints regardless of scheme/host normalisation.
          - Wildcard patterns using '*' (full-width '＊' is also accepted),
            e.g. '/dontScan/*' excludes the path and everything beneath it,
            'https://host/admin/*' excludes that whole sub-tree, and
            '*/preview' matches any path ending in '/preview'. Matching is
            glob-style via fnmatch.
          - Patterns are matched case-insensitively for paths so that
            '/Logout' and '/logout' are treated the same.
        """
        if not url or not self.exclude_urls:
            return False
        try:
            parsed = urlparse(url)
        except Exception:
            parsed = None
        url_path = (parsed.path or "") if parsed else ""
        url_lower = url.lower()
        path_lower = url_path.lower()
        for pattern in self.exclude_urls:
            if not pattern:
                continue
            # Normalise the full-width asterisk that Japanese input often
            # produces ('＊' -> '*') and lower-case for case-insensitivity.
            p = pattern.strip().replace("＊", "*")
            if not p:
                continue
            pl = p.lower()
            is_full_url = pl.startswith(("http://", "https://"))
            target = url_lower if is_full_url else path_lower

            # Wildcard pattern: glob-style match.
            if "*" in pl:
                if fnmatch.fnmatch(target, pl):
                    return True
                # Treat a trailing '/*' as also matching the base path itself
                # so that '/dontScan/*' excludes '/dontScan' (no trailing slash).
                if pl.endswith("/*") and target == pl[:-2]:
                    return True
                continue

            # Full-URL match (exact or prefix), case-insensitive
            if is_full_url:
                if url_lower == pl or url_lower.startswith(pl):
                    return True
                continue
            # Path-only pattern: match against the URL path
            if pl.startswith("/"):
                if path_lower == pl or path_lower.startswith(pl):
                    return True
                continue
            # Bare token: substring match on the path (defensive, lower-cased)
            if pl in path_lower:
                return True
        return False

    def _form_action_url(self, form: dict, page_url: str) -> str:
        """Return the resolved (absolute) action URL of a form, or page_url."""
        action = (form.get("action") or "").strip()
        if not action:
            return page_url
        if action.startswith(("http://", "https://")):
            return action
        try:
            return urljoin(page_url, action)
        except Exception:
            return page_url

    def _is_registration_url(self, url: str) -> bool:
        """Return True if the URL path looks like a new-account registration page."""
        return bool(_REGISTRATION_URL_RE.search(urlparse(url).path))

    def _is_registration_form(self, form: dict) -> bool:
        """
        Return True if this form appears to be a signup / account-creation form.
        Detection signals (any one is sufficient):
          1. A field name / id matches the confirm-password pattern.
          2. The form action URL matches the registration URL pattern.
        """
        # Signal 1: confirm-password field present
        for inp in form.get("inputs", []):
            name = inp.get("name", "") or inp.get("id", "")
            if name and _REGISTRATION_FIELD_RE.match(name):
                return True
        # Signal 2: form action points to a registration endpoint
        action = form.get("action", "")
        if action and _REGISTRATION_URL_RE.search(urlparse(action).path):
            return True
        return False

    def _check_page_for_flags(self, text: str, source: str = ""):
        """Search text for CTF flags; print a banner and store any new finds."""
        if not self.flag_finder or not text:
            return
        found = self.flag_finder.find(text)
        for flag in found:
            if flag not in [f for f, _ in self.ctf_found_flags]:
                self.ctf_found_flags.append((flag, source))
                console.print()
                console.print(
                    f"  [bold white on red]  🚩 FLAG FOUND  [/bold white on red]"
                )
                console.print(
                    f"  [bold yellow]{flag}[/bold yellow]"
                    f"  [dim](source: {source})[/dim]"
                )
                console.print()

    def _record_finding(self, f: Finding, source: str = ""):
        if f is None:
            return
        dedup_key = finding_dedup_key_for(f)
        if dedup_key not in self._finding_dedup:
            # Finding bypassed scanner.record_finding (e.g. direct engine creation).
            # Register it in the shared state now.
            self._finding_dedup.add(dedup_key)
            self.all_findings.append(f)
        # Side effects must always run here.
        # scanner.record_finding() pre-adds the dedup key and appends to all_findings
        # so the branch above is skipped for normal scanner findings — but console
        # output, webhook, payload learning, and flag scanning were never triggered
        # because the old early-return prevented reaching this code.
        if self._notifier:
            asyncio.ensure_future(
                self._notifier.notify_finding(f, self.target_url)
            )
        label = f.check_type.upper()
        loc = f" on [yellow]{source}[/yellow]" if source else ""
        console.print(
            f"    [bold red][FINDING][/bold red] {label}{loc} — {f.evidence[:80]}"
        )
        if f.payload and self.enable_payload_learning:
            from urllib.parse import urlparse as _up
            _domain = _up(self.target_url).hostname or None
            self.payload_learner.record(f.check_type, f.payload, success=True, domain=_domain)
        if self.flag_finder:
            self._check_page_for_flags(f.evidence, f.url)
            body = (f.response or {}).get("body", "") or ""
            if body:
                self._check_page_for_flags(body, f.url)
            if f.dialog_message:
                self._check_page_for_flags(f.dialog_message, f.url)

    # =========================================================================
    # Phase 4.5: Verification — re-test each finding to catch false positives
    # =========================================================================

    _VERIFIABLE_CHECKS = frozenset({
        "xss",
        "sqli",
        "os",
        "ssti",
        "path_traversal",
        "open_redirect",
        "header_injection",
        "nosql",
        "ssrf",
        "deserialization",
        "ldap",
        "xxe",
        "file_upload",
        "race_condition",
        "request_smuggling",
        "websocket",
        "graphql_introspection",
        "graphql_batch",
        "graphql_injection",
        "graphql_sensitive",
        "jwt_no_expiry",
        "jwt_sensitive_data",
        "jwt_weak_secret",
        "jwt_alg_none",
        "jwt_kid_injection",
        "jwt_payload_tamper",
        "cors",
        "host_header",
        "dom_xss",
        "stored_xss",
        "privesc_unauth",
        "privesc_vertical",
        "privesc_horizontal",
        "privesc_param_idor",
        "privesc_cross_acct",
        "privesc_action",
        "privesc_bypass",
        "info_disclosure",
        "session",
        "security_headers",
    })

    async def _phase_verify(self):
        """
        Re-inject each finding's exact payload to confirm the vulnerability
        is reproducible.  Findings that cannot be reproduced are marked
        verified=False (kept in report with a ⚠ badge, not deleted).
        """
        from urllib.parse import parse_qs, urlparse

        to_verify = [
            f for f in self.all_findings
            if f.check_type in self._VERIFIABLE_CHECKS and not f.dialog_confirmed
        ]
        if not to_verify:
            return

        console.print(
            Rule(
                f"[bold blue] Phase 4.5  ·  Verification ({len(to_verify)} finding(s)) [/bold blue]",
                style="blue",
            )
        )
        if self.monitor:
            await self.monitor.emit_status(
                f"Verification: re-testing {len(to_verify)} finding(s)", "running"
            )

        for i, finding in enumerate(to_verify):
            confirmed = await self._verify_one(finding)
            if confirmed:
                console.print(
                    f"  [green][CONFIRMED][/green] {finding.check_type.upper()} "
                    f"on [yellow]{finding.field_name}[/yellow]: reproduced"
                )
            else:
                finding.verified = False
                finding.verification_note = "2回目の試行で再現できませんでした (possible false positive)"
                console.print(
                    f"  [yellow][UNCONFIRMED][/yellow] {finding.check_type.upper()} "
                    f"on [yellow]{finding.field_name}[/yellow]: not reproduced"
                )
            if self.monitor:
                await self.monitor.emit_progress(
                    current=i + 1,
                    total=len(to_verify),
                    message=f"検証 {i+1}/{len(to_verify)}: {finding.check_type}/{finding.field_name}",
                )

    async def _verify_one(self, f: Finding) -> bool:
        """
        Re-inject f.payload into f.field_name on f.url and check if the
        vulnerability is still reproducible.  Returns True if confirmed,
        True if verification could not be performed (don't penalise for nav errors).
        """
        from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
        import re as _re

        if f.check_type.startswith("graphql_"):
            scanner_key = "graphql"
        elif f.check_type.startswith("jwt_"):
            scanner_key = "jwt"
        elif f.check_type.startswith("privesc_"):
            scanner_key = "privesc"
        else:
            scanner_key = f.check_type
        scanner = self.scanners.get(scanner_key)
        if scanner is None:
            return True  # no scanner available → assume confirmed

        verifier = getattr(scanner, "verify_finding", None)
        if verifier:
            scanner_result = await verifier(f)
            if scanner_result is not None:
                # SSTI has an HTTP-level fallback below for URL parameters. Use
                # it when browser-based scanner verification could not reproduce
                # the finding, because loaded assets can make the latest browser
                # response pair point at a script rather than the vulnerable URL.
                if f.check_type == "ssti" and scanner_result is False:
                    pass
                else:
                    return bool(scanner_result)

        # Determine URL-param vs form-field injection context
        is_url_param = f.field_name in parse_qs(
            urlparse(f.url).query, keep_blank_values=True
        )

        if f.check_type == "ssti" and is_url_param:
            try:
                import httpx
                from wscan.scanners.ssti import SSTI_PROBES
                expected_values = [
                    expected for probe, expected, _engine in SSTI_PROBES
                    if probe == f.payload
                ]
                if expected_values:
                    parsed = urlparse(f.url)
                    qs = parse_qs(parsed.query, keep_blank_values=True)

                    def _with_value(value: str) -> str:
                        new_qs = dict(qs)
                        new_qs[f.field_name] = [value]
                        return urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))

                    async with httpx.AsyncClient(
                        **self.httpx_client_kwargs(
                            follow_redirects=True,
                            timeout=self.timeout,
                        )
                    ) as client:
                        baseline_url = _with_value("wscan_ssti_baseline")
                        probe_url = _with_value(f.payload)
                        baseline_resp = await client.get(
                            baseline_url,
                            headers=self.auth_headers(url=baseline_url),
                        )
                        probe_resp = await client.get(
                            probe_url,
                            headers=self.auth_headers(url=probe_url),
                        )
                    baseline_text = baseline_resp.text
                    probe_text = probe_resp.text
                    for expected in expected_values:
                        base_count = baseline_text.count(expected)
                        if expected in probe_text and (
                            base_count == 0 or probe_text.count(expected) > base_count
                        ):
                            return True
                    return False
            except Exception:
                pass

        try:
            await self.browser.navigate(f.url, retries=self.navigation_retries)
            self.browser.reset_dialog()
            source, pair = await scanner._apply_payload(
                f.url, 0, f.field_name, f.payload, is_url_param
            )
            await asyncio.sleep(self._effective_delay)

            if f.check_type == "xss":
                return self.browser.dialog_fired or bool(
                    source and scanner._check_reflected(source, f.payload)
                )

            elif f.check_type == "sqli":
                body = pair.get("response", {}).get("body", "") or source or ""
                return bool(scanner.check_response_for_patterns(body, SQL_ERROR_PATTERNS))

            elif f.check_type == "os":
                OS_OUT_PATTERNS = [r"root:x:", r"uid=\d+\(", r"volume serial", r"directory of"]
                return any(
                    _re.search(p, source or "", _re.IGNORECASE)
                    for p in OS_OUT_PATTERNS
                )

            elif f.check_type == "ssti":
                try:
                    from wscan.scanners.ssti import SSTI_PROBES
                    expected_values = [
                        expected for probe, expected, _engine in SSTI_PROBES
                        if probe == f.payload
                    ] or [expected for _probe, expected, _engine in SSTI_PROBES]
                except Exception:
                    expected_values = ["49", "7777777", "7045744422742119121"]
                return any(expected in (source or "") for expected in expected_values)

            else:
                return True  # path_traversal etc. — difficult to re-check, assume confirmed

        except Exception:
            return True  # navigation/injection failure → assume confirmed

    # =========================================================================
    # Phase 4: Report
    # =========================================================================

    def _merge_additional_report_findings(self) -> None:
        """スコープ内の外部 Finding を一度だけ追加する（重複も出自別に保持）。"""
        if not self.additional_report_findings:
            return

        allowed_findings: list[Finding] = []
        excluded_count = 0
        for finding in self.additional_report_findings:
            url = str(getattr(finding, "url", "") or "").strip()
            if (
                self._is_attack_target_url(url)
                and not self._is_url_excluded(url)
                and self._check_type_requested(finding.check_type)
            ):
                allowed_findings.append(finding)
            else:
                excluded_count += 1

        self.all_findings.extend(allowed_findings)
        self.additional_report_findings.clear()
        if excluded_count:
            console.print(
                f"  [yellow]Agent Finding をスコープ/除外設定により "
                f"{excluded_count} 件除外しました。[/yellow]"
            )

    def _phase_report(self):
        console.print(Rule("[bold green] Phase 4 / 4  ·  Report [/bold green]", style="green"))
        self._save_evidence()
        self._generate_report()
        self._print_summary()
        # A-3: Save payload learning data (if enabled)
        if self.enable_payload_learning:
            try:
                self.payload_learner.save()
            except Exception:
                pass

    async def _phase_report_async(self):
        """Async wrapper for report phase — runs A-1 AI analysis + J remediation after report."""
        # J: LLM リメディエーション提案
        if self.enable_ai_analysis and self.all_findings:
            try:
                from wscan.remediation import generate_fix
                for finding in self.all_findings:
                    if not getattr(finding, "ai_fix", ""):
                        fix_text, fix_is_ai = await generate_fix(finding, self.payload_gen)
                        finding.ai_fix = fix_text
                        # 実際に LLM で生成したか（静的テンプレートか）を記録し、
                        # レポートで "AI 推奨修正" と静的ガイダンスを出し分ける。
                        finding.ai_fix_is_ai = fix_is_ai
            except Exception:
                pass

        self._phase_report()
        # A-1: post-scan AI analysis (if enabled)
        if self.enable_ai_analysis:
            ai_text = await self._ai_analysis_report()
            if ai_text and self.monitor:
                await self.monitor.emit("ai_analysis", {"text": ai_text})

    def _save_evidence(self):
        findings_dicts = [f.to_dict() for f in self.all_findings]

        # I: 差分スキャン
        diff_data: dict = {}
        if self.previous_scan_dir:
            try:
                from wscan.diff_scan import load_previous, diff as _diff
                old_findings = load_previous(self.previous_scan_dir)
                diff_result = _diff(old_findings, findings_dicts)
                diff_data = diff_result.to_dict()
                console.print(f"  [cyan][Diff][/cyan] {diff_result.summary()}")
            except Exception as exc:
                console.print(f"  [yellow]差分スキャン失敗: {exc}[/yellow]")

        llm_summary = self._llm_runtime_summary()
        evidence = {
            "target": self.target_url,
            "scan_date": datetime.datetime.now().isoformat(),
            "checks": self.checks,
            "visited_urls": list(self.visited_urls),
            "llm_summary": llm_summary,
            "findings": findings_dicts,
            "scan_matrix": self.scan_matrix,
            "ctf_flags": [{"flag": flag, "source": src} for flag, src in self.ctf_found_flags],
            "diff": diff_data,
            "attack_plans": [
                {
                    "url": p.url,
                    "page_purpose": p.page_purpose,
                    "planned_by": p.planned_by,
                    "fields": [
                        {
                            "name": fp.name,
                            "risk_score": fp.risk_score,
                            "priority_checks": fp.priority_checks,
                            "rationale": fp.rationale,
                        }
                        for fp in p.fields
                    ],
                }
                for p in self.attack_plans
            ],
        }
        evidence_path = self.output_dir / "evidence.json"
        with open(evidence_path, "w", encoding="utf-8") as fp:
            json.dump(evidence, fp, ensure_ascii=False, indent=2)
        console.print(f"  [dim]Evidence:[/dim] {evidence_path}")
        if llm_summary.get("provider") != "none":
            console.print(
                "  [dim]LLM:     [/dim]"
                f"{llm_summary.get('provider')} / {llm_summary.get('model')} "
                f"(plans: {llm_summary.get('llm_plans')}"
                f" LLM, {llm_summary.get('heuristic_plans')} fallback)"
            )

        # Reproduction package: machine-readable steps + curl script.
        try:
            from wscan.reproduction import write_reproduction_package
            repro = write_reproduction_package(self.all_findings, self.output_dir)
            console.print(f"  [dim]Repro:   [/dim] {repro['json']}")
            console.print(f"  [dim]Curl:    [/dim] {repro['shell']}")
        except Exception as _repro_err:
            console.print(f"  [yellow][Repro] 書き出し失敗: {_repro_err}[/yellow]")

        # Developer-oriented remediation task export.
        try:
            from wscan.action_plan import write_action_plan
            action_plan = write_action_plan(self.all_findings, self.output_dir)
            console.print(f"  [dim]Actions: [/dim] {action_plan['markdown']}")
            console.print(f"  [dim]Tasks:   [/dim] {action_plan['json']}")
        except Exception as _plan_err:
            console.print(f"  [yellow][ActionPlan] 書き出し失敗: {_plan_err}[/yellow]")

        # K: SARIF 2.1.0 出力
        sarif_out = ""
        if self.sarif:
            try:
                from wscan.sarif import write_sarif
                sarif_path = write_sarif(
                    self.all_findings,
                    target_url=self.target_url,
                    output_path=self.output_dir / "report.sarif",
                )
                sarif_out = str(sarif_path)
                console.print(f"  [dim]SARIF:   [/dim] {sarif_path}")
            except Exception as _sarif_err:
                console.print(f"  [yellow][SARIF] 書き出し失敗: {_sarif_err}[/yellow]")

        # L: スキャン完了通知
        if self._notifier and self._notifier.notify_complete:
            _counts: dict[str, int] = {}
            for _f in self.all_findings:
                _counts[_f.severity] = _counts.get(_f.severity, 0) + 1
            _summary = {
                "total": len(self.all_findings),
                "critical": _counts.get("critical", 0),
                "high":     _counts.get("high", 0),
                "medium":   _counts.get("medium", 0),
                "low":      _counts.get("low", 0),
            }
            try:
                import asyncio as _asyncio
                _loop = _asyncio.get_event_loop()
                _loop.run_until_complete(
                    self._notifier.notify_scan_complete(
                        _summary,
                        target_url=self.target_url,
                        report_path=str(self.output_dir / "report.html"),
                        sarif_path=sarif_out,
                    )
                )
            except Exception as _notify_err:
                console.print(f"  [yellow][Notification] 完了通知失敗: {_notify_err}[/yellow]")

    def _generate_report(self):
        import webbrowser
        from .report import ReportGenerator
        gen = ReportGenerator(self.output_dir)

        # 差分スキャン結果を読み込む (evidence.json に書き込み済み)
        diff_result = None
        if self.previous_scan_dir:
            try:
                from wscan.diff_scan import load_previous, diff as _diff
                old_findings = load_previous(self.previous_scan_dir)
                findings_dicts = [f.to_dict() for f in self.all_findings]
                diff_result = _diff(old_findings, findings_dicts)
            except Exception:
                pass

        # F: マルチテンプレートレポート (audit + executive + developer)
        report_path = gen.generate(
            target=self.target_url,
            findings=self.all_findings,
            visited_urls=list(self.visited_urls),
            checks=self.checks,
            attack_plans=self.attack_plans,
            ctf_flags=self.ctf_found_flags,
            page_graph=self.page_graph,
            scan_matrix=self.scan_matrix,
            llm_summary=self._llm_runtime_summary(),
            template="audit",
            diff_result=diff_result,
        )
        # Executive / Developer テンプレートも生成
        for tmpl in ("executive", "developer"):
            try:
                gen.generate(
                    target=self.target_url,
                    findings=self.all_findings,
                    visited_urls=list(self.visited_urls),
                    checks=self.checks,
                    attack_plans=self.attack_plans,
                    ctf_flags=self.ctf_found_flags,
                    page_graph=self.page_graph,
                    scan_matrix=self.scan_matrix,
                    llm_summary=self._llm_runtime_summary(),
                    template=tmpl,
                    diff_result=diff_result,
                )
            except Exception:
                pass

        # D: CI/CD API — レポートパスを monitor に登録
        if self.monitor:
            self.monitor.api_report_path = str(report_path)

        if self.open_report:
            try:
                webbrowser.open(report_path.as_uri())
            except Exception:
                pass

    def _llm_runtime_summary(self) -> dict:
        provider = getattr(self.payload_gen, "provider", "none")
        model = ""
        if provider == "ollama":
            model = getattr(self.payload_gen, "ollama_model", "")
        elif provider == "openai":
            model = getattr(self.payload_gen, "openai_model", "")
        elif provider == "gemini":
            model = getattr(self.payload_gen, "gemini_model", "")
        elif provider == "claude":
            model = getattr(self.payload_gen, "claude_model", "")
        total = len(self.attack_plans)
        llm_plans = sum(1 for p in self.attack_plans if getattr(p, "planned_by", "") == "llm")
        heuristic_plans = sum(1 for p in self.attack_plans if getattr(p, "planned_by", "") != "llm")
        note = ""
        if provider != "none" and heuristic_plans:
            note = "Some pages used heuristic fallback because the LLM response was unavailable or invalid."
        return {
            "provider": provider,
            "model": model,
            "role_models": self.payload_gen.role_model_summary(),
            "total_plans": total,
            "llm_plans": llm_plans,
            "heuristic_plans": heuristic_plans,
            "note": note,
        }

    async def _manual_payload_listener(self) -> None:
        """U-3: Background coroutine — executes manual payloads requested from dashboard."""
        if not self.monitor:
            return
        while self.controller._active:
            try:
                msg = await asyncio.wait_for(
                    self.monitor.manual_payload_queue.get(), timeout=0.3
                )
            except asyncio.TimeoutError:
                continue
            except Exception:
                break
            url        = msg.get("url", "")
            field_name = msg.get("field", "")
            payload    = msg.get("payload", "")
            check_type = msg.get("check_type", "xss")
            if not url or not field_name or not payload:
                continue
            console.print(
                f"  [bold cyan][U-3 Manual][/bold cyan] "
                f"{check_type.upper()} payload on {field_name} @ {url}"
            )
            try:
                scanner = self.scanners.get(check_type)
                if scanner:
                    field = {"name": field_name, "type": "text"}
                    prev = self.custom_payloads.get(check_type)
                    self.custom_payloads[check_type] = [payload]
                    findings = await scanner.scan_field(url, 0, field, is_url_param=False)
                    if prev is None:
                        self.custom_payloads.pop(check_type, None)
                    else:
                        self.custom_payloads[check_type] = prev
                    for f in (findings or []):
                        if f is None:
                            continue
                        f.evidence = f"[ManualExec] {f.evidence}"
                        self._record_finding(f, source=f"manual:{field_name}")
                else:
                    # Generic: just navigate and check for payload in response
                    await self.browser.navigate(url, retries=self.navigation_retries)
                    source, pair = await self.browser.fill_and_submit_form(0, field_name, payload)
                    if payload in (source or ""):
                        console.print(
                            f"  [dim yellow][U-3 Manual] Payload reflected in response[/dim yellow]"
                        )
                    if self.monitor:
                        await self.monitor.emit("manual_result", {
                            "reflected": payload in (source or ""),
                            "field": field_name,
                            "payload": payload,
                        })
            except Exception as e:
                console.print(f"  [yellow][U-3 Manual] Error: {e}[/yellow]")

    # =========================================================================
    # A: Multi-account privilege escalation helpers
    # =========================================================================

    async def _setup_account_sessions(self) -> None:
        """
        For each account in self.accounts, log in via the login URL and
        capture the resulting cookies as a cookie string.
        Populates self.account_sessions.
        """
        if not self.login_url:
            return
        console.print(
            f"  [cyan][A] Setting up {len(self.accounts)} account session(s)…[/cyan]"
        )
        for acct in self.accounts:
            username = acct.get("username", "")
            password = acct.get("password", "")
            role = acct.get("role", "user")
            if not username or not password:
                continue
            cookie_str = await self._browser.create_session_for_account(
                username=username,
                password=password,
                login_url=self.login_url,
                user_field=self.login_user_field,
                pass_field=self.login_pass_field,
                success_indicator=self.login_success_indicator,
            )
            if cookie_str:
                self.account_sessions.append({
                    "username": username,
                    "cookies": cookie_str,
                    "role": role,
                })
                console.print(
                    f"    [green]✓[/green] {username} ({role}) — session captured"
                )
            else:
                console.print(
                    f"    [yellow]✗[/yellow] {username} — login failed, skipping"
                )

    async def _auto_register_accounts(self, pages: list) -> None:
        """
        Auto-detect registration forms in the crawled pages and create
        self.auto_register_count test accounts.  Each successfully
        registered account is then logged in and added to account_sessions.
        """
        import random
        import string

        if not self.login_url:
            return

        # Find registration forms
        reg_forms = []
        for page in pages:
            if self._is_registration_url(page.url):
                if page.forms:
                    reg_forms.append((page.url, page.forms[0]))
                    break
            for form in page.forms:
                if self._is_registration_form(form):
                    reg_forms.append((page.url, form))
                    break
            if reg_forms:
                break

        if not reg_forms:
            console.print(
                "  [yellow][A] No registration form detected — "
                "cannot auto-register accounts.[/yellow]"
            )
            return

        reg_url, reg_form = reg_forms[0]
        console.print(
            f"  [cyan][A] Auto-registering up to {self.auto_register_count} "
            f"test account(s) via {reg_url}[/cyan]"
        )

        for i in range(self.auto_register_count):
            rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
            username = f"wscan_{rand}"
            password = f"Wscan@{rand}1!"
            email = f"wscan_{rand}@example-test.invalid"

            # Fill and submit the registration form via Playwright
            try:
                await self._browser.navigate(reg_url, retries=self.navigation_retries)
                form_inputs = reg_form.get("inputs", [])
                for inp in form_inputs:
                    iname = inp.get("name", "")
                    itype = inp.get("type", "text")
                    if not iname:
                        continue
                    if itype == "email" or "email" in iname.lower():
                        val = email
                    elif "user" in iname.lower() or "login" in iname.lower() or "name" == iname.lower():
                        val = username
                    elif "pass" in iname.lower():
                        val = password
                    else:
                        val = username  # fill unknown fields with username as placeholder
                    await self._browser.page.evaluate(
                        """([n, v]) => {
                            const el = document.querySelector(`[name="${n}"],[id="${n}"]`);
                            if (el) {
                                el.value = v;
                                ['input','change','blur'].forEach(e =>
                                    el.dispatchEvent(new Event(e, {bubbles:true}))
                                );
                            }
                        }""",
                        [iname, val],
                    )

                # Submit
                await self._browser.page.evaluate(
                    """() => {
                        const form = document.querySelector('form');
                        if (!form) return;
                        const btn = form.querySelector(
                            'button[type="submit"],input[type="submit"],[type="submit"]'
                        ) || form.querySelector('button:not([type="button"])');
                        if (btn) btn.click(); else form.submit();
                    }"""
                )
                await self._browser.page.wait_for_load_state("domcontentloaded", timeout=10000)
            except Exception as e:
                console.print(f"    [yellow]✗[/yellow] Auto-register failed for {username}: {e}")
                continue

            # Try to log in with the newly registered credentials
            cookie_str = await self._browser.create_session_for_account(
                username=username,
                password=password,
                login_url=self.login_url,
                user_field=self.login_user_field,
                pass_field=self.login_pass_field,
                success_indicator=self.login_success_indicator,
            )
            if cookie_str:
                self.account_sessions.append({
                    "username": username,
                    "cookies": cookie_str,
                    "role": "registered",
                })
                console.print(
                    f"    [green]✓[/green] {username} registered & logged in"
                )
            else:
                console.print(
                    f"    [yellow]✗[/yellow] {username} registered but login failed"
                )

    # =========================================================================
    # ⑧ ⑨  Enhanced AI Analysis (chain reasoning + per-finding fix suggestions)
    # =========================================================================

    async def _ai_analysis_report(self) -> str:
        """
        A-1 (enhanced): Generate a comprehensive AI analysis of all findings.

        Enhancements:
          ⑧ Vulnerability chain reasoning — asks LLM to identify multi-step
             attack scenarios from combinations of findings.
          ⑨ AI report writing — for each Critical/High finding, the LLM
             produces a business impact statement, code-level fix, and
             OWASP/CWE reference.

        Returns the analysis text (also saved to output_dir/ai_analysis.md).
        Per-finding AI fixes are saved to output_dir/ai_finding_fixes.json.
        """
        if not self.all_findings:
            return ""
        if not await self.payload_gen._check_llm_available():
            return ""

        findings_summary = "\n".join(
            f"- [{f.severity.upper()}] {f.check_type} on {f.url} "
            f"(field: {f.field_name}): {f.evidence[:150]}"
            for f in self.all_findings[:60]
        )

        # ── ⑧ Chain reasoning prompt ────────────────────────────────────
        chain_section = (
            "\n\n## 攻撃チェーン分析 (Vulnerability Chain Analysis)\n"
            "以下の発見を組み合わせた多段攻撃シナリオを最大3つ分析してください。\n"
            "各シナリオには以下を含めてください:\n"
            "  Step 1, Step 2, ... (使用する脆弱性), 攻撃者が得るもの, 最終的なビジネス影響\n"
            "例: XSS → CSRF token 窃取 → アカウント乗っ取り\n"
        )

        prompt = (
            f"You are a security analyst reviewing findings from an automated web security scan.\n"
            f"Target: {self.target_url}\n\n"
            f"Findings ({len(self.all_findings)} total):\n{findings_summary}\n\n"
            f"Please provide (in Japanese):\n"
            f"1. 全体的な攻撃シナリオのナラティブ (これらの脆弱性がどう連鎖するか)\n"
            f"2. 優先度上位3件の修正手順 (具体的なコード例を含む)\n"
            f"3. 推奨 WAF ルールまたは HTTP セキュリティヘッダー設定\n"
            f"4. アプリケーション全体のリスク評価 (Critical/High/Medium/Low)"
            + chain_section
        )
        full_text = ""
        try:
            resp_text = await self._call_llm_text(prompt)
            if resp_text:
                full_text += resp_text
        except Exception as e:
            console.print(f"  [yellow][A-1] AI analysis failed: {e}[/yellow]")

        # ── ⑨ Per-finding fix suggestions ────────────────────────────────
        high_critical = [
            f for f in self.all_findings
            if f.severity in ("critical", "high")
        ][:10]  # cap to avoid excessive LLM calls

        finding_fixes: list[dict] = []
        for f in high_critical:
            fix_prompt = (
                f"Security finding: [{f.severity.upper()}] {f.check_type}\n"
                f"URL: {f.url}  Field: {f.field_name}\n"
                f"Evidence: {f.evidence[:300]}\n\n"
                f"Please respond in Japanese with:\n"
                f"1. ビジネス影響 (非技術者向け、2〜3文)\n"
                f"2. 修正コード例 (推定される言語/フレームワークで)\n"
                f"3. OWASP トップ10 / CWE 参照番号と URL\n"
                f"Keep the response under 400 words."
            )
            try:
                fix_text = await self._call_llm_text(fix_prompt)
                if fix_text:
                    finding_fixes.append({
                        "check_type": f.check_type,
                        "url": f.url,
                        "field_name": f.field_name,
                        "severity": f.severity,
                        "ai_fix": fix_text,
                    })
                    # Attach to the Finding object for the report renderer
                    f.__dict__["ai_fix"] = fix_text
                    f.__dict__["ai_fix_is_ai"] = True
            except Exception:
                pass

        if finding_fixes:
            fixes_path = self.output_dir / "ai_finding_fixes.json"
            fixes_path.write_text(
                json.dumps(finding_fixes, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            full_text += (
                f"\n\n---\n## Individual Finding AI Fixes\n"
                f"See {fixes_path} for per-finding remediation details.\n"
            )

        if full_text:
            analysis_path = self.output_dir / "ai_analysis.md"
            analysis_path.write_text(full_text, encoding="utf-8")
            console.print(
                f"  [dim cyan][A-1][/dim cyan] AI analysis saved → {analysis_path}"
            )

        return full_text

    async def _call_llm_text(self, prompt: str) -> str:
        """Call the configured LLM and return raw text response."""
        from . import llm_client

        with self.payload_gen.use_role("report"):
            text = await llm_client.complete_text(
                self.payload_gen, prompt, max_tokens=1500, timeout=60
            )
        return text or ""

    def _print_summary(self):
        console.print()
        console.print(f"  Target   : [cyan]{self.target_url}[/cyan]")
        console.print(f"  Pages    : [cyan]{len(self.visited_urls)}[/cyan]")
        console.print(f"  Plans    : [cyan]{len(self.attack_plans)}[/cyan]")
        color = "red" if self.all_findings else "green"
        console.print(f"  Findings : [{color}]{len(self.all_findings)}[/{color}]")
        adaptive_count = sum(1 for f in self.all_findings if "[AdaptiveAI]" in f.evidence)
        if adaptive_count:
            console.print(
                f"  [bold magenta]Adaptive AI[/bold magenta] : "
                f"[magenta]{adaptive_count}[/magenta] finding(s) discovered via LLM-generated bypass payloads"
            )
        chain_count = sum(1 for f in self.all_findings if "[ChainDetect]" in f.evidence)
        if chain_count:
            console.print(
                f"  [bold yellow]Chain Detect[/bold yellow] : "
                f"[yellow]{chain_count}[/yellow] finding(s) from stored/second-order vulnerability chain"
            )
        multi_count = sum(1 for f in self.all_findings if "[MultiParam]" in f.evidence)
        if multi_count:
            console.print(
                f"  [bold cyan]Multi-Param [/bold cyan] : "
                f"[cyan]{multi_count}[/cyan] finding(s) from simultaneous multi-field injection"
            )

        if self.all_findings:
            t = Table(show_header=True, header_style="bold magenta", box=rbox.SIMPLE)
            t.add_column("Type",     style="cyan")
            t.add_column("Severity", style="red")
            t.add_column("Field")
            t.add_column("Evidence")
            for f in self.all_findings:
                sc = {"critical": "red", "high": "yellow", "medium": "blue", "low": "green"}.get(f.severity, "white")
                t.add_row(
                    f.check_type.upper(),
                    f"[{sc}]{f.severity}[/{sc}]",
                    f.field_name,
                    f.evidence[:60],
                )
            console.print(t)

        if self.ctf_found_flags:
            console.print()
            console.print(Rule("[bold white on red]  🚩  CTF FLAGS CAPTURED  🚩  [/bold white on red]", style="red"))
            for flag, src in self.ctf_found_flags:
                console.print(f"  [bold yellow]{flag}[/bold yellow]  [dim]← {src}[/dim]")
            console.print(Rule(style="red"))

        console.print(f"\n  [bold green]Report:[/bold green] [cyan]{self.output_dir / 'report.html'}[/cyan]")

    # =========================================================================
    # Helpers
    # =========================================================================

    def _load_yaml(self, path: str) -> dict:
        try:
            with open(path, encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load {path}: {e}[/yellow]")
            return {}
