#!/usr/bin/env python3
"""
WScan - Web Security Scanner
Automated security testing with real-time monitoring dashboard.

Usage:
  python main.py scan <url>
  python main.py scan <url> --payloads custom_payloads.yaml
  python main.py scan <url> --checks sqli xss
  python main.py scan <url> --depth 3 --headless --llm ollama
"""
import asyncio
import argparse
import json
import os
import sys
import webbrowser
from pathlib import Path

# Ensure the wscan package is importable
sys.path.insert(0, str(Path(__file__).parent))

# ──────────────────────────────────────────────────────────────────
# Config file loader (config/wscan.yaml)
# ──────────────────────────────────────────────────────────────────
_CONFIG_PATH = Path(__file__).parent / "config" / "wscan.yaml"


def _load_config(path: Path = _CONFIG_PATH) -> dict:
    """
    Load config/wscan.yaml and return a flat dict of resolved values.
    Returns defaults silently if the file is missing or unparseable.
    """
    cfg: dict = {}
    if not path.exists():
        return cfg
    try:
        import yaml
        from wscan.textio import read_text_resilient
        raw = yaml.safe_load(read_text_resilient(path)) or {}
    except Exception as _yaml_exc:
        import sys
        print(
            f"[wscan] WARNING: failed to parse {path}: {_yaml_exc} — using defaults.",
            file=sys.stderr,
        )
        return cfg

    # ── Flatten into a single namespace ──────────────────────────
    s   = raw.get("scan",     {})
    b   = raw.get("browser",  {})
    l   = raw.get("llm",      {})
    m   = raw.get("monitor",  {})
    pl  = raw.get("planner",  {})
    a   = raw.get("auth",     {})
    f   = raw.get("features", {})
    le  = raw.get("learning", {})
    ct  = raw.get("ctf",      {})
    o   = raw.get("output",   {})

    cfg["checks"]                  = s.get("checks",    ["sqli", "xss", "os"])
    cfg["depth"]                   = int(s.get("depth",     2))
    cfg["max_forms"]               = int(s.get("max_forms", 50))
    cfg["timeout"]                 = int(s.get("timeout",   30))
    cfg["request_delay"]           = float(s.get("request_delay", 0.5))
    cfg["navigation_retries"]      = int(s.get("navigation_retries", 2))
    cfg["exclude_fields"]          = list(s.get("exclude_fields", []))
    cfg["exclude_urls"]            = list(s.get("exclude_urls",   []))
    cfg["target_urls"]             = list(s.get("target_urls",    []))
    cfg["access_urls"]             = list(s.get("access_urls",    []))
    cfg["manual_crawl_file"]       = str(s.get("manual_crawl_file", "") or "")
    cfg["allow_state_changing_probes"] = bool(s.get("allow_state_changing_probes", False))

    cfg["headless"]                = bool(b.get("headless", False))
    cfg["proxy"]                   = str(b.get("proxy", "") or "")
    cfg["tls_client_cert"]         = str(b.get("tls_client_cert", "") or "")
    cfg["tls_client_key"]          = str(b.get("tls_client_key", "") or "")
    cfg["tls_client_pfx"]          = str(b.get("tls_client_pfx", "") or "")
    cfg["tls_client_cert_password"] = str(b.get("tls_client_cert_password", "") or "")
    cfg["tls_ca_cert"]             = str(b.get("tls_ca_cert", "") or "")
    cfg["tls_verify"]              = bool(b.get("tls_verify", False))

    cfg["llm_provider"]            = str(l.get("provider",     "ollama"))
    cfg["ollama_model"]            = str(l.get("ollama_model", "llama3"))
    cfg["ollama_url"]              = str(l.get("ollama_url",   "http://localhost:11434"))
    cfg["openai_model"]            = str(l.get("openai_model", "gpt-4o-mini"))
    cfg["gemini_model"]            = str(l.get("gemini_model", "gemini-2.0-flash"))
    cfg["claude_model"]            = str(l.get("claude_model", "claude-haiku-4-5-20251001"))
    cfg["role_models"]             = {
        str(k): str(v).strip()
        for k, v in (l.get("models", {}) or {}).items()
        if str(v).strip()
    }

    cfg["monitor_enabled"]         = bool(m.get("enabled", True))
    cfg["port"]                    = int(m.get("port", 8765))
    cfg["host"]                    = str(m.get("host", "0.0.0.0"))
    cfg["auth_token"]              = str(m.get("auth_token", ""))
    # 出力の保持ポリシー（0=無制限）。serve モードで自動削除に使う。
    cfg["retention_days"]          = float(m.get("retention_days", 0) or 0)
    cfg["retention_max_scans"]     = int(m.get("retention_max_scans", 0) or 0)
    # スキャン対象スコープ（serve モードの誤爆・悪用防止。空=無制限）。
    cfg["allowed_target_hosts"]    = list(m.get("allowed_target_hosts", []) or [])
    cfg["denied_target_hosts"]     = list(m.get("denied_target_hosts", []) or [])
    # スキャンのウォッチドッグ（分。0=無効）。ハングしたスキャンを自動中断。
    cfg["scan_timeout_minutes"]    = float(m.get("scan_timeout_minutes", 0) or 0)
    # 信頼できるリバースプロキシ配下で X-Forwarded-For を実クライアントIPとして使う。
    cfg["trust_proxy"]             = bool(m.get("trust_proxy", False))

    cfg["use_planner"]             = bool(pl.get("enabled",     True))
    cfg["interactive_plan"]        = bool(pl.get("interactive", False))

    cfg["login_url"]               = str(a.get("login_url",               "") or "")
    cfg["login_user_field"]        = str(a.get("login_user_field",        "username"))
    cfg["login_pass_field"]        = str(a.get("login_pass_field",        "password"))
    cfg["login_success_indicator"] = str(a.get("login_success_indicator", "") or "")
    cfg["auth_user"]               = str(a.get("auth_user", "") or "")
    cfg["auth_pass"]               = str(a.get("auth_pass", "") or "")
    cfg["mfa_type"]                = str(a.get("mfa_type", "") or "")
    cfg["mfa_field"]               = str(a.get("mfa_field", "") or "")
    cfg["mfa_email_account"]       = str(a.get("mfa_email_account", "") or "")
    cfg["mfa_email_address"]       = str(a.get("mfa_email_address", "") or "")
    cfg["mfa_email_imap_host"]     = str(a.get("mfa_email_imap_host", "") or "")
    cfg["mfa_email_imap_port"]     = str(a.get("mfa_email_imap_port", "") or "")
    cfg["mfa_email_imap_user"]     = str(a.get("mfa_email_imap_user", "") or "")
    cfg["mfa_email_imap_password"] = str(a.get("mfa_email_imap_password", "") or "")
    cfg["mfa_email_imap_ssl"]      = a.get("mfa_email_imap_ssl", None)

    cfg["dom_xss"]                 = bool(f.get("dom_xss",          False))
    cfg["ai_analysis"]             = bool(f.get("ai_analysis",      True))
    cfg["waf_detection"]           = bool(f.get("waf_detection",    True))
    cfg["payload_learning"]        = bool(f.get("payload_learning", True))
    cfg["community_payloads"]      = bool(f.get("community_payloads", True))
    cfg["sitemap_crawl"]           = bool(f.get("sitemap_crawl",    True))
    cfg["cvss_scores"]             = bool(f.get("cvss_scores",      True))
    cfg["skip_registration"]       = bool(f.get("skip_registration", True))
    cfg["open_report"]             = bool(f.get("open_report",      True))
    cfg["auto_config"]             = bool(f.get("auto_config",      False))
    cfg["spa_crawl"]               = bool(f.get("spa_crawl",        False))
    cfg["interactive_crawl_review"] = bool(f.get("interactive_crawl_review", False))

    cfg["learning_file"]           = str(le.get("file", "") or "")

    cfg["ctf_mode"]                = bool(ct.get("enabled",      False))
    cfg["ctf_flag_pattern"]        = str(ct.get("flag_pattern",  "") or "")

    cfg["output_dir"]              = str(o.get("dir",           "") or "")
    cfg["payloads_file"]           = str(o.get("payloads_file", "") or "")

    return cfg


# Load once at import time so parse_args() can reference it
_CFG = _load_config()


# 設定スナップショット等で永続化してはいけない秘匿フィールド。キー名に以下の
# 語を含む値（パスワード/シークレット/トークン/APIキー）は伏字にする。
_SECRET_KEY_TOKENS = ("password", "secret", "token", "api_key", "apikey")


def _redact_secrets(cfg: dict) -> dict:
    """秘匿値を伏字にした設定の浅いコピーを返す（ディスク保存・共有用）。

    ダッシュボードは IMAP アプリパスワード等を「送信のみ・非保存」として扱うため、
    成果物（``scan_config.json``）へ平文で書き出さない。
    """
    redacted: dict = {}
    for key, value in (cfg or {}).items():
        lname = str(key).lower()
        if value not in ("", None) and any(tok in lname for tok in _SECRET_KEY_TOKENS):
            redacted[key] = "***REDACTED***"
        else:
            redacted[key] = value
    return redacted


def parse_args():
    parser = argparse.ArgumentParser(
        description="WScan - Web Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py scan https://example.com
  python main.py scan https://example.com --payloads my_payloads.yaml
  python main.py scan https://example.com --checks sqli xss --depth 3
  python main.py scan https://example.com --headless --llm claude
  python main.py scan https://example.com --no-monitor
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── scan subcommand ────────────────────────────────────────────
    scan = sub.add_parser("scan", help="Run a security scan")
    scan.add_argument("url", help="Target URL (e.g. https://example.com)")

    scan.add_argument(
        "--payloads", "-p", metavar="FILE",
        default=_CFG.get("payloads_file") or None,
        help="Custom payloads YAML file (see config/default_payloads.yaml for format)",
    )
    _ALL_CHECKS = [
        # mail_header（IPA 1.8）は再有効化済み（wscan/scanners/__init__.py 参照）。
        # 確証は OOB メール受信（env: WSCAN_OOB_*）で行い、未設定時も反射/エラー
        # 漏えいのヒューリスティック検知が動く。
        "sqli", "xss", "dom_xss", "stored_xss", "os", "path_traversal",
        "session", "csrf", "header_injection", "mail_header",
        "clickjacking", "open_redirect", "ssti", "privesc",
        "cors", "info_disclosure", "host_header", "security_headers",
        "nosql", "deserialization", "request_smuggling", "ssrf",
        "graphql", "jwt", "cms", "xxe", "ldap", "file_upload",
        "race_condition", "websocket", "secret_leak", "sri", "js_static",
    ]
    _default_checks = _CFG.get("checks", ["sqli", "xss", "os"])
    scan.add_argument(
        "--checks", nargs="+",
        choices=_ALL_CHECKS,
        default=_default_checks,
        metavar="CHECK",
        help=(
            f"Security checks to run (default from config: {' '.join(_default_checks)}). "
            "Available: " + ", ".join(_ALL_CHECKS)
        ),
    )
    scan.add_argument(
        "--depth", "-d", type=int, default=_CFG.get("depth", 2), metavar="N",
        help=f"Crawl depth (default: {_CFG.get('depth', 2)})",
    )
    scan.add_argument(
        "--headless", action="store_true", default=_CFG.get("headless", False),
        help="Run browser in headless mode (no visible window)",
    )
    scan.add_argument(
        "--no-monitor", action="store_true",
        default=not _CFG.get("monitor_enabled", True),
        help="Disable the real-time monitoring dashboard",
    )
    scan.add_argument(
        "--llm",
        choices=["ollama", "claude", "openai", "gemini", "none"],
        default=_CFG.get("llm_provider", "ollama"),
        help=(
            f"LLM for payload generation (default from config: {_CFG.get('llm_provider','ollama')}). "
            "openai requires OPENAI_API_KEY. gemini requires GEMINI_API_KEY."
        ),
    )
    scan.add_argument(
        "--ollama-model", default=_CFG.get("ollama_model", "llama3"), metavar="MODEL",
        help=f"Ollama model name (default: {_CFG.get('ollama_model','llama3')})",
    )
    scan.add_argument(
        "--openai-model", default=_CFG.get("openai_model", "gpt-4o-mini"), metavar="MODEL",
        help=f"OpenAI model name (default: {_CFG.get('openai_model','gpt-4o-mini')})",
    )
    scan.add_argument(
        "--gemini-model", default=_CFG.get("gemini_model", "gemini-2.0-flash"), metavar="MODEL",
        help=f"Google Gemini model name (default: {_CFG.get('gemini_model','gemini-2.0-flash')})",
    )
    scan.add_argument(
        "--claude-model", default=_CFG.get("claude_model", "claude-haiku-4-5-20251001"), metavar="MODEL",
        help=f"Claude model name (default: {_CFG.get('claude_model','claude-haiku-4-5-20251001')})",
    )
    for role in ("planner", "payload", "adaptive", "triage", "report"):
        scan.add_argument(
            f"--{role}-model",
            default=_CFG.get("role_models", {}).get(role, ""),
            metavar="MODEL",
            help=f"Override the {role} LLM model. Defaults to the provider model.",
        )
    scan.add_argument(
        "--output", "-o", metavar="DIR",
        default=_CFG.get("output_dir") or None,
        help="Output directory for evidence and reports (default: output/<timestamp>)",
    )
    scan.add_argument(
        "--port", type=int, default=_CFG.get("port", 8765),
        help=f"Monitoring dashboard port (default: {_CFG.get('port', 8765)})",
    )
    scan.add_argument(
        "--timeout", type=int, default=_CFG.get("timeout", 30), metavar="SECS",
        help=f"Request timeout in seconds (default: {_CFG.get('timeout', 30)})",
    )
    scan.add_argument(
        "--max-forms", type=int, default=_CFG.get("max_forms", 50), metavar="N",
        help=f"Max forms to test per page (default: {_CFG.get('max_forms', 50)})",
    )
    scan.add_argument(
        "--exclude", "-e", nargs="+", metavar="PARAM",
        default=_CFG.get("exclude_fields", []),
        help="Parameter/field names to skip (e.g. --exclude csrf_token __token)",
    )
    scan.add_argument(
        "--exclude-file", metavar="FILE",
        help="Text file with one excluded parameter name per line",
    )
    scan.add_argument(
        "--exclude-urls-file", metavar="FILE",
        help=(
            "Text file with URLs/prefixes to skip during crawl and attack "
            "(one entry per line, lines starting with # are ignored)."
        ),
    )
    scan.add_argument(
        "--target-url", dest="target_urls", action="append", default=[],
        metavar="URL_OR_PREFIX",
        help=(
            "Additional URL/origin/prefix to crawl and attack. Repeat for multiple "
            "applications or separate authenticated areas."
        ),
    )
    scan.add_argument(
        "--target-urls-file", metavar="FILE",
        help="Text file with additional crawl-and-attack URL scopes, one per line.",
    )
    scan.add_argument(
        "--access-url", dest="access_urls", action="append", default=[],
        metavar="URL_OR_PREFIX",
        help=(
            "URL/origin/prefix that may be visited for login or supporting flows "
            "but must not be attacked. Repeat for external IdP or utility domains."
        ),
    )
    scan.add_argument(
        "--access-urls-file", metavar="FILE",
        help="Text file with access-only URL scopes, one per line.",
    )
    scan.add_argument(
        "--ctf", action="store_true", default=_CFG.get("ctf_mode", False),
        help="CTF mode: adds SSTI scanner and halves sleep delays for faster scanning",
    )
    scan.add_argument(
        "--ctf-flag-format", metavar="REGEX", default=_CFG.get("ctf_flag_pattern", ""),
        help=(
            "Regex pattern to search for CTF flags (default: auto-detect FLAG/CTF/HTB formats). "
            "Example: 'HTB{[^}]+}' or 'picoCTF{[^}]+}'"
        ),
    )
    scan.add_argument(
        "--cookie", metavar="COOKIES", default="",
        help="Pre-set cookies before scanning (e.g. 'session=abc; token=xyz')",
    )
    scan.add_argument(
        "--cookie-file", metavar="FILE", default="",
        help=(
            "JSON file containing cookies from a successful login session "
            "(browser export format: list of {name, value, domain, path, …} objects)."
        ),
    )
    scan.add_argument(
        "--low-priv-cookies", metavar="COOKIES", default="",
        help=(
            "Cookie string for a low-privilege session used to test vertical "
            "privilege escalation (e.g. 'session=lowprivtoken')."
        ),
    )
    scan.add_argument(
        "--low-priv-cookie-file", metavar="FILE", default="",
        help="JSON file containing low-privilege session cookies (same format as --cookie-file).",
    )
    # Custom HTTP headers (Authorization, X-API-Key, …) — applied to BOTH the
    # Playwright browser context and every direct httpx call site.
    scan.add_argument(
        "-H", "--header", metavar="HEADER", action="append", default=[],
        help=(
            "Custom HTTP header to send with every request, "
            "in 'Name: Value' form. Repeat to send multiple "
            "(e.g. -H 'Authorization: Bearer abc' -H 'X-Tenant: foo')."
        ),
    )
    scan.add_argument(
        "--header-file", metavar="FILE", default="",
        help=(
            "File containing custom HTTP headers. Accepts JSON object, YAML "
            "map, or one 'Name: Value' line per row."
        ),
    )
    scan.add_argument(
        "--header-refresh-cmd", metavar="CMD", default="",
        help=(
            "Shell command whose stdout supplies refreshed HTTP headers "
            "(same format as --header-file). Useful for systems whose "
            "Authorization token must be rotated periodically."
        ),
    )
    scan.add_argument(
        "--header-refresh-interval", metavar="SECONDS", type=float, default=0.0,
        help=(
            "Re-run --header-refresh-cmd this often during the scan "
            "(seconds). 0 disables periodic refresh."
        ),
    )
    scan.add_argument(
        "--auth-user", metavar="USER", default=_CFG.get("auth_user", ""),
        help="Username/email for login form auto-fill",
    )
    scan.add_argument(
        "--auth-pass", metavar="PASS", default=_CFG.get("auth_pass", ""),
        help="Password for login form auto-fill",
    )
    scan.add_argument(
        "--include-registration", action="store_true",
        default=not _CFG.get("skip_registration", True),
        help=(
            "Also test registration / sign-up forms (config default: "
            f"{'include' if not _CFG.get('skip_registration', True) else 'skip'})."
        ),
    )
    scan.add_argument(
        "--allow-state-changing-probes", action="store_true",
        default=_CFG.get("allow_state_changing_probes", False),
        help=(
            "Permit intrusive probes that may mutate server state, e.g. privesc "
            "verb tampering with POST/PUT/PATCH against blocked privileged URLs. "
            "Off by default; only enable against systems you are authorised to "
            "modify (a staging/test environment)."
        ),
    )
    scan.add_argument(
        "--no-planner", action="store_true",
        default=not _CFG.get("use_planner", True),
        help="Disable the AI attack planner.",
    )
    scan.add_argument(
        "--interactive-plan", action="store_true",
        default=_CFG.get("interactive_plan", False),
        help="Open the interactive plan editor before attacking.",
    )
    scan.add_argument(
        "--no-open-report", action="store_true",
        default=not _CFG.get("open_report", True),
        help="Do not automatically open the HTML report after scanning.",
    )
    # CI-3: Proxy support
    scan.add_argument(
        "--proxy", metavar="URL", default=_CFG.get("proxy", ""),
        help=(
            "HTTP proxy URL for all browser/HTTP requests "
            "(e.g. http://127.0.0.1:8080 for Burp Suite / mitmproxy)."
        ),
    )
    scan.add_argument("--tls-client-cert", metavar="FILE", default=_CFG.get("tls_client_cert", ""),
                      help="PEM client certificate for mutual TLS targets.")
    scan.add_argument("--tls-client-key", metavar="FILE", default=_CFG.get("tls_client_key", ""),
                      help="PEM private key for --tls-client-cert.")
    scan.add_argument("--tls-client-pfx", metavar="FILE", default=_CFG.get("tls_client_pfx", ""),
                      help="PKCS#12/PFX client certificate for Playwright browser access.")
    scan.add_argument("--tls-client-cert-password", metavar="TEXT", default=_CFG.get("tls_client_cert_password", ""),
                      help="Passphrase for the client certificate key or PFX file.")
    scan.add_argument("--tls-ca-cert", metavar="FILE", default=_CFG.get("tls_ca_cert", ""),
                      help="CA bundle used to verify the target certificate for httpx requests.")
    scan.add_argument("--tls-verify", action="store_true", default=_CFG.get("tls_verify", False),
                      help="Verify target TLS certificates. By default WScan keeps browser compatibility by ignoring HTTPS errors.")
    # Auth-1: Login automation
    scan.add_argument(
        "--login-url", metavar="URL", default=_CFG.get("login_url", ""),
        help="URL of the login page for automatic authentication before scanning.",
    )
    scan.add_argument(
        "--login-user-field", metavar="NAME", default=_CFG.get("login_user_field", "username"),
        help=f"Username input field name on the login form (default: {_CFG.get('login_user_field','username')}).",
    )
    scan.add_argument(
        "--login-pass-field", metavar="NAME", default=_CFG.get("login_pass_field", "password"),
        help=f"Password input field name on the login form (default: {_CFG.get('login_pass_field','password')}).",
    )
    scan.add_argument(
        "--login-success", metavar="TEXT", default=_CFG.get("login_success_indicator", ""),
        help="Substring expected in the post-login URL or page to confirm success.",
    )
    # MFA (2FA) automation via external MCP servers. Secrets live in env
    # (TOTP_SECRET_* / MCP_EMAIL_SERVER_*); see README.
    scan.add_argument(
        "--mfa-type", metavar="KIND", choices=["totp", "email"],
        default=(_CFG.get("mfa_type") or None),
        help="Solve login MFA via external MCP: 'totp' (mcp-totp-authenticator) "
             "or 'email' (mcp-email-server). Configure via WSCAN_MFA_* env. "
             "Unset → falls back to WSCAN_MFA_TYPE env.",
    )
    scan.add_argument(
        "--mfa-field", metavar="NAME", default=_CFG.get("mfa_field", ""),
        help="One-time-code input field name/id on the login form (default: otp).",
    )
    scan.add_argument(
        "--mfa-email-account", metavar="EMAIL", default=_CFG.get("mfa_email_account", ""),
        help="MFA メール受信に使うアカウント名（mcp-email-server に登録済みの "
             "account_name。通常はメールアドレス）。空ならば WSCAN_MFA_EMAIL_ACCOUNT "
             "env を使う（既存設定をそのまま利用可能）。",
    )
    # 動的 IMAP 認証情報: ツールから直接渡すとサーバ側の事前登録なしで任意アドレス
    # を受信できる（mcp-email-server サブプロセスへ MCP_EMAIL_SERVER_* を注入）。
    # パスワードは環境変数 WSCAN_MFA_EMAIL_IMAP_PASSWORD でも渡せる（プロセス一覧
    # への露出を避けたい場合に推奨）。
    scan.add_argument(
        "--mfa-email-address", metavar="EMAIL", default=_CFG.get("mfa_email_address", ""),
        help="MFA メールのアドレス（動的 IMAP 設定。account 未指定時はこれを account_name に流用）。",
    )
    scan.add_argument(
        "--mfa-email-imap-host", metavar="HOST", default=_CFG.get("mfa_email_imap_host", ""),
        help="動的 IMAP: 受信サーバのホスト（指定すると動的設定モードになる）。",
    )
    scan.add_argument(
        "--mfa-email-imap-port", metavar="PORT", default=_CFG.get("mfa_email_imap_port", ""),
        help="動的 IMAP: ポート（既定 993）。",
    )
    scan.add_argument(
        "--mfa-email-imap-user", metavar="USER", default=_CFG.get("mfa_email_imap_user", ""),
        help="動的 IMAP: ログインユーザー名（既定はメールアドレス）。",
    )
    scan.add_argument(
        "--mfa-email-imap-password", metavar="PASS",
        default=_CFG.get("mfa_email_imap_password", ""),
        help="動的 IMAP: パスワード。WSCAN_MFA_EMAIL_IMAP_PASSWORD env でも可（推奨）。",
    )
    # config の値（bool/文字列）を choices に合う "true"/"false" へ正規化して既定にする。
    _imap_ssl_default = _CFG.get("mfa_email_imap_ssl", None)
    if isinstance(_imap_ssl_default, bool):
        _imap_ssl_default = "true" if _imap_ssl_default else "false"
    elif _imap_ssl_default is not None:
        _imap_ssl_default = str(_imap_ssl_default).strip().lower()
        if _imap_ssl_default not in ("true", "false"):
            _imap_ssl_default = None
    scan.add_argument(
        "--mfa-email-imap-ssl", metavar="BOOL", choices=["true", "false"],
        default=_imap_ssl_default,
        help="動的 IMAP: SSL を使うか（true/false、既定 true）。",
    )
    # A-3: Payload learning
    scan.add_argument(
        "--learning-file", metavar="FILE", default=_CFG.get("learning_file", ""),
        help="JSON file for payload continuous learning (default: config/payload_learning.json).",
    )
    # S-1: DOM XSS
    scan.add_argument(
        "--dom-xss", action="store_true", default=_CFG.get("dom_xss", False),
        help="Enable DOM-based XSS detection (hooks browser DOM sinks via Playwright).",
    )
    # Feature flags that can also be toggled via config
    scan.add_argument(
        "--no-ai-analysis", action="store_true",
        default=not _CFG.get("ai_analysis", True),
        help="Disable post-scan AI comprehensive analysis report.",
    )
    scan.add_argument(
        "--no-waf-detection", action="store_true",
        default=not _CFG.get("waf_detection", True),
        help="Disable WAF auto-detection probe before crawling.",
    )
    scan.add_argument(
        "--no-payload-learning", action="store_true",
        default=not _CFG.get("payload_learning", True),
        help="Disable payload continuous learning (don't load/save success rates).",
    )
    scan.add_argument(
        "--community-payloads",
        action=argparse.BooleanOptionalAction,
        default=_CFG.get("community_payloads", True),
        help="Enable generated community payloads from config/community_payloads.yaml.",
    )
    scan.add_argument(
        "--no-adaptive-payloads", action="store_true",
        default=False,
        help="Disable the second-pass LLM adaptive payload refinement per field.",
    )
    scan.add_argument(
        "--no-sitemap-crawl", action="store_true",
        default=not _CFG.get("sitemap_crawl", True),
        help="Disable sitemap.xml / robots.txt crawl seeding.",
    )
    scan.add_argument(
        "--concurrency", "-j", type=int, default=1, metavar="N",
        help=(
            "Number of parallel browser workers for Phase 3 (default: 1 = serial). "
            "Each worker gets its own Playwright page so N pages are attacked simultaneously. "
            "Recommended range: 2-4. Higher values increase speed but also server load."
        ),
    )
    scan.add_argument(
        "--fast", "-F", action="store_true", default=False,
        help=(
            "高速スキャンモード (ベストエフォート): ペイロード上限 12・深さ 1・遅延 0 で "
            "高リスク脆弱性を素早く発見する。各フラグで個別上書き可能。"
        ),
    )
    scan.add_argument(
        "--max-payloads", type=int, default=0, metavar="N",
        help=(
            "フィールド・チェックタイプ毎のペイロード上限 (0=無制限)。"
            "--fast 時のデフォルトは 12。単独でも指定可能。"
        ),
    )
    scan.add_argument(
        "--delay", type=float, default=_CFG.get("request_delay", 0.5), metavar="SECS",
        help=(
            "リクエスト間の待機秒数 (デフォルト: config scan.request_delay または 0.5)。"
            "--fast 指定時は 0 に上書きされる。本番環境への負荷軽減に活用。"
        ),
    )
    scan.add_argument(
        "--navigation-retries", type=int, default=_CFG.get("navigation_retries", 2), metavar="N",
        help=(
            "ページ遷移がタイムアウト/一時失敗した場合の再試行回数 "
            "(デフォルト: config scan.navigation_retries または 2)。"
        ),
    )
    scan.add_argument(
        "--no-sarif", action="store_true", default=False,
        help="SARIF 2.1.0 レポートファイル (report.sarif) の出力を無効にする。",
    )
    scan.add_argument(
        "--notify-webhook", metavar="URL", default="",
        help="脆弱性検出時に通知を POST する Slack / Webhook の URL。",
    )
    scan.add_argument(
        "--notify-severity", choices=["critical", "high", "medium", "low"],
        default="high", metavar="LEVEL",
        help="通知する最低重大度 (デフォルト: high)。",
    )
    scan.add_argument(
        "--har", metavar="FILE", default="",
        help="HAR ファイルからエンドポイントと Cookie をインポートしてスキャンのシードに使用する。",
    )
    scan.add_argument(
        "--manual-crawl", metavar="FILE", default=_CFG.get("manual_crawl_file", ""),
        help="手動巡回で保存した JSON から URL と Cookie をインポートしてスキャンのシードに使用する。",
    )
    # A: Multi-account privilege escalation
    scan.add_argument(
        "--accounts", metavar="USER:PASS,...",
        default="",
        help=(
            "Comma-separated list of user:password pairs for multi-account "
            "privilege escalation testing. "
            "Example: --accounts admin:admin123,user1:pass1,user2:pass2"
        ),
    )
    scan.add_argument(
        "--accounts-file", metavar="FILE",
        default="",
        help=(
            "YAML file with account list for privilege escalation testing. "
            "Format: accounts: [{username: x, password: y, role: z}]"
        ),
    )
    scan.add_argument(
        "--auto-register", action="store_true",
        default=_CFG.get("auto_register", False),
        help=(
            "Automatically register test accounts via detected registration forms "
            "and use them for privilege escalation testing."
        ),
    )
    scan.add_argument(
        "--auto-register-count", type=int, default=_CFG.get("auto_register_count", 2), metavar="N",
        help="Number of test accounts to auto-register (default: 2).",
    )
    # ①: SPA crawl
    scan.add_argument(
        "--spa-crawl", action="store_true",
        default=_CFG.get("spa_crawl", False),
        help=(
            "Enable SPA/dynamic content crawl: click interactive elements "
            "to discover routes rendered by React/Vue/Angular."
        ),
    )

    # I: Diff scan — previous output directory
    scan.add_argument(
        "--previous-scan", metavar="DIR",
        default=None,
        help=(
            "Path to a previous scan output directory (containing evidence.json). "
            "When specified, the report will highlight new / fixed / persistent findings."
        ),
    )

    # Auto-config wizard
    _ac_default = _CFG.get("auto_config", False)
    scan.add_argument(
        "--auto-config",
        action=argparse.BooleanOptionalAction,
        default=_ac_default,
        help=(
            "Run the LLM-powered scan configuration wizard before scanning. "
            "Interviews you about the target and auto-generates optimal settings. "
            "Use --no-auto-config to disable."
        ),
    )

    # ── import-payloads サブコマンド ───────────────────────────────
    import_payloads = sub.add_parser(
        "import-payloads",
        help="Fetch public payload lists and write config/community_payloads.yaml",
    )
    import_payloads.add_argument(
        "--output",
        default="config/community_payloads.yaml",
        metavar="FILE",
        help="Output YAML path (default: config/community_payloads.yaml).",
    )
    import_payloads.add_argument(
        "--allow-destructive",
        action="store_true",
        default=False,
        help="Keep destructive payload patterns that are filtered by default.",
    )
    import_payloads.add_argument(
        "--per-type-cap",
        type=int,
        default=None,
        metavar="N",
        help="Maximum payload count per check_type.",
    )
    import_payloads.add_argument(
        "--check",
        default="",
        metavar="xss,sqli",
        help="Comma-separated check_type list to import.",
    )

    # ── agent subcommand ───────────────────────────────────────────
    agent = sub.add_parser(
        "agent",
        help=(
            "Agent Browser Mode: LLM directly controls a real browser to autonomously "
            "discover and exploit vulnerabilities (requires browser-use)"
        ),
    )
    agent.add_argument("url", help="Target URL (e.g. https://example.com)")
    agent.add_argument(
        "--llm",
        choices=["claude", "openai", "ollama"],
        default=_CFG.get("llm_provider", "claude"),
        help=(
            "LLM provider that drives the browser agent "
            "(default: claude). Requires corresponding API key."
        ),
    )
    agent.add_argument(
        "--model", metavar="MODEL", default="",
        help=(
            "Model name (default: claude-sonnet-4-5-20250929 / gpt-4o-mini / llama3). "
            "Leave blank to use provider default."
        ),
    )
    agent.add_argument(
        "--ollama-url", metavar="URL",
        default=_CFG.get("ollama_url", "http://localhost:11434"),
        help=f"Ollama endpoint (default: {_CFG.get('ollama_url','http://localhost:11434')})",
    )
    _AGENT_CHECKS = [
        "xss", "sqli", "ssti", "os", "path_traversal",
        "ssrf", "open_redirect", "csrf", "header_injection",
    ]
    agent.add_argument(
        "--checks", nargs="+",
        choices=_AGENT_CHECKS,
        default=["xss", "sqli", "ssti", "os", "path_traversal", "ssrf"],
        metavar="CHECK",
        help=(
            "Vulnerability checks for the agent to test "
            "(default: xss sqli ssti os path_traversal ssrf). "
            "Available: " + ", ".join(_AGENT_CHECKS)
        ),
    )
    agent.add_argument(
        "--max-steps", type=int, default=100, metavar="N",
        help="Maximum agent steps before stopping (default: 100)",
    )
    agent.add_argument(
        "--headless", action="store_true", default=_CFG.get("headless", True),
        help="Run browser in headless mode (default: true)",
    )
    agent.add_argument(
        "--no-headless", action="store_true", default=False,
        help="Show browser window (disables headless)",
    )
    agent.add_argument(
        "--auth-user", metavar="USER", default=_CFG.get("auth_user", ""),
        help="Username for pre-scan login",
    )
    agent.add_argument(
        "--auth-pass", metavar="PASS", default=_CFG.get("auth_pass", ""),
        help="Password for pre-scan login",
    )
    agent.add_argument(
        "--login-url", metavar="URL", default=_CFG.get("login_url", ""),
        help="Login page URL (agent will log in before testing)",
    )
    agent.add_argument(
        "--output", "-o", metavar="DIR",
        default=_CFG.get("output_dir") or None,
        help="Output directory for report and evidence (default: output/agent_<timestamp>)",
    )
    agent.add_argument(
        "--port", type=int, default=_CFG.get("port", 8765),
        help=f"Monitoring dashboard port (default: {_CFG.get('port', 8765)})",
    )
    agent.add_argument(
        "--no-monitor", action="store_true", default=False,
        help="Disable the real-time monitoring dashboard",
    )
    agent.add_argument(
        "--no-open-report", action="store_true", default=False,
        help="Do not automatically open the HTML report after scanning",
    )

    # triage subcommand
    triage = sub.add_parser(
        "triage",
        help="Fast vulnerability assessment: crawl and analyse page structure without sending payloads",
    )
    triage.add_argument("url", help="Target URL")
    triage.add_argument(
        "--depth", "-d", type=int, default=_CFG.get("depth", 2), metavar="N",
        help=f"Crawl depth (default: {_CFG.get('depth', 2)})",
    )
    triage.add_argument(
        "--headless", action="store_true", default=True,
        help="Run browser in headless mode (default: true for triage)",
    )
    triage.add_argument(
        "--proxy", metavar="URL", default=_CFG.get("proxy", ""),
        help="HTTP proxy URL",
    )
    triage.add_argument(
        "--timeout", type=int, default=_CFG.get("timeout", 20), metavar="SECS",
        help=f"Page load timeout in seconds (default: {_CFG.get('timeout', 20)})",
    )
    triage.add_argument(
        "--llm", choices=["ollama", "claude", "openai", "gemini", "none"],
        default=_CFG.get("llm_provider", "none"),
        help="LLM provider for AI attack-strategy insights (default: none)",
    )
    triage.add_argument(
        "--ollama-model", default=_CFG.get("ollama_model", "llama3"), metavar="MODEL",
    )
    triage.add_argument(
        "--openai-model", default=_CFG.get("openai_model", "gpt-4o-mini"), metavar="MODEL",
    )
    triage.add_argument(
        "--gemini-model", default=_CFG.get("gemini_model", "gemini-2.0-flash"), metavar="MODEL",
    )
    triage.add_argument(
        "--claude-model", default=_CFG.get("claude_model", "claude-haiku-4-5-20251001"), metavar="MODEL",
    )
    for role in ("planner", "payload", "adaptive", "triage", "report"):
        triage.add_argument(
            f"--{role}-model",
            default=_CFG.get("role_models", {}).get(role, ""),
            metavar="MODEL",
            help=f"Override the {role} LLM model. Defaults to the provider model.",
        )
    triage.add_argument(
        "--output", "-o", metavar="FILE",
        help="Save triage report as JSON to this file path",
    )

    # ── serve subcommand (GUI-first: start dashboard, configure via browser) ──
    serve = sub.add_parser(
        "serve",
        help="Start the dashboard server only — configure and launch scans from the browser",
    )
    serve.add_argument(
        "--port", type=int, default=_CFG.get("port", 8765),
        help=f"Dashboard port (default: {_CFG.get('port', 8765)})",
    )
    serve.add_argument(
        "--host", default=os.environ.get("WSCAN_HOST", _CFG.get("host", "0.0.0.0")),
        metavar="ADDR",
        help="Interface to bind (default: 0.0.0.0 — reachable from the intranet). "
             "Use 127.0.0.1 to restrict to localhost.",
    )
    serve.add_argument(
        "--auth-token", default=os.environ.get("WSCAN_AUTH_TOKEN", _CFG.get("auth_token", "")),
        metavar="TOKEN",
        help="Shared access token. When set, the web UI requires login and the "
             "API requires an 'Authorization: Bearer <token>' header. "
             "Can also be supplied via the WSCAN_AUTH_TOKEN environment variable.",
    )
    serve.add_argument(
        "--insecure", dest="insecure", action="store_true", default=False,
        help="Allow binding to a PUBLIC (non-private) address WITHOUT an auth token. "
             "Intranet binds (loopback / private IPs) are already allowed unauthenticated "
             "for in-house use; this flag is only needed to expose the control panel "
             "unauthenticated on a global IP (strongly discouraged).",
    )
    serve.add_argument(
        "--open-browser", dest="open_browser", action="store_true", default=None,
        help="Open a browser on the host after start (default: only when bound to localhost).",
    )
    serve.add_argument(
        "--no-open-browser", dest="open_browser", action="store_false",
        help="Never open a browser on the host (recommended for headless servers).",
    )

    # A-4: Natural language setup subcommand
    setup = sub.add_parser("setup", help="Interactively configure scan options via natural language")
    setup.add_argument("description", nargs="?", default="",
                       help="Natural language description of the target")
    setup.add_argument("--llm", choices=["ollama", "claude", "openai", "gemini", "none"],
                       default=_CFG.get("llm_provider", "ollama"))
    setup.add_argument("--ollama-model", default=_CFG.get("ollama_model", "llama3"), metavar="MODEL")
    setup.add_argument("--ollama-url", default=_CFG.get("ollama_url", "http://localhost:11434"), metavar="URL")

    # M: Batch scan subcommand
    batch_cmd = sub.add_parser(
        "batch",
        help="複数ターゲットを YAML ファイルで一括スキャンする",
        description="YAML ファイルに定義された複数 URL を順次スキャンし、統合サマリーを生成します。",
    )
    batch_cmd.add_argument(
        "targets_file", metavar="TARGETS_YAML",
        help="バッチ定義 YAML ファイルのパス",
    )
    batch_cmd.add_argument(
        "--output", "-o", metavar="DIR", default="",
        help="統合レポートの出力ベースディレクトリ (デフォルト: output/batch_<timestamp>/)",
    )

    # H: Flow recorder subcommand
    record = sub.add_parser(
        "record",
        help="Record browser interactions as a replayable JSON flow file",
    )
    record.add_argument("url", help="Start URL to navigate to when recording begins")
    record.add_argument(
        "--output", "-o", default="flows/recording.json", metavar="FILE",
        help="Output path for the recorded flow JSON (default: flows/recording.json)",
    )
    record.add_argument(
        "--headless", action="store_true", default=False,
        help="Run in headless mode (not recommended for recording)",
    )

    manual = sub.add_parser(
        "manual-crawl",
        help="Open a visible browser, record manual browsing, and save scan seed JSON",
    )
    manual.add_argument("url", help="Start URL to navigate to when manual crawling begins")
    manual.add_argument(
        "--output", "-o", default="flows/manual_crawl.json", metavar="FILE",
        help="Output path for the manual crawl JSON (default: flows/manual_crawl.json)",
    )
    manual.add_argument(
        "--headless", action="store_true", default=False,
        help="Run in headless mode (not recommended for manual crawling)",
    )
    manual.add_argument(
        "--proxy", metavar="URL", default=_CFG.get("proxy", ""),
        help="HTTP proxy URL for the manual crawl browser",
    )

    args = parser.parse_args()
    args.ollama_model_explicit = any(
        a == "--ollama-model" or a.startswith("--ollama-model=")
        for a in sys.argv[1:]
    )
    args.role_model_explicit = {
        role: any(
            a == f"--{role}-model" or a.startswith(f"--{role}-model=")
            for a in sys.argv[1:]
        )
        for role in ("planner", "payload", "adaptive", "triage", "report")
    }
    args.role_models = {
        role: getattr(args, f"{role}_model", "").strip()
        for role in ("planner", "payload", "adaptive", "triage", "report")
        if getattr(args, f"{role}_model", "").strip()
    }
    return args


def _load_cookie_file(path: str, console) -> list:
    """Load cookies from a JSON export file. Returns a list of cookie dicts."""
    if not path:
        return []
    try:
        from wscan.textio import read_text_resilient
        raw = read_text_resilient(path).strip()
        data = json.loads(raw)
        if isinstance(data, list):
            return data
        # Some exporters wrap as {"cookies": [...]}
        if isinstance(data, dict):
            for key in ("cookies", "Cookie", "cookie"):
                if isinstance(data.get(key), list):
                    return data[key]
        console.print(f"[yellow]Warning: unexpected cookie file format in {path}[/yellow]")
        return []
    except Exception as ex:
        console.print(f"[yellow]Warning: could not load cookie file '{path}': {ex}[/yellow]")
        return []


def _llm_model_display(args) -> str:
    """Return a short model info string for the startup banner."""
    role_models = getattr(args, "role_models", {}) or {}
    role_suffix = ""
    if role_models:
        role_suffix = "  [dim]roles: " + ", ".join(
            f"{role}={model}" for role, model in sorted(role_models.items())
        ) + "[/dim]"
    if args.llm == "ollama":
        return f"Model    : [blue]{args.ollama_model}[/blue] (Ollama){role_suffix}"
    if args.llm == "openai":
        return f"Model    : [blue]{args.openai_model}[/blue] (OpenAI){role_suffix}"
    if args.llm == "gemini":
        return f"Model    : [blue]{args.gemini_model}[/blue] (Gemini){role_suffix}"
    if args.llm == "claude":
        return f"Model    : [blue]{args.claude_model}[/blue] (Claude){role_suffix}"
    return "Model    : [dim]none[/dim]"


async def _resolve_ollama_model(args, console) -> None:
    """Choose an installed Ollama model when the user did not specify one."""
    if getattr(args, "llm", "") != "ollama":
        return

    try:
        import httpx
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{getattr(args, 'ollama_url', 'http://localhost:11434')}/api/tags")
        if resp.status_code != 200:
            return
        names = [m.get("name", "") for m in resp.json().get("models", []) if m.get("name")]
    except Exception:
        return

    if not names:
        return

    def _select(current: str) -> str:
        if current in names:
            return current
        preferred_exact = [
            "qwen2.5-coder:latest",
            "qwen2.5-coder",
            "qwen3:8b",
            "qwen3:latest",
            "llama3.1:8b",
            "llama3.1:latest",
            "llama3:latest",
        ]
        selected = next((name for name in preferred_exact if name in names), "")
        if not selected:
            for prefix in ("qwen2.5-coder", "qwen3", "llama3.1", "llama3", "gemma3"):
                selected = next((name for name in names if name.startswith(prefix)), "")
                if selected:
                    break
        return selected or current

    if not getattr(args, "ollama_model_explicit", False):
        selected = _select(getattr(args, "ollama_model", ""))
        if selected != getattr(args, "ollama_model", ""):
            console.print(
                f"[cyan]Ollama model auto-selected:[/cyan] "
                f"[green]{selected}[/green] "
                f"[dim](configured default '{args.ollama_model}' is not installed)[/dim]"
            )
            args.ollama_model = selected

    role_models = dict(getattr(args, "role_models", {}) or {})
    explicit = getattr(args, "role_model_explicit", {}) or {}
    changed_roles = []
    for role, model in list(role_models.items()):
        if explicit.get(role):
            continue
        selected = _select(model)
        if selected != model:
            role_models[role] = selected
            changed_roles.append(f"{role}={selected}")
            setattr(args, f"{role}_model", selected)
    if changed_roles:
        console.print(
            "[cyan]Ollama role model auto-selected:[/cyan] "
            + "[green]" + ", ".join(changed_roles) + "[/green]"
        )
    args.role_models = role_models


async def run_agent(args):
    """Agent Browser Mode — LLM autonomously controls the browser to find vulnerabilities."""
    import uvicorn
    from rich.console import Console
    from rich.panel import Panel
    from wscan.monitor import MonitorServer
    from wscan.agent_engine import AgentEngine

    console = Console()

    headless = not getattr(args, "no_headless", False)

    model_display = args.model or "(default)"
    console.print(Panel.fit(
        f"[bold magenta]WScan — Agent Browser Mode[/bold magenta]\n"
        f"Target  : [yellow]{args.url}[/yellow]\n"
        f"LLM     : [blue]{args.llm}[/blue] / {model_display}\n"
        f"Checks  : [green]{', '.join(args.checks)}[/green]\n"
        f"Steps   : [dim]max {args.max_steps}[/dim]",
        border_style="magenta",
    ))

    if getattr(args, "no_monitor", False):
        monitor = MonitorServer(port=args.port)
        engine = AgentEngine(
            url=args.url,
            llm_provider=args.llm,
            llm_model=args.model or "",
            ollama_url=getattr(args, "ollama_url", "http://localhost:11434"),
            checks=args.checks,
            headless=headless,
            auth_user=getattr(args, "auth_user", "") or "",
            auth_pass=getattr(args, "auth_pass", "") or "",
            login_url=getattr(args, "login_url", "") or "",
            max_steps=args.max_steps,
            output_dir=args.output or None,
            open_report=not getattr(args, "no_open_report", False),
            monitor=monitor,
            port=args.port,
        )
        await engine.run()
        return

    # With monitoring dashboard
    monitor = MonitorServer(port=args.port)
    config = uvicorn.Config(
        app=monitor.app,
        host="0.0.0.0",
        port=args.port,
        log_level="error",
    )
    server = uvicorn.Server(config)

    async def run_agent_task():
        await asyncio.sleep(1.5)
        console.print(
            f"\n[cyan]Monitoring dashboard:[/cyan] "
            f"[underline]http://localhost:{args.port}[/underline]"
        )
        webbrowser.open(f"http://localhost:{args.port}")

        try:
            engine = AgentEngine(
                url=args.url,
                llm_provider=args.llm,
                llm_model=args.model or "",
                ollama_url=getattr(args, "ollama_url", "http://localhost:11434"),
                checks=args.checks,
                headless=headless,
                auth_user=getattr(args, "auth_user", "") or "",
                auth_pass=getattr(args, "auth_pass", "") or "",
                login_url=getattr(args, "login_url", "") or "",
                max_steps=args.max_steps,
                output_dir=args.output or None,
                open_report=not getattr(args, "no_open_report", False),
                monitor=monitor,
                port=args.port,
            )
            await engine.run()
            console.print("[dim]Dashboard is still running — press Ctrl+C to stop.[/dim]")
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            console.print(f"\n[red]Error: {exc}[/red]")
            raise
        finally:
            server.should_exit = True

    await asyncio.gather(server.serve(), run_agent_task())


async def run_scan(args):
    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    # ── Fast mode preset ──────────────────────────────────────────────
    # Apply defaults only for options the user did NOT explicitly set.
    # Explicit CLI flags always win over the preset.
    if getattr(args, "fast", False):
        _DEPTH_DEFAULT    = 2
        _FORMS_DEFAULT    = 50
        _CONC_DEFAULT     = 1
        _CHECKS_DEFAULT   = ["sqli", "xss", "os"]  # defined in add_argument default
        _LLM_DEFAULT      = "ollama"
        if args.depth       == _DEPTH_DEFAULT:  args.depth       = 1
        if args.max_forms   == _FORMS_DEFAULT:  args.max_forms   = 3
        if args.concurrency == _CONC_DEFAULT:   args.concurrency = 2
        if args.checks      == _CHECKS_DEFAULT: args.checks      = ["sqli", "xss"]
        if args.llm         == _LLM_DEFAULT:    args.llm         = "none"
        if not args.headless:                   args.headless    = True
        if not getattr(args, "no_planner",        False): args.no_planner        = True
        if not getattr(args, "no_waf_detection",  False): args.no_waf_detection  = True
        if not getattr(args, "no_sitemap_crawl",  False): args.no_sitemap_crawl  = True
        if not getattr(args, "no_ai_analysis",    False): args.no_ai_analysis    = True
        if getattr(args, "max_payloads", 0) == 0:         args.max_payloads      = 12
        args.delay = 0.0  # fast mode forces zero delay
        console.print(
            "[bold yellow]⚡ FAST MODE[/bold yellow] — "
            f"ペイロード上限 {args.max_payloads}、遅延 0、深さ {args.depth}"
        )

    await _resolve_ollama_model(args, console)

    checks_display = ', '.join(args.checks) if args.checks else "all IPA checks"
    planner_display = "off" if getattr(args, "no_planner", False) else "on (AI-driven)"
    concurrency_val = getattr(args, "concurrency", 1)
    concurrency_display = (
        f"[bold green]{concurrency_val} workers[/bold green]"
        if concurrency_val > 1
        else "[dim]serial[/dim]"
    )
    console.print(Panel.fit(
        f"[bold cyan]WScan - Web Security Scanner[/bold cyan]\n"
        f"Target   : [yellow]{args.url}[/yellow]\n"
        f"Checks   : [green]{checks_display}[/green]\n"
        f"Planner  : [cyan]{planner_display}[/cyan]\n"
        f"Depth    : [blue]{args.depth}[/blue]   "
        f"LLM: [blue]{args.llm}[/blue]   "
        f"Headless: [blue]{args.headless}[/blue]   "
        f"Workers: {concurrency_display}\n"
        + _llm_model_display(args),
        border_style="cyan",
    ))

    # ── Auto-config wizard (opt-in) ────────────────────────────────
    _run_auto_config = bool(getattr(args, "auto_config", False))
    if _run_auto_config:
        from wscan.payload_gen import PayloadGenerator
        from wscan.auto_config import run_wizard, apply_to_args
        _pg = PayloadGenerator(
            provider=args.llm,
            ollama_model=getattr(args, "ollama_model", "llama3"),
            ollama_url=getattr(args, "ollama_url", "http://localhost:11434"),
            openai_model=getattr(args, "openai_model", "gpt-4o-mini"),
            gemini_model=getattr(args, "gemini_model", "gemini-2.0-flash"),
            claude_model=getattr(args, "claude_model", "claude-haiku-4-5-20251001"),
            role_models=getattr(args, "role_models", {}),
        )
        _wizard_result = await run_wizard(_pg)
        if _wizard_result is not None:
            apply_to_args(_wizard_result, args)
            # Rebuild checks display after wizard
            checks_display = ', '.join(args.checks) if args.checks else "all IPA checks"
            console.print(f"[cyan]Auto-config applied:[/cyan] checks=[green]{checks_display}[/green]  "
                          f"depth=[blue]{args.depth}[/blue]")

    # Build exclude list from --exclude and --exclude-file
    exclude_fields = list(args.exclude)
    if args.exclude_file:
        try:
            from wscan.textio import read_text_resilient
            lines = read_text_resilient(args.exclude_file).splitlines()
            exclude_fields += [l.strip() for l in lines if l.strip() and not l.startswith("#")]
        except Exception as ex:
            console.print(f"[yellow]Warning: Could not read exclude file: {ex}[/yellow]")

    if exclude_fields:
        console.print(f"Excluded params : [yellow]{', '.join(exclude_fields)}[/yellow]")

    # Build cookie list from --cookie-file (JSON export format)
    cookie_list: list = _load_cookie_file(getattr(args, "cookie_file", "") or "", console)
    if cookie_list:
        console.print(f"Auth cookies    : [green]{len(cookie_list)} cookie(s) loaded from file[/green]")

    # Build low-privilege cookie list from --low-priv-cookie-file
    low_priv_cookie_list: list = _load_cookie_file(
        getattr(args, "low_priv_cookie_file", "") or "", console
    )
    low_priv_cookies: str = getattr(args, "low_priv_cookies", "") or ""
    if low_priv_cookie_list:
        console.print(
            f"Low-priv cookies: [cyan]{len(low_priv_cookie_list)} cookie(s) loaded — "
            f"vertical privilege-escalation testing enabled[/cyan]"
        )
    elif low_priv_cookies:
        console.print(
            "[cyan]Low-priv cookies provided — "
            "vertical privilege-escalation testing enabled[/cyan]"
        )

    # Build exclude-urls list from --exclude-urls-file
    exclude_urls: list = []
    excl_urls_file = getattr(args, "exclude_urls_file", None)
    if excl_urls_file:
        try:
            from wscan.textio import read_text_resilient
            lines = read_text_resilient(excl_urls_file).splitlines()
            exclude_urls = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
            console.print(f"Excluded URLs   : [yellow]{len(exclude_urls)} entry/entries from {excl_urls_file}[/yellow]")
        except Exception as ex:
            console.print(f"[yellow]Warning: Could not read exclude-urls file: {ex}[/yellow]")

    def _read_scope_file(path: str) -> list[str]:
        if not path:
            return []
        try:
            from wscan.textio import read_text_resilient
            lines = read_text_resilient(path).splitlines()
            return [l.strip() for l in lines if l.strip() and not l.lstrip().startswith("#")]
        except Exception as ex:
            console.print(f"[yellow]Warning: Could not read scope file {path}: {ex}[/yellow]")
            return []

    target_urls = [
        *_CFG.get("target_urls", []),
        *(getattr(args, "target_urls", []) or []),
        *_read_scope_file(getattr(args, "target_urls_file", "") or ""),
    ]
    access_urls = [
        *_CFG.get("access_urls", []),
        *(getattr(args, "access_urls", []) or []),
        *_read_scope_file(getattr(args, "access_urls_file", "") or ""),
    ]
    if target_urls or access_urls:
        console.print(
            f"Scope           : [cyan]{len(target_urls)}[/cyan] additional attack, "
            f"[cyan]{len(access_urls)}[/cyan] access-only"
        )

    # Build checks list (add dom_xss if requested, allow wizard to have updated args.checks)
    checks_list = list(args.checks)
    if getattr(args, "dom_xss", False) and "dom_xss" not in checks_list:
        checks_list.append("dom_xss")

    # A: Build accounts list from --accounts or --accounts-file
    import yaml as _yaml
    _accounts_list: list = []
    _accounts_str = getattr(args, "accounts", "") or ""
    if _accounts_str:
        for pair in _accounts_str.split(","):
            pair = pair.strip()
            if ":" in pair:
                user, pw = pair.split(":", 1)
                _accounts_list.append({"username": user.strip(), "password": pw.strip(), "role": "user"})
    _accounts_file = getattr(args, "accounts_file", "") or ""
    if _accounts_file:
        try:
            from wscan.textio import read_text_resilient
            _af_data = _yaml.safe_load(read_text_resilient(_accounts_file)) or {}
            _accounts_list.extend(_af_data.get("accounts", []))
        except Exception as _ex:
            console.print(f"[yellow]Warning: Could not read accounts file: {_ex}[/yellow]")
    if _accounts_list:
        console.print(
            f"Accounts        : [cyan]{len(_accounts_list)} account(s) loaded for "
            f"privilege escalation testing[/cyan]"
        )

    # Build custom HTTP header set: --header-file underneath, CLI -H values on top.
    from wscan.header_manager import parse_header_args, load_header_file
    _resolved_headers: dict = {}
    _hdr_file = getattr(args, "header_file", "") or ""
    if _hdr_file:
        try:
            _resolved_headers.update(load_header_file(_hdr_file))
        except Exception as _hex:
            console.print(f"[yellow]Warning: could not load header file: {_hex}[/yellow]")
    _cli_headers = parse_header_args(getattr(args, "header", []) or [])
    _resolved_headers.update(_cli_headers)
    if _resolved_headers:
        console.print(
            f"Custom headers  : [cyan]{len(_resolved_headers)} header(s) "
            f"({', '.join(_resolved_headers.keys())})[/cyan]"
        )
    if (getattr(args, "header_refresh_cmd", "") or "") and (
        getattr(args, "header_refresh_interval", 0.0) or 0.0
    ) > 0:
        console.print(
            f"Header refresh  : [cyan]every "
            f"{getattr(args, 'header_refresh_interval', 0.0)}s via shell command[/cyan]"
        )

    def _engine_kwargs(monitor_obj):
        return dict(
            url=args.url,
            monitor=monitor_obj,
            payloads_file=args.payloads,
            depth=args.depth,
            headless=args.headless,
            llm_provider=args.llm,
            ollama_model=args.ollama_model,
            openai_model=args.openai_model,
            gemini_model=args.gemini_model,
            claude_model=args.claude_model,
            role_models=getattr(args, "role_models", {}),
            checks=checks_list,
            output_dir=args.output,
            timeout=args.timeout,
            max_forms=args.max_forms,
            exclude_fields=exclude_fields,
            exclude_urls=exclude_urls,
            target_urls=target_urls,
            access_urls=access_urls,
            ctf_mode=getattr(args, "ctf", False),
            ctf_flag_pattern=getattr(args, "ctf_flag_format", "") or "",
            cookies=getattr(args, "cookie", "") or "",
            cookie_list=cookie_list,
            low_priv_cookies=low_priv_cookies,
            low_priv_cookie_list=low_priv_cookie_list,
            auth_user=getattr(args, "auth_user", "") or "",
            auth_pass=getattr(args, "auth_pass", "") or "",
            use_planner=not getattr(args, "no_planner", False),
            interactive_plan=getattr(args, "interactive_plan", False),
            skip_registration=not getattr(args, "include_registration", False),
            open_report=not getattr(args, "no_open_report", False),
            proxy=getattr(args, "proxy", "") or "",
            login_url=getattr(args, "login_url", "") or "",
            login_user_field=getattr(args, "login_user_field", "username") or "username",
            login_pass_field=getattr(args, "login_pass_field", "password") or "password",
            login_success_indicator=getattr(args, "login_success", "") or "",
            # None=未指定(env に委ねる) / ""=明示無効 / "totp"|"email"=明示有効
            mfa_type=getattr(args, "mfa_type", None),
            mfa_field=getattr(args, "mfa_field", "") or "",
            mfa_email_account=getattr(args, "mfa_email_account", "") or "",
            mfa_email_imap={
                "address": getattr(args, "mfa_email_address", "") or "",
                "host": getattr(args, "mfa_email_imap_host", "") or "",
                "port": getattr(args, "mfa_email_imap_port", "") or "",
                "user": getattr(args, "mfa_email_imap_user", "") or "",
                "password": getattr(args, "mfa_email_imap_password", "") or "",
                "ssl": {"true": True, "false": False}.get(
                    getattr(args, "mfa_email_imap_ssl", None)
                ),
            },
            learning_file=getattr(args, "learning_file", "") or "",
            # Feature on/off flags (from config or CLI)
            enable_ai_analysis=not getattr(args, "no_ai_analysis", False),
            enable_waf_detection=not getattr(args, "no_waf_detection", False),
            enable_payload_learning=not getattr(args, "no_payload_learning", False),
            enable_community_payloads=getattr(args, "community_payloads", True),
            enable_adaptive_payloads=not getattr(args, "no_adaptive_payloads", False),
            enable_sitemap_crawl=not getattr(args, "no_sitemap_crawl", False),
            enable_llm_web_browsing=getattr(args, "llm_web_browsing", False),
            concurrency=getattr(args, "concurrency", 1),
            flows=getattr(args, "flows", None) or [],
            max_payloads=getattr(args, "max_payloads", 0),
            fast_mode=getattr(args, "fast", False),
            # A: Multi-account privilege escalation
            accounts=_accounts_list,
            auto_register=getattr(args, "auto_register", False),
            auto_register_count=getattr(args, "auto_register_count", 2),
            allow_state_changing_probes=getattr(args, "allow_state_changing_probes", False),
            # ①: SPA crawl
            spa_crawl=getattr(args, "spa_crawl", False),
            # I: 差分スキャン
            previous_scan_dir=getattr(args, "previous_scan", None),
            # N: リクエストレート制御
            request_delay=getattr(args, "delay", 0.5),
            navigation_retries=getattr(args, "navigation_retries", 2),
            # K: SARIF 出力
            sarif=not getattr(args, "no_sarif", False),
            # L: Webhook/Slack 通知
            webhook_url=getattr(args, "notify_webhook", "") or "",
            notify_min_severity=getattr(args, "notify_severity", "high"),
            # O: HAR インポート
            har_path=getattr(args, "har", "") or "",
            manual_crawl_path=getattr(args, "manual_crawl", "") or "",
            # Custom headers + periodic refresh
            headers=_resolved_headers,
            header_refresh_cmd=getattr(args, "header_refresh_cmd", "") or "",
            header_refresh_interval=getattr(args, "header_refresh_interval", 0.0) or 0.0,
            tls_client_cert=getattr(args, "tls_client_cert", "") or "",
            tls_client_key=getattr(args, "tls_client_key", "") or "",
            tls_client_pfx=getattr(args, "tls_client_pfx", "") or "",
            tls_client_cert_password=getattr(args, "tls_client_cert_password", "") or "",
            tls_ca_cert=getattr(args, "tls_ca_cert", "") or "",
            tls_verify=getattr(args, "tls_verify", False),
        )

    if args.no_monitor:
        # Simple mode - no web dashboard
        from wscan.engine import ScanEngine

        engine = ScanEngine(**_engine_kwargs(None))
        await engine.run()
        return

    # ── With monitoring dashboard ──────────────────────────────────
    import uvicorn
    from wscan.monitor import MonitorServer
    from wscan.engine import ScanEngine

    monitor = MonitorServer(port=args.port)
    config = uvicorn.Config(
        app=monitor.app,
        host="0.0.0.0",
        port=args.port,
        log_level="error",
    )
    server = uvicorn.Server(config)

    async def run_scanner_task():
        # Wait for uvicorn to be ready
        await asyncio.sleep(1.5)

        console.print(
            f"\n[cyan]Monitoring dashboard:[/cyan] "
            f"[underline]http://localhost:{args.port}[/underline]"
        )
        webbrowser.open(f"http://localhost:{args.port}")

        try:
            engine = ScanEngine(**_engine_kwargs(monitor))
            await engine.run()

            console.print(
                f"\n[bold green]Scan complete![/bold green]  "
                f"Report: [cyan]{engine.output_dir / 'report.html'}[/cyan]"
            )
            console.print(
                "[dim]Dashboard is still running — press Ctrl+C to stop.[/dim]"
            )
            # Keep dashboard alive so the user can review findings
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            console.print(f"\n[red]Error: {exc}[/red]")
            raise
        finally:
            server.should_exit = True

    await asyncio.gather(
        server.serve(),
        run_scanner_task(),
    )


def _bind_is_intranet(host: str) -> bool:
    """bind 先がイントラネット（ループバック / プライベートIP）かを判定する。

    0.0.0.0 / :: は全インタフェース待受なので、実際の LAN IP を解決して判定する。
    判定できない／グローバルIPの場合は False（＝無認証公開は要 --insecure）。
    """
    import ipaddress
    import socket
    h = (host or "").strip()
    if h in ("127.0.0.1", "localhost", "::1"):
        return True
    candidates = []
    if h in ("0.0.0.0", "::", ""):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            candidates.append(s.getsockname()[0])
            s.close()
        except Exception:
            return False
    else:
        candidates.append(h)
    for c in candidates:
        try:
            ip = ipaddress.ip_address(c)
        except ValueError:
            return False
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
    return False


async def run_serve(args):
    """
    GUI-first mode: start the dashboard server, show configuration form in
    the browser, then launch the scan engine once the user submits settings.
    """
    import uvicorn
    from rich.console import Console
    from rich.panel import Panel
    from wscan.monitor import MonitorServer
    from wscan.engine import ScanEngine

    console = Console()
    port = args.port
    host = getattr(args, "host", "0.0.0.0") or "0.0.0.0"
    auth_token = (getattr(args, "auth_token", "") or "").strip()

    # Decide whether to pop a browser on the host. Default: only when bound to
    # loopback (a local developer). On a real server (0.0.0.0 / a LAN IP) we
    # stay headless unless --open-browser was passed explicitly.
    is_loopback = host in ("127.0.0.1", "localhost", "::1")
    is_intranet = _bind_is_intranet(host)

    # 安全策: 認証無しで起動してよいのはイントラネット（ループバック / プライベートIP）まで。
    # 社内イントラネット利用を想定し、プライベート網への無認証起動は許可する（警告のみ）。
    # グローバルIPへ無認証で晒そうとした場合のみ既定で拒否する（--insecure で明示許容）。
    if not is_intranet and not auth_token and not getattr(args, "insecure", False):
        console.print(Panel.fit(
            "[bold red]起動を中止しました — 無認証でグローバル公開しようとしています[/bold red]\n"
            f"  Bind: [underline]{host}:{port}[/underline]（プライベートIPではありません）\n"
            "  この状態ではインターネット上の誰でもスキャナを操作できてしまいます。\n\n"
            "  対処のいずれか:\n"
            "   • トークンを設定: [cyan]--auth-token <TOKEN>[/cyan] または環境変数 WSCAN_AUTH_TOKEN\n"
            "   • イントラネット限定にする: [cyan]--host 127.0.0.1[/cyan] やプライベートIPへ bind\n"
            "   • どうしても無認証公開する: [cyan]--insecure[/cyan]（非推奨）",
            border_style="red",
        ))
        return

    # イントラネットへ無認証で起動するケースは警告を出す（社内利用の既定動作）。
    if is_intranet and not is_loopback and not auth_token:
        console.print(Panel.fit(
            "[bold yellow]無認証でイントラネットに公開します[/bold yellow]\n"
            f"  Bind: [underline]{host}:{port}[/underline]（プライベート網）\n"
            "  同一ネットワークの誰でもスキャナを操作できます。社内限定での利用に留めてください。\n"
            "  認証を有効化するには [cyan]--auth-token <TOKEN>[/cyan] / 環境変数 WSCAN_AUTH_TOKEN。",
            border_style="yellow",
        ))

    if getattr(args, "open_browser", None) is None:
        open_browser = is_loopback
    else:
        open_browser = bool(args.open_browser)

    # Best-effort LAN address hint so the operator knows the intranet URL.
    lan_hint = ""
    if not is_loopback:
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            lan_ip = s.getsockname()[0]
            s.close()
            lan_hint = f"\n  Intranet : [underline]http://{lan_ip}:{port}[/underline]"
        except Exception:
            lan_hint = ""

    auth_line = (
        "  Auth     : [green]token required[/green] (login page enabled)"
        if auth_token else
        "  Auth     : [yellow]DISABLED[/yellow] — anyone on the network can use this scanner!"
    )
    console.print(Panel.fit(
        f"[bold cyan]WScan — Server Mode[/bold cyan]\n"
        f"  Bind     : [underline]http://{host}:{port}[/underline]"
        f"{lan_hint}\n"
        f"  Local    : [underline]http://localhost:{port}[/underline]\n"
        f"{auth_line}\n"
        "  The dashboard stays up — run as many scans as you like.\n"
        "  Press Ctrl+C to stop.",
        border_style="cyan",
    ))

    monitor = MonitorServer(port=port, auth_token=auth_token)
    # 出力の保持ポリシー（env が優先、無ければ config/wscan.yaml の値）。
    try:
        monitor.retention_days = float(
            os.environ.get("WSCAN_RETENTION_DAYS", _CFG.get("retention_days", 0)) or 0
        )
        monitor.retention_max_scans = int(
            os.environ.get("WSCAN_RETENTION_MAX_SCANS", _CFG.get("retention_max_scans", 0)) or 0
        )
    except (TypeError, ValueError):
        monitor.retention_days = 0
        monitor.retention_max_scans = 0

    def _split_hosts(env_name: str, cfg_key: str) -> list:
        raw = os.environ.get(env_name, "")
        if raw.strip():
            return [h.strip() for h in raw.replace(",", " ").split() if h.strip()]
        return list(_CFG.get(cfg_key, []) or [])
    monitor.allowed_target_hosts = _split_hosts("WSCAN_ALLOWED_HOSTS", "allowed_target_hosts")
    monitor.denied_target_hosts = _split_hosts("WSCAN_DENIED_HOSTS", "denied_target_hosts")
    try:
        monitor.scan_max_seconds = float(
            os.environ.get("WSCAN_SCAN_TIMEOUT_MIN", _CFG.get("scan_timeout_minutes", 0)) or 0
        ) * 60
    except (TypeError, ValueError):
        monitor.scan_max_seconds = 0
    _tp = os.environ.get("WSCAN_TRUST_PROXY", "")
    monitor.trust_proxy = (
        _tp.strip().lower() in ("1", "true", "yes", "on") if _tp.strip()
        else bool(_CFG.get("trust_proxy", False))
    )
    if monitor.allowed_target_hosts:
        console.print(f"[dim]対象スコープ(許可): {', '.join(monitor.allowed_target_hosts)}[/dim]")
    if monitor.denied_target_hosts:
        console.print(f"[dim]対象スコープ(拒否): {', '.join(monitor.denied_target_hosts)}[/dim]")

    monitor.default_scan_cfg = {
        "checks": _CFG.get("checks", ["sqli", "xss", "os"]),
        "depth": _CFG.get("depth", 2),
        "timeout": _CFG.get("timeout", 30),
        "max_forms": _CFG.get("max_forms", 50),
        "request_delay": _CFG.get("request_delay", 0.5),
        "navigation_retries": _CFG.get("navigation_retries", 2),
        "proxy": _CFG.get("proxy", ""),
        "tls_client_cert": _CFG.get("tls_client_cert", ""),
        "tls_client_key": _CFG.get("tls_client_key", ""),
        "tls_client_pfx": _CFG.get("tls_client_pfx", ""),
        "tls_client_cert_password": _CFG.get("tls_client_cert_password", ""),
        "tls_ca_cert": _CFG.get("tls_ca_cert", ""),
        "tls_verify": _CFG.get("tls_verify", False),
        "llm": _CFG.get("llm_provider", "ollama"),
        "ollama_model": _CFG.get("ollama_model", "llama3"),
        "openai_model": _CFG.get("openai_model", "gpt-4o-mini"),
        "gemini_model": _CFG.get("gemini_model", "gemini-2.0-flash"),
        "claude_model": _CFG.get("claude_model", "claude-haiku-4-5-20251001"),
        "role_models": _CFG.get("role_models", {}),
        "auth_user": _CFG.get("auth_user", ""),
        "auth_pass": _CFG.get("auth_pass", ""),
        "login_url": _CFG.get("login_url", ""),
        "login_user_field": _CFG.get("login_user_field", "username"),
        "login_pass_field": _CFG.get("login_pass_field", "password"),
        "login_success_indicator": _CFG.get("login_success_indicator", ""),
        "mfa_type": _CFG.get("mfa_type", ""),
        "mfa_field": _CFG.get("mfa_field", ""),
        "mfa_email_account": _CFG.get("mfa_email_account", ""),
        "mfa_email_address": _CFG.get("mfa_email_address", ""),
        "mfa_email_imap_host": _CFG.get("mfa_email_imap_host", ""),
        "mfa_email_imap_port": _CFG.get("mfa_email_imap_port", ""),
        "mfa_email_imap_user": _CFG.get("mfa_email_imap_user", ""),
        "mfa_email_imap_ssl": _CFG.get("mfa_email_imap_ssl", ""),
        "exclude_fields": ", ".join(_CFG.get("exclude_fields", []) or []),
        "exclude_urls": "\n".join(_CFG.get("exclude_urls", []) or []),
        "target_urls": "\n".join(_CFG.get("target_urls", []) or []),
        "access_urls": "\n".join(_CFG.get("access_urls", []) or []),
        "manual_crawl_file": _CFG.get("manual_crawl_file", ""),
        "toggles": {
            "headless": _CFG.get("headless", False),
            "skip_registration": _CFG.get("skip_registration", True),
            "open_report": _CFG.get("open_report", True),
            "use_planner": _CFG.get("use_planner", True),
            "interactive_plan": _CFG.get("interactive_plan", False),
            "enable_ai_analysis": _CFG.get("ai_analysis", True),
            "enable_waf_detection": _CFG.get("waf_detection", True),
            "enable_payload_learning": _CFG.get("payload_learning", True),
            "enable_community_payloads": _CFG.get("community_payloads", True),
            "enable_sitemap_crawl": _CFG.get("sitemap_crawl", True),
            "spa_crawl": _CFG.get("spa_crawl", False),
            "interactive_crawl_review": _CFG.get("interactive_crawl_review", False),
            "ctf_mode": _CFG.get("ctf_mode", False),
            "tls_verify": _CFG.get("tls_verify", False),
            "allow_state_changing_probes": _CFG.get("allow_state_changing_probes", False),
        },
    }
    # /api/auto-config エンドポイント用に LLM 設定をキャッシュ
    _llm_section = _CFG.get("llm", {}) if isinstance(_CFG.get("llm"), dict) else {}
    monitor.llm_cfg = {
        "provider":     _CFG.get("llm_provider", _llm_section.get("provider", "none")),
        "ollama_model": _CFG.get("ollama_model", _llm_section.get("ollama_model", "llama3")),
        "ollama_url":   _CFG.get("ollama_url",   _llm_section.get("ollama_url", "http://localhost:11434")),
        "openai_model": _CFG.get("openai_model", _llm_section.get("openai_model", "gpt-4o-mini")),
        "gemini_model": _CFG.get("gemini_model", _llm_section.get("gemini_model", "gemini-2.0-flash")),
        "claude_model": _CFG.get("claude_model", _llm_section.get("claude_model", "claude-haiku-4-5-20251001")),
        "role_models":  _CFG.get("role_models", _llm_section.get("models", {}) or {}),
    }
    config = uvicorn.Config(app=monitor.app, host=host, port=port, log_level="error")
    server = uvicorn.Server(config)

    async def run_one_scan(cfg):
        """Run a single scan for one submitted config and return when done.

        Unlike the legacy one-shot flow, this never shuts the server down —
        the dashboard stays up so the operator can launch the next scan.
        """
        url = cfg.get("url", "").strip()
        if not url:
            console.print("[red]No target URL provided — ignoring request.[/red]")
            await monitor.emit_status(
                "ターゲットURLが空のため、リクエストを無視しました。", "error"
            )
            return

        checks = cfg.get("checks", ["sqli", "xss", "os"]) or ["sqli", "xss", "os"]
        # ダッシュボードで選択された LLM 設定を auto-config エンドポイント用にも反映
        if cfg.get("llm"):
            monitor.llm_cfg.update({
                "provider":     cfg.get("llm", "none"),
                "ollama_model": cfg.get("ollama_model", "llama3"),
                "ollama_url":   cfg.get("ollama_url", "http://localhost:11434"),
                "openai_model": cfg.get("openai_model", "gpt-4o-mini"),
                "gemini_model": cfg.get("gemini_model", "gemini-2.0-flash"),
                "claude_model": cfg.get("claude_model", "claude-haiku-4-5-20251001"),
                "role_models":  cfg.get("role_models", {}) or {},
            })
        await monitor.emit_scan_started(cfg)

        # ── Agent Browser mode ─────────────────────────────────────
        if cfg.get("agent_mode"):
            from wscan.agent_engine import AgentEngine
            await monitor.emit_status(f"Agent Browser: {url} をスキャン中", "running")
            try:
                agent_engine = AgentEngine(
                    url=url,
                    llm_provider=cfg.get("llm", "claude") or "claude",
                    llm_model=cfg.get("agent_model", "") or "",
                    ollama_url=cfg.get("agent_ollama_url", "http://localhost:11434") or "http://localhost:11434",
                    checks=checks,
                    headless=bool(cfg.get("headless", True)),
                    auth_user=cfg.get("auth_user", "") or "",
                    auth_pass=cfg.get("auth_pass", "") or "",
                    login_url=cfg.get("login_url", "") or "",
                    max_steps=int(cfg.get("agent_max_steps", 50)),
                    open_report=bool(cfg.get("open_report", True)),
                    monitor=monitor,
                    port=port,
                )
                await agent_engine.run()
                console.print("[dim]Agent scan finished — dashboard ready for the next scan.[/dim]")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                console.print(f"\n[red]Agent Error: {exc}[/red]")
                await monitor.emit_status(f"Agent エラー: {exc}", "error")
            return

        # ── Hybrid Mode: Agent偵察 (Phase 1) → 通常スキャン (Phase 2) ────
        seed_urls: list = []
        if cfg.get("hybrid_mode"):
            from wscan.agent_engine import AgentEngine
            await monitor.emit_status("🔀 ハイブリッド Phase 1: Agent偵察中...", "running")
            try:
                recon_engine = AgentEngine(
                    url=url,
                    llm_provider=cfg.get("hybrid_llm", "claude") or "claude",
                    llm_model=cfg.get("hybrid_model", "") or "",
                    ollama_url=cfg.get("hybrid_ollama_url", "http://localhost:11434") or "http://localhost:11434",
                    checks=[],
                    headless=bool(cfg.get("headless", True)),
                    auth_user=cfg.get("auth_user", "") or "",
                    auth_pass=cfg.get("auth_pass", "") or "",
                    login_url=cfg.get("login_url", "") or "",
                    max_steps=int(cfg.get("hybrid_max_steps", 30)),
                    open_report=False,
                    monitor=monitor,
                    port=port,
                )
                handoff = await recon_engine.run_recon()
                seed_urls = handoff.discovered_urls
                await monitor.emit_status(
                    f"🔀 Phase 2: {len(seed_urls)} URL 発見済み。通常スキャン開始...", "running"
                )
            except Exception as exc:
                console.print(
                    f"[yellow]⚠ 偵察フェーズ失敗 ({exc})。"
                    f"URL シードなしで通常スキャンを続行します。[/yellow]"
                )
                seed_urls = []

        await monitor.emit_status(f"Starting scan of {url}", "running")

        try:
            engine = ScanEngine(
                url=url,
                monitor=monitor,
                depth=int(cfg.get("depth", 2)),
                timeout=int(cfg.get("timeout", 30)),
                max_forms=int(cfg.get("max_forms", 50)),
                headless=bool(cfg.get("headless", True)),
                concurrency=int(cfg.get("concurrency", 1)),
                checks=checks,
                llm_provider=cfg.get("llm", "none") or "none",
                ollama_model=cfg.get("ollama_model", "llama3") or "llama3",
                openai_model=cfg.get("openai_model", "gpt-4o-mini") or "gpt-4o-mini",
                gemini_model=cfg.get("gemini_model", "gemini-2.0-flash") or "gemini-2.0-flash",
                claude_model=cfg.get("claude_model", "claude-haiku-4-5-20251001") or "claude-haiku-4-5-20251001",
                role_models=cfg.get("role_models", {}) or {},
                auth_user=cfg.get("auth_user", "") or "",
                auth_pass=cfg.get("auth_pass", "") or "",
                cookies=cfg.get("cookies", "") or "",
                proxy=cfg.get("proxy", "") or "",
                tls_client_cert=cfg.get("tls_client_cert", "") or "",
                tls_client_key=cfg.get("tls_client_key", "") or "",
                tls_client_pfx=cfg.get("tls_client_pfx", "") or "",
                tls_client_cert_password=cfg.get("tls_client_cert_password", "") or "",
                tls_ca_cert=cfg.get("tls_ca_cert", "") or "",
                tls_verify=bool(cfg.get("tls_verify", False)),
                login_url=cfg.get("login_url", "") or "",
                login_user_field=cfg.get("login_user_field", "username") or "username",
                login_pass_field=cfg.get("login_pass_field", "password") or "password",
                login_success_indicator=cfg.get("login_success_indicator", "") or "",
                # ダッシュボードは常に mfa_type を送る("" = UI で「無効」選択)。
                # "" は env を上書きして無効化。キー欠落(None)時のみ env に委ねる。
                mfa_type=cfg.get("mfa_type"),
                mfa_field=cfg.get("mfa_field", "") or "",
                mfa_email_account=cfg.get("mfa_email_account", "") or "",
                mfa_email_imap={
                    "address": cfg.get("mfa_email_address", "") or "",
                    "host": cfg.get("mfa_email_imap_host", "") or "",
                    "port": cfg.get("mfa_email_imap_port", "") or "",
                    "user": cfg.get("mfa_email_imap_user", "") or "",
                    "password": cfg.get("mfa_email_imap_password", "") or "",
                    "ssl": cfg.get("mfa_email_imap_ssl")
                    if isinstance(cfg.get("mfa_email_imap_ssl"), bool)
                    else {"true": True, "false": False}.get(
                        str(cfg.get("mfa_email_imap_ssl") or "").lower()
                    ),
                },
                payloads_file=cfg.get("payloads_file") or None,
                learning_file=cfg.get("learning_file") or None,
                output_dir=cfg.get("output_dir") or None,
                cookie_list=[],
                low_priv_cookies=cfg.get("low_priv_cookies", "") or "",
                low_priv_cookie_list=[],
                use_planner=bool(cfg.get("use_planner", True)),
                interactive_plan=bool(cfg.get("interactive_plan", False)),
                interactive_crawl_review=bool(cfg.get("interactive_crawl_review", False)),
                skip_registration=bool(cfg.get("skip_registration", True)),
                open_report=bool(cfg.get("open_report", True)),
                enable_ai_analysis=bool(cfg.get("enable_ai_analysis", True)),
                enable_waf_detection=bool(cfg.get("enable_waf_detection", True)),
                enable_payload_learning=bool(cfg.get("enable_payload_learning", True)),
                enable_community_payloads=bool(cfg.get("enable_community_payloads", True)),
                enable_sitemap_crawl=bool(cfg.get("enable_sitemap_crawl", True)),
                enable_llm_web_browsing=bool(cfg.get("enable_llm_web_browsing", False)),
                ctf_mode=bool(cfg.get("ctf_mode", False)),
                ctf_flag_pattern=cfg.get("ctf_flag_pattern", "") or "",
                exclude_fields=cfg.get("exclude_fields", []) or [],
                exclude_urls=cfg.get("exclude_urls", []) or [],
                target_urls=cfg.get("target_urls", []) or [],
                access_urls=cfg.get("access_urls", []) or [],
                flows=cfg.get("flows", []) or [],
                spa_crawl=bool(cfg.get("spa_crawl", False)),
                fast_mode=bool(cfg.get("fast_mode", False)),
                max_payloads=int(cfg.get("max_payloads", 0)),
                request_delay=float(cfg.get("request_delay", 0.5) or 0.0),
                navigation_retries=int(cfg.get("navigation_retries", 2)),
                accounts=cfg.get("accounts", []) or [],
                auto_register=bool(cfg.get("auto_register", False)),
                auto_register_count=int(cfg.get("auto_register_count", 2)),
                allow_state_changing_probes=bool(
                    cfg.get(
                        "allow_state_changing_probes",
                        _CFG.get("allow_state_changing_probes", False),
                    )
                ),
                seed_urls=seed_urls or None,
                manual_crawl_path=cfg.get("manual_crawl_file", "") or "",
                headers=cfg.get("headers", {}) or {},
                header_refresh_cmd=cfg.get("header_refresh_cmd", "") or "",
                header_refresh_interval=float(cfg.get("header_refresh_interval", 0.0) or 0.0),
            )
            # アウトプットフォルダに送信された設定スナップショットを保存しておく
            # (ブラウザの自動ダウンロードに頼らず、レポートと同じ場所に残す)
            try:
                import json as _json, datetime as _dt
                snapshot_path = engine.output_dir / "scan_config.json"
                snapshot_path.write_text(
                    _json.dumps(
                        {
                            "tool": "WScan",
                            "kind": "wscan-scan-config-snapshot",
                            "submitted_at": _dt.datetime.now().isoformat(timespec="seconds"),
                            "config": _redact_secrets(cfg),
                        },
                        ensure_ascii=False,
                        indent=2,
                    ),
                    encoding="utf-8",
                )
            except Exception as _exc:
                console.print(f"[yellow]設定スナップショット保存に失敗: {_exc}[/yellow]")
            await engine.run()
            # 完了時に手動巡回JSONがあればアウトプットフォルダにコピー
            try:
                manual_src = cfg.get("manual_crawl_file", "") or ""
                if manual_src:
                    src_path = Path(manual_src)
                    if src_path.exists() and src_path.is_file():
                        import shutil as _shutil
                        _shutil.copy2(src_path, engine.output_dir / src_path.name)
            except Exception as _exc:
                console.print(f"[yellow]手動巡回JSONのコピーに失敗: {_exc}[/yellow]")
            console.print(
                f"\n[bold green]Scan complete![/bold green]  "
                f"Report: [cyan]{engine.output_dir / 'report.html'}[/cyan]"
            )
            console.print("[dim]Dashboard ready for the next scan.[/dim]")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            console.print(f"\n[red]Error: {exc}[/red]")
            await monitor.emit_status(f"スキャン中にエラーが発生しました: {exc}", "error")
        return

    async def serve_task():
        # Open a browser on the host only when explicitly requested or when the
        # server is bound to localhost (i.e. a developer running it locally).
        await asyncio.sleep(1.2)
        if open_browser:
            try:
                webbrowser.open(f"http://localhost:{port}")
            except Exception:
                pass

        # 起動時に保持ポリシーを一度適用（前回までの古い成果物を整理）。
        try:
            pruned = monitor.prune_old_scans()
            if pruned:
                console.print(f"[dim]保持ポリシー: 古いスキャン {len(pruned)} 件を削除しました。[/dim]")
        except Exception:
            pass

        # Persistent loop: accept and run one scan at a time, indefinitely.
        while not server.should_exit:
            # While idle, KEEP the previous scan's results/status/report so
            # CI/API clients can still poll /api/v1/scan/results and fetch the
            # report after completion. The per-scan reset happens only when a new
            # scan is accepted (the request handlers set status=scanning and clear
            # findings), not the moment the previous result was published.
            monitor.scan_in_progress = False
            # NOTE: ここで event をクリアしない。直前の完了処理(await 通知送信)中に
            # スケジューラ/API が立てた要求を取りこぼし、しかも next_run は前進済みで
            # 1 周期スキップされるのを防ぐため、消費は「要求検出後」に行う。
            # Tell the dashboard it is ready for a new scan config.
            await monitor.emit_awaiting_config()
            # Wait until a config is submitted from the GUI / API / WebSocket,
            # but wake periodically so a shutdown (Ctrl+C) is honoured even when
            # the loop is otherwise idle and blocked on the event.
            while not server.should_exit and not monitor.scan_request_event.is_set():
                try:
                    await asyncio.wait_for(monitor.scan_request_event.wait(), timeout=0.5)
                except asyncio.TimeoutError:
                    pass
            if server.should_exit:
                break
            # 要求を消費（検出直後に同期的にクリア＋busy 化。間に await を挟まないので
            # 並行する別要求は scan_in_progress / event により確実に弾かれる）。
            monitor.scan_request_event.clear()
            monitor.scan_in_progress = True
            monitor.mark_scan_started()  # watchdog 計測開始
            # New scan accepted: clear the previous run's event log so this scan
            # starts from a clean slate in the dashboard. Also drop any pending
            # interactive modal (e.g. the idle awaiting_config) so a client that
            # reconnects mid-scan is not shown a stale config form / old review.
            monitor.event_history.clear()
            monitor.pending_interactive = None
            cfg = monitor.scan_request_data or {}
            try:
                if monitor.scan_max_seconds:
                    # watchdog はまず graceful な abort を要求する(scheduler_task)。
                    # それでも戻らないハングに備え、上限＋猶予(60s)で強制 cancel し、
                    # 「次のスキャンへ進む」を必ず保証する。
                    hard_timeout = monitor.scan_max_seconds + 60
                    try:
                        await asyncio.wait_for(run_one_scan(cfg), timeout=hard_timeout)
                    except asyncio.TimeoutError:
                        console.print(
                            f"\n[red]watchdog: スキャンが上限＋猶予({hard_timeout:.0f}秒)を"
                            f"超えたため強制終了しました。[/red]"
                        )
                        # status を error にし、ポータル/CI が「終わらないスキャン」を
                        # ポーリングし続けないよう可視化する。
                        monitor.api_scan_status = "error"
                        try:
                            await monitor.emit_status(
                                "スキャンが上限時間を超えたため強制終了しました。", "error"
                            )
                        except Exception:
                            pass
                else:
                    await run_one_scan(cfg)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                console.print(f"\n[red]Unexpected error: {exc}[/red]")
            finally:
                monitor.scan_in_progress = False
                # スキャン完了通知（ポータルで設定された Webhook へ）。
                try:
                    await monitor.send_scan_complete_notification()
                except Exception:
                    pass
                # スキャン完了毎に保持ポリシーを適用（実行中スキャンは保護）。
                try:
                    monitor.prune_old_scans()
                except Exception:
                    pass

    async def scheduler_task():
        # 定期スキャンの期限を監視し、アイドル時に1件ずつ起動する。
        await asyncio.sleep(3.0)
        while not server.should_exit:
            try:
                # ハングしたスキャンの自動停止（watchdog）。
                if monitor.watchdog_check():
                    console.print(
                        f"[yellow]watchdog: スキャンが上限時間({monitor.scan_max_seconds:.0f}秒)を"
                        f"超えたため中断を要求しました。[/yellow]"
                    )
                sid = monitor.trigger_due_schedules()
                if sid:
                    console.print(f"[dim]スケジュール {sid}: 定期スキャンを起動しました。[/dim]")
            except Exception:
                pass
            # 10 秒ごとにチェック（watchdog の粒度。shutdown も小刻みに確認）。
            for _ in range(10):
                if server.should_exit:
                    break
                await asyncio.sleep(1.0)

    # Run the server and the scan loop side by side. When the server shuts down
    # (Ctrl+C / SIGTERM), cancel the idle scan loop so the process exits promptly
    # instead of hanging on a pending scan-request wait.
    server_coro = asyncio.ensure_future(server.serve())
    worker_coro = asyncio.ensure_future(serve_task())
    scheduler_coro = asyncio.ensure_future(scheduler_task())
    try:
        await server_coro
    finally:
        worker_coro.cancel()
        scheduler_coro.cancel()
        for _c in (worker_coro, scheduler_coro):
            try:
                await _c
            except asyncio.CancelledError:
                pass


async def run_triage(args):
    """Triage mode — fast structural analysis without payload injection."""
    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    console.print(Panel.fit(
        f"[bold cyan]WScan Triage Mode[/bold cyan]\n"
        f"Target  : [yellow]{args.url}[/yellow]\n"
        f"Depth   : [blue]{args.depth}[/blue]   "
        f"LLM: [blue]{args.llm}[/blue]\n"
        "[dim]No payloads will be sent — structural and header analysis only[/dim]",
        border_style="cyan",
    ))

    from wscan.triage import TriageEngine, render_triage_report

    engine = TriageEngine(
        url=args.url,
        depth=args.depth,
        headless=getattr(args, "headless", True),
        proxy=getattr(args, "proxy", "") or "",
        timeout=getattr(args, "timeout", 20),
        llm_provider=getattr(args, "llm", "none"),
        ollama_model=getattr(args, "ollama_model", "llama3"),
        openai_model=getattr(args, "openai_model", "gpt-4o-mini"),
        gemini_model=getattr(args, "gemini_model", "gemini-2.0-flash"),
        claude_model=getattr(args, "claude_model", "claude-haiku-4-5-20251001"),
        role_models=getattr(args, "role_models", {}),
    )

    report = await engine.run()
    render_triage_report(report, console)

    # Optional JSON output
    output_file = getattr(args, "output", None)
    if output_file:
        Path(output_file).write_text(
            __import__("json").dumps(report.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        console.print(f"\n[green]Triage report saved:[/green] {output_file}")


async def run_setup(args):
    """A-4: Natural language scan configuration assistant."""
    from rich.console import Console
    from rich.panel import Panel
    console = Console()

    console.print(Panel.fit(
        "[bold cyan]WScan Setup Assistant[/bold cyan]\n"
        "Describe your target and I'll suggest optimal scan options.",
        border_style="cyan",
    ))

    description = args.description
    if not description:
        try:
            description = input("Describe your target (e.g. 'EC site with login, admin panel, REST API'): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(0)

    if not description:
        print("No description provided.")
        sys.exit(1)

    prompt = (
        f"You are a web security scanner configuration assistant.\n"
        f"The user wants to scan this target: {description}\n\n"
        f"Available checks: sqli, xss, dom_xss, os, ssti, path_traversal, "
        f"csrf, header_injection, mail_header, open_redirect, clickjacking, session, privesc, "
        f"nosql, deserialization, ssrf, graphql, jwt, cms, xxe, ldap, file_upload, "
        f"race_condition, websocket\n\n"
        f"Based on the description, suggest the optimal scan command. "
        f"Return a JSON object with these fields:\n"
        f"  checks: list of check names to enable\n"
        f"  depth: crawl depth (1-5)\n"
        f"  reason: brief explanation\n"
        f"  flags: additional CLI flags as a list of strings (e.g. ['--dom-xss', '--depth 3'])\n\n"
        f"Return ONLY valid JSON."
    )

    from wscan.payload_gen import PayloadGenerator
    pg = PayloadGenerator(
        provider=args.llm,
        ollama_model=args.ollama_model,
        ollama_url=getattr(args, "ollama_url", "http://localhost:11434"),
        openai_model=getattr(args, "openai_model", "gpt-4o-mini"),
        gemini_model=getattr(args, "gemini_model", "gemini-2.0-flash"),
        claude_model=getattr(args, "claude_model", "claude-haiku-4-5-20251001"),
        role_models=getattr(args, "role_models", {}),
    )

    suggestion = None
    if await pg._check_llm_available():
        try:
            import re as _re
            raw = await pg._call_llm(prompt) or []
            # _call_llm returns list; for setup we need text → call backends directly
            # Fallback: use text-based call
        except Exception:
            pass

    # Simple heuristic fallback
    checks = ["sqli", "xss", "os"]
    depth = 2
    flags: list[str] = []
    desc_lower = description.lower()
    if "api" in desc_lower or "rest" in desc_lower or "graphql" in desc_lower:
        checks += ["header_injection"]
    if "admin" in desc_lower or "dashboard" in desc_lower:
        checks += ["privesc"]
        depth = 3
    if "login" in desc_lower or "auth" in desc_lower:
        checks += ["session", "csrf"]
    if "redirect" in desc_lower or "link" in desc_lower:
        checks += ["open_redirect"]
    if "template" in desc_lower or "render" in desc_lower:
        checks += ["ssti"]
    if "dom" in desc_lower or "spa" in desc_lower or "react" in desc_lower or "vue" in desc_lower:
        flags.append("--dom-xss")
    checks = list(dict.fromkeys(checks))  # dedup

    cmd = f"python main.py scan <URL> --checks {' '.join(checks)} --depth {depth}"
    if flags:
        cmd += " " + " ".join(flags)

    console.print(f"\n[bold]Suggested scan command:[/bold]")
    console.print(f"  [green]{cmd}[/green]")
    console.print(f"\n[dim]Checks selected: {', '.join(checks)}[/dim]")
    console.print(f"[dim]Crawl depth: {depth}[/dim]")


async def run_batch(args):
    """M: 複数ターゲットを YAML バッチ定義ファイルでスキャンする。"""
    from rich.console import Console
    from pathlib import Path
    from wscan.batch_runner import BatchRunner

    console = Console()
    console.print(f"\n[bold cyan][Batch] バッチスキャン開始[/bold cyan]")
    console.print(f"  定義ファイル: [cyan]{args.targets_file}[/cyan]")

    runner = BatchRunner.load_from_yaml(args.targets_file)
    if getattr(args, "output", ""):
        runner.output_base = Path(args.output)

    await runner.run()

    console.print(runner.summary_text())
    summary_path = runner.save_batch_summary_json()
    console.print(f"\n  [dim]Batch summary:[/dim] {summary_path}")


async def run_record(args):
    """H: ブラウザ操作を記録して JSON フロー ファイルに保存する。"""
    from rich.console import Console
    from wscan.flow_recorder import FlowRecorder

    console = Console()
    recorder = FlowRecorder()
    console.print(f"\n[bold cyan][FlowRecorder] 記録モード開始[/bold cyan]")
    console.print(f"  対象 URL: [cyan]{args.url}[/cyan]")
    console.print(f"  出力先:   [cyan]{args.output}[/cyan]")
    console.print(f"  ブラウザ操作後、Ctrl+C で記録を終了してください。\n")
    try:
        steps = await recorder.record_interactive(
            start_url=args.url,
            output_path=args.output,
            headless=getattr(args, "headless", False),
        )
        console.print(f"\n[bold green]✓ {len(steps)} ステップを保存しました:[/bold green] {args.output}")
        console.print(
            f"\n[dim]このフロー ファイルをスキャンで使用するには:[/dim]\n"
            f"  python main.py scan <URL> --flows {args.output}"
        )
    except Exception as exc:
        console.print(f"[red]記録中にエラーが発生しました: {exc}[/red]")


async def run_manual_crawl(args):
    """Visible-browser manual crawl recording for scan seeding."""
    from rich.console import Console
    from wscan.manual_crawl import ManualCrawlSession

    console = Console()
    session = ManualCrawlSession()
    console.print(f"\n[bold cyan][Manual Crawl] 手動巡回を開始します[/bold cyan]")
    console.print(f"  対象 URL: [cyan]{args.url}[/cyan]")
    console.print(f"  出力先:   [cyan]{args.output}[/cyan]")
    console.print("  ブラウザで対象サイトを操作し、終了したら Ctrl+C を押してください。\n")
    try:
        await session.start(
            start_url=args.url,
            output_path=args.output,
            headless=getattr(args, "headless", False),
            proxy=getattr(args, "proxy", "") or "",
        )
        while True:
            await asyncio.sleep(1)
    except (KeyboardInterrupt, asyncio.CancelledError):
        status = await session.stop()
        console.print(
            f"\n[bold green]✓ 手動巡回を保存しました:[/bold green] {args.output}\n"
            f"  URL: [cyan]{status.get('url_count', 0)}[/cyan]  "
            f"Steps: [cyan]{status.get('step_count', 0)}[/cyan]"
        )
        console.print(
            f"\n[dim]この巡回結果をスキャンで使用するには:[/dim]\n"
            f"  python main.py scan {args.url} --manual-crawl {args.output}"
        )
    except Exception as exc:
        await session.stop()
        console.print(f"[red]手動巡回中にエラーが発生しました: {exc}[/red]")


def run_import_payloads(args):
    """公開ペイロード集を取得して community_payloads.yaml を生成する。"""
    from rich.console import Console
    from wscan.payload_importer import SOURCES, build_corpus, write_yaml

    console = Console()
    sources = SOURCES
    checks_arg = (getattr(args, "check", "") or "").strip()
    if checks_arg:
        requested = [c.strip() for c in checks_arg.split(",") if c.strip()]
        unknown = [c for c in requested if c not in SOURCES]
        if unknown:
            console.print(
                "[red]Unknown check_type:[/red] "
                + ", ".join(unknown)
                + f"\n[dim]Available: {', '.join(SOURCES)}[/dim]"
            )
            raise SystemExit(2)
        sources = {check_type: SOURCES[check_type] for check_type in requested}

    per_type_cap = getattr(args, "per_type_cap", None)
    if per_type_cap is not None and per_type_cap <= 0:
        console.print("[red]--per-type-cap must be a positive integer.[/red]")
        raise SystemExit(2)

    corpus = build_corpus(
        sources,
        allow_destructive=bool(getattr(args, "allow_destructive", False)),
        per_type_cap=per_type_cap,
    )
    write_yaml(args.output, corpus, sources=sources)

    console.print(f"[bold green]Community payloads written:[/bold green] {args.output}")
    for check_type, payloads in corpus.items():
        console.print(f"  {check_type}: [cyan]{len(payloads)}[/cyan]")


def main():
    # Make stdout/stderr tolerant of non-ASCII output (streaming LLM text,
    # payload snippets) on consoles whose native codec can't encode it.
    from wscan.textio import configure_console
    configure_console()
    args = parse_args()
    try:
        if args.command == "setup":
            asyncio.run(run_setup(args))
        elif args.command == "triage":
            asyncio.run(run_triage(args))
        elif args.command == "serve":
            asyncio.run(run_serve(args))
        elif args.command == "manual-crawl":
            asyncio.run(run_manual_crawl(args))
        elif args.command == "agent":
            asyncio.run(run_agent(args))
        elif args.command == "record":
            asyncio.run(run_record(args))
        elif args.command == "batch":
            asyncio.run(run_batch(args))
        elif args.command == "import-payloads":
            run_import_payloads(args)
        else:
            asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)


if __name__ == "__main__":
    main()
