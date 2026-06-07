"""公開ペイロード集を取得し、WScan 用 YAML へ正規化する。"""
from __future__ import annotations

import datetime as _dt
import re
import sys
from pathlib import Path
from typing import Mapping

import httpx
import yaml


# 取り込み対象は「スキャナが get_payloads() 経由で default/community を実際に投入する」
# check_type だけに限定する。ssti/ldap/nosql/xxe/dom_xss のスキャナは固定プローブ
# （＋文脈適応の evolution wave）のみを使い community を消費しないため、取り込むと
# 「ファイルにあるのにスキャンで使われない」誤解を生む。これらは context_mutator の
# 固定セットでカバーする。
SOURCES: dict[str, list[str]] = {
    "xss": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/XSS_Polyglots.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/IntrudersXSS.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/xss_payloads_quick.txt",
    ],
    "sqli": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Generic_Fuzz.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Generic_ErrorBased.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Auth_Bypass.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/SQLi_Polyglots.txt",
    ],
    "os": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/Intruder/command_exec.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Command%20Injection/Intruder/command-execution-unix.txt",
    ],
    "path_traversal": [
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/directory_traversal.txt",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/deep_traversal.txt",
    ],
}

USER_AGENT = "wscan-payload-importer/1.0"
_MARKDOWN_HEADING_RE = re.compile(r"^#{1,6}\s+\S")
_CONTROL_ONLY_RE = re.compile(r"^[\x00-\x1f\x7f]+$")
_DESTRUCTIVE_RE_LIST = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"rm\s+-rf\s+/",
        r"\bmkfs\b",
        r":\s*\(\)\s*\{",
        r"\bshutdown\b",
        r"\breboot\b",
        r"format\s+c:",
        r">\s*/dev/sda\b",
        # ── 破壊的 DDL/DML（検出には不要。スキーマ/データを壊す） ──
        r"\bdrop\s+(?:database|schema|table|view|index|function|procedure|trigger|user)\b",
        r"\btruncate\s+table\b",
        r"\bdelete\s+from\b",
        r"\balter\s+table\b[^\n]*\bdrop\b",
        # ── Windows のシステム改変（アカウント作成・FW無効化・RDP有効化） ──
        r"\bnet\s+user\b[^\n]*\/add",
        r"\bnet\s+localgroup\b[^\n]*\/add",
        r"\bnetsh\b[^\n]*\bfirewall\b",
        r"fDenyTSConnections",
        r"\bwmic\b[^\n]*\buseraccount\b[^\n]*\bcreate\b",
    )
]

# 外部コールバック/データ持ち出し/バインド・リバースシェル系。スキャン対象から
# 第三者へ通信を張る・情報を送り出す・待受シェルを立てる（= 検出プローブではなく
# 実害）ため、allow_destructive でも常に除外する。
# 例: Shellshock の `() { :;}; curl http://<外部IP>/...?user=`whoami``、
#     reverse/bind shell (`nc -e /bin/sh`, `bash -i`, `/dev/tcp/...`, perl/python socket)、
#     外部 script を動的読込する XSS ビーコン。
# ※ローカル読取の検出プローブ（`../../etc/shadow` 等）は持ち出しではないので除外しない。
_EXFILTRATION_RE_LIST = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        # Shellshock の持ち出しは外部 curl/wget を伴うので下の通信クライアント規則で捕捉する
        # （`() {` 自体は fork 爆弾 `:(){ … };:` 等の破壊系とも衝突するため、ここでは使わない）。
        r"curl|wget",  # 外向き通信クライアント（端末エスケープ等で難読化されても拾えるよう部分一致）
        r"\b(?:nslookup|dig|telnet|lwp-download|certutil)\b",
        r"Invoke-WebRequest|Net\.WebClient|DownloadString",  # PowerShell 外部取得
        # ── バインド/リバースシェル（対象上で待受・接続を張る＝検出プローブではなく実害） ──
        r"\bn(?:c|cat)\b|netcat",  # netcat 待受/接続
        r"-e\s*/bin/(?:sh|bash)",  # nc -e /bin/sh
        r"\bmkfifo\b",  # 名前付きパイプ式 reverse shell
        r"SOCK_STREAM|fsockopen|socket\(|/inet/tcp/|pty\.spawn|Net::Telnet",  # perl/python/ruby reverse shell
        r"/dev/tcp/",  # bash reverse shell / 外部送出
        r"\bbash\s+-i\b",  # 対話的 reverse shell
        r"createElement\(['\"]script['\"]\)[^\n]{0,60}\.src",  # 外部 script を動的読込する XSS ビーコン
        r"\bsrc\s*=\s*[\"']?(?:https?:)?//",  # 外部リソース読込（<script src=//host> 等。反射で第三者JSを実行）
    )
]


def parse_payload_lines(
    text: str,
    *,
    allow_destructive: bool = False,
    max_len: int = 2000,
) -> list[str]:
    """取得テキストを行単位のペイロード一覧へ正規化する。"""
    payloads: list[str] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if len(line) > max_len:
            continue
        if _CONTROL_ONLY_RE.fullmatch(line):
            continue
        if _MARKDOWN_HEADING_RE.match(line):
            continue
        if not allow_destructive and any(rx.search(line) for rx in _DESTRUCTIVE_RE_LIST):
            continue
        # 外部コールバック/持ち出しは allow_destructive でも常に除外（送信先が
        # 運用者の管理外＝第三者であり、認可テストでも適切でないため）。
        if any(rx.search(line) for rx in _EXFILTRATION_RE_LIST):
            continue
        if line in seen:
            continue
        seen.add(line)
        payloads.append(line)
    return payloads


def fetch_text(url: str, timeout: float = 20.0) -> str:
    """ネットワーク取得をこの関数に隔離する。"""
    resp = httpx.get(
        url,
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    )
    resp.raise_for_status()
    return resp.text


def build_corpus(
    sources: Mapping[str, list[str]] | None = None,
    *,
    allow_destructive: bool = False,
    per_type_cap: int | None = None,
) -> dict[str, list[str]]:
    """マニフェストを取得して check_type ごとのペイロード集合を作る。"""
    selected_sources = sources or SOURCES
    corpus: dict[str, list[str]] = {}
    for check_type, urls in selected_sources.items():
        merged: list[str] = []
        seen: set[str] = set()
        for url in urls:
            try:
                text = fetch_text(url)
            except Exception as exc:
                print(
                    f"[wscan] WARNING: payload source fetch failed: {url}: {exc}",
                    file=sys.stderr,
                )
                continue
            for payload in parse_payload_lines(
                text,
                allow_destructive=allow_destructive,
            ):
                if payload in seen:
                    continue
                seen.add(payload)
                merged.append(payload)
                if per_type_cap is not None and len(merged) >= per_type_cap:
                    break
            if per_type_cap is not None and len(merged) >= per_type_cap:
                break
        corpus[check_type] = merged
    return corpus


def _repo_urls_from_sources(sources: Mapping[str, list[str]]) -> list[str]:
    repos: list[str] = []
    seen: set[str] = set()
    for urls in sources.values():
        for url in urls:
            match = re.match(r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/", url)
            if not match:
                continue
            repo_url = f"https://github.com/{match.group(1)}/{match.group(2)}"
            if repo_url in seen:
                continue
            seen.add(repo_url)
            repos.append(repo_url)
    return repos


def write_yaml(
    path: str | Path,
    corpus: Mapping[str, list[str]],
    *,
    sources: Mapping[str, list[str]],
) -> None:
    """出典コメント付きで community_payloads.yaml を書き出す。"""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    generated_at = _dt.datetime.now(_dt.UTC).replace(microsecond=0).isoformat()
    repo_urls = _repo_urls_from_sources(sources)
    comments = [
        "# WScan Community Payloads",
        f"# 取得日時 (UTC): {generated_at}",
        "# 出典:",
        *[f"# - {repo_url}" for repo_url in repo_urls],
        "# 各上流リポジトリの LICENSE に従って利用してください。",
        "",
    ]
    body = yaml.safe_dump(
        dict(corpus),
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    output_path.write_text("\n".join(comments) + body, encoding="utf-8")
