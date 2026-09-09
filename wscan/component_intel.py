"""コンポーネント/バージョンの EOL 照会（endoflife.date）— 通常ツール層の外部エンリッチ。

サーバが開示する技術バナー（``Server`` / ``X-Powered-By`` / ``X-AspNet-Version`` /
``X-Generator``）や CMS 検出から得た **製品名+バージョン**を、無料の endoflife.date API へ
照会し、サポート終了（EOL）を判定する。全ローカル実装ではなく無料 API を叩く方針で、
API 情報（base URL・timeout 等）は設定で管理する（``config/wscan.yaml`` の ``component_intel``）。

設計原則（``llm_web_tools`` と同じ薄い足場）:
- **純粋関数**（``parse_components_from_headers`` / ``match_cycle`` / ``evaluate_eol``）は
  ネットワーク非依存でテスト可能。判定ロジックはここに集約する。
- **ネットワーク層**（``fetch_product_cycles`` / ``check_component_eol``）は **失敗しても raise せず**
  ``None`` を返す（スキャンを壊さない・偽陰性にしない）。任意の httpx client を注入でき、テストで
  差し替え可能。
- 外部へ送るのは **製品名（slug）のみ**。target URL・ヘッダ値全体・個人情報は送らない。

opt-in（``features.component_intel``＝既定 off）で、スキャンのネット非依存原則を壊さない。
"""
from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass
from typing import Optional

try:  # httpx はランタイム依存だが、純粋関数だけ使うテスト/経路では未 import でも動くように保護
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore


# 既定の endoflife.date base URL（設定で上書き可能）。
DEFAULT_EOL_BASE_URL = "https://endoflife.date"

# 既定の OSV.dev base URL（JS ライブラリの既知脆弱性照会・鍵不要）。
DEFAULT_OSV_BASE_URL = "https://api.osv.dev"

# 既定の NVD base URL（CVE 照会・任意 API キーでレート緩和）。
DEFAULT_NVD_BASE_URL = "https://services.nvd.nist.gov"

# NVD 照会用の **保守的な** vendor:product CPE マップ（限定オプション）。CPE の当たり判定は
# ノイズが多い（古い CVE も混じる）ため、対応付けが確実な少数の製品だけを対象にする。実測で
# 件数が返る vendor を採用。ここに無い製品は NVD 照会しない（誤 CPE で誤検知しない）。
_NVD_CPE_MAP: dict[str, str] = {
    "nginx": "cpe:2.3:a:f5:nginx",
    "php": "cpe:2.3:a:php:php",
    "apache": "cpe:2.3:a:apache:http_server",
    "httpd": "cpe:2.3:a:apache:http_server",
    "tomcat": "cpe:2.3:a:apache:tomcat",
    "openssl": "cpe:2.3:a:openssl:openssl",
}
_NVD_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1, "none": 0}

# ネットワーク層の既定タイムアウト（秒）。
DEFAULT_TIMEOUT = 8.0


@dataclass(frozen=True)
class Component:
    """検出した 1 コンポーネント（製品名+バージョン+開示元）。"""

    product: str      # 正規化した製品名（例: "nginx", "php", "apache"）
    version: str      # 検出バージョン（例: "1.18.0"）
    source: str       # 開示元（例: "server", "x-powered-by", "cms"）
    raw: str = ""     # 元の生値（監査用）


# ``Server`` / ``X-Powered-By`` の "name/version" 形（例: nginx/1.18.0, PHP/7.4.3）。
_BANNER_RE = re.compile(r"([A-Za-z][A-Za-z0-9_.+-]*)\s*/\s*([0-9][A-Za-z0-9_.+-]*)")
# ``X-Generator`` の "name version" 形（例: Drupal 7, WordPress 6.1）。
_GENERATOR_RE = re.compile(r"([A-Za-z][A-Za-z0-9_.+-]*)\s+v?([0-9][A-Za-z0-9_.+-]*)")

# 検出製品名（小文字）→ endoflife.date の product slug。
# ここに無い製品は EOL 照会をスキップする（保守側＝誤照会しない）。実測で存在する slug のみ。
_PRODUCT_SLUGS: dict[str, str] = {
    "nginx": "nginx",
    "apache": "apache",
    "httpd": "apache",
    "php": "php",
    "drupal": "drupal",
    "wordpress": "wordpress",
    "django": "django",
    "laravel": "laravel",
    "joomla": "joomla",
    "magento": "magento",
    "python": "python",
    "node": "nodejs",
    "nodejs": "nodejs",
    "openssl": "openssl",
    "tomcat": "tomcat",
    "iis": "internet-explorer",  # 注: IIS 単体 slug は無いため既定では扱わない（下の除外を参照）
}
# slug が信頼できないものは照会対象から外す（誤 slug で誤判定しないため）。
_EXCLUDED_PRODUCTS = frozenset({"iis"})


@dataclass(frozen=True)
class Library:
    """ページが読み込む外部 JS ライブラリ（name+version+ecosystem+URL）。"""

    name: str
    version: str
    ecosystem: str    # OSV の ecosystem（例: "npm"）
    url: str


def _norm_product(name: str) -> str:
    return (name or "").strip().lower()


# 主要 CDN の URL からライブラリ名+バージョンを抽出する（純粋・保守側）。いずれも npm パッケージ。
#   jsdelivr: https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js
#   cdnjs/google: .../ajax/libs/jquery/3.4.1/jquery.min.js
#   unpkg: https://unpkg.com/jquery@3.4.1/dist/jquery.min.js
#   ファイル名埋め込み: .../jquery-3.4.1.min.js（推測度が高いので semver 形のみ）
_LIB_URL_PATTERNS = (
    re.compile(r"/npm/((?:@[\w.-]+/)?[\w.-]+)@(\d[\w.\-]*)"),
    re.compile(r"/ajax/libs/([\w.-]+)/(\d[\w.\-]*)/"),
    re.compile(r"unpkg\.com/((?:@[\w.-]+/)?[\w.-]+)@(\d[\w.\-]*)"),
    re.compile(r"/([\w.-]+?)-(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js(?:$|[?#])"),
)


def _norm_version(v: str) -> str:
    v = (v or "").strip()
    return v[1:] if v[:1] in ("v", "V") and v[1:2].isdigit() else v


def parse_js_libraries(html: str, base_url: str = "") -> list[Library]:
    """HTML の外部 ``<script src>`` から (name, version, npm) を抽出する（純粋・ネットワーク非依存）。

    主要 CDN（jsdelivr/cdnjs/unpkg/google）とファイル名埋め込みバージョンに限定して保守的に解析する
    （誤検出を避ける＝確実性重視）。バージョンを取れないものは返さない。重複は (name, version) で排除。
    ``base_url`` は相対 src の解決に使う。
    """
    from urllib.parse import urljoin  # 局所 import（純粋関数を軽く保つ）
    from . import js_analysis

    if not html:
        return []
    out: list[Library] = []
    seen: set[tuple[str, str]] = set()
    for src in js_analysis.extract_external_script_srcs(html):
        absolute = urljoin(base_url, (src or "").strip())
        for pat in _LIB_URL_PATTERNS:
            m = pat.search(absolute)
            if not m:
                continue
            name = m.group(1).strip().lower()
            version = _norm_version(m.group(2))
            if not name or not version or not version[0].isdigit():
                continue
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            out.append(Library(name=name, version=version, ecosystem="npm", url=absolute))
            break  # 1 src につき最初に一致したパターンだけ
    return out


def summarize_osv_vulns(vulns: list[dict]) -> dict:
    """OSV の vulns から報告用サマリを作る（純粋）。

    ``{"ids": [...], "cves": [...], "max_severity": "CRITICAL|HIGH|MODERATE|LOW|",
       "summary": "先頭 vuln の要約"}``。severity は database_specific.severity を優先。
    """
    ids: list[str] = []
    cves: list[str] = []
    rank = {"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1}
    max_sev, max_rank = "", -1
    summary = ""
    for v in vulns or []:
        if not isinstance(v, dict):
            continue
        vid = v.get("id")
        if vid:
            ids.append(str(vid))
        for a in v.get("aliases", []) or []:
            if isinstance(a, str) and a.upper().startswith("CVE-"):
                cves.append(a)
        sev = str((v.get("database_specific") or {}).get("severity", "") or "").strip()
        r = rank.get(sev.lower(), -1)
        if r > max_rank:
            max_rank, max_sev = r, sev.upper()
        if not summary and v.get("summary"):
            summary = str(v["summary"])
    # 重複 CVE を排除しつつ順序保持
    cves = list(dict.fromkeys(cves))
    return {"ids": ids, "cves": cves, "max_severity": max_sev, "summary": summary}


def parse_components_from_headers(headers: dict) -> list[Component]:
    """レスポンスヘッダから (製品名, バージョン) を抽出する（純粋・ネットワーク非依存）。

    対象ヘッダ:
      - ``Server``            例: ``nginx/1.18.0`` / ``Apache/2.4.29 (Ubuntu)``
      - ``X-Powered-By``      例: ``PHP/7.4.3``
      - ``X-AspNet-Version``  例: ``4.0.30319``（製品は asp.net 固定）
      - ``X-Generator``       例: ``Drupal 7 (https://drupal.org)`` / ``WordPress 6.1``

    バージョンを伴わないバナー（``ASP.NET`` 単体等）は返さない（照会不能）。重複は
    (product, version) で排除する。判定は ``version`` が明示されているものだけ＝確実性重視。
    """
    lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    found: list[Component] = []
    seen: set[tuple[str, str]] = set()

    def _add(product: str, version: str, source: str, raw: str) -> None:
        p, v = _norm_product(product), (version or "").strip()
        if not p or not v:
            return
        key = (p, v)
        if key in seen:
            return
        seen.add(key)
        found.append(Component(product=p, version=v, source=source, raw=raw))

    for hdr in ("server", "x-powered-by"):
        val = lower.get(hdr, "")
        for m in _BANNER_RE.finditer(val):
            _add(m.group(1), m.group(2), hdr, val)

    aspnet = lower.get("x-aspnet-version", "").strip()
    if aspnet and aspnet[0].isdigit():
        _add("asp.net", aspnet, "x-aspnet-version", aspnet)

    gen = lower.get("x-generator", "")
    for m in _GENERATOR_RE.finditer(gen):
        _add(m.group(1), m.group(2), "x-generator", gen)

    return found


def eol_product_slug(product: str) -> Optional[str]:
    """正規化製品名を endoflife.date の slug へ写す（未対応/除外は ``None``）。"""
    p = _norm_product(product)
    if p in _EXCLUDED_PRODUCTS:
        return None
    return _PRODUCT_SLUGS.get(p)


def match_cycle(cycles: list[dict], version: str) -> Optional[dict]:
    """endoflife.date の cycle 一覧から、検出バージョンに一致する cycle を返す（純粋）。

    cycle は "7.4" のような release train 識別子。``version`` が cycle と完全一致、または
    ``cycle + "."`` で始まるものを一致とみなし、複数一致時は **最も具体的（長い cycle）** を採る
    （例: version "7.4.3" は cycle "7.4" に一致、"7" より優先）。一致無しは ``None``。
    """
    ver = (version or "").strip()
    if not ver or not isinstance(cycles, list):
        return None
    best: Optional[dict] = None
    best_len = -1
    for c in cycles:
        if not isinstance(c, dict):
            continue
        cyc = str(c.get("cycle", "")).strip()
        if not cyc:
            continue
        if ver == cyc or ver.startswith(cyc + "."):
            if len(cyc) > best_len:
                best, best_len = c, len(cyc)
    return best


def evaluate_eol(cycle: dict, today: Optional[_dt.date] = None) -> Optional[bool]:
    """cycle の ``eol`` フィールドから EOL 判定する（純粋）。

    ``eol`` は endoflife.date 仕様で bool（``True``/``False``）または ISO 日付文字列。
    - ``True``            → EOL（True）
    - ``False``           → サポート中（False）
    - ``"YYYY-MM-DD"``    → その日付 <= today なら EOL（True）、未来なら False
    - 欠落/解釈不能        → 不明（None）
    """
    if not isinstance(cycle, dict) or "eol" not in cycle:
        return None
    eol = cycle.get("eol")
    if isinstance(eol, bool):
        return eol
    if isinstance(eol, str):
        try:
            eol_date = _dt.date.fromisoformat(eol.strip())
        except ValueError:
            return None
        ref = today or _dt.date.today()
        return eol_date <= ref
    return None


async def fetch_product_cycles(
    product_slug: str,
    *,
    base_url: str = DEFAULT_EOL_BASE_URL,
    timeout: float = DEFAULT_TIMEOUT,
    client: "Optional[httpx.AsyncClient]" = None,
) -> Optional[list[dict]]:
    """endoflife.date の ``/api/{product}.json`` を取得する（graceful・失敗時 None）。

    外部へ送るのは product slug のみ。target 情報は一切送らない。``client`` を注入すると
    テストで差し替え可能（未指定なら httpx で都度生成）。
    """
    slug = (product_slug or "").strip().strip("/")
    if not slug or httpx is None:
        return None
    url = f"{base_url.rstrip('/')}/api/{slug}.json"
    try:
        if client is not None:
            resp = await client.get(url, timeout=timeout)
        else:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
                resp = await c.get(url)
        if resp.status_code != 200:
            return None
        data = resp.json()
    except Exception:
        return None
    return data if isinstance(data, list) else None


async def check_component_eol(
    component: Component,
    *,
    base_url: str = DEFAULT_EOL_BASE_URL,
    timeout: float = DEFAULT_TIMEOUT,
    today: Optional[_dt.date] = None,
    client: "Optional[httpx.AsyncClient]" = None,
) -> Optional[dict]:
    """1 コンポーネントの EOL を照会する。結果 dict、照会不能/不一致/不明は ``None``。

    戻り値（EOL/サポート中を確定できたときのみ非 None）:
      ``{"product","version","source","slug","cycle","eol","is_eol","latest"}``
    ``is_eol`` は True=EOL / False=サポート中。判定不能（cycle 不一致や eol 不明）は None を返す
    （偽の Finding を作らない・確実性重視）。
    """
    slug = eol_product_slug(component.product)
    if not slug:
        return None
    cycles = await fetch_product_cycles(
        slug, base_url=base_url, timeout=timeout, client=client
    )
    if not cycles:
        return None
    cycle = match_cycle(cycles, component.version)
    if not cycle:
        return None
    is_eol = evaluate_eol(cycle, today=today)
    if is_eol is None:
        return None
    return {
        "product": component.product,
        "version": component.version,
        "source": component.source,
        "slug": slug,
        "cycle": str(cycle.get("cycle", "")),
        "eol": cycle.get("eol"),
        "is_eol": bool(is_eol),
        "latest": cycle.get("latest", ""),
    }


async def lookup_osv(
    ecosystem: str,
    name: str,
    version: str,
    *,
    base_url: str = DEFAULT_OSV_BASE_URL,
    timeout: float = DEFAULT_TIMEOUT,
    client: "Optional[httpx.AsyncClient]" = None,
) -> Optional[list[dict]]:
    """OSV.dev へ (ecosystem, name, version) を照会し vulns 一覧を返す（graceful・失敗時 None）。

    ``POST /v1/query`` に **パッケージ名+バージョン+ecosystem のみ**を送る（target 情報は送らない）。
    脆弱性なしは ``[]``、照会不能/失敗は ``None``（区別して呼び出し側が扱えるように）。
    """
    if not (name and version and ecosystem) or httpx is None:
        return None
    url = f"{base_url.rstrip('/')}/v1/query"
    body = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    try:
        if client is not None:
            resp = await client.post(url, json=body, timeout=timeout)
        else:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
                resp = await c.post(url, json=body)
        if resp.status_code != 200:
            return None
        data = resp.json()
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    vulns = data.get("vulns")
    return vulns if isinstance(vulns, list) else []


def nvd_product_cpe(product: str) -> Optional[str]:
    """製品名を NVD の vendor:product CPE prefix へ写す（未対応は None・保守側）。"""
    return _NVD_CPE_MAP.get(_norm_product(product))


def summarize_nvd(data: dict) -> dict:
    """NVD の /cves 応答から報告用サマリを作る（純粋）。

    ``{"total": int, "cve_ids": [...上位], "max_severity": "CRITICAL|HIGH|..."}``。
    深刻度は cvssMetricV31/V30/V2 の baseSeverity（V2 は baseScore→段階）から最大を採る。
    """
    total = int(data.get("totalResults", 0) or 0)
    ids: list[str] = []
    max_sev, max_rank = "", -1
    for item in (data.get("vulnerabilities") or []):
        cve = (item or {}).get("cve") or {}
        cid = cve.get("id")
        if cid:
            ids.append(str(cid))
        metrics = cve.get("metrics") or {}
        sev = ""
        for key in ("cvssMetricV31", "cvssMetricV30"):
            arr = metrics.get(key) or []
            if arr:
                sev = str((arr[0].get("cvssData") or {}).get("baseSeverity", "") or "")
                break
        if not sev:
            arr = metrics.get("cvssMetricV2") or []
            if arr:
                sev = str(arr[0].get("baseSeverity", "") or "")
        r = _NVD_SEV_RANK.get(sev.lower(), -1)
        if r > max_rank:
            max_rank, max_sev = r, sev.upper()
    return {"total": total, "cve_ids": ids, "max_severity": max_sev}


async def lookup_nvd(
    product: str,
    version: str,
    *,
    base_url: str = DEFAULT_NVD_BASE_URL,
    api_key: str = "",
    timeout: float = DEFAULT_TIMEOUT,
    results_per_page: int = 5,
    client: "Optional[httpx.AsyncClient]" = None,
) -> Optional[dict]:
    """NVD の CVE API を CPE で照会し summarize_nvd の結果を返す（graceful・失敗時 None）。

    限定オプション（保守的 CPE マップにある製品のみ）。API キーは任意で、あればヘッダ
    ``apiKey`` を付けてレート制限を緩和する（無くても動作）。外部へ送るのは CPE（製品名+
    バージョン）のみで target 情報は送らない。CVE なし（total=0）は ``{"total":0,...}`` を返す。
    """
    cpe_prefix = nvd_product_cpe(product)
    if not cpe_prefix or not version or httpx is None:
        return None
    cpe_name = f"{cpe_prefix}:{version}:*:*:*:*:*:*:*"
    url = f"{base_url.rstrip('/')}/rest/json/cves/2.0"
    params = {"cpeName": cpe_name, "resultsPerPage": results_per_page}
    headers = {"apiKey": api_key} if api_key else None
    try:
        if client is not None:
            resp = await client.get(url, params=params, headers=headers, timeout=timeout)
        else:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
                resp = await c.get(url, params=params, headers=headers)
        if resp.status_code != 200:
            return None
        data = resp.json()
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    return summarize_nvd(data)
