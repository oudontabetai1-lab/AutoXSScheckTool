"""追加 HTTP ヘッダの送信先オリジンを判定する純粋関数。"""
from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse


_BLANK_URLS = frozenset({"", "about:blank", "chrome://newtab/", "about:newtab"})


def _url_origin(url: str) -> str:
    """URL から比較用の scheme://host[:port] を抽出する。"""
    try:
        parsed = urlparse(str(url or "").strip())
        hostname = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError):
        return ""
    if not parsed.scheme or not parsed.netloc or not hostname:
        return ""
    normalized_host = hostname.lower()
    try:
        normalized_host = normalized_host.encode("idna").decode("ascii")
    except UnicodeError:
        # 壊れたホスト名でもスコープ判定自体は例外にせず、従来の小文字表現へ戻す。
        pass
    if ":" in normalized_host:
        normalized_host = f"[{normalized_host}]"
    scheme = parsed.scheme.lower()
    default_ports = {"http": 80, "https": 443}
    port_suffix = (
        f":{port}"
        if port is not None and port != default_ports.get(scheme)
        else ""
    )
    return f"{scheme}://{normalized_host}{port_suffix}"


def effective_origin_url(current_url: str, intended_url: str) -> str:
    """オリジン判定に使う URL を返す。

    current_url が未確定（about:blank 等）なら intended_url を使う。
    """
    normalized_current = str(current_url or "").strip()
    if normalized_current in _BLANK_URLS:
        return str(intended_url or "").strip()
    return normalized_current


def expand_scheme_variants(
    origins: set,
    urls_without_scheme: set,
) -> set:
    """scheme を自動補完した URL について http/https 両方のオリジンを足す（純粋関数）。

    Agent は scheme 無しの対象を ``http://`` へ正規化するため、そのままでは
    同一ホストの HTTP→HTTPS リダイレクト後にスコープ外と判定されてしまう。
    ユーザーが scheme を明示した場合は広げない（意図を尊重する）。
    """
    expanded = set(origins)
    for raw_url in urls_without_scheme or ():
        value = str(raw_url or "").strip().rstrip("/")
        if not value:
            continue
        # scheme 無しの入力なので、両 scheme を明示的に組み立てて判定する。
        for scheme in ("http", "https"):
            origin = _url_origin(f"{scheme}://{value}")
            if origin:
                expanded.add(origin)
    return expanded


def allowed_header_origins(
    target_url: str,
    target_urls: list[str],
    access_urls: list[str],
    login_url: str = "",
    urls_without_scheme: Optional[set] = None,
) -> set[str]:
    """認証ヘッダを送ってよいオリジン集合を返す。

    *urls_without_scheme* には「利用者が scheme を書かなかった入力」を渡す。
    その host は http/https 両方を許可し、HTTPS 昇格でヘッダが外れないようにする。
    """
    origins: set[str] = set()
    for url in [target_url, *target_urls, *access_urls, login_url]:
        origin = _url_origin(url)
        if origin:
            origins.add(origin)
    return expand_scheme_variants(origins, urls_without_scheme or set())


def headers_allowed_for_url(url: str, allowed_origins: set[str]) -> bool:
    """URL が許可オリジンに属する場合だけ True を返す。"""
    origin = _url_origin(url)
    return bool(origin and origin in allowed_origins)
