"""追加 HTTP ヘッダの送信先オリジンを判定する純粋関数。"""
from __future__ import annotations

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


def allowed_header_origins(
    target_url: str,
    target_urls: list[str],
    access_urls: list[str],
    login_url: str = "",
) -> set[str]:
    """認証ヘッダを送ってよいオリジン集合を返す。"""
    origins: set[str] = set()
    for url in [target_url, *target_urls, *access_urls, login_url]:
        origin = _url_origin(url)
        if origin:
            origins.add(origin)
    return origins


def headers_allowed_for_url(url: str, allowed_origins: set[str]) -> bool:
    """URL が許可オリジンに属する場合だけ True を返す。"""
    origin = _url_origin(url)
    return bool(origin and origin in allowed_origins)
