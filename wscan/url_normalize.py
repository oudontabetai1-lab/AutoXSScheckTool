"""checkpoint キー専用の保守的な URL 正規化。"""
from __future__ import annotations

from urllib.parse import unquote_plus, urlsplit, urlunsplit


# 値にかかわらず run ごとに変化し得ることが明確なキーだけを除く。
_VOLATILE_QUERY_KEYS = frozenset(
    {
        "_",
        "t",
        "ts",
        "time",
        "timestamp",
        "nonce",
        "_nonce",
        "cb",
        "_cb",
        "cachebuster",
        "cache_buster",
        "cache-buster",
        "cachebust",
        "rand",
        "random",
        "_dc",
        "csrf",
        "_csrf",
        "csrf-token",
        "csrf_token",
        "csrftoken",
        "csrfmiddlewaretoken",
        "xsrf",
        "xsrf-token",
        "xsrf_token",
        "x-csrf-token",
        "x_csrf_token",
        "x-xsrf-token",
        "x_xsrf_token",
        "anti-csrf-token",
        "anti_csrf_token",
        "authenticity_token",
        "requestverificationtoken",
        "__requestverificationtoken",
    }
)


def _split_query_item(item: str) -> tuple[str, str]:
    """raw query item から判定用の key/value をデコードして返す。"""
    raw_key, separator, raw_value = item.partition("=")
    key = unquote_plus(raw_key, encoding="utf-8", errors="strict")
    value = (
        unquote_plus(raw_value, encoding="utf-8", errors="strict")
        if separator
        else ""
    )
    return key, value


def normalize_url_for_key(url: str) -> str:
    """揮発クエリを除き、checkpoint identity 用の安定した URL を返す。

    未知のキー、パス、値、および scheme/netloc の表記は保持する。クエリ項目の raw
    表現も保持し、判定とソートにだけデコード済みキーを使う。解析不能時は安全側として
    入力をそのまま返す。
    """
    try:
        parsed = urlsplit(url)
        # urlsplit は scheme を暗黙に小文字化するため、入力時の表記を退避する。
        raw_scheme = url[: url.find(":")] if parsed.scheme else ""
        kept: list[tuple[str, str]] = []
        for item in parsed.query.split("&") if parsed.query else []:
            key, value = _split_query_item(item)
            folded_key = key.casefold()
            if folded_key in _VOLATILE_QUERY_KEYS:
                continue
            if folded_key == "v" and value.isascii() and value.isdigit():
                continue
            kept.append((key, item))

        # 同名キーの値順には意味があり得るため、安定ソートでキー間の順序だけを揃える。
        kept.sort(key=lambda pair: pair[0])
        return urlunsplit(
            parsed._replace(
                scheme=raw_scheme,
                query="&".join(item for _, item in kept),
                fragment="",
            )
        )
    except Exception:
        return url
