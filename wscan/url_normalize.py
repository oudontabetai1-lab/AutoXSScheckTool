"""checkpoint キー専用の保守的な URL 正規化。"""
from __future__ import annotations

from urllib.parse import unquote_plus, urlsplit, urlunsplit


# 名前だけで意味を持ち得ない、純粋なキャッシュバスター/CSRF トークン。
_ALWAYS_VOLATILE_KEYS = frozenset(
    {
        "_",
        "cb",
        "_cb",
        "cachebuster",
        "cache_buster",
        "cache-buster",
        "cachebust",
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

# 名前自体がtransienceを強く示すため、epoch数字またはランダムトークンの場合に除くキー。
_TRANSIENT_NAME_KEYS = frozenset({"nonce", "_nonce", "rand", "random"})


def _looks_random_token(value: str) -> bool:
    """16文字以上のhex/base64url英数トークンらしさを判定する（純粋）。"""
    return len(value) >= 16 and all(
        char.isascii() and (char.isalnum() or char in "_-") for char in value
    )


def _looks_epoch_digits(value: str) -> bool:
    """8桁以上のASCII数字列かを判定する（純粋）。"""
    return len(value) >= 8 and value.isascii() and value.isdigit()


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

    未知のキー、パス末尾以外、値、および scheme/netloc の表記は保持する。パスの
    trailing slash だけを除き、クエリ項目の raw 表現も保持して、判定とソートにだけ
    デコード済みキーを使う。解析不能時は安全側として入力をそのまま返す。
    """
    try:
        parsed = urlsplit(url)
        # urlsplit は scheme を暗黙に小文字化するため、入力時の表記を退避する。
        raw_scheme = url[: url.find(":")] if parsed.scheme else ""
        kept: list[tuple[str, str]] = []
        for item in parsed.query.split("&") if parsed.query else []:
            key, value = _split_query_item(item)
            folded_key = key.casefold()
            if folded_key in _ALWAYS_VOLATILE_KEYS:
                continue
            if folded_key in _TRANSIENT_NAME_KEYS and (
                _looks_epoch_digits(value) or _looks_random_token(value)
            ):
                continue
            # 曖昧名キー（時刻/版）は value だけで transience を確実に判定できず、
            # 通常層では偽陰性が最悪のため保持する。標準的 cache-buster 名は
            # ALWAYS set が吸収する。`t=<epoch>` 型の非標準 cache-buster は
            # 正規化しない（安全側の既知制約）。
            kept.append((key, item))

        # 同名キーの値順には意味があり得るため、安定ソートでキー間の順序だけを揃える。
        kept.sort(key=lambda pair: pair[0])
        # manual_crawl._strip_in_page_anchor と同じ規則。predicate は循環 import を
        # 避けるため複製しているので、変更時は両者の挙動を一致させること。
        fragment = parsed.fragment
        keep_frag = (
            fragment
            if fragment[:1] in ("/", "!") or "/" in fragment
            else ""
        )
        return urlunsplit(
            parsed._replace(
                scheme=raw_scheme,
                path=parsed.path.rstrip("/"),
                query="&".join(item for _, item in kept),
                fragment=keep_frag,
            )
        )
    except Exception:
        return url
