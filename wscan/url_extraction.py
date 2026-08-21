"""JS/JSON 資産から抽出した URL 候補の妥当性判定（LLM 非依存の純粋関数）。

`browser._collect_urls_from_loaded_assets` の `url_re` は `()*+?;=` 等を許容文字に
含むため、minified JS の**正規表現リテラルや式**を `/…` ルートとして誤抽出する
（例: `/(?:` `/16*(a.flipX?-1:1` `/()?;=`）。これらのゴミ URL は (1) 無駄クロール
(2) 高価なプランナー LLM の浪費 (3) 実ルート到達の阻害 を招く（0009 C1）。

ここでは「実在ルートらしさ」を**path 部のコード由来メタ文字**で判定し、誤抽出を
除去する。ブラウザ非依存の純粋関数として分離し、フィクスチャ無しでテスト可能に保つ
（本リポの「検出/判定ロジックは純粋関数へ分離」規約）。除去は保守側に倒し、判断に
迷う候補は**残す**（実ルートの取りこぼし＝到達性低下は C1 の目的に反するため）。
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# URL の path として **RFC 上そもそも不正**な文字（gen-delim/式メタ文字）。実ルートには
# 生では現れず、minified JS の regex リテラルや式片を強く示唆する。
# 除外理由: `* + ( )` は path の sub-delim として**正当**（`/languages/C++`・OData `/Products(1)`・
#   parameterless `/GetDefault()`）なのでここには入れない。regex らしい括弧だけ `_parens_look_like_regex`
#   で別途弾く。`?;=&` はクエリで正当（path から除かれる）。`~ . - _ % @ , ! $ ' :` 等も path で正当。
_STRONG_METACHARS = re.compile(r"[\\|^{}<>`\[\]]")

# path に残る regex 由来シーケンス。`.*`/`.+`（任意文字の量指定）は実 path にまず出ない強い
# 正規表現シグナル。**クエリではなく path** にのみ適用する（実ルートの `?pattern=.*` のような
# クエリ値で誤除去しないため）。
_PATH_REGEX_HINTS = (".*", ".+")


def _parens_look_like_regex(path: str) -> bool:
    """path 中の丸括弧が正規表現片らしいかを返す（純粋）。

    実ルートの括弧（OData `/Products(1)`・parameterless `/GetDefault()/value`）は許容し、
    **regex 特有の形だけ**を弾く: 非キャプチャ/先読み群 `(?` ／ バランス崩れ（切れた regex・
    `/16*(a` や `/(` 等）／ **識別子直後でない `(`**（`/(...)` のように区切り直後で始まる括弧＝
    regex リテラル片。関数呼び出し様の `\\w(` は残す）。
    """
    if "(?" in path:
        return True
    # 関数/コレクション様（識別子・数字・`)` の直後の `(` ）以外の開き括弧は式/regex 片寄り。
    for m in re.finditer(r"\(", path):
        prev = path[m.start() - 1] if m.start() > 0 else ""
        if not (prev.isalnum() or prev in "_)"):
            return True
    depth = 0
    for ch in path:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return True
    return depth != 0


def is_plausible_route_candidate(resolved_url: str) -> bool:
    """解決済み URL が「実在しうるルート/API」の体裁かを返す（純粋）。

    False = JS 由来のゴミ（regex/式片）と判定。判定は「URL として不正な文字」＋「regex 特有の
    形」に絞り、誤って実ルートを落とさないよう保守的（迷ったら True）。OData/関数様の括弧・
    `+`/`*` を含む path・クエリのメタ文字・origin-root は実ルートとして残す。曖昧な候補は残し、
    実在しなければ下流の crawl が 404 で落とす（到達性維持を優先）。
    """
    if not resolved_url:
        return False
    try:
        parsed = urlparse(resolved_url)
    except Exception:
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    if not parsed.netloc:
        return False
    path = parsed.path or ""
    # 本丸: path に URL として不正な文字が混ざる候補は regex/式の誤抽出として除去。
    # （origin-root `https://host/` はスコープ内の別オリジン等で実ルートになりうるので残す。）
    if _STRONG_METACHARS.search(path):
        return False
    # 丸括弧は OData/関数様で正当。regex 特有の括弧だけ弾く。
    if _parens_look_like_regex(path):
        return False
    # regex 由来シーケンスは **path にのみ** 適用（クエリ値の `.*` 等で実ルートを落とさない）。
    if any(hint in path for hint in _PATH_REGEX_HINTS):
        return False
    return True


# url_re が URL 候補として許容しない一方、正規表現リテラルでは**継続**に使われる文字。
# 抽出器はこれらの手前で match を打ち切るため、切り詰め後の候補（`/foo|bar/`→`/foo`、
# `/abc[0-9]/`→`/abc`）は一見正常な path に見えて post-filter を通過してしまう。match の
# **直後の文字**がこれらなら、regex リテラルの途中で切れた証拠として抽出時に弾く（0009 C1）。
_REGEX_CONTINUATION_CHARS = frozenset("|[]\\^{}")


def regex_literal_end(body: str, pos: int) -> int:
    """`body[pos]` 以降にある正規表現リテラルの閉じ `/`（+flags）の直後 index を返す（純粋）。

    切り詰められた regex 片（`/escpat\\/subpat/` の escaped slash 等）を後続の finditer が
    再抽出しないよう、切り詰め検知後にリテラルの残りを読み飛ばすために使う。escaped char
    （`\\x`）と文字クラス `[...]`（内部の `/` は閉じでない）を考慮する。閉じが見つからなければ
    `pos` を返す（読み飛ばさない＝安全側）。
    """
    i = pos
    n = len(body)
    in_class = False
    while i < n:
        c = body[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            i += 1
            while i < n and body[i] in "dgimsuvy":
                i += 1
            return i
        i += 1
    return pos


def truncated_regex_literal(next_char: str) -> bool:
    """抽出 match の直後の1文字が regex リテラルの継続を示すかを返す（純粋）。

    `browser._collect_urls_from_loaded_assets` が `url_re.finditer` の各 match について
    `body[end:end+1]` を渡す。True なら候補は regex リテラルの切り詰めなので採用しない。
    """
    return bool(next_char) and next_char in _REGEX_CONTINUATION_CHARS


# JS で正規表現リテラルを導く（`/` の直前に来うる）文脈文字。文字列リテラルの直前は引用符
# や識別子なので、これらと区別できる。空白は読み飛ばして直前の非空白文字を見る。
# `\` を含むのは、regex 内の escaped slash（`/foo\/bar/`）で finditer が再開して `/bar/` を
# 別候補に切り出すため。直前が `\` の `/…/` 形は regex 片のみ（実 path 片は `/…/`形にならない）。
_REGEX_CONTEXT_PREV = frozenset("=(,:[!&|?{;<>~^*%\\")
# `return /re/` のように regex を導く式キーワード。直前トークンがこれらでも regex 文脈。
_REGEX_PRECEDING_KEYWORDS = frozenset({
    "return", "throw", "yield", "typeof", "case", "delete", "void",
    "in", "of", "new", "do", "else", "instanceof",
})
# 条件の `)` の直後に文（regex リテラル）が来る制御ヘッダ。`if (x) /re/.test(y)` は regex だが
# 関数呼び出し `f() /2/` は除算なので、`)` は対応する `(` の前トークンで区別する。
_CONTROL_HEADER_KEYWORDS = frozenset({"if", "while", "for", "switch", "catch"})
# 閉じた正規表現リテラルの形 `/…/flags`。flags は現行の全 JS フラグ（d/g/i/m/s/u/v/y）。
# url_re 文字だけで構成される `/foo.bar/` `/foo$/` `/foo+/` `/foo*/` `/foo/d` 等は切り詰められない
# ので、この形＋文脈で判定する。
_REGEX_LITERAL_SHAPE = re.compile(r"^/.+/[dgimsuvy]*$")
# メソッド呼び出しで使う regex（`/foo/.test(x)`）は url_re が suffix まで取り込み末尾一致しない。
# 「閉じた `/…/flags` の直後にメンバアクセス `.`」の形も regex リテラルとして扱う。
_REGEX_MEMBER_CALL = re.compile(r"^/.+?/[dgimsuvy]*\.")
_IDENTIFIER_TAIL = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*$")


def preceding_is_regex_context(preceding_text: str) -> bool:
    """match 直前のテキストが JS 正規表現を導く文脈かを返す（純粋）。

    末尾空白を読み飛ばし、(1) 直前文字が regex 文脈演算子 `_REGEX_CONTEXT_PREV`、または
    (2) 直前トークンが `return`/`throw`/`yield` 等の式キーワード、または (3) 行頭/式先頭
    （空）なら True。文字列リテラル由来（直前が引用符や通常の識別子）は False。
    """
    stripped = preceding_text.rstrip(" \t\r\n")
    if not stripped:
        return True
    last = stripped[-1]
    if last in _REGEX_CONTEXT_PREV:
        return True
    m = _IDENTIFIER_TAIL.search(stripped)
    if m and m.group(0) in _REGEX_PRECEDING_KEYWORDS:
        return True
    # `)` は制御ヘッダ（if/while/for/switch/catch）の条件閉じなら文が続く＝regex 文脈。
    # 関数呼び出しの `)` の後は除算なので、対応する `(` の直前トークンで区別する。
    if last == ")":
        depth = 0
        i = len(stripped) - 1
        while i >= 0:
            if stripped[i] == ")":
                depth += 1
            elif stripped[i] == "(":
                depth -= 1
                if depth == 0:
                    break
            i -= 1
        if depth == 0 and i > 0:
            before = stripped[:i].rstrip(" \t\r\n")
            km = _IDENTIFIER_TAIL.search(before)
            if km and km.group(0) in _CONTROL_HEADER_KEYWORDS:
                return True
    return False


def preceding_nonspace(body: str, index: int) -> str:
    """`body[index]` の手前で最初に現れる非空白文字を返す（無ければ空文字。純粋）。"""
    i = index - 1
    while i >= 0 and body[i] in " \t\r\n":
        i -= 1
    return body[i] if i >= 0 else ""


def is_regex_literal_extraction(preceding_text: str, match_text: str) -> bool:
    """抽出 match が JS 正規表現リテラルらしいかを、直前文脈と形で判定する（純粋）。

    切り詰められない完全な regex リテラル（`/foo.bar/` 等、url_re 文字のみ）は content だけでは
    実ルートと区別できないため、**直前が regex を導く文脈**（演算子・式キーワード `return`/`throw`
    等・行頭）で、かつ match が (a) 閉じた `/…/flags` の形、または (b) その直後にメンバ呼び出し
    `.`（`/foo/.test(x)`）のときに regex と見なす。文字列リテラル由来（直前が引用符/通常の識別子）
    は除外される。完全な判別には JS 字句解析が要るため保守的で、取りこぼした regex は下流 crawl
    が 404 で落とす（実ルートを誤除去しないことを優先）。

    ``preceding_text`` は match 直前のテキスト（末尾数十文字で十分）。後方互換で単一文字も可。
    """
    if not preceding_is_regex_context(preceding_text):
        return False
    return bool(
        _REGEX_LITERAL_SHAPE.match(match_text)
        or _REGEX_MEMBER_CALL.match(match_text)
    )


def strip_trailing_noise(candidate: str) -> str:
    """url_re が過剰に取り込んだ末尾のノイズだけを剥がす（純粋）。

    空白・引用符・`<>`・`,`・`;` は常に剥がす。末尾の閉じ括弧 `)]}` は、**釣り合わない
    余分な閉じ**（`(/api/x)`→`/api/x)` のような外側の閉じを取り込んだ場合）だけ剥がし、
    釣り合っている閉じ（OData `/Products(1)`・関数 `/GetDefault()`）は**残す**。旧実装は
    `)]}` を無条件 rstrip して OData/関数ルートを不均衡化し誤除去していた（0009 C1・Codex #100）。
    """
    candidate = candidate.rstrip(" \t\r\n\"'`<>,;")
    while candidate and candidate[-1] in ")]}":
        opens = sum(candidate.count(c) for c in "([{")
        closes = sum(candidate.count(c) for c in ")]}")
        if closes > opens:
            candidate = candidate[:-1]
        else:
            break
    return candidate


def filter_route_candidates(resolved_urls) -> list[str]:
    """URL 候補列から実在ルートらしいものだけを順序保持で返す（純粋）。"""
    seen: set[str] = set()
    kept: list[str] = []
    for url in resolved_urls or []:
        if url in seen:
            continue
        seen.add(url)
        if is_plausible_route_candidate(url):
            kept.append(url)
    return kept
