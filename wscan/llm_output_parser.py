"""LLM 生テキストから JSON を頑健に取り出す純粋関数群（D7）。

背景（2026-08-20 4モデルプローブ）: 良質な攻撃 payload を生成したのに、素朴な正規表現
（非貪欲 `\\[.*?\\]` / 貪欲 `\\{.*\\}`）が **配列内の `]`／前置き／コードフェンス／
テンプレートリテラル** で途中終了し、ツール側で抽出失敗＝**モデルの当たり外れがパーサ
側で生まれていた**。

方針は CLAUDE.md ハーネス設計 原則5「構造化出力は防御的にパース」のフォールバック連鎖:
  reasoning(`<think>`)除去 → コードフェンス除去 → 直接 json.loads →
  文字列/エスケープを認識する平衡括弧スキャンで全候補を走査 → 各候補を json.loads。
**壊れたら安全側（呼び出し側は既定へフォールバック）** は維持し、各候補は必ず
json.loads を通すため「それらしいが壊れた JSON」を採らない（誤検知を作らない）。
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterator, Optional


_THINK_BLOCK = re.compile(r"<think\b[^>]*>.*?</think\s*>", re.DOTALL | re.IGNORECASE)
_THINK_OPEN = re.compile(r"<think\b[^>]*>.*", re.DOTALL | re.IGNORECASE)
# 言語タグ付きの ``` は**改行で終わる開始フェンス行**のときだけタグごと除去する。
# 改行が無い1行フェンス（```json["a"]```）でタグ扱いして中身まで飲み込まないため。
_FENCE = re.compile(r"```[^\n`]*\r?\n|```", re.IGNORECASE)


def strip_reasoning(text: str) -> str:
    """`<think>...</think>` 推論ブロックを除去する（未閉じは行末まで除去）。"""
    if not text:
        return ""
    text = _THINK_BLOCK.sub(" ", text)
    text = _THINK_OPEN.sub(" ", text)  # 閉じ忘れの `<think>` は以降を捨てる
    return text


def strip_code_fences(text: str) -> str:
    """```lang フェンス行と閉じ ``` を除去し、中身は残す。"""
    if not text:
        return ""
    return _FENCE.sub("", text)


def _reasoning_spans(text: str) -> list:
    """`<think>...</think>` 推論ブロックの (start, end) 範囲を返す。

    候補 JSON が推論ブロックに**完全内包**されるか判定するために使う。閉じられた
    ブロックに加え、閉じ忘れの `<think>` は以降を末尾まで推論として扱う。
    """
    spans = [(m.start(), m.end()) for m in _THINK_BLOCK.finditer(text)]
    for m in re.finditer(r"<think\b[^>]*>", text, re.IGNORECASE):
        if any(s <= m.start() < e for s, e in spans):
            continue
        if not re.search(r"</think\s*>", text[m.end():], re.IGNORECASE):
            spans.append((m.start(), len(text)))
            break
    return spans


def _fully_inside(start: int, end: int, spans: list) -> bool:
    """[start, end) が いずれかの推論スパンに完全内包されるか。"""
    return any(s <= start and end <= e for s, e in spans)


def _iter_balanced_pos(text: str, opener: str, closer: str) -> Iterator[tuple]:
    """平衡した opener..closer を (開始位置, 部分文字列) で列挙する。

    各 opener を候補の起点として試し、閉じなければ**次の opener から再試行**する
    （prose の未閉じ括弧 `Use [ literally ... ["payload"]` が後続の本物を飲み込んで
    何も yield しない事故を防ぐ・#92 r5）。opener を見つけるまでの prose 中の `"` は
    文字列として追跡しない（候補開始後のみ in_str 追跡）。閉じた候補の後ろから走査を続ける。
    """
    n = len(text)
    i = 0
    while i < n:
        if text[i] != opener:
            i += 1
            continue
        depth = 0
        in_str = False
        escaped = False
        end = -1
        for j in range(i, n):
            ch = text[j]
            if in_str:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
                continue
            if ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    end = j
                    break
        if end >= 0:
            yield i, text[i : end + 1]
            i = end + 1
        else:
            # この opener からは閉じられない。次の opener から復帰する。
            i += 1


def _iter_balanced(text: str, opener: str, closer: str) -> Iterator[str]:
    """平衡した opener..closer 部分文字列を列挙する（位置を捨てた薄いラッパ）。"""
    for _start, chunk in _iter_balanced_pos(text, opener, closer):
        yield chunk


def _candidates(text: str, opener: str, closer: str) -> Iterator[str]:
    """候補を「壊しにくい順」に出す。

    1. 直接パース（そのまま）
    2. **推論ブロックの外側**にある平衡候補（reasoning は除去しない＝payload 文字列内の
       `<think>` を保つ）。`<think>...</think>` に**完全内包**される候補（思考モデルが
       出す下書き JSON）は除外し、最終回答や `<think>` を含む payload を優先採用する。
    3. 最後の手段として reasoning も除去して平衡スキャン（2 で何も取れないときだけ）。

    これで2つの要求を両立する: (a) `["<think onmouseover=alert(1)>x</think>"]` の payload
    は配列ブラケットが推論スパン外なので保持、(b) `<think>{下書き}</think> {最終}` の
    下書きは推論スパン内なので無視して最終を採用。各候補は json.loads を通すので
    誤採用は起きない。
    """
    if text:
        yield text.strip()
    # 生テキストをそのまま平衡スキャンする。フェンス(```)は括弧の外なので prose として
    # スキップされ、JSON 文字列内の ``` は in_str 追跡で保持される（Markdown-injection
    # payload を壊さない）。推論ブロックに完全内包される候補（思考モデルの下書き）は除外。
    spans = _reasoning_spans(text)
    for start, chunk in _iter_balanced_pos(text, opener, closer):
        if not _fully_inside(start, start + len(chunk), spans):
            yield chunk
    # 最終フォールバック: 上で何も取れないときだけ reasoning とフェンスを除去して再走査。
    cleaned = strip_code_fences(strip_reasoning(text))
    for chunk in _iter_balanced(cleaned, opener, closer):
        yield chunk


def _loads(chunk: str) -> Optional[Any]:
    try:
        return json.loads(chunk)
    except (json.JSONDecodeError, ValueError):
        return None


def extract_json_array_of_strings(text: str) -> Optional[list[str]]:
    """文字列の JSON 配列を頑健に取り出す。見つからなければ None。

    候補が「全要素が文字列の list」のときのみ採用する（型の緩い受理はしない＝
    別構造を payload と誤認しない）。
    """
    if not text:
        return None
    for chunk in _candidates(text, "[", "]"):
        data = _loads(chunk)
        if isinstance(data, list) and data and all(isinstance(x, str) for x in data):
            return data
    return None


def extract_json_object(text: str, predicate=None) -> Optional[dict]:
    """JSON オブジェクトを頑健に取り出す。見つからなければ None。

    ``predicate`` を渡すと、それを満たす最初の dict まで候補探索を続ける。前置きに別の
    無関係なオブジェクト（例 `Metadata: {"note":"draft"}`）があっても、本命のスキーマに
    合う候補まで読み飛ばせる（合致が無ければ None＝呼び出し側は安全側へフォールバック）。
    """
    if not text:
        return None
    for chunk in _candidates(text, "{", "}"):
        data = _loads(chunk)
        if isinstance(data, dict) and (predicate is None or predicate(data)):
            return data
    return None
