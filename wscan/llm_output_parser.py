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
    """平衡した opener..closer を (開始位置, 部分文字列) で列挙する。"""
    depth = 0
    start = -1
    in_str = False
    escaped = False
    for i, ch in enumerate(text):
        # 候補（opener）開始前は文字列追跡をしない。prose 中の孤立した `"` で string
        # mode に入り、後続の opener を握りつぶして有効な JSON を取り逃す事故を防ぐ。
        if depth == 0:
            if ch == opener:
                depth = 1
                start = i
                in_str = False
                escaped = False
            continue
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
            if depth == 0 and start >= 0:
                yield start, text[start : i + 1]
                start = -1


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
    base = strip_code_fences(text)
    spans = _reasoning_spans(base)
    for start, chunk in _iter_balanced_pos(base, opener, closer):
        if not _fully_inside(start, start + len(chunk), spans):
            yield chunk
    cleaned = strip_reasoning(base)
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


def extract_json_object(text: str) -> Optional[dict]:
    """JSON オブジェクトを頑健に取り出す。見つからなければ None。"""
    if not text:
        return None
    for chunk in _candidates(text, "{", "}"):
        data = _loads(chunk)
        if isinstance(data, dict):
            return data
    return None
