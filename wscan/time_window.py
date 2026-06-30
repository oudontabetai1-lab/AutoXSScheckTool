"""
検査時間帯ゲート（純粋関数）
============================
スキャンを「実行してよい時間帯」だけに限定するための判定ロジック。

- ``--allowed-hours`` … この時間帯**だけ**攻撃を行う（業務時間外のみ等）。
- ``--forbidden-hours`` … この時間帯は攻撃を**止める**（ピーク時間の保護等）。

両方指定した場合は「allowed に入っていて、かつ forbidden に入っていない」ときだけ
許可する（forbidden が優先）。allowed 未指定なら「forbidden 以外は常時許可」。

時刻判定はすべてローカルタイム（``datetime`` のナイーブ値）で行う純粋関数。
ブラウザ/ネットワーク非依存でテストできるよう、副作用は持たない。

仕様文字列の例::

    "09:00-18:00"                 # 毎日 9〜18 時
    "Mon-Fri 22:00-06:00"        # 平日の夜間（日跨ぎ）
    "Sat,Sun 00:00-24:00"        # 週末終日
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Optional

# 曜日略称 → Python の weekday() 値（Mon=0 .. Sun=6）
_DAY_INDEX = {
    "mon": 0, "tue": 1, "wed": 2, "thu": 3,
    "fri": 4, "sat": 5, "sun": 6,
}
_DAY_ORDER = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


@dataclass(frozen=True)
class WindowRule:
    """1 本の時間帯ルール。

    ``days`` は対象曜日（weekday 値）の集合。``start`` / ``end`` は 0:00 からの分。
    ``end <= start`` のときは「日跨ぎ」（例: 22:00-06:00）として扱う。
    """
    days: frozenset[int]
    start: int  # minutes from midnight, 0..1439
    end: int    # minutes from midnight, 1..1440

    def contains(self, dt: datetime) -> bool:
        minute = dt.hour * 60 + dt.minute
        if self.start < self.end:
            # 通常の同日内ウィンドウ
            return dt.weekday() in self.days and self.start <= minute < self.end
        # 日跨ぎ: 開始曜日の start 以降、または翌日扱いで end 未満
        if dt.weekday() in self.days and minute >= self.start:
            return True
        prev_day = (dt.weekday() - 1) % 7
        return prev_day in self.days and minute < self.end


def _parse_days(token: str) -> Optional[frozenset[int]]:
    """"Mon-Fri" / "Sat,Sun" / "Wed" などを weekday 集合へ。

    空トークンは「曜日指定なし＝全曜日」（意図的）。一方、非空なのに有効な曜日を
    1 つも解釈できない（"Weekdays" 等の誤記）場合は **None を返して不正を通知** する。
    全曜日へ黙って広げると ``--allowed-hours`` の許可窓を意図せず広げてしまうため。
    """
    token = token.strip().lower()
    if not token:
        return frozenset(range(7))
    days: set[int] = set()
    for part in token.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            a, b = a.strip()[:3], b.strip()[:3]
            if a in _DAY_INDEX and b in _DAY_INDEX:
                ia, ib = _DAY_ORDER.index(a), _DAY_ORDER.index(b)
                seq = (
                    _DAY_ORDER[ia : ib + 1]
                    if ia <= ib
                    else _DAY_ORDER[ia:] + _DAY_ORDER[: ib + 1]
                )
                days.update(_DAY_INDEX[d] for d in seq)
        else:
            key = part[:3]
            if key in _DAY_INDEX:
                days.add(_DAY_INDEX[key])
    # 非空トークンで 1 つも解釈できなければ不正（None）
    return frozenset(days) if days else None


def _parse_hhmm(token: str) -> Optional[int]:
    token = token.strip()
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", token)
    if not m:
        return None
    h, mm = int(m.group(1)), int(m.group(2))
    if h == 24 and mm == 0:
        return 1440
    if 0 <= h <= 23 and 0 <= mm <= 59:
        return h * 60 + mm
    return None


def parse_window(spec: str) -> Optional[WindowRule]:
    """1 本の仕様文字列を WindowRule に。解釈不能なら None。"""
    spec = (spec or "").strip()
    if not spec:
        return None
    # 末尾の "HH:MM-HH:MM" を取り出し、前段を曜日トークンとみなす
    m = re.search(r"(\d{1,2}:\d{2})\s*-\s*(\d{1,2}:\d{2})\s*$", spec)
    if not m:
        return None
    start = _parse_hhmm(m.group(1))
    end = _parse_hhmm(m.group(2))
    if start is None or end is None or start == end:
        return None
    day_token = spec[: m.start()].strip()
    days = _parse_days(day_token)
    if days is None:
        # 曜日トークンが不正（"Weekdays" 等の誤記）→ ルールごと破棄（黙って全曜日に
        # 広げない）。許可窓が意図せず広がるのを防ぐ。
        return None
    return WindowRule(days=days, start=start, end=end)


def parse_windows(specs: Optional[Iterable[str]]) -> list[WindowRule]:
    """複数仕様を WindowRule 群に解釈する。

    リスト（CLI の ``action="append"`` 等）でも、各要素が ``;``/改行区切りで複数
    ウィンドウを含む（``--allowed-hours '09:00-12:00; 13:00-18:00'``）場合に対応する。
    カンマは曜日リスト（``"Sat,Sun 00:00-24:00"``）専用なので分割に使わない。
    """
    if not specs:
        return []
    if isinstance(specs, str):
        specs = [specs]
    rules: list[WindowRule] = []
    for item in specs:
        for piece in re.split(r"[;\n]", str(item)):
            rule = parse_window(piece)
            if rule is not None:
                rules.append(rule)
    return rules


def is_allowed(
    now: datetime,
    allowed: list[WindowRule],
    forbidden: list[WindowRule],
) -> bool:
    """``now`` にスキャンを実行してよいか。

    - forbidden のいずれかに入っていれば常に不可。
    - allowed が空なら（forbidden 以外は）可。
    - allowed が非空なら、いずれかの allowed に入っているときだけ可。
    """
    if any(r.contains(now) for r in forbidden):
        return False
    if not allowed:
        return True
    return any(r.contains(now) for r in allowed)


def seconds_until_allowed(
    now: datetime,
    allowed: list[WindowRule],
    forbidden: list[WindowRule],
    max_horizon_hours: int = 24 * 8,
) -> float:
    """次に許可される瞬間までの秒数。今が許可なら 0.0。

    分刻みで先読みする（最大 ``max_horizon_hours`` 時間先まで）。地平線内に許可が
    見つからなければ ``float('inf')`` を返す（呼び出し側が異常として扱える）。
    """
    if is_allowed(now, allowed, forbidden):
        return 0.0
    # 次の分境界へ丸めてから走査（秒・マイクロ秒は切り捨て）
    probe = now.replace(second=0, microsecond=0) + timedelta(minutes=1)
    for _ in range(max_horizon_hours * 60):
        if is_allowed(probe, allowed, forbidden):
            return max(0.0, (probe - now).total_seconds())
        probe += timedelta(minutes=1)
    return float("inf")
