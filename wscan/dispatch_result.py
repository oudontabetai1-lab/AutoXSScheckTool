"""dispatcher facade の typed 結果（0035-C）。純粋・決定論。挙動は持たない。"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from wscan.scanner_contract import Carrier, TransportKind


class DispatchState(str, Enum):
    SENT = "sent"                    # transport が実際に送信し応答を得た
    UNSUPPORTED = "unsupported"      # capability 非対応
    BLOCKED = "blocked"              # state profile / scope で送信不可
    UNEXECUTABLE = "unexecutable"    # template 不在等で実行不能（未送信）
    TRANSPORT_ERROR = "transport_error"  # 送信/transport 失敗（timeout を含む）


@dataclass(frozen=True)
class DispatchResult:
    """dispatch の typed 結果。legacy (source, pair) を保持し移行互換を保つ。"""

    state: DispatchState
    carrier: Carrier
    source: str = ""
    pair: dict = field(default_factory=dict)
    transport: TransportKind | None = None
    note: str = ""

    @property
    def sent(self) -> bool:
        return self.state == DispatchState.SENT

    @property
    def has_response(self) -> bool:
        return bool(self.pair) and self.state == DispatchState.SENT


# canonical location から得た carrier が現状使う代表 transport（分類メモ用）。
_CARRIER_TRANSPORT_HINT: dict[Carrier, TransportKind] = {
    Carrier.QUERY: TransportKind.PLAYWRIGHT,
    Carrier.FORM: TransportKind.PLAYWRIGHT,
    Carrier.JSON: TransportKind.HTTPX,
}


def transport_hint_for(carrier: Carrier) -> "TransportKind | None":
    """carrier の代表 transport（現状の _apply_ip 経路に基づく目安・純粋）。"""
    return _CARRIER_TRANSPORT_HINT.get(carrier)
