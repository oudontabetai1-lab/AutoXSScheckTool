"""Scanner capability contract（0035-A）。

各 scanner が「どの carrier を、どの value kind/transport/payload shape で検査できるか」を
機械可読に宣言するための純粋モジュール。scan/verify のロジックは持たない（宣言と検証のみ）。

0035-A の段階では *挙動を変えない*。ここで宣言した contract は capability matrix の生成と
contract test に使うだけで、dispatch 実装への配線は 0035-C 以降で行う。
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Carrier(str, Enum):
    QUERY = "query"
    FORM = "form"
    JSON = "json"
    XML = "xml"
    MULTIPART = "multipart"
    HEADER = "header"
    COOKIE = "cookie"
    PATH = "path"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"


# 全 carrier（宣言の網羅性チェックに使う）
ALL_CARRIERS: frozenset[Carrier] = frozenset(Carrier)


class ValueKind(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    NULL = "null"
    OBJECT = "object"
    ARRAY = "array"
    BINARY = "binary"
    UNKNOWN = "unknown"


class CapabilityState(str, Enum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    PLANNED = "planned"


class TransportKind(str, Enum):
    PLAYWRIGHT = "playwright"   # ブラウザ経由（form/query の実 UI 送信、DOM）
    HTTPX = "httpx"             # 直接 HTTP（json/xml/multipart/header/cookie/path）
    WEBSOCKET = "websocket"     # WS メッセージ
    OOB = "oob"                # out-of-band（mail sink 等）
    DOM = "dom"                # ブラウザ DOM 観測（dom_xss）


class PayloadShape(str, Enum):
    SCALAR = "scalar"           # 文字列/数値をそのまま埋め込む
    STRUCTURED = "structured"   # object/array 構造（nosql $ne, graphql variables 等）
    BINARY = "binary"           # multipart file 等のバイナリ本体


class ExecutionKind(str, Enum):
    FIELD_INJECTION = "field_injection"     # parameter に payload を注入する
    PAGE_ANALYSIS = "page_analysis"         # page/response/header を解析する
    STORED_OBSERVATION = "stored_observation"  # 注入後に別ページで観測する（stored xss 等）
    PROTOCOL_MESSAGE = "protocol_message"   # ws/graphql の endpoint/message 単位


class Prerequisite(str, Enum):
    AUTH_SESSION = "auth_session"
    OOB_SINK = "oob_sink"
    MULTI_ACCOUNT = "multi_account"
    SECOND_REQUEST = "second_request"       # race/smuggling 等、複数リクエスト前提
    BROWSER = "browser"                     # 実ブラウザ必須
    API_SPEC = "api_spec"                   # OpenAPI/Postman シード前提


class StateChangeClass(str, Enum):
    READ_ONLY = "read_only"
    CONDITIONAL = "conditional"
    ALWAYS = "always"


class CostClass(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class CarrierCapability:
    carrier: Carrier
    state: CapabilityState
    value_kinds: frozenset[ValueKind] = frozenset()
    transports: frozenset[TransportKind] = frozenset()
    payload_shapes: frozenset[PayloadShape] = frozenset()
    browser_required: bool = False
    structured_payload: bool = False
    reason: str = ""
    task: str = ""   # planned のとき必須（例: "0035-D"）


@dataclass(frozen=True)
class ScannerContract:
    execution_kinds: frozenset[ExecutionKind]
    capabilities: tuple[CarrierCapability, ...]
    prerequisites: frozenset[Prerequisite] = frozenset()
    state_change: StateChangeClass = StateChangeClass.CONDITIONAL
    cost: CostClass = CostClass.MEDIUM

    def capability(self, carrier: Carrier) -> CarrierCapability | None:
        for cap in self.capabilities:
            if cap.carrier == carrier:
                return cap
        return None

    def supported_carriers(self) -> frozenset[Carrier]:
        return frozenset(
            c.carrier for c in self.capabilities if c.state == CapabilityState.SUPPORTED
        )

    @property
    def has_page_level(self) -> bool:
        return ExecutionKind.PAGE_ANALYSIS in self.execution_kinds

    @property
    def supports_json_body(self) -> bool:
        return Carrier.JSON in self.supported_carriers()

    @property
    def always_state_changing(self) -> bool:
        return self.state_change == StateChangeClass.ALWAYS


# 旧 location 語彙 -> Carrier の互換マッピング（各 scanner で個別変換しない）
LOCATION_TO_CARRIER: dict[str, Carrier] = {
    "url_param": Carrier.QUERY,
    "query": Carrier.QUERY,
    "form": Carrier.FORM,
    "json_body": Carrier.JSON,
    "json": Carrier.JSON,
}


def validate_scanner_contract(check: str, contract: ScannerContract) -> list[str]:
    """contract の静的健全性を検証し、違反メッセージの list を返す（空=健全）。"""
    errors: list[str] = []
    if not isinstance(contract, ScannerContract):
        return [f"{check}: CONTRACT is not a ScannerContract"]
    if not contract.execution_kinds:
        errors.append(f"{check}: execution_kinds is empty")
    seen: set[Carrier] = set()
    for cap in contract.capabilities:
        if cap.carrier in seen:
            errors.append(f"{check}: duplicate carrier {cap.carrier.value}")
        seen.add(cap.carrier)
        if cap.state == CapabilityState.SUPPORTED:
            if not cap.value_kinds:
                errors.append(f"{check}:{cap.carrier.value}: supported but no value_kinds")
            if not cap.transports:
                errors.append(f"{check}:{cap.carrier.value}: supported but no transports")
        else:  # unsupported / planned
            if not cap.reason:
                errors.append(f"{check}:{cap.carrier.value}: {cap.state.value} but no reason")
            if cap.state == CapabilityState.PLANNED and not cap.task:
                errors.append(f"{check}:{cap.carrier.value}: planned but no task id")
    # 全 carrier を明示分類（網羅性）
    missing = ALL_CARRIERS - seen
    if missing:
        names = ", ".join(sorted(c.value for c in missing))
        errors.append(f"{check}: carriers not classified: {names}")
    return errors


def _cell(cap: CarrierCapability | None) -> str:
    """matrix セル記号。0035-A では E2E 未接続なので supported は 's'。"""
    if cap is None:
        return "?"
    if cap.state == CapabilityState.SUPPORTED:
        return "s"      # 宣言 supported・E2E 未接続（0034 で 'S' へ昇格）
    if cap.state == CapabilityState.PLANNED:
        return "P"
    return "U"          # unsupported


def build_capability_matrix(contracts: dict[str, ScannerContract]) -> dict:
    """capability matrix の JSON 正本（純粋・0034 scorecard へ供給する形）。"""
    carriers = [c.value for c in Carrier]
    rows = {}
    for check in sorted(contracts):
        contract = contracts[check]
        cells = {}
        for carrier in Carrier:
            cap = contract.capability(carrier)
            cells[carrier.value] = {
                "symbol": _cell(cap),
                "state": cap.state.value if cap else "unclassified",
                "reason": cap.reason if cap else "",
                "task": cap.task if cap else "",
                "value_kinds": sorted(vk.value for vk in (cap.value_kinds if cap else frozenset())),
            }
        rows[check] = {
            "execution_kinds": sorted(e.value for e in contract.execution_kinds),
            "state_change": contract.state_change.value,
            "cost": contract.cost.value,
            "prerequisites": sorted(p.value for p in contract.prerequisites),
            "carriers": cells,
        }
    return {"carriers": carriers, "scanners": rows}
