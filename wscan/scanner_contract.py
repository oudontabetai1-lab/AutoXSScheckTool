"""Scanner capability contract（0035-A）。

各 scanner が「どの carrier を、どの value kind/transport/payload shape で検査できるか」を
機械可読に宣言するための純粋モジュール。scan/verify のロジックは持たない（宣言と検証のみ）。

0035-A の段階では *挙動を変えない*。ここで宣言した contract は capability matrix の生成と
contract test に使うだけで、dispatch 実装への配線は 0035-C 以降で行う。
"""
from __future__ import annotations

import html
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


# 実ブラウザを要する transport（browser_required と整合させる）
BROWSER_TRANSPORTS: frozenset[TransportKind] = frozenset(
    {TransportKind.PLAYWRIGHT, TransportKind.DOM}
)


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
            # dispatch が scalar/structured/binary を選べるよう payload_shapes も必須にする。
            if not cap.payload_shapes:
                errors.append(f"{check}:{cap.carrier.value}: supported but no payload_shapes")
            # transport が browser 系（Playwright/DOM）を1つでも含むなら browser_required を True に。
            # httpx を併記していても実経路が browser を通る（navigate/fill_and_submit で form 取得等）
            # 場合があり、browserless フィルタが「browser 無しで実行可」と誤認しないため。
            if (cap.transports & BROWSER_TRANSPORTS) and not cap.browser_required:
                errors.append(
                    f"{check}:{cap.carrier.value}: browser transport but browser_required=False"
                )
            # 逆に browser_required=True なら browser transport を1つは宣言する。
            if cap.browser_required and not (cap.transports & BROWSER_TRANSPORTS):
                errors.append(
                    f"{check}:{cap.carrier.value}: browser_required but no browser transport"
                )
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
                # 宣言された capability を下流（0034 scorecard/dispatcher）が完全再構成できるよう
                # value_kinds だけでなく transports/payload_shapes/browser_required/structured_payload も出す。
                "value_kinds": sorted(vk.value for vk in (cap.value_kinds if cap else frozenset())),
                "transports": sorted(t.value for t in (cap.transports if cap else frozenset())),
                "payload_shapes": sorted(s.value for s in (cap.payload_shapes if cap else frozenset())),
                "browser_required": bool(cap.browser_required) if cap else False,
                "structured_payload": bool(cap.structured_payload) if cap else False,
            }
        rows[check] = {
            "execution_kinds": sorted(e.value for e in contract.execution_kinds),
            "state_change": contract.state_change.value,
            "cost": contract.cost.value,
            "prerequisites": sorted(p.value for p in contract.prerequisites),
            "carriers": cells,
        }
    return {"carriers": carriers, "scanners": rows}


def render_capability_matrix_markdown(matrix: dict) -> str:
    """capability matrix（build_capability_matrix の出力）を人間向け Markdown へ整形（純粋）。

    行=scanner・列=carrier のセル記号表（s=supported/E2E 未接続, P=planned, U=unsupported,
    ?=未分類）＋凡例＋planned の task 別一覧を出す。JSON dict だけから生成し再計算しない。
    """
    carriers = list(matrix.get("carriers", []))
    scanners = matrix.get("scanners", {})
    lines = [
        "# Scanner capability matrix",
        "",
        "各 scanner が入力経路（carrier）ごとに何を検査できるかの一覧。",
        "凡例: `s`=supported（E2E 未接続）, `P`=planned, `U`=unsupported, `?`=未分類。",
        "",
        "| scanner | state_change | " + " | ".join(carriers) + " |",
        "|---|---|" + "|".join(["---"] * len(carriers)) + "|",
    ]
    # 集計・planned 収集・非対応/予定の理由収集（primary use case = 「なぜ検査できないか」）
    counts: dict[str, int] = {}
    planned_by_task: dict[str, list[str]] = {}
    reasons_by_scanner: dict[str, list[str]] = {}
    for check in sorted(scanners):
        row = scanners[check]
        cells = row.get("carriers", {})
        symbols = []
        for carrier in carriers:
            cell = cells.get(carrier, {})
            sym = cell.get("symbol", "?")
            symbols.append(sym)
            counts[sym] = counts.get(sym, 0) + 1
            state = cell.get("state")
            if state == "planned":
                task = cell.get("task") or "(no task)"
                planned_by_task.setdefault(task, []).append(f"{check}.{carrier}")
            if state in ("planned", "unsupported"):
                reason = cell.get("reason") or ""
                suffix = f"（planned: {cell.get('task') or 'no task'}）" if state == "planned" else ""
                if reason:
                    reasons_by_scanner.setdefault(check, []).append(
                        f"- `{carrier}` — {reason}{suffix}"
                    )
        lines.append(
            f"| {check} | {row.get('state_change', '')} | " + " | ".join(symbols) + " |"
        )
    lines += [
        "",
        "## 集計",
        "",
        "| 記号 | 意味 | 件数 |",
        "|---|---|---:|",
        f"| s | supported（E2E 未接続） | {counts.get('s', 0)} |",
        f"| P | planned | {counts.get('P', 0)} |",
        f"| U | unsupported | {counts.get('U', 0)} |",
    ]
    if counts.get("?"):
        lines.append(f"| ? | 未分類 | {counts['?']} |")
    if planned_by_task:
        lines += ["", "## Planned（task 別）", ""]
        for task in sorted(planned_by_task):
            cells = ", ".join(sorted(planned_by_task[task]))
            lines.append(f"- **{task}**: {cells}")
    if reasons_by_scanner:
        lines += [
            "",
            "## 非対応・予定の理由（なぜその carrier を検査できないか）",
            "",
        ]
        for check in sorted(reasons_by_scanner):
            lines.append(f"### {check}")
            lines.extend(reasons_by_scanner[check])
            lines.append("")
    return "\n".join(lines) + "\n"


# HTML セル記号→(ラベル, 背景色)。未実装セル（U/P/?）を色で可視化する（0035-E）。
# `s` は _cell()/Markdown renderer と同義で「宣言された capability（E2E 未接続）」であり、
# 「実際にその carrier を突いた」ことは意味しない。誤認防止のため凡例・集計にこの但し書きを保持する。
_CELL_STYLE = {
    "s": ("supported（宣言のみ・E2E 未接続）", "#e6f4ea", "#1e7e34"),
    "P": ("planned", "#fff3cd", "#856404"),
    "U": ("unsupported", "#e9ecef", "#6c757d"),
    "?": ("unclassified", "#fde2e1", "#b00020"),
}


def render_capability_matrix_html(matrix: dict) -> str:
    """capability matrix（build_capability_matrix の出力）を HTML 断片へ整形（純粋）。

    行=scanner・列=carrier の記号グリッド。未実装セル（U/P/?）を色分けし、各セルの
    `title` 属性へ state/value_kinds/transports/reason を載せる（hover で「なぜ検査できないか」）。
    レポートの coverage セクションへ埋める用途。空 matrix では空文字を返す（セクションごと省略）。
    JSON dict だけから生成し再計算しない。scanner_contract 内で self.escape に依存しないよう
    stdlib html.escape を使う（純粋・テスト容易）。
    """
    scanners = matrix.get("scanners", {}) or {}
    carriers = list(matrix.get("carriers", []) or [])
    if not scanners or not carriers:
        return ""

    def esc(value) -> str:
        return html.escape(str(value), quote=True)

    header = "".join(f"<th>{esc(c)}</th>" for c in carriers)
    counts: dict[str, int] = {}
    body_rows = []
    for check in sorted(scanners):
        row = scanners[check]
        cells_meta = row.get("carriers", {}) or {}
        tds = []
        for carrier in carriers:
            cell = cells_meta.get(carrier, {}) or {}
            sym = cell.get("symbol", "?")
            counts[sym] = counts.get(sym, 0) + 1
            _label, bg, fg = _CELL_STYLE.get(sym, _CELL_STYLE["?"])
            vks = ", ".join(cell.get("value_kinds", []) or []) or "-"
            trs = ", ".join(cell.get("transports", []) or []) or "-"
            reason = cell.get("reason", "") or ""
            task = cell.get("task", "") or ""
            title = f"{cell.get('state', '')}; value_kinds={vks}; transports={trs}"
            if reason:
                title += f"; reason={reason}"
            if task:
                title += f"; task={task}"
            tds.append(
                f'<td title="{esc(title)}" '
                f'style="background:{bg};color:{fg};text-align:center;font-weight:600">'
                f"{esc(sym)}</td>"
            )
        body_rows.append(
            f"<tr><th style=\"text-align:left\">{esc(check)}</th>"
            f"<td style=\"text-align:center\">{esc(row.get('state_change', ''))}</td>"
            + "".join(tds)
            + "</tr>"
        )

    legend = " ".join(
        f'<span style="background:{bg};color:{fg};padding:1px 6px;border-radius:3px">'
        f"{esc(sym)}={esc(label)}</span>"
        for sym, (label, bg, fg) in _CELL_STYLE.items()
    )
    # `s` は「宣言のみ・E2E 未接続」なので「実際に検査した」と誤読されないよう明記する。
    summary = (
        f"supported（宣言のみ・E2E 未接続） {counts.get('s', 0)} / "
        f"planned {counts.get('P', 0)} / unsupported {counts.get('U', 0)}"
        + (f" / unclassified {counts['?']}" if counts.get("?") else "")
    )
    return (
        '<details style="margin-top:14px"><summary style="cursor:pointer;font-weight:600">'
        "Scanner capability matrix（in-scope の scanner × carrier）</summary>"
        f'<p style="margin:6px 0">凡例: {legend}</p>'
        f"<p>{esc(summary)}</p>"
        '<div class="table-wrap"><table><thead><tr><th>scanner</th><th>state_change</th>'
        f"{header}</tr></thead><tbody>"
        + "".join(body_rows)
        + "</tbody></table></div>"
        '<p style="color:#666;font-size:0.9em">セル記号の詳細（value_kinds/transports/理由）は'
        "各セルにマウスを重ねると表示されます。</p>"
        "</details>"
    )
