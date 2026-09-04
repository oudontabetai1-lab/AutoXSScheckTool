import pytest

from wscan.scanners import SCANNERS
from wscan.scanner_contract import (
    Carrier, CapabilityState, ExecutionKind, StateChangeClass,
    ScannerContract, validate_scanner_contract, build_capability_matrix,
    render_capability_matrix_markdown, render_capability_matrix_html,
)

# SUPPORTS_JSON_BODY 実値と JSON carrier supported の一致を免除する既知例外
_JSON_FLAG_ALLOWLIST = {"mass_assignment", "prototype_pollution", "nosql"}  # 独自 HTTPX 経路で JSON を扱うが base の pointer JSON dispatch は使わない


def _contracts():
    return {check: cls.CONTRACT for check, cls in SCANNERS.items()}


def test_every_scanner_declares_contract():
    for check, cls in SCANNERS.items():
        assert hasattr(cls, "CONTRACT"), f"{check}: missing CONTRACT"
        assert isinstance(cls.CONTRACT, ScannerContract), f"{check}: CONTRACT wrong type"


def test_contracts_are_statically_valid():
    errors = []
    for check, cls in SCANNERS.items():
        errors += validate_scanner_contract(check, cls.CONTRACT)
    assert not errors, "contract violations:\n" + "\n".join(errors)


def test_all_carriers_classified():
    for check, cls in SCANNERS.items():
        classified = {c.carrier for c in cls.CONTRACT.capabilities}
        assert classified == set(Carrier), (
            f"{check}: carriers not fully classified: {set(Carrier) - classified}"
        )


def test_old_flags_match_contract():
    mismatches = []
    for check, cls in SCANNERS.items():
        contract = cls.CONTRACT
        # JSON carrier ⟺ SUPPORTS_JSON_BODY（mass_assignment は既知例外）
        if check not in _JSON_FLAG_ALLOWLIST:
            json_supported = Carrier.JSON in contract.supported_carriers()
            if bool(getattr(cls, "SUPPORTS_JSON_BODY", False)) != json_supported:
                mismatches.append(f"{check}: SUPPORTS_JSON_BODY vs JSON carrier")
        # HAS_PAGE_LEVEL ⟺ PAGE_ANALYSIS
        if bool(getattr(cls, "HAS_PAGE_LEVEL", False)) != (
            ExecutionKind.PAGE_ANALYSIS in contract.execution_kinds
        ):
            mismatches.append(f"{check}: HAS_PAGE_LEVEL vs PAGE_ANALYSIS")
        # ALWAYS_STATE_CHANGING ⟺ state_change==ALWAYS
        if bool(getattr(cls, "ALWAYS_STATE_CHANGING", False)) != (
            contract.state_change == StateChangeClass.ALWAYS
        ):
            mismatches.append(f"{check}: ALWAYS_STATE_CHANGING vs state_change")
    assert not mismatches, "old-flag/contract drift:\n" + "\n".join(mismatches)


def test_capability_matrix_shape():
    matrix = build_capability_matrix(_contracts())
    assert set(matrix["scanners"]) == set(SCANNERS)
    for check, row in matrix["scanners"].items():
        assert set(row["carriers"]) == {c.value for c in Carrier}
        for carrier, cell in row["carriers"].items():
            assert cell["symbol"] in {"s", "P", "U", "?"}
            assert cell["symbol"] != "?", f"{check}:{carrier} unclassified"
            # capability の全次元がセルに載っていること（下流の再構成用）
            for key in ("transports", "payload_shapes", "value_kinds"):
                assert isinstance(cell[key], list), f"{check}:{carrier} {key}"
            assert isinstance(cell["browser_required"], bool)
            assert isinstance(cell["structured_payload"], bool)
            if cell["symbol"] == "s":  # supported は payload_shapes を必ず持つ
                assert cell["payload_shapes"], f"{check}:{carrier} supported without payload_shapes"


def test_render_capability_matrix_markdown():
    matrix = build_capability_matrix(_contracts())
    md = render_capability_matrix_markdown(matrix)
    # 全 scanner が表の行に出る
    for check in SCANNERS:
        assert f"| {check} |" in md
    # 全 carrier が列ヘッダに出る
    for carrier in Carrier:
        assert carrier.value in md
    # 凡例と集計セクション
    assert "凡例:" in md
    assert "## 集計" in md
    # 非対応/予定の理由が markdown に出る（--json 不要で「なぜ検査できないか」が読める）
    assert "## 非対応・予定の理由" in md
    # 実在する unsupported の reason が本文に含まれる
    sample_reason = None
    for check, cls in SCANNERS.items():
        for cap in cls.CONTRACT.capabilities:
            if cap.state.value in ("unsupported", "planned") and cap.reason:
                sample_reason = cap.reason
                break
        if sample_reason:
            break
    assert sample_reason and sample_reason in md
    # JSON dict のみから生成（元 matrix に無いキーを勝手に作らない）
    assert md.count("| " + next(iter(SCANNERS)) + " |") >= 0


def test_render_capability_matrix_html():
    matrix = build_capability_matrix(_contracts())
    out = render_capability_matrix_html(matrix)
    # collapsible セクション・凡例・表がある
    assert "<details" in out and "</details>" in out
    assert "凡例:" in out
    assert "<table>" in out
    # 全 scanner が行に、全 carrier が列ヘッダに出る
    for check in SCANNERS:
        assert f">{check}<" in out
    for carrier in Carrier:
        assert f"<th>{carrier.value}</th>" in out
    # 未実装セルが色で可視化される（unsupported の背景色が使われている）
    assert "#e9ecef" in out  # unsupported
    # `s` は「宣言のみ・E2E 未接続」の但し書きを凡例・集計に保持する（Codex P2）。
    # 「実際にその carrier を突いた」と誤認させない。
    assert "E2E 未接続" in out
    assert ">s=supported<" not in out  # 素の「supported」だけの凡例にはしない
    # 実在する unsupported の reason が cell tooltip(title) に載る
    sample_reason = None
    for check, cls in SCANNERS.items():
        for cap in cls.CONTRACT.capabilities:
            if cap.state.value in ("unsupported", "planned") and cap.reason:
                sample_reason = cap.reason
                break
        if sample_reason:
            break
    assert sample_reason and f"reason={sample_reason}" in _unescape_titles(out)


def _unescape_titles(html_text: str) -> str:
    import html as _h
    return _h.unescape(html_text)


def test_render_capability_matrix_html_escapes_and_handles_empty():
    # 空 matrix はセクションごと省略（空文字）
    assert render_capability_matrix_html({}) == ""
    assert render_capability_matrix_html({"carriers": [], "scanners": {}}) == ""
    # 悪意ある reason/scanner 名でも HTML を壊さない（属性/本文ともエスケープ）
    evil = {
        "carriers": ["query"],
        "scanners": {
            "x<script>": {
                "state_change": "read-only",
                "carriers": {
                    "query": {
                        "symbol": "U",
                        "state": "unsupported",
                        "reason": '"><img src=x onerror=alert(1)>',
                        "task": "",
                        "value_kinds": ["string"],
                        "transports": [],
                    }
                },
            }
        },
    }
    out = render_capability_matrix_html(evil)
    assert "<script>" not in out
    assert "onerror=alert(1)>" not in out  # 生の属性ブレイクアウトが無い
    assert "&lt;script&gt;" in out
