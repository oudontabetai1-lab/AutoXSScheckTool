"""F09: record→scan --flows の往復が実際に効くことを検証する。

record は steps の**リスト**を保存し、fill step は CSS selector を持つ。
- main._load_flow_files がリスト/｛name,steps｝の両形式を flow dict へ読み込むこと。
- 読み込んだ dict が ScanFlow へ復元され、fill が selector で解決されること
  （案内どおり `scan --flows <file>` が動く）。
- 壊れたファイルは skip して他を止めないこと。
"""
import asyncio
import json

from main import _load_flow_files
from wscan.flow_runner import FlowRunner, ScanFlow


def test_load_flow_files_wraps_steps_list(tmp_path):
    # record が保存する形式（bare steps list）。
    rec = tmp_path / "recording.json"
    rec.write_text(json.dumps([
        {"action": "navigate", "url": "http://t.test/login"},
        {"action": "fill", "selector": "#user", "value": "alice"},
        {"action": "click", "selector": "button[type=submit]"},
    ]), encoding="utf-8")

    flows = _load_flow_files([str(rec)])
    assert len(flows) == 1
    assert flows[0]["name"] == "recording"          # file stem を name に
    assert flows[0]["steps"][1]["selector"] == "#user"


def test_load_flow_files_accepts_named_dict(tmp_path):
    named = tmp_path / "login.json"
    named.write_text(json.dumps(
        {"name": "ログイン", "steps": [{"action": "navigate", "url": "http://t/x"}]}
    ), encoding="utf-8")

    flows = _load_flow_files([str(named)])
    assert flows == [{"name": "ログイン", "steps": [{"action": "navigate", "url": "http://t/x"}]}]


def test_load_flow_files_skips_broken_file_keeps_rest(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps([{"action": "navigate", "url": "http://t/x"}]), encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    missing = tmp_path / "nope.json"

    flows = _load_flow_files([str(bad), str(good), str(missing)])
    assert [f["name"] for f in flows] == ["good"]   # 壊れた/欠落は skip、good は残る


def test_none_returns_empty():
    assert _load_flow_files(None) == []


def test_skips_structurally_broken_steps(tmp_path):
    # JSON 妥当でも step が非 dict（[1]）や timeout 非数値だと後段の FlowStep.from_dict が
    # 落ちてスキャン全体を止める。_load_flow_files で検証して skip すること（#170 P2）。
    nondict = tmp_path / "nondict.json"
    nondict.write_text(json.dumps([1, 2]), encoding="utf-8")
    badtimeout = tmp_path / "badtimeout.json"
    badtimeout.write_text(json.dumps([{"action": "wait", "timeout": "soon"}]), encoding="utf-8")
    good = tmp_path / "good.json"
    good.write_text(json.dumps([{"action": "navigate", "url": "http://t/x"}]), encoding="utf-8")

    flows = _load_flow_files([str(nondict), str(badtimeout), str(good)])
    assert [f["name"] for f in flows] == ["good"]   # 壊れた step 構造は skip、good は残す


def test_roundtrip_recorded_fill_uses_selector(tmp_path):
    """読み込んだ recording を ScanFlow 化し、fill が selector で解決されることを確認。"""
    rec = tmp_path / "rec.json"
    rec.write_text(json.dumps([
        {"action": "fill", "selector": "#user", "value": "secret"},
    ]), encoding="utf-8")
    flows = ScanFlow.list_from_dicts(_load_flow_files([str(rec)]))
    assert len(flows) == 1

    captured = {}

    class _RecPage:
        async def evaluate(self, js, arg=None):
            captured["arg"] = arg
            return bool(arg and arg[0])

        async def wait_for_load_state(self, *a, **k):
            return None

    class _Browser:
        def __init__(self):
            self.page = _RecPage()

    ok = asyncio.run(FlowRunner(_Browser()).run(flows[0]))
    assert ok is True
    # fill が [selector, field, value] を JS へ渡し、selector で要素解決する。
    assert captured["arg"] == ["#user", "", "secret"]
