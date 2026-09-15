"""F10: FlowRunner が存在しない入力欄/送信先を成功扱いにしないことを検証する。

fill 対象欄が無いのに成功扱いで後続へ進むと、前提操作の欠落を見逃す。
非存在欄への fill / 送信先の無い submit は失敗として run() を False にし、
後続の依存 step を実行しないことを確認する。正常な fill は完走する。
"""
import asyncio
import types
from unittest.mock import MagicMock, patch

from wscan.flow_runner import FlowRunner, FlowStep, ScanFlow


class _FakePage:
    def __init__(self, *, fill_ok=True, submit_ok=True):
        self.fill_ok = fill_ok
        self.submit_ok = submit_ok

    async def evaluate(self, js, arg=None):
        # fill は [field, value] を渡す。submit は引数なし。
        return self.fill_ok if arg is not None else self.submit_ok

    async def wait_for_load_state(self, *a, **k):
        return None


class _FakeBrowser:
    def __init__(self, page):
        self.page = page
        self.navigated = []

    async def navigate(self, url):
        self.navigated.append(url)


def _run(browser, steps):
    flow = ScanFlow(name="t", steps=steps)
    return asyncio.run(FlowRunner(browser).run(flow))


def test_fill_missing_field_fails_and_stops_dependent_steps():
    browser = _FakeBrowser(_FakePage(fill_ok=False))
    ok = _run(browser, [
        FlowStep(action="fill", field="ghost", value="x"),
        FlowStep(action="navigate", url="http://after.test/"),  # 後続（依存）
    ])
    assert ok is False                 # 前提 fill 失敗で flow 失敗
    assert browser.navigated == []     # 後続の依存 step を成功扱いで進めない


def test_fill_existing_field_completes():
    browser = _FakeBrowser(_FakePage(fill_ok=True))
    ok = _run(browser, [FlowStep(action="fill", field="user", value="x")])
    assert ok is True


def test_submit_without_target_fails():
    browser = _FakeBrowser(_FakePage(submit_ok=False))
    ok = _run(browser, [FlowStep(action="submit")])
    assert ok is False


def test_attack_one_page_skips_when_pre_attack_flow_fails():
    """前提 flow 失敗時、caller(_attack_one_page)が攻撃を skip し unscannable 記録すること。

    F10 の本丸: run() が False を返しても production caller が無視すると、未認証ページを
    そのまま攻撃してしまう。caller が結果を見て skip＋coverage gap 記録することを検証。
    """
    from wscan.engine import ScanEngine

    eng = ScanEngine.__new__(ScanEngine)

    page_scanned = {"called": False}

    class _PageScanner:
        HAS_PAGE_LEVEL = True

        async def scan_page(self, url):
            page_scanned["called"] = True
            return []

    eng.scanners = {"security_headers": _PageScanner()}  # page-level 検査の番兵
    eng._checkpoint_is_done = lambda *a, **k: False
    eng._checkpoint_mark_done = lambda *a, **k: None
    eng._record_scan_matrix = lambda *a, **k: None
    eng._record_finding = lambda *a, **k: None
    eng.concurrency = 1
    eng.navigation_retries = 0
    eng.flows = [ScanFlow(name="login", steps=[
        FlowStep(action="fill", field="ghost", value="x"),
        FlowStep(action="navigate", url="http://t.test/admin"),
    ])]
    eng._browser = types.SimpleNamespace(   # browser プロパティは worker 非在時 _browser を返す
        page=types.SimpleNamespace(url="http://t.test/admin")
    )
    eng._record_unscannable_url = MagicMock()

    async def _noop(*a, **k):
        return None

    eng._maybe_relogin_for_page = _noop
    eng._sync_cookies_from_browser = _noop
    eng._save_checkpoint = lambda *a, **k: None

    page = types.SimpleNamespace(
        url="http://t.test/admin", forms=[{"x": 1}], url_params=[]
    )

    class _FailRunner:
        def __init__(self, browser):
            pass

        async def run(self, flow):
            return False  # 前提 flow 失敗

    attacked = {"called": False}
    # flow ブロック以降（攻撃）へ進んだら検知できるよう番兵を置く。
    eng._attack_field = lambda *a, **k: attacked.__setitem__("called", True)

    with patch("wscan.engine.FlowRunner", _FailRunner):
        asyncio.run(eng._attack_one_page(page, {}))

    eng._record_unscannable_url.assert_called_once()
    assert "flow" in str(eng._record_unscannable_url.call_args).lower()
    assert attacked["called"] is False        # 攻撃（field）へ進んでいない
    assert page_scanned["called"] is False    # page-level 検査も走っていない（前提flow前に判定）
