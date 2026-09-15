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
    def __init__(self, page, nav_ok=True):
        self.page = page
        self.navigated = []
        self.nav_ok = nav_ok

    async def navigate(self, url):
        self.navigated.append(url)
        return self.nav_ok


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


def test_navigate_failure_fails_flow():
    # navigate が False（4xx/timeout）を返したら flow 失敗（成功扱いにしない）。
    browser = _FakeBrowser(_FakePage(), nav_ok=False)
    ok = _run(browser, [FlowStep(action="navigate", url="http://t.test/x")])
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


def test_cookies_resynced_after_successful_pre_attack_flow():
    """成功した flow の後、page-level 検査の前に engine.cookies を採り直すこと（#167 P1）。

    login flow がセッション Cookie を発行/更新するため、flow 前の sync だけだと HTTP
    scanner が空/失効 Cookie で protected を叩く。flow 後に再 sync することを検証。
    """
    from wscan.engine import ScanEngine

    order = []
    eng = ScanEngine.__new__(ScanEngine)
    eng.scanners = {}                 # page-level は本テストの焦点外（no-op）
    eng.concurrency = 1
    eng.flows = [ScanFlow(name="login", steps=[
        FlowStep(action="navigate", url="http://t.test/admin"),
    ])]
    eng._browser = types.SimpleNamespace(
        page=types.SimpleNamespace(url="http://t.test/admin")
    )
    eng._record_unscannable_url = MagicMock()

    async def _relogin(*a, **k):
        return None

    async def _sync(*a, **k):
        order.append("sync")

    eng._maybe_relogin_for_page = _relogin
    eng._sync_cookies_from_browser = _sync
    eng._save_checkpoint = lambda *a, **k: None

    page = types.SimpleNamespace(url="http://t.test/admin", forms=[], url_params=[])

    class _OkRunner:
        def __init__(self, browser):
            pass

        async def run(self, flow):
            order.append("flow")
            return True

    with patch("wscan.engine.FlowRunner", _OkRunner):
        asyncio.run(eng._attack_one_page(page, {}))

    assert "flow" in order and "sync" in order
    # flow の後に少なくとも1回 sync が走る（fresh cookie を engine.cookies へ反映）。
    assert order.index("sync", order.index("flow") + 1) > order.index("flow")
    eng._record_unscannable_url.assert_not_called()  # 成功時は unscannable 記録しない


def test_pre_attack_flow_redirected_to_login_is_skipped():
    """flow が 200 で login/別URL へ redirect した場合、page-level 検査前に skip する（#167 P1）。"""
    from wscan.engine import ScanEngine

    page_scanned = {"called": False}

    class _PageScanner:
        HAS_PAGE_LEVEL = True

        async def scan_page(self, url):
            page_scanned["called"] = True
            return []

    eng = ScanEngine.__new__(ScanEngine)
    eng.scanners = {"security_headers": _PageScanner()}
    eng._checkpoint_is_done = lambda *a, **k: False
    eng._checkpoint_mark_done = lambda *a, **k: None
    eng._record_scan_matrix = lambda *a, **k: None
    eng._record_finding = lambda *a, **k: None
    eng.concurrency = 1
    eng.navigation_retries = 0
    eng.flows = [ScanFlow(name="login", steps=[
        FlowStep(action="navigate", url="http://t.test/admin"),
    ])]

    class _Br:
        def __init__(self):
            self.page = types.SimpleNamespace(url="http://t.test/login")  # redirect 着地

        async def navigate(self, url, retries=0):
            return True  # 200 だが依然 login に留まる（復帰失敗）

    eng._browser = _Br()
    eng._record_unscannable_url = MagicMock()

    async def _noop(*a, **k):
        return None

    eng._maybe_relogin_for_page = _noop
    eng._sync_cookies_from_browser = _noop
    eng._save_checkpoint = lambda *a, **k: None

    page = types.SimpleNamespace(url="http://t.test/admin", forms=[{"x": 1}], url_params=[])

    class _OkRunner:
        def __init__(self, browser):
            pass

        async def run(self, flow):
            return True  # run 自体は成功扱いだが着地が target でない

    with patch("wscan.engine.FlowRunner", _OkRunner):
        asyncio.run(eng._attack_one_page(page, {}))

    eng._record_unscannable_url.assert_called_once()
    assert page_scanned["called"] is False  # 誤ページに page-level を当てない


def test_pre_attack_flow_fragment_change_is_on_target():
    """flow 後に #fragment だけ変わった場合（tab遷移等）は target 上とみなし skip しない（#167 P1）。"""
    from wscan.engine import ScanEngine

    page_scanned = {"called": False}

    class _PageScanner:
        HAS_PAGE_LEVEL = True

        async def scan_page(self, url):
            page_scanned["called"] = True
            return []

    eng = ScanEngine.__new__(ScanEngine)
    eng.scanners = {"security_headers": _PageScanner()}
    eng._checkpoint_is_done = lambda *a, **k: False
    eng._checkpoint_mark_done = lambda *a, **k: None
    eng._record_scan_matrix = lambda *a, **k: None
    eng._record_finding = lambda *a, **k: None
    eng.concurrency = 1
    eng.navigation_retries = 0
    eng.flag_finder = None
    eng.flows = [ScanFlow(name="login", steps=[
        FlowStep(action="navigate", url="http://t.test/admin"),
    ])]

    navs = []

    class _Br:
        def __init__(self):
            self.page = types.SimpleNamespace(url="http://t.test/admin#settings")  # fragment のみ差

        async def navigate(self, url, retries=0):
            navs.append(url)
            return True

    eng._browser = _Br()
    eng._record_unscannable_url = MagicMock()

    async def _noop(*a, **k):
        return None

    eng._maybe_relogin_for_page = _noop
    eng._sync_cookies_from_browser = _noop
    eng._save_checkpoint = lambda *a, **k: None
    eng._ensure_authenticated = _noop

    page = types.SimpleNamespace(url="http://t.test/admin", forms=[], url_params=[])

    class _OkRunner:
        def __init__(self, browser):
            pass

        async def run(self, flow):
            return True

    with patch("wscan.engine.FlowRunner", _OkRunner):
        asyncio.run(eng._attack_one_page(page, {}))

    eng._record_unscannable_url.assert_not_called()  # fragment 差は離脱扱いしない
    assert navs == []                                # 不要な base への再navもしない
    assert page_scanned["called"] is True            # target 上として page-level 実行


def test_urls_same_page_ignores_fragment_only():
    """_urls_same_page: fragment 差は同一、path/query 差は別（着地先検証・attack前re-navで共有）。"""
    from wscan.engine import ScanEngine

    same = ScanEngine._urls_same_page
    assert same("http://t/admin", "http://t/admin#settings") is True
    assert same("http://t/admin/", "http://t/admin") is True
    assert same("http://t/admin", "http://t/login") is False
    assert same("http://t/view?page=admin", "http://t/view?page=home") is False
    assert same("", "http://t/admin") is False
