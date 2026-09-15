"""F10: FlowRunner が存在しない入力欄/送信先を成功扱いにしないことを検証する。

fill 対象欄が無いのに成功扱いで後続へ進むと、前提操作の欠落を見逃す。
非存在欄への fill / 送信先の無い submit は失敗として run() を False にし、
後続の依存 step を実行しないことを確認する。正常な fill は完走する。
"""
import asyncio

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
