"""time-based SQLi 検証の no-sleep 対照比較のテスト。

恒常的に遅いエンドポイントを time-based 陽性と誤判定しないこと（対照リクエストと
の差が小さいときは棄却）、および正当な遅延差は受理することを確認する。
"""
import types
import unittest

from wscan.scanners.sqli import SQLiScanner


def _pair(elapsed: float) -> dict:
    # 実データは epoch 秒（非ゼロ）。基準を 1000.0 として経過を表現する。
    return {"request": {"timestamp": 1000.0}, "response": {"timestamp": 1000.0 + elapsed}}


def _finding() -> types.SimpleNamespace:
    return types.SimpleNamespace(
        url="http://victim.test/item",
        field_name="id",
        payload="1' AND SLEEP(3)--",
        evidence_type="sqli_time",
        evidence_details={"threshold_seconds": 2.5},
    )


class TimeBasedVerifyTests(unittest.IsolatedAsyncioTestCase):
    def _scanner(self, sleep_elapsed: float, control_elapsed: float) -> SQLiScanner:
        sc = object.__new__(SQLiScanner)

        async def fake_apply(url, form_index, field_name, payload, is_url_param):
            # SLEEP ペイロードは遅い応答、対照("1")は control_elapsed を返す。
            t = sleep_elapsed if "SLEEP" in payload else control_elapsed
            return "", _pair(t)

        sc._apply_payload = fake_apply
        return sc

    async def test_rejects_when_control_also_slow(self):
        # SLEEP 5.0s だが対照も 4.5s（差 0.5s < 2s）→ 恒常的に遅いだけ → 棄却。
        sc = self._scanner(sleep_elapsed=5.0, control_elapsed=4.5)
        self.assertFalse(await sc.verify_finding(_finding()))

    async def test_accepts_when_control_fast(self):
        # SLEEP 3.2s・対照 0.2s（差 3.0s ≥ 2s）→ 受理。
        sc = self._scanner(sleep_elapsed=3.2, control_elapsed=0.2)
        self.assertTrue(await sc.verify_finding(_finding()))

    async def test_rejects_when_sleep_below_threshold(self):
        # SLEEP 応答自体が閾値未満 → 即棄却（対照も見ない）。
        sc = self._scanner(sleep_elapsed=1.0, control_elapsed=0.1)
        self.assertFalse(await sc.verify_finding(_finding()))


class ResponseElapsedTests(unittest.TestCase):
    def test_elapsed_and_threshold(self):
        sc = object.__new__(SQLiScanner)
        self.assertEqual(sc.response_elapsed(_pair(3.0)), 3.0)
        self.assertTrue(sc.response_time_exceeded(_pair(3.0), threshold=2.5))
        self.assertFalse(sc.response_time_exceeded(_pair(1.0), threshold=2.5))

    def test_elapsed_none_when_no_timestamps(self):
        sc = object.__new__(SQLiScanner)
        self.assertIsNone(sc.response_elapsed({"request": {}, "response": {}}))


if __name__ == "__main__":
    unittest.main()
