"""adaptive LLM 障害時の checkpoint 完了判定を検証する。"""
import asyncio
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, call

from wscan.engine import ScanEngine


class AdaptiveCheckpointRetryTests(unittest.IsolatedAsyncioTestCase):
    def _engine(
        self,
        generation_result,
        *,
        generation_status=None,
        scan_side_effect=None,
    ):
        scan_field = AsyncMock(return_value=[])
        if scan_side_effect is not None:
            scan_field.side_effect = scan_side_effect

        async def scan_injection_point(ip, field):
            return await scan_field(
                ip.url, ip.form_index, field, ip.legacy_is_url_param()
            )

        scanner = types.SimpleNamespace(
            scan_field=scan_field,
            scan_injection_point=AsyncMock(side_effect=scan_injection_point),
        )
        check_llm_available = AsyncMock(return_value=True)
        checkpoint_is_done = MagicMock(return_value=False)
        checkpoint_mark_done = MagicMock()

        def checkpoint_is_done_ip(ip, check):
            return checkpoint_is_done(
                ip.url,
                ip.display_name,
                ip.form_index,
                check,
                ip.legacy_is_url_param(),
            )

        def checkpoint_mark_done_ip(ip, check):
            checkpoint_mark_done(
                ip.url,
                ip.display_name,
                ip.form_index,
                check,
                ip.legacy_is_url_param(),
            )

        engine = types.SimpleNamespace(
            scanners={"xss": scanner},
            payload_gen=types.SimpleNamespace(
                default_payloads={"xss": []},
                _check_llm_available=check_llm_available,
            ),
            all_findings=[],
            flag_finder=None,
            adaptive_enabled=True,
            _adaptive_llm_available=None,
            _adaptive_llm_availability_lock=asyncio.Lock(),
            adaptive_engine=types.SimpleNamespace(
                generate=AsyncMock(
                    return_value=(
                        generation_result,
                        generation_status
                        or ("transient" if generation_result is None else "ok"),
                    )
                )
            ),
            browser=types.SimpleNamespace(
                page=types.SimpleNamespace(content=AsyncMock(return_value="<html></html>"))
            ),
            waf_detector=types.SimpleNamespace(_detected=None),
            completed_fields=0,
            total_fields=1,
            monitor=None,
            _checkpoint_is_done=checkpoint_is_done,
            _checkpoint_mark_done=checkpoint_mark_done,
            _checkpoint_is_done_ip=MagicMock(side_effect=checkpoint_is_done_ip),
            _checkpoint_mark_done_ip=MagicMock(side_effect=checkpoint_mark_done_ip),
            _record_scan_matrix=MagicMock(),
            _record_finding=MagicMock(),
            _save_checkpoint=MagicMock(),
        )
        engine._adaptive_attack_field = types.MethodType(
            ScanEngine._adaptive_attack_field, engine
        )
        engine._injection_point_for = types.MethodType(
            ScanEngine._injection_point_for, engine
        )
        return engine

    async def test_llm_failure_does_not_mark_adaptive_done(self):
        engine = self._engine(None)

        await ScanEngine._scan_field(
            engine, "https://example.test", 0, {"name": "q"}
        )

        self.assertNotIn(
            call("https://example.test", "q", 0, "(adaptive:xss)", False),
            engine._checkpoint_mark_done.call_args_list,
        )

    async def test_successful_empty_result_marks_adaptive_done(self):
        engine = self._engine([])

        await ScanEngine._scan_field(
            engine, "https://example.test", 0, {"name": "q"}
        )

        self.assertIn(
            call("https://example.test", "q", 0, "(adaptive:xss)", False),
            engine._checkpoint_mark_done.call_args_list,
        )

    async def test_adaptive_scanner_error_returns_none_and_stays_incomplete(self):
        engine = self._engine(
            ["<svg/onload=alert(1)>"],
            scan_side_effect=RuntimeError("temporary browser failure"),
        )

        result = await engine._adaptive_attack_field(
            "https://example.test", 0, {"name": "q"}, False, ["xss"], None
        )

        self.assertIsNone(result)
        self.assertNotIn(
            call("https://example.test", "q", 0, "(adaptive:xss)", False),
            engine._checkpoint_mark_done.call_args_list,
        )

    async def test_scan_field_does_not_mark_scanner_error_as_adaptive_done(self):
        engine = self._engine(
            ["<svg/onload=alert(1)>"],
            scan_side_effect=[[], RuntimeError("temporary browser failure")],
        )

        await ScanEngine._scan_field(
            engine, "https://example.test", 0, {"name": "q"}
        )

        self.assertNotIn(
            call("https://example.test", "q", 0, "(adaptive:xss)", False),
            engine._checkpoint_mark_done.call_args_list,
        )

    async def test_legacy_field_marker_skips_all_adaptive_checks(self):
        engine = self._engine(["<svg/onload=alert(1)>"])
        engine._checkpoint_is_done.side_effect = (
            lambda _url, _field, _form, check, _is_url_param=False:
            check == "(adaptive)"
        )

        await ScanEngine._scan_field(
            engine, "https://example.test", 0, {"name": "q"}
        )

        engine.adaptive_engine.generate.assert_not_awaited()
        self.assertEqual(engine.scanners["xss"].scan_field.await_count, 1)

    async def test_unavailable_llm_marks_adaptive_done_and_converges(self):
        completed: set[tuple[str, str]] = set()

        def is_done(_url, field, _form, check, _is_url_param=False):
            return (field, check) in completed

        def mark_done(_url, field, _form, check, _is_url_param=False):
            completed.add((field, check))

        engine = self._engine(None)
        engine.payload_gen._check_llm_available.return_value = False
        engine._checkpoint_is_done.side_effect = is_done
        engine._checkpoint_mark_done.side_effect = mark_done

        await ScanEngine._scan_field(
            engine, "https://example.test", 0, {"name": "q"}
        )
        await ScanEngine._scan_field(
            engine, "https://example.test", 0, {"name": "other"}
        )
        # resume では標準・adaptive とも完了済みの field を再試行しない。
        await ScanEngine._scan_field(
            engine, "https://example.test", 0, {"name": "q"}
        )

        self.assertIn(("q", "(adaptive:xss)"), completed)
        self.assertIn(("other", "(adaptive:xss)"), completed)
        self.assertEqual(engine.scanners["xss"].scan_field.await_count, 2)
        engine.payload_gen._check_llm_available.assert_awaited_once()
        engine.adaptive_engine.generate.assert_not_awaited()
        engine.browser.page.content.assert_not_awaited()

    async def test_unavailable_llm_returns_empty_success(self):
        engine = self._engine(None)
        engine.payload_gen._check_llm_available.return_value = False

        result = await engine._adaptive_attack_field(
            "https://example.test", 0, {"name": "q"}, False, ["xss"], None
        )

        self.assertEqual(result, [])
        self.assertIn(
            call("https://example.test", "q", 0, "(adaptive:xss)", False),
            engine._checkpoint_mark_done.call_args_list,
        )
        engine.adaptive_engine.generate.assert_not_awaited()

    async def test_permanent_or_unavailable_generation_disables_later_calls(self):
        for status in ("permanent", "unavailable"):
            with self.subTest(status=status):
                engine = self._engine([], generation_status=status)

                first = await engine._adaptive_attack_field(
                    "https://example.test", 0, {"name": "q"}, False, ["xss"], None
                )
                second = await engine._adaptive_attack_field(
                    "https://example.test", 0, {"name": "other"}, False, ["xss"], None
                )

                self.assertEqual(first, [])
                self.assertEqual(second, [])
                self.assertFalse(engine._adaptive_llm_available)
                engine.adaptive_engine.generate.assert_awaited_once()

    async def test_transient_or_empty_generation_keeps_availability_for_retry(self):
        for status in ("transient", "empty"):
            with self.subTest(status=status):
                engine = self._engine(None, generation_status=status)

                first = await engine._adaptive_attack_field(
                    "https://example.test", 0, {"name": "q"}, False, ["xss"], None
                )
                second = await engine._adaptive_attack_field(
                    "https://example.test", 0, {"name": "other"}, False, ["xss"], None
                )

                self.assertIsNone(first)
                self.assertIsNone(second)
                self.assertTrue(engine._adaptive_llm_available)
                self.assertEqual(engine.adaptive_engine.generate.await_count, 2)


class AdaptivePartialResumeTests(unittest.IsolatedAsyncioTestCase):
    async def test_resume_retries_only_failed_check(self):
        completed: set[str] = set()

        def is_done(_url, _field, _form, check, _is_url_param=False):
            return check in completed

        def mark_done(_url, _field, _form, check, _is_url_param=False):
            completed.add(check)

        generation_attempts: dict[str, int] = {}

        async def generate(*, check_type, **_kwargs):
            generation_attempts[check_type] = generation_attempts.get(check_type, 0) + 1
            if check_type == "sqli" and generation_attempts[check_type] == 1:
                return None, "transient"
            return [f"adaptive-{check_type}"], "ok"

        xss_scan = AsyncMock(side_effect=[[], []])
        sqli_scan = AsyncMock(side_effect=[[], []])

        async def xss_scan_injection_point(ip, field):
            return await xss_scan(
                ip.url, ip.form_index, field, ip.legacy_is_url_param()
            )

        async def sqli_scan_injection_point(ip, field):
            return await sqli_scan(
                ip.url, ip.form_index, field, ip.legacy_is_url_param()
            )

        checkpoint_is_done = MagicMock(side_effect=is_done)
        checkpoint_mark_done = MagicMock(side_effect=mark_done)

        def checkpoint_is_done_ip(ip, check):
            return checkpoint_is_done(
                ip.url,
                ip.display_name,
                ip.form_index,
                check,
                ip.legacy_is_url_param(),
            )

        def checkpoint_mark_done_ip(ip, check):
            checkpoint_mark_done(
                ip.url,
                ip.display_name,
                ip.form_index,
                check,
                ip.legacy_is_url_param(),
            )

        engine = types.SimpleNamespace(
            scanners={
                "xss": types.SimpleNamespace(
                    scan_field=xss_scan,
                    scan_injection_point=AsyncMock(
                        side_effect=xss_scan_injection_point
                    ),
                ),
                "sqli": types.SimpleNamespace(
                    scan_field=sqli_scan,
                    scan_injection_point=AsyncMock(
                        side_effect=sqli_scan_injection_point
                    ),
                ),
            },
            payload_gen=types.SimpleNamespace(
                default_payloads={"xss": [], "sqli": []},
                _check_llm_available=AsyncMock(return_value=True),
            ),
            all_findings=[],
            flag_finder=None,
            adaptive_enabled=True,
            _adaptive_llm_available=None,
            _adaptive_llm_availability_lock=asyncio.Lock(),
            adaptive_engine=types.SimpleNamespace(generate=AsyncMock(side_effect=generate)),
            browser=types.SimpleNamespace(
                page=types.SimpleNamespace(content=AsyncMock(return_value="<html></html>"))
            ),
            waf_detector=types.SimpleNamespace(_detected=None),
            completed_fields=0,
            total_fields=1,
            monitor=None,
            _checkpoint_is_done=checkpoint_is_done,
            _checkpoint_mark_done=checkpoint_mark_done,
            _checkpoint_is_done_ip=MagicMock(side_effect=checkpoint_is_done_ip),
            _checkpoint_mark_done_ip=MagicMock(side_effect=checkpoint_mark_done_ip),
            _record_scan_matrix=MagicMock(),
            _record_finding=MagicMock(),
            _save_checkpoint=MagicMock(),
        )
        engine._adaptive_attack_field = types.MethodType(
            ScanEngine._adaptive_attack_field, engine
        )
        engine._injection_point_for = types.MethodType(
            ScanEngine._injection_point_for, engine
        )

        await ScanEngine._scan_field(
            engine, "https://example.test", 0, {"name": "q"}
        )

        self.assertIn("(adaptive:xss)", completed)
        self.assertNotIn("(adaptive:sqli)", completed)
        self.assertEqual(xss_scan.await_count, 2)  # first-pass + adaptive
        self.assertEqual(sqli_scan.await_count, 1)  # payload 生成失敗で adaptive 未実行

        await ScanEngine._scan_field(
            engine, "https://example.test", 0, {"name": "q"}
        )

        self.assertEqual(xss_scan.await_count, 2)  # resume では再攻撃しない
        self.assertEqual(sqli_scan.await_count, 2)  # 失敗した adaptive だけ再試行
        self.assertIn("(adaptive:sqli)", completed)
        generated_checks = [
            item.kwargs["check_type"]
            for item in engine.adaptive_engine.generate.await_args_list
        ]
        self.assertEqual(generated_checks, ["xss", "sqli", "sqli"])


if __name__ == "__main__":
    unittest.main()
