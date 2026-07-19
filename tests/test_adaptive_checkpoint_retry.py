"""adaptive LLM 障害時の checkpoint 完了判定を検証する。"""
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, call

from wscan.engine import ScanEngine


class AdaptiveCheckpointRetryTests(unittest.IsolatedAsyncioTestCase):
    def _engine(self, generation_result):
        scanner = types.SimpleNamespace(scan_field=AsyncMock(return_value=[]))
        engine = types.SimpleNamespace(
            scanners={"xss": scanner},
            payload_gen=types.SimpleNamespace(default_payloads={"xss": []}),
            all_findings=[],
            flag_finder=None,
            adaptive_enabled=True,
            adaptive_engine=types.SimpleNamespace(
                generate=AsyncMock(return_value=generation_result)
            ),
            browser=types.SimpleNamespace(
                page=types.SimpleNamespace(content=AsyncMock(return_value="<html></html>"))
            ),
            waf_detector=types.SimpleNamespace(_detected=None),
            completed_fields=0,
            total_fields=1,
            monitor=None,
            _checkpoint_is_done=MagicMock(return_value=False),
            _checkpoint_mark_done=MagicMock(),
            _record_scan_matrix=MagicMock(),
            _record_finding=MagicMock(),
            _save_checkpoint=MagicMock(),
        )
        engine._adaptive_attack_field = types.MethodType(
            ScanEngine._adaptive_attack_field, engine
        )
        return engine

    async def test_llm_failure_does_not_mark_adaptive_done(self):
        engine = self._engine(None)

        await ScanEngine._scan_field(
            engine, "https://example.test", 0, {"name": "q"}
        )

        self.assertNotIn(
            call("https://example.test", "q", 0, "(adaptive)", False),
            engine._checkpoint_mark_done.call_args_list,
        )

    async def test_successful_empty_result_marks_adaptive_done(self):
        engine = self._engine([])

        await ScanEngine._scan_field(
            engine, "https://example.test", 0, {"name": "q"}
        )

        self.assertIn(
            call("https://example.test", "q", 0, "(adaptive)", False),
            engine._checkpoint_mark_done.call_args_list,
        )


if __name__ == "__main__":
    unittest.main()
