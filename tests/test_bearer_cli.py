"""`scan --bearer` の既定値が control-plane トークンを流用しないことの検証。

serve の保護トークン `WSCAN_AUTH_TOKEN` はダッシュボード/API を守るための値で、
スキャン対象へ `Authorization: Bearer` として送るべきではない。両者を取り違えると
管理トークンが検査対象とそのログへ漏れるため、`--bearer` は `WSCAN_BEARER`
（と明示 `--bearer` / config の bearer_token）だけを参照する。
"""
import os
import sys
import unittest
from unittest import mock

import main


class BearerCliDefaultTests(unittest.TestCase):
    def _parse_bearer(self, env: dict) -> str:
        # WSCAN_BEARER / WSCAN_AUTH_TOKEN を確実に制御して parse_args を再構築する
        # （既定値は add_argument 実行時に os.environ を読むため）。
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WSCAN_BEARER", None)
            os.environ.pop("WSCAN_AUTH_TOKEN", None)
            for k, v in env.items():
                os.environ[k] = v
            with mock.patch.object(sys, "argv", ["main.py", "scan", "http://example.com"]):
                args = main.parse_args()
        return getattr(args, "bearer", None)

    def test_auth_token_does_not_leak_into_bearer(self):
        # ダッシュボード保護トークンだけがある状態では --bearer は空。
        self.assertEqual(self._parse_bearer({"WSCAN_AUTH_TOKEN": "dashboard-secret"}), "")

    def test_wscan_bearer_populates_bearer(self):
        self.assertEqual(
            self._parse_bearer({"WSCAN_BEARER": "target-token"}), "target-token"
        )

    def test_wscan_bearer_wins_when_both_set(self):
        # 両方あっても対象用の WSCAN_BEARER のみを採用する。
        self.assertEqual(
            self._parse_bearer(
                {"WSCAN_BEARER": "target-token", "WSCAN_AUTH_TOKEN": "dashboard-secret"}
            ),
            "target-token",
        )


if __name__ == "__main__":
    unittest.main()
