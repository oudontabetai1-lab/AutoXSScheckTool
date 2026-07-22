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


class TotpConfigDefaultsTests(unittest.TestCase):
    """config(wscan.yaml)の TOTP パラメータが CLI 既定に反映されることの検証。

    digits/period が 0・algorithm が空だと ScanEngine が override を送らず 6/30/SHA1 に
    落ちるため、raw Base32 / QR 運用で config の非標準値が無視されてはいけない。
    """

    def _parse_args(self, cfg_overrides: dict):
        with mock.patch.dict(main._CFG, cfg_overrides, clear=False):
            with mock.patch.dict(os.environ, {}, clear=False):
                for k in ("WSCAN_MFA_TOTP_DIGITS", "WSCAN_MFA_TOTP_PERIOD",
                          "WSCAN_MFA_TOTP_ALGORITHM"):
                    os.environ.pop(k, None)
                with mock.patch.object(
                    sys, "argv", ["main.py", "scan", "http://example.com"]
                ):
                    return main.parse_args()

    def test_config_totp_params_become_cli_defaults(self):
        args = self._parse_args(
            {"mfa_totp_digits": 8, "mfa_totp_period": 45, "mfa_totp_algorithm": "SHA256"}
        )
        self.assertEqual(args.mfa_totp_digits, 8)
        self.assertEqual(args.mfa_totp_period, 45)
        self.assertEqual(args.mfa_totp_algorithm, "SHA256")

    def test_absent_config_keeps_zero_empty_defaults(self):
        # 未設定なら 0/空（=ScanEngine が override を送らず内部既定 6/30/SHA1）。
        args = self._parse_args({})
        self.assertEqual(args.mfa_totp_digits, 0)
        self.assertEqual(args.mfa_totp_period, 0)
        self.assertEqual(args.mfa_totp_algorithm, "")


if __name__ == "__main__":
    unittest.main()
