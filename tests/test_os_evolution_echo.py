"""OS進化wave の echo マーカー判定 `_echo_marker_executed` の回帰テスト。

反射するだけの無害なエンドポイント（入力を画面に出すだけ）を OS コマンド注入と
誤検知しないこと、かつ実際にコマンド出力として marker が出た場合は検知すること。
"""
import unittest

from wscan.scanners.os_injection import _echo_marker_executed


class EchoMarkerExecutedTests(unittest.TestCase):
    MARKER = "wscanEVO42"

    def test_plain_reflection_is_not_execution(self):
        # `& echo wscanEVO42` をそのまま反射（HTMLエスケープ含む）→ 実行ではない
        for reflected in (
            "Fetched preview for & echo wscanEVO42 — 200 OK",
            "Fetched preview for &amp; echo wscanEVO42 — 200 OK",
            "You searched for: ; echo wscanEVO42",
            "result: $(echo wscanEVO42)",
            "out: ;${IFS}echo${IFS}wscanEVO42",
        ):
            self.assertFalse(
                _echo_marker_executed(reflected, self.MARKER),
                f"reflection misdetected as execution: {reflected!r}",
            )

    def test_command_output_is_execution(self):
        # echo が消費され marker 単体が出力 → 実行とみなす
        for output in (
            "PING host\n--- stats ---\nwscanEVO42\n",
            "wscanEVO42",
            "diagnostics complete\nwscanEVO42\ndone",
        ):
            self.assertTrue(
                _echo_marker_executed(output, self.MARKER),
                f"command output not detected: {output!r}",
            )

    def test_mixed_reflection_and_execution_is_execution(self):
        # 反射(echo付き)と実行出力(単体)の両方がある → 脆弱と判定
        src = "echo wscanEVO42 was run; output below:\nwscanEVO42\n"
        self.assertTrue(_echo_marker_executed(src, self.MARKER))

    def test_absent_marker_or_empty(self):
        self.assertFalse(_echo_marker_executed("", self.MARKER))
        self.assertFalse(_echo_marker_executed("no marker here", self.MARKER))
        self.assertFalse(_echo_marker_executed("wscanEVO42", ""))


if __name__ == "__main__":
    unittest.main()
