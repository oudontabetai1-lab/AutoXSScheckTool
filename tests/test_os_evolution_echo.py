"""OS進化wave の echo マーカー判定 `_echo_marker_executed` の回帰テスト。

反射するだけの無害なエンドポイント（入力を画面に出すだけ）を OS コマンド注入と
誤検知しないこと、かつ実際にコマンド出力として marker が出た場合は検知すること。
"""
import unittest

from wscan.scanners.os_injection import _echo_marker_executed, _is_time_based_os


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


class StoredEndpointBaselineGuardTests(unittest.TestCase):
    """stored/反射エンドポイントでの echo マーカー自己汚染ガードの回帰テスト。

    OSScanner は evolution probe として「素の marker（echo 無し）」を投入する。
    投稿が永続化・再描画される stored エンドポイント（例: コメント一覧）では、この
    probe の素 marker が後続ペイロードの応答にも現れ、`_echo_marker_executed` だけ
    では「実行」と誤判定する。scan_field は probe 後に取り直した baseline と比較し
    （``executed and not _echo_marker_executed(baseline, marker)``）誤検知を防ぐ。
    ここではその合成判定を純粋ロジックとして固定する。
    """
    MARKER = "wscanEVO253"

    def _executed_with_baseline(self, source: str, baseline: str) -> bool:
        # scan_field の echo マーカー採用条件と同じ合成判定。
        return _echo_marker_executed(source, self.MARKER) and not _echo_marker_executed(
            baseline, self.MARKER
        )

    def test_stored_probe_reflection_is_not_execution(self):
        # probe の素 marker が一覧へ永続化 → payload 応答にも post-probe baseline にも
        # 同じ素 marker が現れる → 実行ではない（誤検知しない）。
        stored_listing = (
            "<article>; echo wscanEVO253</article>\n"
            "<article>wscanEVO253</article>\n"   # probe（素 marker）の反射
        )
        post_probe_baseline = stored_listing  # baseline も同じ素 marker を含む
        self.assertFalse(
            self._executed_with_baseline(stored_listing, post_probe_baseline)
        )

    def test_genuine_execution_survives_baseline_guard(self):
        # 実行された場合のみ payload 応答に素 marker が現れ、baseline には無い。
        baseline = "Server: 10.10.0.2\nName: intranet.local\n"
        executed = "Server: 10.10.0.2\nName: host\nwscanEVO253\n"
        self.assertTrue(self._executed_with_baseline(executed, baseline))


class IsTimeBasedOsTests(unittest.TestCase):
    def test_detects_delay_directives(self):
        for p in (
            "|| sleep 10",
            "; sleep 3",
            "& ping -n 5 127.0.0.1",
            "| ping -c 3 127.0.0.1",
            "& timeout /t 5",
        ):
            self.assertTrue(_is_time_based_os(p), f"missed delay payload: {p!r}")

    def test_ignores_non_delay(self):
        for p in ("; id", "| cat /etc/passwd", "", "echo hello"):
            self.assertFalse(_is_time_based_os(p), f"false delay: {p!r}")


if __name__ == "__main__":
    unittest.main()
