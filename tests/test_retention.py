"""保持ポリシー（古いスキャンの自動削除）の純粋ロジックのテスト。

`select_scans_to_prune` は FS/HTTP に依存しない純粋関数。削除対象 id の
選定だけを検証する（実削除は別途 prune_old_scans が担当）。
"""
import datetime
import unittest

from wscan.monitor import select_scans_to_prune


def _scan(epoch: int) -> dict:
    # スキャン id は str(int(time.time())) 形式（エポック秒）。
    return {"id": str(epoch), "started_at": ""}


class SelectScansToPruneTests(unittest.TestCase):
    NOW = 1_000_000_000  # 固定の現在時刻（エポック秒）

    def test_no_policy_keeps_everything(self):
        scans = [_scan(self.NOW - i * 86400) for i in range(10)]
        self.assertEqual(
            select_scans_to_prune(scans, max_age_days=0, max_scans=0, now_epoch=self.NOW),
            [],
        )

    def test_max_scans_keeps_newest_n(self):
        # 5件中、新しい3件を残し古い2件を削除。
        scans = [_scan(self.NOW - i * 86400) for i in range(5)]  # 0(最新)..4(最古)
        doomed = select_scans_to_prune(scans, max_scans=3, now_epoch=self.NOW)
        self.assertEqual(set(doomed), {
            str(self.NOW - 3 * 86400),
            str(self.NOW - 4 * 86400),
        })

    def test_max_age_days_deletes_old(self):
        scans = [
            _scan(self.NOW - 1 * 86400),   # 1日前 → 残す
            _scan(self.NOW - 10 * 86400),  # 10日前 → 削除
            _scan(self.NOW - 40 * 86400),  # 40日前 → 削除
        ]
        doomed = select_scans_to_prune(scans, max_age_days=7, now_epoch=self.NOW)
        self.assertEqual(set(doomed), {
            str(self.NOW - 10 * 86400),
            str(self.NOW - 40 * 86400),
        })

    def test_protected_id_is_never_deleted(self):
        scans = [_scan(self.NOW - i * 86400) for i in range(5)]
        old = str(self.NOW - 4 * 86400)  # 通常なら削除対象
        doomed = select_scans_to_prune(
            scans, max_scans=1, now_epoch=self.NOW, protected_ids={old},
        )
        self.assertNotIn(old, doomed)

    def test_combined_age_and_count(self):
        scans = [_scan(self.NOW - i * 86400) for i in range(6)]
        doomed = select_scans_to_prune(
            scans, max_age_days=3, max_scans=2, now_epoch=self.NOW,
        )
        # max_scans=2 → 新しい2件以外削除、max_age=3日 → 3日超も削除。和集合。
        kept = set(s["id"] for s in scans) - set(doomed)
        self.assertEqual(kept, {str(self.NOW), str(self.NOW - 1 * 86400)})

    def test_non_numeric_id_uses_started_at(self):
        old_iso = datetime.datetime.fromtimestamp(self.NOW - 40 * 86400).isoformat()
        new_iso = datetime.datetime.fromtimestamp(self.NOW - 1 * 86400).isoformat()
        scans = [
            {"id": "custom-old", "started_at": old_iso},
            {"id": "custom-new", "started_at": new_iso},
        ]
        doomed = select_scans_to_prune(scans, max_age_days=7, now_epoch=self.NOW)
        self.assertEqual(doomed, ["custom-old"])


if __name__ == "__main__":
    unittest.main()
