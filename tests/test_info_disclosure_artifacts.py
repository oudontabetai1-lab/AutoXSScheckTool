"""0017: 忘れ物 artifact / ディレクトリリスティング検出の単体テスト（純粋・オフライン）。"""
import re
import types
import unittest
from unittest import mock

from wscan.scanners import info_disclosure as m
from wscan.scanners import SCANNERS


class DirectoryListingTests(unittest.TestCase):
    def test_apache_autoindex(self):
        body = '<html><head><title>Index of /uploads</title></head><body>'\
               '<h1>Index of /uploads</h1><a href="?C=N;O=D">Name</a></body></html>'
        self.assertTrue(m.detect_directory_listing(body))

    def test_iis_listing(self):
        self.assertTrue(m.detect_directory_listing("<pre>[To Parent Directory]<br>file.txt"))

    def test_negative_normal_page(self):
        self.assertFalse(m.detect_directory_listing(
            "<html><head><title>Welcome</title></head><body>Home</body></html>"))

    def test_empty(self):
        self.assertFalse(m.detect_directory_listing(""))


class ContentPatternTests(unittest.TestCase):
    """新規 _CONTENT_PATTERNS が対象の忘れ物ファイル内容に一致することを固定する。"""

    def _matches(self, sample: str) -> list[str]:
        # 本番の _classify_sensitive_body と同じく、エラー署名と artifact 署名の両方を見る。
        patterns = {**m._CONTENT_PATTERNS, **m._ARTIFACT_PATTERNS}
        return [
            label for pat, label in patterns.items()
            if re.search(pat, sample, re.IGNORECASE | re.DOTALL)
        ]

    def test_git_head(self):
        self.assertIn(".git/HEAD content", self._matches("ref: refs/heads/main\n"))

    def test_git_config_existing(self):
        # 既存の .git config パターンも継続して機能する。
        self.assertIn(".git config content", self._matches("[core]\n\trepositoryformatversion = 0"))

    def test_htpasswd(self):
        self.assertIn(".htpasswd hashes", self._matches("admin:$apr1$abcd$ef.ghij/kl\n"))

    def test_aws_credentials(self):
        self.assertIn(".aws credentials", self._matches(
            "[default]\naws_access_key_id = AKIAxxxx\naws_secret_access_key = yyyy"))

    def test_private_key(self):
        self.assertIn("private key file", self._matches(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1r..."))

    def test_npmrc(self):
        self.assertIn(".npmrc registry token", self._matches("//registry.npmjs.org/:_authToken=abc"))

    def test_sql_dump(self):
        self.assertIn("SQL dump content", self._matches(
            "-- MySQL dump\nCREATE TABLE users (id int);\nINSERT INTO users VALUES (1);"))

    def test_env_still_matches(self):
        # 既存の .env シグネチャは継続。
        self.assertIn(".env file content", self._matches("APP_KEY=base64:xxx\nDB_PASSWORD=secret"))


class PathCoverageTests(unittest.TestCase):
    def test_leftover_paths_registered(self):
        for p in ("/.git/config", "/.env", "/.htpasswd", "/id_rsa", "/backup.sql",
                  "/.aws/credentials", "/.DS_Store"):
            self.assertIn(p, m._SENSITIVE_PATHS, p)

    def test_no_duplicate_paths(self):
        # 忘れ物 artifact 追加時に既存パスを重複登録していないこと（二重 GET / 二重 Finding 防止）。
        paths = list(m._SENSITIVE_PATHS)
        dups = {p for p in paths if paths.count(p) > 1}
        self.assertEqual(dups, set(), f"duplicate sensitive paths: {dups}")


class PatternSeparationTests(unittest.TestCase):
    """artifact 署名は通常ページ HTML の監査（_check_error_page）に混ぜない。"""

    def test_artifact_signatures_not_in_error_patterns(self):
        # SQL DDL・ZIP・.git/HEAD 断片は正常ページにも現れ得るので _CONTENT_PATTERNS には無い。
        error_labels = set(m._CONTENT_PATTERNS.values())
        for label in ("SQL dump content", "ZIP archive (possible backup)",
                      ".git/HEAD content", ".aws credentials", "private key file"):
            self.assertNotIn(label, error_labels, label)

    def test_error_page_body_with_sql_ddl_not_flagged(self):
        # SQL チュートリアルの CREATE TABLE を含む通常ページ本文はエラー署名に一致しない。
        body = "<html><body><code>CREATE TABLE users (id INT);</code></body></html>"
        matched = [lab for pat, lab in m._CONTENT_PATTERNS.items()
                   if re.search(pat, body, re.IGNORECASE | re.DOTALL)]
        self.assertEqual(matched, [])


class DirListingTests(unittest.TestCase):
    def test_strong_marker_alone_confirms(self):
        self.assertTrue(m.detect_directory_listing(
            '<html><body>[To Parent Directory]<br></body></html>'))

    def test_title_only_not_enough(self):
        # タイトルに "Index of /" があるだけの通常ページは確定しない（FP 防止）。
        self.assertFalse(m.detect_directory_listing(
            "<html><head><title>Index of / our products</title></head>"
            "<body>Welcome to our catalog.</body></html>"))

    def test_title_with_corroboration_confirms(self):
        self.assertTrue(m.detect_directory_listing(
            "<html><head><title>Index of /files</title></head><body>"
            '<a href="../">Parent Directory</a><br>'
            '<a href="a.txt">a.txt</a> 01-Jan-2020 12:00</body></html>'))

    def test_empty_body(self):
        self.assertFalse(m.detect_directory_listing(""))

    def test_nginx_empty_autoindex_parent_link_only(self):
        # nginx の空 autoindex は `<a href="../">../</a>` だけが補強行。`../`（末尾スラッシュ）を
        # 親ディレクトリ行として受理する（Codex #156）。
        self.assertTrue(m.detect_directory_listing(
            '<html><head><title>Index of /uploads/</title></head><body>'
            '<h1>Index of /uploads/</h1><hr><pre><a href="../">../</a>'
            '</pre><hr></body></html>'))


class LabelApplicabilityTests(unittest.TestCase):
    def test_label_scoped_to_path(self):
        # AWS creds は .env 署名にも一致し得るが、/.aws/ パスでは .env ラベルを採らない。
        self.assertFalse(m._label_applies(".env file content", "/.aws/credentials"))
        self.assertTrue(m._label_applies(".aws credentials", "/.aws/credentials"))

    def test_catch_all_sql_signature_not_applied_to_git_path(self):
        # soft-404 の catch-all（CREATE TABLE を含む解説ページ）が /.git/config を機密化しない。
        self.assertFalse(m._label_applies("SQL dump content", "/.git/config"))
        self.assertTrue(m._label_applies("SQL dump content", "/backup.sql"))

    def test_path_agnostic_labels_always_apply(self):
        self.assertTrue(m._label_applies("Database error", "/anything"))
        self.assertTrue(m._label_applies("phpinfo() output", "/x/y"))

    def test_secret_path(self):
        self.assertTrue(m._is_secret_path("/.aws/credentials"))
        self.assertTrue(m._is_secret_path("/.env.bak"))
        self.assertFalse(m._is_secret_path("/index.html"))

    def test_env_is_secret_label(self):
        self.assertIn(".env file content", m._SECRET_ARTIFACT_LABELS)


class DsStoreSignatureTests(unittest.TestCase):
    def test_real_ds_store_header_matches(self):
        # 実 .DS_Store は 00 00 00 01 "Bud1"。復号本文でこの完全ヘッダに一致する。
        body = "\x00\x00\x00\x01Bud1\x00\x00\x00\x00some-metadata"
        labels = [lab for pat, lab in m._ARTIFACT_PATTERNS.items()
                  if re.search(pat, body, re.IGNORECASE | re.DOTALL)]
        self.assertIn(".DS_Store metadata", labels)

    def test_bare_bud1_word_does_not_falsely_match(self):
        # 単なる "Bud1" 文字列（先頭バイト無し）は一致しない（正規ヘッダのみ）。
        self.assertNotIn(".DS_Store metadata",
                         [lab for pat, lab in m._ARTIFACT_PATTERNS.items()
                          if re.search(pat, "Bud1 is a word", re.IGNORECASE)])


class _FakeResp:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text
        self.headers = {}


class _FakeRespCT:
    def __init__(self, status_code, text="", content_type=""):
        self.status_code = status_code
        self.text = text
        self.headers = {"content-type": content_type}


class CatchAllComparisonTests(unittest.TestCase):
    def test_same_catch_all_true_modulo_path(self):
        base = "<html>Unknown page /wscan-nonexistent-probe-8f3a1c9e2b.zzz not found. CREATE TABLE demo</html>"
        cand = "<html>Unknown page /backup.sql not found. CREATE TABLE demo</html>"
        self.assertTrue(m._same_catch_all(cand, "/backup.sql", base, m._SOFT404_PROBE))

    def test_different_body_not_catch_all(self):
        base = "<html>404 not found</html>"
        cand = "-- real dump\nCREATE TABLE users (id int);\nINSERT INTO users VALUES (1);"
        self.assertFalse(m._same_catch_all(cand, "/backup.sql", base, m._SOFT404_PROBE))

    def test_empty_baseline_false(self):
        self.assertFalse(m._same_catch_all("anything", "/x", "", m._SOFT404_PROBE))

    def test_dynamic_fields_tolerated(self):
        # catch-all が per-request な timestamp/nonce/trace-id/CSRF/UUID を含んでも同一判定する
        # （動的値の差だけで別物にしない・Codex #156）。
        base = ('<html>Not found /wscan-nonexistent-probe-8f3a1c9e2b.zzz '
                'ts=2026-09-10T07:15:20Z nonce="a1b2c3d4e5f6a7b8" '
                'trace_id=9f8e7d6c5b4a3021 req=12345678901 '
                'id=550e8400-e29b-41d4-a716-446655440000. CREATE TABLE demo</html>')
        cand = ('<html>Not found /.env ts=2026-09-10T09:41:02Z nonce="ffeeddccbbaa9988" '
                'trace_id=1122334455667788 req=99887766554 '
                'id=6ba7b810-9dad-11d1-80b4-00c04fd430c8. CREATE TABLE demo</html>')
        self.assertTrue(m._same_catch_all(cand, "/.env", base, m._SOFT404_PROBE))

    def test_high_similarity_is_catch_all(self):
        base = "Error page. The requested resource was not found on this server. Please try again."
        cand = "Error page. The requested resource was not found on this server. Please retry now."
        self.assertTrue(m._same_catch_all(cand, "/.git/config", base, m._SOFT404_PROBE))

    def test_dir_catch_all_echoing_path_uses_matching_probe_path(self):
        # 短い catch-all autoindex が要求 path を echo する場合、baseline 比較にも実 probe path
        # （ディレクトリ形 _SOFT404_DIR_PROBE）を渡さないと baseline 側の echo が残り誤検知する。
        base = "<html><h1>Index of /wscan-nonexistent-probe-8f3a1c9e2b/</h1></html>"
        cand = "<html><h1>Index of /uploads/</h1></html>"
        # 正しい probe path（ディレクトリ形）を渡せば同一 catch-all と判定できる。
        self.assertTrue(m._same_catch_all(cand, "/uploads/", base, m._SOFT404_DIR_PROBE))
        # 旧来の .zzz path では baseline の echo が残り類似度が落ちて取りこぼす（回帰ガード）。
        self.assertFalse(m._same_catch_all(cand, "/uploads/", base, m._SOFT404_PROBE))


class SensitiveVerifyTests(unittest.IsolatedAsyncioTestCase):
    def _scanner(self):
        engine = types.SimpleNamespace(
            browser=None, monitor=None, payload_gen=None, wave_errors=[],
            proxy="", timeout=10)
        return SCANNERS["info_disclosure"](engine)

    async def test_soft404_catch_all_fails_verification(self):
        scanner = self._scanner()
        catch_all = "Unknown path {p}. CREATE TABLE demo (id int);"

        async def _get(url, follow_redirects=False):
            from urllib.parse import urlparse
            return _FakeResp(200, catch_all.format(p=urlparse(url).path))
        scanner._get = _get
        finding = types.SimpleNamespace(
            evidence_type="info_sensitive_resource",
            url="http://x/backup.sql",
            evidence_details={"path": "/backup.sql", "matched_label": "SQL dump content"})
        self.assertFalse(await scanner.verify_finding(finding))

    async def test_soft404_origin_real_nonhtml_artifact_verifies(self):
        # SPA シェルを返す soft-404 origin でも、baseline と異なる実在の非HTML artifact
        # (/web.config.bak 等・署名無し) は fallback で verify される（Codex #156）。
        scanner = self._scanner()

        async def _get(url, follow_redirects=False):
            if "wscan-nonexistent" in url:
                return _FakeRespCT(200, "<html>SPA shell</html>", "text/html")  # soft-404 catch-all
            return _FakeRespCT(200, "secret-config-blob-not-the-shell-xyz", "application/octet-stream")
        scanner._get = _get
        finding = types.SimpleNamespace(
            evidence_type="info_sensitive_resource",
            url="http://x/web.config.bak",
            evidence_details={"path": "/web.config.bak",
                              "matched_label": "non-HTML content (possible sensitive file)"})
        self.assertTrue(await scanner.verify_finding(finding))

    async def test_genuine_artifact_still_verifies(self):
        scanner = self._scanner()

        async def _get(url, follow_redirects=False):
            from urllib.parse import urlparse
            if "wscan-nonexistent" in url:
                return _FakeResp(404, "not found")  # サーバは正しく 404（soft-404 でない）
            return _FakeResp(200, "-- dump\nCREATE TABLE users (id int);")
        scanner._get = _get
        finding = types.SimpleNamespace(
            evidence_type="info_sensitive_resource",
            url="http://x/backup.sql",
            evidence_details={"path": "/backup.sql", "matched_label": "SQL dump content"})
        self.assertTrue(await scanner.verify_finding(finding))


class DirListingVerifyTests(unittest.IsolatedAsyncioTestCase):
    def _scanner(self):
        engine = types.SimpleNamespace(
            browser=None, monitor=None, payload_gen=None, wave_errors=[],
            proxy="", timeout=10)
        return SCANNERS["info_disclosure"](engine)

    async def test_directory_listing_reverified_true(self):
        scanner = self._scanner()

        async def _get(url, follow_redirects=False):
            if "wscan-nonexistent" in url:
                return _FakeResp(404, "not found")  # 正規サーバ: 未知ディレクトリは 404
            return _FakeResp(200, "<html><title>Index of /uploads</title>"
                                  '<a href="../">Parent Directory</a>'
                                  '<a href="a.txt">a.txt</a> 01-Jan-2020 12:00</html>')
        scanner._get = _get
        finding = types.SimpleNamespace(
            evidence_type="info_directory_listing", url="http://x/uploads/",
            evidence_details={})
        self.assertTrue(await scanner.verify_finding(finding))

    async def test_directory_listing_reverify_false_when_gone(self):
        scanner = self._scanner()

        async def _get(url, follow_redirects=False):
            return _FakeResp(404, "not found")
        scanner._get = _get
        finding = types.SimpleNamespace(
            evidence_type="info_directory_listing", url="http://x/uploads/",
            evidence_details={})
        self.assertFalse(await scanner.verify_finding(finding))

    async def test_directory_listing_soft404_catch_all_fails_verify(self):
        # 未知ディレクトリを同じ autoindex 風 catch-all に書き換える origin では、verify で False。
        scanner = self._scanner()
        catch_all = ("<html><title>Index of /</title><a href=\"../\">Parent Directory</a>"
                     "<a href=\"x\">x</a> 01-Jan-2020 12:00</html>")

        async def _get(url, follow_redirects=False):
            return _FakeResp(200, catch_all)  # プローブも候補も同一 catch-all
        scanner._get = _get
        finding = types.SimpleNamespace(
            evidence_type="info_directory_listing", url="http://x/uploads/",
            evidence_details={})
        self.assertFalse(await scanner.verify_finding(finding))


if __name__ == "__main__":
    unittest.main()
