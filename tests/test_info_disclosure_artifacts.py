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


class RedactionTests(unittest.TestCase):
    def test_private_key_redacted(self):
        out = m._redact_sensitive(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA...\n-----END...")
        self.assertIn("BEGIN OPENSSH PRIVATE KEY", out)
        self.assertIn("[REDACTED]", out)
        self.assertNotIn("b3BlbnNzaC1r", out)

    def test_aws_secret_redacted(self):
        out = m._redact_sensitive(
            "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
        self.assertNotIn("wJalrXUtnFEMI", out)
        self.assertIn("[REDACTED]", out)

    def test_npmrc_token_redacted(self):
        out = m._redact_sensitive("//registry.npmjs.org/:_authToken=abc123secretvalue\n")
        self.assertNotIn("abc123secretvalue", out)


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


class RedactionShaTests(unittest.TestCase):
    def test_sha_htpasswd_hash_redacted(self):
        out = m._redact_sensitive("admin:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n")
        self.assertNotIn("W6ph5Mm5Pz8GgiULbPgzG37mj9g=", out)
        self.assertIn("[REDACTED]", out)

    def test_ssha_htpasswd_hash_redacted(self):
        out = m._redact_sensitive("user:{SSHA}abcdEFGHsecretbase64==\n")
        self.assertNotIn("abcdEFGHsecretbase64==", out)

    def test_apr1_still_redacted(self):
        out = m._redact_sensitive("admin:$apr1$abcd$ef.ghij/klmnop\n")
        self.assertNotIn("ef.ghij/klmnop", out)


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


if __name__ == "__main__":
    unittest.main()
