"""0017: 忘れ物 artifact / ディレクトリリスティング検出の単体テスト（純粋・オフライン）。"""
import re
import unittest

from wscan.scanners import info_disclosure as m


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
        return [
            label for pat, label in m._CONTENT_PATTERNS.items()
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


if __name__ == "__main__":
    unittest.main()
