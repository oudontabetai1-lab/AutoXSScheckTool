import unittest

from wscan import oob_email as oe


def _raw(to="", subject="", body="", frm="app@target.test", ctype="text/plain"):
    return (
        f"From: {frm}\r\n"
        f"To: {to}\r\n"
        f"Subject: {subject}\r\n"
        f"Content-Type: {ctype}; charset=utf-8\r\n"
        f"\r\n"
        f"{body}\r\n"
    ).encode("utf-8")


class TokenTests(unittest.TestCase):
    def test_token_format_and_uniqueness(self):
        t1 = oe.make_oob_token("Scan #42!")
        t2 = oe.make_oob_token("Scan #42!")
        self.assertTrue(t1.startswith("wscan-oob-"))
        self.assertNotEqual(t1, t2)
        # sanitised scan id keeps only [a-z0-9]
        self.assertIn("scan42", t1)
        # safe for email local part / headers
        for ch in (" ", "@", "#", "!"):
            self.assertNotIn(ch, t1)

    def test_oob_address(self):
        self.assertEqual(oe.oob_address("tok", "oob.example.com"), "tok@oob.example.com")


class ConfigTests(unittest.TestCase):
    def test_from_env_defaults(self):
        cfg = oe.OOBEmailConfig.from_env({})
        self.assertEqual(cfg.protocol, "imap")
        self.assertEqual(cfg.effective_port, 993)
        self.assertFalse(cfg.configured)

    def test_from_env_pop3_and_ports(self):
        cfg = oe.OOBEmailConfig.from_env({
            "WSCAN_OOB_PROTOCOL": "pop3",
            "WSCAN_OOB_HOST": "mail.test",
            "WSCAN_OOB_USERNAME": "u",
            "WSCAN_OOB_PASSWORD": "p",
            "WSCAN_OOB_SSL": "false",
            "WSCAN_OOB_DOMAIN": "oob.test",
        })
        self.assertEqual(cfg.protocol, "pop3")
        self.assertEqual(cfg.effective_port, 110)  # POP3 non-SSL default
        self.assertTrue(cfg.configured)
        self.assertEqual(cfg.domain, "oob.test")

    def test_explicit_port_wins(self):
        cfg = oe.OOBEmailConfig.from_env({"WSCAN_OOB_PORT": "1993"})
        self.assertEqual(cfg.effective_port, 1993)


class ParseTests(unittest.TestCase):
    def test_parse_plain(self):
        r = oe.parse_email(_raw(to="wscan-oob-abc@oob.test", subject="Welcome",
                                 body="hello world"), uid="7")
        self.assertEqual(r.uid, "7")
        self.assertIn("wscan-oob-abc@oob.test", r.to_addrs)
        self.assertEqual(r.subject, "Welcome")
        self.assertIn("hello world", r.body)

    def test_parse_multipart_prefers_plain(self):
        raw = (
            b"From: a@b.test\r\nTo: x@oob.test\r\nSubject: s\r\n"
            b"Content-Type: multipart/alternative; boundary=BB\r\n\r\n"
            b"--BB\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
            b"PLAINTOKEN body\r\n"
            b"--BB\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
            b"<p>HTMLTOKEN</p>\r\n--BB--\r\n"
        )
        r = oe.parse_email(raw)
        self.assertIn("PLAINTOKEN", r.body)


class MatchTests(unittest.TestCase):
    def test_match_in_to(self):
        r = oe.parse_email(_raw(to="wscan-oob-tok123@oob.test", body="x"))
        self.assertTrue(oe.email_matches_token(r, "wscan-oob-tok123"))

    def test_match_in_body_case_insensitive(self):
        r = oe.parse_email(_raw(to="inbox@oob.test", body="ping TOK999 here"))
        self.assertTrue(oe.email_matches_token(r, "tok999"))

    def test_no_match(self):
        r = oe.parse_email(_raw(to="inbox@oob.test", body="nothing"))
        self.assertFalse(oe.email_matches_token(r, "tok999"))
        self.assertFalse(oe.email_matches_token(r, ""))

    def test_filter_messages(self):
        raws = [
            ("1", _raw(to="a@oob.test", body="no")),
            ("2", _raw(to="wscan-oob-hit@oob.test", body="yes")),
            ("3", _raw(to="b@oob.test", subject="contains wscan-oob-hit")),
        ]
        hits = oe.filter_messages(raws, "wscan-oob-hit")
        self.assertEqual({h.uid for h in hits}, {"2", "3"})


class SinkGuardTests(unittest.TestCase):
    def test_search_raises_when_unconfigured(self):
        sink = oe.EmailSink(oe.OOBEmailConfig.from_env({}))
        with self.assertRaises(RuntimeError):
            sink.search("tok")


if __name__ == "__main__":
    unittest.main()
