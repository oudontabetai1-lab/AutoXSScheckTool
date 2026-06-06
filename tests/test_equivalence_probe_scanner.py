import types
import unittest

from wscan.scanners.base import BaseScanner


def _make_engine():
    return types.SimpleNamespace(
        browser=object(),
        monitor=None,
        payload_gen=object(),
        _finding_dedup=set(),
    )


class _AnsiInjectableScanner(BaseScanner):
    """Scanner whose backend concatenates adjacent SQL string literals.

    Simulates an injectable field: ``AA' 'BB`` collapses to ``AABB`` while every
    other form is reflected verbatim.
    """

    CHECK_TYPE = "sqli"

    async def scan_field(self, *a, **k):  # pragma: no cover - abstract stub
        return []

    async def _apply_payload(self, url, form_index, field_name, payload, is_url_param):
        if "' '" in payload and payload.count("'") == 2:
            body = "result: " + payload.replace("' '", "")  # adjacent literals merge
        else:
            body = "result: " + payload                     # reflected verbatim
        # Record the payload on the request so tests can confirm the returned
        # pair belongs to the probe that actually triggered the verdict.
        return body, {"request": {"post_data": payload}, "response": {"body": body}}


class _SafeScanner(_AnsiInjectableScanner):
    """Backend that never concatenates — everything is reflected verbatim."""

    async def _apply_payload(self, url, form_index, field_name, payload, is_url_param):
        body = "result: " + payload
        return body, {"response": {"body": body}}


class EquivalenceProbeScannerTests(unittest.IsolatedAsyncioTestCase):
    async def test_injectable_backend_is_detected(self):
        scanner = _AnsiInjectableScanner(_make_engine())
        result = await scanner.run_equivalence_probe(
            "http://t.test/search", 0, "q", False, context="sql"
        )
        self.assertIsNotNone(result)
        verdict, pair = result
        self.assertTrue(verdict.injectable)
        self.assertEqual(verdict.matched_dialect, "ansi")
        self.assertTrue(pair)
        # The returned pair must belong to the probe that triggered the verdict
        # (the matched payload), not whichever probe ran last.
        self.assertEqual(
            pair.get("request", {}).get("post_data"),
            verdict.details.get("matched_payload"),
        )

    async def test_safe_backend_is_not_flagged(self):
        scanner = _SafeScanner(_make_engine())
        result = await scanner.run_equivalence_probe(
            "http://t.test/search", 0, "q", False, context="sql"
        )
        self.assertIsNone(result)

    async def test_unknown_context_returns_none(self):
        scanner = _AnsiInjectableScanner(_make_engine())
        result = await scanner.run_equivalence_probe(
            "http://t.test/search", 0, "q", False, context="nope"
        )
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
