"""フォーム action origin を学習キーへ配線するブラウザ非依存テスト。"""

from wscan.engine import CrawledPage, ScanEngine
from wscan.scanners.base import Finding


class _CapturingLearner:
    def __init__(self):
        self.calls = []

    def record(self, check_type, payload, success, domain=None):
        self.calls.append((check_type, payload, success, domain))


def _thin_engine():
    engine = object.__new__(ScanEngine)
    engine._form_target_origins = {}
    return engine


def test_form_action_registry_populates_injection_point_target_origin():
    engine = _thin_engine()
    page = CrawledPage(
        url="http://a.test/page/",
        html="",
        forms=[
            {"action": "http://b.test/submit", "inputs": []},
            {"action": "/same-origin", "inputs": []},
            {"action": "mailto:ops@example.test", "inputs": []},
        ],
        url_params=[],
        depth=0,
    )

    engine._register_form_target_origins(page)

    assert engine._form_target_origins == {
        ("http://a.test/page", 0): "http://b.test",
        ("http://a.test/page", 1): "http://a.test",
    }
    cross_origin_ip = engine._injection_point_for(
        "http://a.test/page/", "q", 0, False
    )
    same_origin_ip = engine._injection_point_for(
        "http://a.test/page/", "q", 1, False
    )
    fallback_ip = engine._injection_point_for(
        "http://a.test/page/", "q", 2, False
    )
    assert cross_origin_ip.target_origin == "http://b.test"
    assert same_origin_ip.target_origin == "http://a.test"
    assert fallback_ip.target_origin == ""


def test_record_finding_prefers_action_origin_and_falls_back_to_page_origin():
    engine = _thin_engine()
    engine._finding_dedup = set()
    engine.all_findings = []
    engine._notifier = None
    engine.enable_payload_learning = True
    engine.payload_learner = _CapturingLearner()
    engine.flag_finder = None

    action_finding = Finding(
        check_type="xss",
        severity="high",
        url="http://a.test/page",
        field_name="q",
        payload="<b-only>",
        evidence="dialog",
        injection_target_origin="http://b.test",
    )
    legacy_finding = Finding(
        check_type="xss",
        severity="high",
        url="http://a.test/legacy",
        field_name="q2",
        payload="<a-only>",
        evidence="dialog",
    )

    engine._record_finding(action_finding)
    engine._record_finding(legacy_finding)

    assert engine.payload_learner.calls == [
        ("xss", "<b-only>", True, "http://b.test"),
        ("xss", "<a-only>", True, "http://a.test"),
    ]
