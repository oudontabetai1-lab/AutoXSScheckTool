from wscan.injection_point import InjectionPoint


def test_submit_index_defaults_to_form_index():
    ip = InjectionPoint.for_form("http://x/a", "q", 3)
    assert ip.dom_index == -1
    assert ip.submit_index == 3


def test_submit_index_uses_dom_index_when_set():
    ip = InjectionPoint.for_form("http://x/a", "q", 0, dom_index=2)
    assert ip.form_index == 0
    assert ip.submit_index == 2


def test_stable_key_parts_uses_form_index_not_dom():
    ip = InjectionPoint.for_form("http://x/a", "q", 0, dom_index=2)
    assert ip.stable_key_parts()[2] == "0"


def test_finding_provenance_round_trips_dom_index():
    """verify フェーズが正しい DOM フォームへ再送できるよう、finding provenance に
    dom_index が永続化され、injection_point_from_finding が submit_index を復元する。"""
    from wscan.scanners.base import Finding, injection_point_from_finding

    f = Finding(
        check_type="xss", severity="high", url="http://x/feedback",
        field_name="msg", payload="<b>x</b>", evidence="reflected",
        injection_location="form", injection_form_index=0, injection_dom_index=1,
    )
    # to_dict/from_dict（checkpoint 永続化）で dom_index が保持される
    restored = Finding.from_dict(f.to_dict())
    assert restored.injection_dom_index == 1
    # provenance からの ip 復元: checkpoint 用は form_index、ブラウザ再送は submit_index
    ip = injection_point_from_finding(restored)
    assert ip.form_index == 0
    assert ip.submit_index == 1


def test_finding_provenance_defaults_dom_index_to_fallback():
    """dom_index 未指定（旧 Finding 相当）は -1 として復元され、submit_index は form_index にフォールバック。"""
    from wscan.scanners.base import Finding, injection_point_from_finding

    f = Finding(
        check_type="sqli", severity="high", url="http://x/a",
        field_name="q", payload="'", evidence="sql error", injection_location="form",
        injection_form_index=2,
    )
    d = f.to_dict()
    d.pop("injection_dom_index", None)   # 旧 Finding にはキーが無い
    restored = Finding.from_dict(d)
    assert restored.injection_dom_index == -1
    ip = injection_point_from_finding(restored)
    assert ip.submit_index == 2          # form_index にフォールバック
