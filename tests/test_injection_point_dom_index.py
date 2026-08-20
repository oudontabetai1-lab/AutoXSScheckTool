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
