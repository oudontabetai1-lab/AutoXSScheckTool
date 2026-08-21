from types import SimpleNamespace

from wscan.adaptive_observations import format_deterministic_observations


def test_static_js_tainted_flow_is_prioritised_and_bounded():
    risks = [
        SimpleNamespace(
            sink="innerHTML",
            tainted=True,
            source="location.hash",
            line=7,
        ),
        SimpleNamespace(
            sink="document.write",
            tainted=False,
            source="",
            line=12,
        ),
    ]

    output = format_deterministic_observations(risks, max_flows=1)

    assert "## Deterministic scanner observations" in output
    assert "Static JS analysis: tainted flow location.hash -> innerHTML" in output
    assert "document.write" not in output


def test_untainted_sink_is_not_presented_as_tainted_flow():
    # source を辿れない単独 sink は、汚染フロー/likelihood を捏造せず「存在」だけ伝える。
    risks = [SimpleNamespace(sink="innerHTML", tainted=False, source="", line=3)]
    output = format_deterministic_observations(risks)
    assert "DOM sink innerHTML present" in output
    assert "source not traced" in output
    assert "user-controlled input" not in output
    assert "likely DOM XSS" not in output


def test_reflection_context_is_formatted():
    output = format_deterministic_observations(
        context={
            "context": "double_quoted_attr",
            "attribute": "value",
            "quote": '"',
        }
    )

    assert "Deterministic reflection context" in output
    assert "double_quoted_attr" in output


def test_only_surviving_special_characters_are_formatted():
    output = format_deterministic_observations(surviving={"<", ">", "a"})

    assert "Characters surviving" in output
    assert output.rsplit(": ", 1)[1] == "<>"


def test_empty_observations_return_empty_string():
    assert format_deterministic_observations() == ""
    assert format_deterministic_observations(None, None, None) == ""
    assert format_deterministic_observations([], {}, set()) == ""


def test_js_analysis_integration_formats_tainted_source_to_sink():
    from wscan import js_analysis

    html = (
        '<script>document.getElementById("target").innerHTML = '
        "location.hash;</script>"
    )
    risks = []
    for source in js_analysis.extract_inline_scripts(html):
        risks.extend(js_analysis.analyze_js(source))

    tainted = [risk for risk in risks if risk.tainted]
    assert tainted

    output = format_deterministic_observations(risks)

    assert tainted[0].source in output
    assert "DOM XSS" in output
