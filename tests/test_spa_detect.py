import pytest

from wscan.spa_detect import detect_spa


@pytest.mark.parametrize(
    ("html", "framework", "signal"),
    [
        ("<html><APP-ROOT></APP-ROOT></html>", "Angular", "<app-root>"),
        ('<main data-reactroot=""></main>', "React", "data-reactroot"),
        ('<script id="__NEXT_DATA__" type="application/json">{}</script>', "Next.js", "__NEXT_DATA__"),
        ('<div id="__next"></div>', "Next.js", 'id="__next"'),
        ("<script>window.__NUXT__={}</script>", "Nuxt", "__NUXT__"),
        ('<section data-v-ab12cd=""></section>', "Vue", "data-v-"),
    ],
)
def test_explicit_framework_markers_are_high_confidence_spa(html, framework, signal):
    info = detect_spa(html)

    assert info.is_spa is True
    assert info.framework == framework
    assert info.confidence == "high"
    assert signal in info.signals


@pytest.mark.parametrize(
    ("html", "framework"),
    [
        (
            '<div id="root"></div><script>React.createElement("main")</script>',
            "React",
        ),
        (
            '<div id="app"></div><script src="/assets/vue.runtime.min.js"></script>',
            "Vue",
        ),
    ],
)
def test_generic_mount_id_requires_matching_framework_trace(html, framework):
    info = detect_spa(html)

    assert info.is_spa is True
    assert info.framework == framework
    assert info.confidence == "high"


@pytest.mark.parametrize(
    "html",
    [
        "",
        "<html><body><h1>静的サイト</h1><p>通常の案内ページです。</p></body></html>",
        '<html><body><form action="/search"><input name="q"></form></body></html>',
        '<html><body><div id="root">React 入門</div></body></html>',
    ],
)
def test_normal_or_ambiguous_html_is_not_spa(html):
    info = detect_spa(html)

    assert info.is_spa is False
    assert info.framework == "unknown"
    assert info.confidence == "low"


def test_weak_layout_signals_never_enable_spa_on_their_own():
    html = """
    <html><body><main></main>
      <script src="/assets/a.js"></script>
      <script src="/assets/b.js"></script>
      <script src="/assets/c.js"></script>
    </body></html>
    """

    info = detect_spa(html)

    assert info.is_spa is False
    assert info.confidence == "low"
    assert "forms=0" in info.signals
    assert "external_scripts=3" in info.signals
    assert "visible_text_sparse" in info.signals
