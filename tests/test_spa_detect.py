import pytest

from wscan.spa_detect import detect_spa


@pytest.mark.parametrize(
    ("html", "framework", "signal"),
    [
        ("<html><APP-ROOT></APP-ROOT></html>", "Angular", "<app-root>"),
        ('<main data-reactroot=""></main>', "React", "data-reactroot"),
        ('<script id="__NEXT_DATA__" type="application/json">{}</script>', "Next.js", "__NEXT_DATA__"),
        ('<div id="__next"></div>', "Next.js", 'id="__next"'),
        ("<script>window.__NUXT__={}</script>", "Nuxt", "window.__NUXT__"),
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
        # data-id="__next" は id="__next" ではない（\b がハイフン後にも境界を作る
        # 問題の回帰・Codex #104 P2）。メタ属性を持つ静的ページを SPA と誤判定しない。
        '<html><body><article data-id="__next">記事</article></body></html>',
        '<html><body><div data-id="root"></div>'
        '<script src="/assets/index-9f3a2b.js"></script></body></html>',
        # 裸の __next_f トークンを表示するだけの静的ドキュメント/エラーページは
        # Next.js ではない（self.__next_f の実行式に限定・Codex #104 P2）。
        '<html><body><p>The <code>__next_f</code> hydration token</p></body></html>',
        '<html><body><pre>self.__next_f</pre> と書かれた解説記事</body></html>',
        # 実行式でも <code>/<pre> の表示テキストなら Next.js ではない（script 本文に
        # 限定・Codex #104 P2）。
        '<html><body><code>self.__next_f.push([1])</code> の例</body></html>',
        # 非実行 script（text/plain / application/json）の式は実行されないので非SPA
        # （Codex #104 P2）。
        '<html><body><script type="text/plain">self.__next_f.push([1])</script></body></html>',
        '<html><body><script type="application/json">'
        '{"note":"window.__NUXT__ example"}</script></body></html>',
        # __NEXT_DATA__ / id="__next" を表示テキストとして含む静的ドキュメントは
        # Next.js ではない（script の id 属性 / 実タグ内属性に限定・Codex #104 P2）。
        '<html><body><code>__NEXT_DATA__</code> はハイドレーション用</body></html>',
        '<html><body><pre>id="__next"</pre> と書くと…</body></html>',
        # inert 領域（コメント/<template>/script 文字列）内の markup 例は非SPA
        # （Codex #104 P2）。
        '<html><body><!-- <app-root></app-root> --></body></html>',
        '<html><body><template><app-root></app-root></template></body></html>',
        '<html><body><script>var demo = "<app-root></app-root>";</script></body></html>',
        '<html><body><!-- <div id="__next"></div> --></body></html>',
        # inert 要素内の React SSR コメント <!--$--> は無効（Codex #104 P2）。
        '<html><body><template><!--$--></template></body></html>',
        '<html><body><script>const ex = "<!--$-->";</script></body></html>',
        # ネストした inert 要素内の markup も無効（非貪欲 regex では残っていた・Codex #104 P2）。
        '<html><body><template><template></template>'
        '<app-root></app-root></template></body></html>',
        # 前置のあるハイフン付き属性（x-data-reactroot）は真の data-reactroot ではない
        # （Codex #104 P2）。
        '<html><body><div id="root"></div><div x-data-reactroot></div></body></html>',
        # コメント内の </template> テキストを実 close と誤認しない（Codex #104 P2）。
        '<template><!-- </template><app-root> --></template>',
        # 入れ子 raw-text（script 文字列）内の </template> も実 close ではない。
        '<template><script>var x="</template>";</script>'
        '<app-root></app-root></template>',
        # 属性値内のマーカー文字列は実属性ではない（Codex #104 P2）。
        '<html><body><div title="id=\'__next\'"></div></body></html>',
        # コメント/inert 内の script は実行されないので JS 式マーカーにならない（Codex #104 P2）。
        '<html><body><!-- <script>self.__next_f.push([])</script> --></body></html>',
        '<html><body><template><script>self.__next_f.push([])</script>'
        '</template></body></html>',
        # 未終端コメント（truncated 応答）は EOF まで内容扱い（Codex #104 P2）。
        '<html><body><!-- <app-root></app-root>',
        '<html><body><!-- <div id="__next"></div>',
        # 属性値内に直列化された <script> 文字列は実 script ではない（Codex #104 P2）。
        '<html><body><div title="<script>self.__next_f.push([])</script>">x</div></body></html>',
        # 属性値内の </template> テキストで inert 領域を早期に閉じない（Codex #104 P2）。
        '<template><div title="</template>"><app-root></app-root></div></template>',
        # 属性値内の <app-root> は実タグではない（Codex #104 P2）。
        '<html><body><div title="<app-root></app-root>">static</div></body></html>',
        # 外部 script（src あり）の本文は実行されないので JS 式マーカーにならない
        # （Codex #104 P2）。
        '<html><body><script src="/analytics.js">self.__next_f.push([])</script></body></html>',
        # 後続の引用属性値内の > / </div> で偽の空マウントを作らない（Codex #104 P2）。
        '<html><body><div id="root" title="></div>">static</div>'
        '<script src="/assets/site.js"></script></body></html>',
        # src="" / bare src の script も外部扱いで本文は実行されない（Codex #104 P2）。
        '<html><body><script src="">self.__next_f.push([])</script></body></html>',
        '<html><body><script src>self.__next_f.push([])</script></body></html>',
        # 完全なタグ形の属性値（<script id="__NEXT_DATA__"> 等）は実タグではない
        # （Codex #104 P2）。
        '<html><body><div title="<script id=\'__NEXT_DATA__\'></script>">'
        'static</div></body></html>',
        '<html><body><div title="<div id=\'root\'></div>">static</div>'
        '<script src="/assets/x-abc123.js"></script></body></html>',
        # inert コンテナ（template/noscript 等）の開始タグ属性は mount マーカーではない
        # （Codex #104 P2）。
        '<html><body><template id="__next"></template></body></html>',
        '<html><body><template id="app"></template>'
        '<script src="/assets/site.js"></script></body></html>',
        # 実行 script の文字列/コメント内の構文は実行式ではない（Codex #104 P2）。
        '<html><body><script>const example = "self.__next_f.push([])"</script></body></html>',
        '<html><body><script>// self.__next_f.push([])</script></body></html>',
        # iframe/xmp の本文は実行/レンダリングされない raw-text（Codex #104 P2）。
        '<html><body><iframe><script>self.__next_f.push([])</script></iframe></body></html>',
        '<html><body><xmp><app-root></app-root></xmp></body></html>',
        # 正規表現リテラル内の構文は実行式ではない（Codex #104 P2）。
        '<html><body><script>const marker = /self.__next_f.push/;</script></body></html>',
        # キーワード後の正規表現リテラルも実行式ではない（Codex #104 P2）。
        '<html><body><script>function f(){ return /self.__next_f.push/; }</script></body></html>',
        # JS 識別子は大小区別。SELF.__NEXT_F は self.__next_f ではない（Codex #104 P2）。
        '<html><body><script>SELF.__NEXT_F.PUSH([])</script></body></html>',
    ],
)
def test_normal_or_ambiguous_html_is_not_spa(html):
    info = detect_spa(html)

    assert info.is_spa is False
    assert info.framework == "unknown"
    assert info.confidence == "low"


@pytest.mark.parametrize(
    ("html", "framework", "signal"),
    [
        # Next.js App Router（RSC）は __NEXT_DATA__ / id="__next" を出さず
        # self.__next_f.push(...) だけを吐くことがある。
        (
            '<div id="__next-x"></div><script>self.__next_f.push([1,"a"])</script>',
            "Next.js",
            "self.__next_f",
        ),
        # Nuxt 3 は window.__NUXT__ でなく __NUXT_DATA__ / id="__nuxt"。
        (
            '<div id="__nuxt"></div><script id="__NUXT_DATA__">[]</script>',
            "Nuxt",
            "__NUXT_DATA__",
        ),
        (
            '<div id="__nuxt"></div><script src="/_nuxt/entry.js"></script>',
            "Nuxt",
            'id="__nuxt"',
        ),
    ],
)
def test_modern_framework_bootstrap_markers_are_high_confidence(html, framework, signal):
    info = detect_spa(html)

    assert info.is_spa is True
    assert info.framework == framework
    assert info.confidence == "high"
    assert signal in info.signals


def test_commented_inert_opener_does_not_hide_real_marker():
    # コメント化された <template> を live opener と誤認して以降を捨てないこと
    # （実 <app-root> を見逃す偽陰性の回帰・Codex #104 P2）。
    info = detect_spa("<html><body><!-- <template> --> <app-root></app-root></body></html>")
    assert info.is_spa is True
    assert info.framework == "Angular"


def test_real_marker_between_separate_inert_blocks_is_spa():
    # 別々の inert ブロックの間にある実 markup マーカーは消さない（貪欲除去による
    # 偽陰性を避ける・Codex #104 P2）。
    info = detect_spa(
        "<html><body><template>A</template>"
        "<app-root></app-root><template>B</template></body></html>"
    )
    assert info.is_spa is True
    assert info.framework == "Angular"


def test_executable_script_type_still_detected():
    # 明示的な実行可能 type の script 本文は判定対象（Codex #104 P2 の除外で落とさない）。
    info = detect_spa(
        '<html><body><script type="text/javascript">'
        'self.__next_f.push([1])</script></body></html>'
    )
    assert info.is_spa is True
    assert info.framework == "Next.js"


def test_mime_type_with_parameters_is_executable():
    # text/javascript; charset=utf-8 は essence が実行可能 type なので除外しない
    # （偽陰性の回帰・Codex #104 P2）。
    info = detect_spa(
        '<html><body><script type="text/javascript; charset=utf-8">'
        'self.__next_f.push([1])</script></body></html>'
    )
    assert info.is_spa is True
    assert info.framework == "Next.js"


def test_type_like_text_in_other_attribute_does_not_exclude_script():
    # 別属性の引用値内 type= を実 script type と誤認して実行 script を除外しない
    # （偽陰性の回帰・Codex #104 P2）。
    info = detect_spa(
        "<html><body><script data-example='type=\"text/plain\"'>"
        "self.__next_f.push([1])</script></body></html>"
    )
    assert info.is_spa is True
    assert info.framework == "Next.js"


@pytest.mark.parametrize(
    ("html", "framework"),
    [
        # 本番 React シェル: 空の id="root" ＋ ハッシュ付きバンドルのみ
        # （data-reactroot も React.createElement も react 名の script も無い）。
        (
            '<html><body><div id="root"></div>'
            '<script src="/assets/index-9f3a2b.js"></script></body></html>',
            "React",
        ),
        # 汎用マウント id="app" が空＋バンドル＝クライアント描画前提の SPA シェル。
        (
            '<html><body><main id="app">  </main>'
            '<script src="/static/bundle.js"></script></body></html>',
            "SPA",
        ),
    ],
)
def test_production_empty_mount_shell_is_high_confidence_spa(html, framework):
    info = detect_spa(html)

    assert info.is_spa is True
    assert info.framework == framework
    assert info.confidence == "high"


def test_empty_mount_with_bundle_module_script_is_spa():
    # 外部 src がバンドル痕跡（既知ディレクトリ /assets/）を持つ module は SPA。
    info = detect_spa(
        '<html><body><div id="root"></div>'
        '<script type="module" src="/assets/entry-9f3a2b.js"></script></body></html>'
    )
    assert info.is_spa is True
    assert info.confidence == "high"


def test_hydrated_react_ssr_markers_are_spa_even_with_content():
    # SSR/RSC/Suspense の React 固有コメントは、hydration 済みで root に内容が
    # あっても React を示す（Codex #104 P1・本番 SSR React を拾う）。
    info = detect_spa(
        '<html><body><div id="root"><!--$--><h1>App</h1><!--/$--></div>'
        '<script src="/assets/index-9f3a2b.js"></script></body></html>'
    )
    assert info.is_spa is True
    assert info.framework == "React"
    assert info.confidence == "high"
    assert "react-ssr-marker" in info.signals


@pytest.mark.parametrize(
    "html",
    [
        # 空マウントだがバンドル script が無い → シェルと断定しない。
        '<html><body><div id="root"></div></body></html>',
        # 空マウント＋無関係な単発 script（analytics）→ アプリバンドルでないので非SPA
        # （Codex #104 P2・誤有効化の回避）。
        '<html><body><div id="app"></div>'
        '<script src="/analytics.js"></script></body></html>',
        # 空マウント＋インライン module（src 無し）→ 外部バンドルでないので非SPA
        # （type="module" 単独では判定しない・Codex #104 P2）。
        '<html><body><div id="root"></div>'
        '<script type="module">console.log("hi")</script></body></html>',
        # 空マウント＋非バンドル src の module → 非SPA。
        '<html><body><div id="app"></div>'
        '<script type="module" src="/analytics.js"></script></body></html>',
        # data-src（遅延プレースホルダ・未ロード）は実 src ではないので非SPA
        # （\bsrc が data-src に一致する問題の回帰・Codex #104 P2）。
        '<html><body><div id="root"></div>'
        '<script data-src="/assets/index-abcdef.js"></script></body></html>',
        # マウントに内容がある（サーバ描画済み）＋ script → 静的サイト扱い。
        '<html><body><div id="root"><h1>ようこそ</h1><p>案内です。</p></div>'
        '<script src="/assets/site.js"></script></body></html>',
        # 既知の限界（documented limitation・Codex #104 P1）: 内容ありの root ＋
        # ハッシュ付きバンドルだが React 固有マーカーが一切無いページは、SSR の
        # 通常サイトと静的 HTML だけでは区別できないため非SPA とする（誤有効化を
        # 選ばない保守側。必要なら利用者が --spa-crawl を明示）。
        '<html><body><div id="root"><h1>Welcome</h1></div>'
        '<script src="/assets/index-9f3a2b.js"></script></body></html>',
    ],
)
def test_empty_mount_shell_requires_empty_mount_and_bundle(html):
    info = detect_spa(html)

    assert info.is_spa is False
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
