"""_form_submit_url: submit ボタンの formaction が form.action を上書きすることの検証（G6/P1）。

fill_and_submit_form は submit control を click するため、formaction があればそれが実効
送信先。WAF 応答の origin 帰属（req_origin）はこの実効送信先から導く必要がある。
"""
import unittest

from wscan.engine import ScanEngine


class FormSubmitUrlTests(unittest.TestCase):
    def _eng(self):
        return object.__new__(ScanEngine)  # メソッドは self 状態非依存

    def test_prefers_formaction_absolute(self):
        eng = self._eng()
        form = {"action": "https://a.test/post", "formaction": "https://b.test/override"}
        self.assertEqual(eng._form_submit_url(form, "https://a.test/page"), "https://b.test/override")

    def test_resolves_relative_formaction(self):
        eng = self._eng()
        form = {"action": "https://a.test/post", "formaction": "/override"}
        self.assertEqual(eng._form_submit_url(form, "https://b.test/page"), "https://b.test/override")

    def test_falls_back_to_action_when_no_formaction(self):
        eng = self._eng()
        form = {"action": "https://a.test/post", "formaction": ""}
        self.assertEqual(eng._form_submit_url(form, "https://a.test/page"), "https://a.test/post")


if __name__ == "__main__":
    unittest.main()
