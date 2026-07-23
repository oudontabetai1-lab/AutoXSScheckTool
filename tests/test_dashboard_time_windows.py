"""ダッシュボードの検査時間帯設定に関する薄い配線テスト。"""

import ast
import shutil
import subprocess
import unittest
from pathlib import Path


class ServeTimeWindowWiringTests(unittest.TestCase):
    def test_defaults_and_scan_engine_receive_time_windows(self):
        tree = ast.parse(Path("main.py").read_text(encoding="utf-8"))
        run_serve = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "run_serve"
        )

        defaults = next(
            node.value
            for node in ast.walk(run_serve)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute)
                and target.attr == "default_scan_cfg"
                for target in node.targets
            )
            and isinstance(node.value, ast.Dict)
        )
        default_keys = {
            key.value for key in defaults.keys if isinstance(key, ast.Constant)
        }
        self.assertIn("allowed_hours", default_keys)
        self.assertIn("forbidden_hours", default_keys)

        engine_call = next(
            node
            for node in ast.walk(run_serve)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ScanEngine"
            and any(keyword.arg == "header_refresh_interval" for keyword in node.keywords)
        )
        keywords = {keyword.arg: keyword.value for keyword in engine_call.keywords}
        for key in ("allowed_hours", "forbidden_hours"):
            value = keywords[key]
            self.assertIsInstance(value, ast.BoolOp)
            self.assertIsInstance(value.op, ast.Or)
            self.assertIsInstance(value.values[-1], ast.Constant)
            self.assertIsNone(value.values[-1].value)


class DashboardTimeWindowJsTests(unittest.TestCase):
    def test_time_window_controls_cover_normal_hybrid_and_persistence(self):
        html = Path("templates/dashboard.html").read_text(encoding="utf-8")

        self.assertIn('id="cfgAllowedHours"', html)
        self.assertIn('id="cfgForbiddenHours"', html)
        self.assertEqual(html.count("...timeWindowFields(),"), 4)
        self.assertGreaterEqual(html.count("applyTimeWindows(cfg);"), 3)

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for dashboard JS test")
    def test_time_window_helpers_trim_lines_and_omit_empty_values(self):
        html = Path("templates/dashboard.html").read_text(encoding="utf-8")
        start = html.index("function timeWindowFields()")
        end = html.index("function applyMfaTotp(cfg)", start)
        functions = html[start:end]
        script = f"""
const elements = {{
  cfgAllowedHours: {{value: '  Mon-Fri 22:00-06:00  \\n\\n Sat,Sun 00:00-24:00 '}},
  cfgForbiddenHours: {{value: '   '}},
}};
global.document = {{
  getElementById: id => elements[id] || null,
}};
{functions}

const collected = timeWindowFields();
if (JSON.stringify(collected.allowed_hours) !==
    JSON.stringify(['Mon-Fri 22:00-06:00', 'Sat,Sun 00:00-24:00'])) process.exit(10);
if ('forbidden_hours' in collected) process.exit(11);

applyTimeWindows({{
  allowed_hours: ['Mon 01:00-02:00', 'Tue 03:00-04:00'],
  forbidden_hours: 'Wed 05:00-06:00',
}});
if (elements.cfgAllowedHours.value !== 'Mon 01:00-02:00\\nTue 03:00-04:00') process.exit(20);
if (elements.cfgForbiddenHours.value !== 'Wed 05:00-06:00') process.exit(21);
"""
        result = subprocess.run(
            [shutil.which("node"), "-e", script],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
