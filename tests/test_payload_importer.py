import yaml

from wscan import payload_importer
from wscan.engine import merge_community_payloads
from wscan.payload_importer import build_corpus, parse_payload_lines, write_yaml


def test_parse_payload_lines_filters_noise_and_preserves_payloads():
    text = "\n".join(
        [
            "",
            "  <script>alert(1)</script>  ",
            "<script>alert(1)</script>",
            "## markdown heading",
            "\x01\x02",
            "${IFS}cat${IFS}/etc/passwd",
            "A" * 2001,
            "DROP TABLE users",
        ]
    )

    assert parse_payload_lines(text) == [
        "<script>alert(1)</script>",
        "${IFS}cat${IFS}/etc/passwd",
        "DROP TABLE users",
    ]
    assert parse_payload_lines("short\n" + ("A" * 11), max_len=10) == ["short"]


def test_parse_payload_lines_destructive_denylist_default_and_opt_in():
    text = "\n".join(
        [
            "rm -rf /",
            "mkfs.ext4 /dev/sda1",
            ":(){ :|:& };:",
            "shutdown now",
            "reboot",
            "DROP DATABASE prod",
            "format c:",
            "cat payload > /dev/sda",
            "1; DROP TABLE users--",
        ]
    )

    assert parse_payload_lines(text) == ["1; DROP TABLE users--"]
    assert parse_payload_lines(text, allow_destructive=True) == [
        "rm -rf /",
        "mkfs.ext4 /dev/sda1",
        ":(){ :|:& };:",
        "shutdown now",
        "reboot",
        "DROP DATABASE prod",
        "format c:",
        "cat payload > /dev/sda",
        "1; DROP TABLE users--",
    ]


def test_build_corpus_uses_fetch_text_monkeypatch(monkeypatch):
    sources = {
        "xss": ["https://example.test/xss-1", "https://example.test/xss-2"],
        "sqli": ["https://example.test/sqli"],
    }
    responses = {
        "https://example.test/xss-1": "<svg/onload=alert(1)>\n# heading\nsame",
        "https://example.test/xss-2": "same\n<img src=x onerror=alert(1)>",
        "https://example.test/sqli": "' OR 1=1--\nDROP DATABASE prod",
    }

    monkeypatch.setattr(payload_importer, "fetch_text", lambda url: responses[url])

    assert build_corpus(sources) == {
        "xss": ["<svg/onload=alert(1)>", "same", "<img src=x onerror=alert(1)>"],
        "sqli": ["' OR 1=1--"],
    }
    assert build_corpus(sources, per_type_cap=1) == {
        "xss": ["<svg/onload=alert(1)>"],
        "sqli": ["' OR 1=1--"],
    }


def test_write_yaml_round_trips_with_source_comment(tmp_path):
    output = tmp_path / "community_payloads.yaml"
    sources = {
        "xss": [
            "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/XSS_Polyglots.txt",
        ],
        "ssti": [
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/template-engines-expression.txt",
        ],
    }
    corpus = {"xss": ["<script>alert(1)</script>"], "ssti": ["{{7*7}}"]}

    write_yaml(output, corpus, sources=sources)

    written = output.read_text(encoding="utf-8")
    assert written.startswith("# WScan Community Payloads")
    assert "https://github.com/swisskyrepo/PayloadsAllTheThings" in written
    assert "https://github.com/danielmiessler/SecLists" in written
    assert "各上流リポジトリの LICENSE" in written
    assert yaml.safe_load(written) == corpus


def test_merge_community_payloads_can_be_enabled_or_skipped_by_caller():
    curated = {
        "xss": ["curated", "shared"],
        "sqli": ["' OR 1=1--"],
        "llm_prompts": {"xss": "prompt"},
    }
    community = {
        "xss": ["shared", "community"],
        "os": ["id"],
        "llm_prompts": ["should-not-overwrite"],
    }

    assert merge_community_payloads(curated, community) == {
        "xss": ["curated", "shared", "community"],
        "sqli": ["' OR 1=1--"],
        "llm_prompts": {"xss": "prompt"},
        "os": ["id"],
    }
    assert curated["xss"] == ["curated", "shared"]


def test_merge_interleaves_so_community_survives_generator_cap():
    # curated だけで no-LLM の件数 cap(40) を使い切る規模でも、community が
    # cap 内（先頭40件）に現れること（Codex P2 指摘の回帰）。
    curated = {"sqli": [f"curated{i}" for i in range(60)]}
    community = {"sqli": [f"community{i}" for i in range(60)]}

    merged = merge_community_payloads(curated, community)["sqli"]

    first40 = merged[:40]
    assert any(p.startswith("community") for p in first40), (
        "community payloads never reach the no-LLM generator cap"
    )
    # curated 優先(2:1)は保たれている
    assert merged[0] == "curated0" and merged[1] == "curated1"
    assert merged[2] == "community0"
    # 重複なし・全件保持
    assert len(merged) == len(set(merged)) == 120
