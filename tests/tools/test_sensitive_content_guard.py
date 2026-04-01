from pathlib import Path

import tools.sensitive_content_guard as guard


def test_detects_github_pat(tmp_path: Path):
    f = tmp_path / "leak.txt"
    f.write_text("token = 'github_pat_abcdefghijklmnopqrstuvwxyz123456'\n", encoding="utf-8")

    findings = guard.scan([f])
    assert findings
    assert any(item["pattern"] == "github_pat" for item in findings)


def test_allowlisted_path_is_skipped(tmp_path: Path):
    root = tmp_path / "docs" / "examples"
    root.mkdir(parents=True)
    f = root / "sample.txt"
    f.write_text("secret='supersecretvalue123456789'\n", encoding="utf-8")

    findings = guard.scan([f])
    assert findings == []


def test_safe_content_has_no_findings(tmp_path: Path):
    f = tmp_path / "safe.txt"
    f.write_text("print('hello world')\n", encoding="utf-8")

    findings = guard.scan([f])
    assert findings == []
