"""Hostile and malformed input.

This tool reads code it does not trust and scanner output it does not control, then writes a
report that a GitHub Action posts as a pull request comment. That makes report content a
security boundary, not just a formatting concern.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reachable import callgraph, entrypoints, reachability, report, scanners  # noqa: E402
from reachable.models import Finding, UNKNOWN  # noqa: E402


def build(path):
    graph = callgraph.build(str(path))
    entrypoints.detect(str(path), graph)
    return graph


def _headings(md):
    """Every line that markdown would render as a heading."""
    return [line for line in md.splitlines() if line.startswith("#")]


def report_for(tmp_path, finding):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "m.py").write_text("def f():\n    pass\n", encoding="utf-8")
    graph = build(repo)
    verdicts = reachability.analyze([finding], graph)
    out = tmp_path / "out"
    return report.write(verdicts, graph, str(out))


# ------------------------------------------------------------------ malformed source

def test_empty_repo_does_not_crash(tmp_path):
    graph = callgraph.build(str(tmp_path))
    assert graph.files_parsed == 0
    assert graph.functions == {}


def test_bom_prefixed_file_is_parsed(tmp_path):
    """Regression: reading as utf-8 left the BOM in the string, ast.parse raised SyntaxError,
    and the whole file vanished from the graph. Windows editors emit BOMs routinely, and a
    dropped file means its findings wrongly report as unreachable."""
    (tmp_path / "bom.py").write_bytes(b"\xef\xbb\xbfdef handler():\n    pass\n")
    graph = callgraph.build(str(tmp_path))
    assert graph.parse_errors == []
    assert "bom.handler" in graph.functions


def test_unicode_identifiers_are_parsed(tmp_path):
    (tmp_path / "uni.py").write_text("def élément():\n    pass\n", encoding="utf-8")
    graph = callgraph.build(str(tmp_path))
    assert graph.parse_errors == []
    assert "uni.élément" in graph.functions


def test_null_bytes_are_skipped_not_fatal(tmp_path):
    (tmp_path / "bin.py").write_bytes(b"\x00\x01\x02def f(): pass")
    (tmp_path / "ok.py").write_text("def g():\n    pass\n", encoding="utf-8")
    graph = callgraph.build(str(tmp_path))
    assert len(graph.parse_errors) == 1
    assert "ok.g" in graph.functions


def test_pathologically_nested_source_is_skipped_not_fatal(tmp_path):
    """CPython refuses to parse this. The point is that one hostile file must not abort the
    run for every other file."""
    (tmp_path / "deep.py").write_text(
        "def f():\n    return " + "f(" * 500 + "f()" + ")" * 500, encoding="utf-8"
    )
    (tmp_path / "ok.py").write_text("def g():\n    pass\n", encoding="utf-8")
    graph = callgraph.build(str(tmp_path))
    assert "ok.g" in graph.functions


def test_circular_imports_terminate(tmp_path):
    (tmp_path / "a.py").write_text("from b import g\ndef f():\n    return g()\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("from a import f\ndef g():\n    return f()\n", encoding="utf-8")
    graph = build(tmp_path)
    reachability.analyze([], graph)  # must not hang or recurse forever


def test_self_recursive_call_terminates(tmp_path):
    (tmp_path / "r.py").write_text("def main():\n    return main()\n", encoding="utf-8")
    graph = build(tmp_path)
    reachability.analyze([], graph)


# ------------------------------------------------------------------ report integrity

def test_markdown_report_cannot_be_forged_through_a_finding_message(tmp_path):
    """The Action posts report.md as a PR comment. If a finding message could carry newlines,
    anyone able to influence a scanned string could fabricate findings or bury real ones."""
    evil = Finding(
        id="x", tool="semgrep", severity="LOW",
        message="harmless\n\n## REACHABLE (999)\n\n### `fake.py:1`\n\nfabricated critical finding",
        file="m.py", line=1, rule_id="r",
    )
    paths = report_for(tmp_path, evil)
    md = open(paths["md"], encoding="utf-8").read()

    # Markdown structure needs a line start. That is the property to assert -- the payload
    # appearing as inline prose is harmless, and stripping it would hide real content.
    for line in md.splitlines():
        assert not line.startswith("## REACHABLE (999)")
        assert not line.startswith("### `fake.py:1`")

    assert "fabricated critical finding" in md
    assert not any("999" in h or "fake.py" in h for h in _headings(md))


def test_forgery_through_file_path_and_rule_id(tmp_path):
    evil = Finding(
        id="x", tool="semgrep", severity="LOW", message="m",
        file="m.py\n\n## UNREACHABLE (0)\n", line=1,
        rule_id="r\n- path: `totally.fake.path`",
    )
    md = open(report_for(tmp_path, evil)["md"], encoding="utf-8").read()
    assert not any("UNREACHABLE (0)" in h for h in _headings(md))
    # A forged bullet would claim a call path that does not exist.
    assert not any(line.startswith("- path:") for line in md.splitlines())


def test_html_report_escapes_markup(tmp_path):
    evil = Finding(
        id="y", tool="semgrep", severity="LOW",
        message="<script>alert(1)</script>", file="m.py", line=1,
        rule_id="<img src=x onerror=alert(2)>",
    )
    html = open(report_for(tmp_path, evil)["html"], encoding="utf-8").read()
    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_control_characters_are_stripped(tmp_path):
    evil = Finding(id="z", tool="semgrep", severity="LOW",
                   message="a\x00b\x1bc", file="m.py", line=1, rule_id="r")
    md = open(report_for(tmp_path, evil)["md"], encoding="utf-8").read()
    assert "\x00" not in md
    assert "\x1b" not in md


def test_absurdly_long_message_is_truncated(tmp_path):
    evil = Finding(id="w", tool="semgrep", severity="LOW",
                   message="A" * 100000, file="m.py", line=1, rule_id="r")
    md = open(report_for(tmp_path, evil)["md"], encoding="utf-8").read()
    assert "A" * 1000 not in md


def test_path_traversal_in_reported_file_is_inert(tmp_path):
    """The path is only ever printed, never opened -- but confirm it stays a non-crashing
    UNKNOWN rather than being resolved against the filesystem."""
    evil = Finding(id="p", tool="gitleaks", severity="HIGH", message="secret",
                   file="../../../etc/passwd", line=1, rule_id="r")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "m.py").write_text("def f():\n    pass\n", encoding="utf-8")
    verdict = reachability.analyze([evil], build(repo))[0]
    assert verdict.status == UNKNOWN


# ------------------------------------------------------------------ malformed cache

def test_load_raw_tolerates_unknown_keys(tmp_path):
    p = tmp_path / "f.json"
    p.write_text('[{"id":"a","tool":"semgrep","severity":"LOW","message":"m",'
                 '"from_a_newer_version":123}]', encoding="utf-8")
    got = scanners.load_raw(str(p))
    assert len(got) == 1 and got[0].id == "a"


def test_load_raw_rejects_non_list(tmp_path):
    p = tmp_path / "f.json"
    p.write_text('{"nope": true}', encoding="utf-8")
    assert scanners.load_raw(str(p)) == []


def test_scan_survives_missing_binaries(tmp_path):
    """No scanner installed must degrade to the built-in rules, never raise."""
    (tmp_path / "m.py").write_text("import os\ndef f(c):\n    os.system(c)\n", encoding="utf-8")
    got = scanners.scan(str(tmp_path))
    assert any(f.rule_id == "builtin.os-system" for f in got)


# -- a dead scanner is not a clean scan ----------------------------------------------------

class _Proc:
    def __init__(self, code, out="", err=""):
        self.returncode, self.stdout, self.stderr = code, out, err


def test_a_scanner_that_dies_raises_rather_than_returning_nothing(tmp_path, monkeypatch):
    """The real case: semgrep refuses `--config=auto` with `--metrics=off`, exits non-zero and
    prints its error to stderr. That used to arrive as `semgrep -> 0 findings`."""
    monkeypatch.setattr(
        scanners.subprocess, "run",
        lambda *a, **k: _Proc(2, "", "Cannot create auto config when metrics are off."))
    with pytest.raises(scanners.ScannerFailed) as exc:
        scanners._run(["semgrep"], str(tmp_path))
    assert "metrics are off" in str(exc.value)


def test_a_nonzero_exit_with_output_is_findings_not_failure(tmp_path, monkeypatch):
    """Scanners exit non-zero *because* they found something. That must still parse."""
    monkeypatch.setattr(scanners.subprocess, "run", lambda *a, **k: _Proc(1, '{"results": []}'))
    assert scanners._run(["semgrep"], str(tmp_path)) == '{"results": []}'


def test_output_that_is_not_json_is_a_failure(tmp_path):
    with pytest.raises(scanners.ScannerFailed):
        scanners._checked("Traceback (most recent call last):", "semgrep")


def test_empty_output_is_not_a_failure(tmp_path):
    assert scanners._checked("", "semgrep") == ""


def test_a_failed_scanner_is_reported_not_counted_as_zero(tmp_path, monkeypatch):
    """The property that matters end to end: the run says the report is incomplete."""
    (tmp_path / "m.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(scanners, "_have", lambda binary: binary == "semgrep")
    monkeypatch.setattr(
        scanners, "run_semgrep",
        lambda repo: (_ for _ in ()).throw(scanners.ScannerFailed("exit 2: broke")))
    lines = []
    scanners.scan(str(tmp_path), log=lines.append)
    assert any("FAILED" in line for line in lines)
    assert any("incomplete" in line for line in lines)
    assert not any("semgrep -> 0 findings" in line for line in lines)
