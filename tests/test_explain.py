"""The explanations are a feature, not decoration.

If someone opens a pull request based on this report, these paragraphs are what they will
say when a maintainer asks "why is this a problem?". They have to be present, they have to
be readable, and every rule the scanner can emit has to have one.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reachable import builtin_scan, explain, reachability, report  # noqa: E402
from reachable.models import REACHABLE, UNKNOWN, UNREACHABLE  # noqa: E402


def test_every_builtin_rule_has_an_explanation():
    """A finding with no explanation is one the user cannot defend in review.

    Reads the rule IDs out of the scanner source rather than hardcoding a list, so adding a
    rule without writing its explanation fails here instead of shipping silently.
    """
    import re

    emitted = set()
    source = open(builtin_scan.__file__, encoding="utf-8").read()
    for slug in re.findall(r'self\._add\(\s*node,\s*"([\w-]+)"', source):
        emitted.add("builtin.%s" % slug)

    assert emitted, "no rule IDs found -- the extraction pattern needs updating"
    missing = sorted(r for r in emitted if r not in explain.EXPLANATIONS)
    assert not missing, "rules with no plain-English explanation: %s" % missing


def test_explanations_are_complete_and_non_trivial():
    for rule_id, e in explain.EXPLANATIONS.items():
        assert len(e.what) > 30, rule_id
        assert len(e.why) > 60, rule_id
        assert len(e.check) >= 2, rule_id
        assert len(e.say) > 40, rule_id
        assert all(step.strip() for step in e.check), rule_id


def test_unknown_rule_falls_back_by_keyword():
    """External scanners emit rule IDs this project has never seen."""
    e = explain.for_finding("python.lang.security.audit.dangerous-subprocess-use", "")
    assert e is explain.EXPLANATIONS["builtin.subprocess-shell-true"]

    e = explain.for_finding("some.rule.id", "MD5 hash used for password")
    assert e is explain.EXPLANATIONS["builtin.weak-hash"]


def test_completely_unknown_rule_gets_generic_not_a_crash():
    e = explain.for_finding("totally.unrecognised.rule", "something happened")
    assert e is explain.GENERIC
    assert e.check  # still tells the user how to investigate


def test_every_verdict_is_explained():
    for status in (REACHABLE, UNREACHABLE, UNKNOWN):
        headline, detail = explain.for_verdict(status)
        assert headline and detail, status


def test_unreachable_explanation_admits_it_can_be_wrong():
    """Understating uncertainty here is how someone ignores a live bug."""
    _, detail = explain.for_verdict(UNREACHABLE)
    assert "wrong" in detail.lower() or "cannot see" in detail.lower()


def test_path_in_words_describes_a_web_route():
    story = explain.path_in_words(
        ["app.routes.upload", "app.storage.save", "app.util.run_cmd"],
        "entry point: decorator: @app.route",
    )
    assert "visits a web address" in story
    assert "save" in story and "run_cmd" in story


def test_path_in_words_describes_a_main_guard():
    story = explain.path_in_words(["tool.main"], "called from __main__ in tool")
    assert "runs this file directly" in story


def test_path_in_words_handles_empty_path():
    assert explain.path_in_words([]) == ""


# ------------------------------------------------------------------ report integration

def _report(tmp_path, plain=True):
    from reachable import callgraph, entrypoints
    from reachable.models import Finding

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import subprocess\n"
        "def handler(cmd):\n"
        "    subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )
    graph = callgraph.build(str(repo))
    entrypoints.detect(str(repo), graph)
    finding = Finding(id="a", tool="builtin", severity="HIGH",
                      message="subprocess called with shell=True", file="app.py", line=3,
                      rule_id="builtin.subprocess-shell-true")
    verdicts = reachability.analyze([finding], graph)
    out = tmp_path / ("out_plain" if plain else "out_brief")
    return report.write(verdicts, graph, str(out), include_unknown=True, plain=plain)


def test_markdown_report_contains_the_explanation(tmp_path):
    md = open(_report(tmp_path)["md"], encoding="utf-8").read()
    assert "Explain this in plain English" in md
    assert "How to check this yourself" in md
    assert "If someone asks you to explain it" in md
    assert "Words used above" in md  # glossary


def test_html_report_contains_the_explanation(tmp_path):
    html = open(_report(tmp_path)["html"], encoding="utf-8").read()
    assert "Explain this in plain English" in html
    assert "How to check this yourself" in html


def test_brief_mode_omits_explanations(tmp_path):
    paths = _report(tmp_path, plain=False)
    md = open(paths["md"], encoding="utf-8").read()
    html = open(paths["html"], encoding="utf-8").read()
    assert "Explain this in plain English" not in md
    assert "Explain this in plain English" not in html
    # The findings themselves must still be there.
    assert "app.py:3" in md


def test_explanations_do_not_break_html_escaping(tmp_path):
    """Explanation text is trusted, but it shares a document with untrusted findings."""
    html = open(_report(tmp_path)["html"], encoding="utf-8").read()
    assert "<script" not in html
