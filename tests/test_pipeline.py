"""End-to-end tests over tests/fixtures/sample_app.

The fixture is small on purpose: every assertion here should be verifiable by reading the
five files it contains. If a test fails, the fixture is the spec.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reachable import callgraph, entrypoints, reachability, report  # noqa: E402
from reachable.models import Finding, REACHABLE, UNKNOWN, UNREACHABLE  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "sample_app")


def line_of(rel_path, needle):
    """Locate a marker line so tests do not hardcode line numbers."""
    path = os.path.join(FIXTURE, rel_path)
    with open(path, encoding="utf-8") as fh:
        for i, line in enumerate(fh, start=1):
            if needle in line:
                return i
    raise AssertionError("marker %r not found in %s" % (needle, rel_path))


@pytest.fixture(scope="module")
def graph():
    g = callgraph.build(FIXTURE)
    entrypoints.detect(FIXTURE, g)
    return g


# ----------------------------------------------------------------- call graph

def test_functions_are_registered(graph):
    for qual in (
        "app.util.run_cmd",
        "app.util.slugify",
        "app.storage.save",
        "app.storage.purge",
        "app.routes.upload",
        "app.dead.parse_blob",
    ):
        assert qual in graph.functions, qual


def test_cross_module_import_edge_resolves(graph):
    """`from .util import run_cmd` then `run_cmd(...)` must produce an exact edge."""
    edges = {(e.caller, e.callee) for e in graph.edges}
    assert ("app.storage.save", "app.util.run_cmd") in edges
    assert ("app.routes.upload", "app.storage.save") in edges


def test_parse_errors_are_empty(graph):
    assert graph.parse_errors == []


# ---------------------------------------------------------------- entry points

def test_route_decorator_is_an_entry_point(graph):
    assert graph.functions["app.routes.upload"].is_entry


def test_ordinary_helper_is_not_an_entry_point(graph):
    assert not graph.functions["app.util.run_cmd"].is_entry
    assert not graph.functions["app.dead.parse_blob"].is_entry


# --------------------------------------------------------------- reachability

def test_reachable_finding_gets_a_path(graph):
    finding = Finding(
        id="t1",
        tool="semgrep",
        severity="ERROR",
        message="command injection",
        file="app/util.py",
        line=line_of("app/util.py", "SINK-REACHABLE") + 1,
        rule_id="python.lang.security.subprocess-shell-true",
    )
    verdict = reachability.analyze([finding], graph)[0]

    assert verdict.status == REACHABLE
    assert verdict.sink == "app.util.run_cmd"
    assert verdict.path[0] == "app.routes.upload"
    assert verdict.path[-1] == "app.util.run_cmd"


def test_dead_code_finding_is_unreachable(graph):
    finding = Finding(
        id="t2",
        tool="semgrep",
        severity="ERROR",
        message="insecure deserialization",
        file="app/dead.py",
        line=line_of("app/dead.py", "SINK-UNREACHABLE") + 1,
        rule_id="python.lang.security.pickle-loads",
    )
    verdict = reachability.analyze([finding], graph)[0]

    assert verdict.status == UNREACHABLE
    assert verdict.sink == "app.dead.parse_blob"
    assert verdict.path == []


def test_module_level_finding_is_unknown_not_reachable(graph):
    """Module bodies run on import, but whether the module is imported is a separate
    question. UNKNOWN is the honest answer; UNREACHABLE would be a false all-clear."""
    finding = Finding(
        id="t3",
        tool="semgrep",
        severity="WARNING",
        message="module level constant",
        file="app/dead.py",
        line=line_of("app/dead.py", "TRUSTED = False"),
        rule_id="x",
    )
    verdict = reachability.analyze([finding], graph)[0]
    assert verdict.status == UNKNOWN


def test_class_body_reference_is_an_entry_point(graph):
    """Regression: Flask wires its session hash as `digest_method = staticmethod(_lazy_sha1)`
    in a class body. Skipping ClassDef reported that live crypto path as dead code."""
    assert graph.functions["app.registry.sign_payload"].is_entry


def test_class_body_registered_finding_is_reachable(graph):
    finding = Finding(
        id="t8",
        tool="semgrep",
        severity="MEDIUM",
        message="weak hash",
        file="app/registry.py",
        line=line_of("app/registry.py", "SINK-CLASS-REGISTERED") + 1,
        rule_id="python.lang.security.insecure-hash",
    )
    assert reachability.analyze([finding], graph)[0].status == REACHABLE


def test_finding_inside_main_guard_is_reachable(graph):
    """Code under `if __name__ == "__main__":` is exactly what runs when the file is
    executed. UNKNOWN would understate it."""
    finding = Finding(
        id="t9",
        tool="semgrep",
        severity="MEDIUM",
        message="debug mode enabled",
        file="app/registry.py",
        line=line_of("app/registry.py", "SINK-MAIN-GUARD"),
        rule_id="python.flask.debug-enabled",
    )
    verdict = reachability.analyze([finding], graph)[0]
    assert verdict.status == REACHABLE
    assert "__main__" in verdict.reason


def test_non_python_file_is_unknown(graph):
    finding = Finding(
        id="t4", tool="gitleaks", severity="HIGH", message="secret",
        file="config/settings.yaml", line=3, rule_id="generic-api-key",
    )
    assert reachability.analyze([finding], graph)[0].status == UNKNOWN


# ---------------------------------------------------------- dependency findings

def test_dep_finding_without_import_is_unknown(graph):
    finding = Finding(
        id="t5", tool="osv", severity="HIGH", message="CVE in a package nothing imports",
        rule_id="GHSA-xxxx", package="some-unused-lib",
    )
    verdict = reachability.analyze([finding], graph)[0]
    assert verdict.status == UNKNOWN
    assert "no import" in verdict.reason


def test_dep_finding_with_reachable_import_is_reachable(graph):
    """`app.storage` imports nothing external, but `app.util` imports subprocess and is
    reachable — a stand-in for a vulnerable third-party package."""
    finding = Finding(
        id="t6", tool="osv", severity="HIGH", message="CVE in subprocess-like package",
        rule_id="GHSA-yyyy", package="subprocess",
    )
    verdict = reachability.analyze([finding], graph)[0]
    assert verdict.status == REACHABLE


# --------------------------------------------------------------------- report

def test_report_writes_all_three_artifacts(graph, tmp_path):
    finding = Finding(
        id="t7", tool="semgrep", severity="ERROR", message="command injection",
        file="app/util.py", line=line_of("app/util.py", "SINK-REACHABLE") + 1,
        rule_id="r",
    )
    verdicts = reachability.analyze([finding], graph)
    paths = report.write(verdicts, graph, str(tmp_path))

    for key in ("json", "md", "html"):
        assert os.path.isfile(paths[key])
        assert os.path.getsize(paths[key]) > 0

    html = open(paths["html"], encoding="utf-8").read()
    assert "app.routes.upload" in html
    # The report must be openable offline: no external asset may be referenced.
    for marker in ("http://", "https://", "<script"):
        assert marker not in html
