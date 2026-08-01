"""Phase 4 — the answer: can anything actually reach this finding?

BFS from every entry point across the call graph, then look up each finding's enclosing
function in the resulting set.

Where the analysis cannot see, it says UNKNOWN. It never says UNREACHABLE on a guess —
UNREACHABLE is the verdict that tells someone to ignore a finding, so it has to be earned.
"""

from __future__ import annotations

from collections import deque
from typing import Dict, List, Optional, Set, Tuple

from .models import (
    CallGraph,
    EXACT,
    Finding,
    NAME,
    REACHABLE,
    UNKNOWN,
    UNREACHABLE,
    Verdict,
)


def _bfs(graph: CallGraph) -> Tuple[Set[str], Dict[str, Optional[str]], Dict[str, str]]:
    """Returns (reachable qualnames, parent map for path rebuild, weakest edge confidence)."""
    adj = graph.adjacency()
    reachable: Set[str] = set()
    parent: Dict[str, Optional[str]] = {}
    confidence: Dict[str, str] = {}

    queue: deque = deque()
    for fn in graph.entry_points():
        if fn.qualname not in reachable:
            reachable.add(fn.qualname)
            parent[fn.qualname] = None
            confidence[fn.qualname] = EXACT
            queue.append(fn.qualname)

    while queue:
        node = queue.popleft()
        for edge in adj.get(node, []):
            if edge.callee in reachable:
                continue
            if edge.callee not in graph.functions:
                continue
            reachable.add(edge.callee)
            parent[edge.callee] = node
            # A path is only as trustworthy as its weakest link.
            confidence[edge.callee] = (
                NAME if edge.confidence == NAME or confidence[node] == NAME else EXACT
            )
            queue.append(edge.callee)

    return reachable, parent, confidence


def _path(qual: str, parent: Dict[str, Optional[str]]) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    cur: Optional[str] = qual
    while cur is not None and cur not in seen:
        seen.add(cur)
        out.append(cur)
        cur = parent.get(cur)
    out.reverse()
    return out


def _package_modules(graph: CallGraph, package: str) -> List[str]:
    """Modules importing `package`. Distribution names and import names differ, so compare
    loosely — `ruamel-yaml` on PyPI is `ruamel` on import."""
    if not package:
        return []
    norm = package.lower().replace("-", "_")
    roots = {norm, norm.split("_")[0]}
    hits = []
    for module, table in graph.imports.items():
        for target in table.values():
            root = target.split(".")[0].lower()
            if root in roots:
                hits.append(module)
                break
    return hits


def _dep_verdict(
    finding: Finding,
    graph: CallGraph,
    reachable: Set[str],
    parent: Dict[str, Optional[str]],
) -> Verdict:
    """Dependency findings have no line number, so map them through package imports instead."""
    modules = _package_modules(graph, finding.package)
    if not modules:
        return Verdict(
            finding=finding,
            status=UNKNOWN,
            confidence=NAME,
            reason="no import of '%s' found in first-party code" % finding.package,
        )

    for qual in reachable:
        fn = graph.functions.get(qual)
        if fn is None:
            continue
        owner = qual.rsplit(".", 1)[0]
        if any(owner == m or owner.startswith(m + ".") for m in modules):
            return Verdict(
                finding=finding,
                status=REACHABLE,
                sink=qual,
                path=_path(qual, parent),
                confidence=NAME,
                reason="reachable code in a module importing '%s'" % finding.package,
            )

    return Verdict(
        finding=finding,
        status=UNREACHABLE,
        confidence=NAME,
        reason="'%s' imported only by unreachable modules" % finding.package,
    )


def analyze(findings: List[Finding], graph: CallGraph, log=None) -> List[Verdict]:
    log = log or (lambda *_a, **_k: None)
    reachable, parent, confidence = _bfs(graph)
    log("%d of %d functions reachable" % (len(reachable), len(graph.functions)))

    verdicts: List[Verdict] = []
    for finding in findings:
        if finding.tool == "osv" or (not finding.line and finding.package):
            verdicts.append(_dep_verdict(finding, graph, reachable, parent))
            continue

        if not finding.file.endswith(".py"):
            verdicts.append(
                Verdict(
                    finding=finding,
                    status=UNKNOWN,
                    reason="not a Python file; outside the call graph",
                )
            )
            continue

        fn = graph.enclosing(finding.file, finding.line)
        if fn is None:
            verdicts.append(
                Verdict(
                    finding=finding,
                    status=UNKNOWN,
                    reason="module-level code; runs on import, but whether the module is "
                           "imported is a separate question",
                )
            )
            continue

        if fn.qualname in reachable:
            verdicts.append(
                Verdict(
                    finding=finding,
                    status=REACHABLE,
                    sink=fn.qualname,
                    path=_path(fn.qualname, parent),
                    confidence=confidence.get(fn.qualname, EXACT),
                    reason="entry point: %s" % (_entry_reason(graph, parent, fn.qualname)),
                )
            )
        else:
            verdicts.append(
                Verdict(
                    finding=finding,
                    status=UNREACHABLE,
                    sink=fn.qualname,
                    reason="no path from any detected entry point",
                )
            )

    _log_summary(verdicts, log)
    return verdicts


def _entry_reason(graph: CallGraph, parent: Dict[str, Optional[str]], qual: str) -> str:
    root = _path(qual, parent)[0] if _path(qual, parent) else qual
    fn = graph.functions.get(root)
    return fn.entry_reason if fn and fn.entry_reason else root


def _log_summary(verdicts: List[Verdict], log) -> None:
    counts = {REACHABLE: 0, UNREACHABLE: 0, UNKNOWN: 0}
    for v in verdicts:
        counts[v.status] = counts.get(v.status, 0) + 1
    log(
        "%d findings -> %d reachable, %d unreachable, %d unknown"
        % (len(verdicts), counts[REACHABLE], counts[UNREACHABLE], counts[UNKNOWN])
    )
