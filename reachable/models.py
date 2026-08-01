"""Shared dataclasses. Every stage of the pipeline speaks in these types."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

# Verdict values
REACHABLE = "REACHABLE"
UNREACHABLE = "UNREACHABLE"
UNKNOWN = "UNKNOWN"

# Edge confidence values
EXACT = "exact"
NAME = "name"


@dataclass
class Finding:
    """One normalized result from any scanner."""

    id: str
    tool: str
    severity: str
    message: str
    file: str = ""
    line: int = 0
    end_line: int = 0
    rule_id: str = ""
    package: str = ""
    fixed_version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FuncDef:
    """A function or method node in the call graph."""

    qualname: str
    file: str
    lineno: int
    end_lineno: int
    is_entry: bool = False
    entry_reason: str = ""
    is_method: bool = False

    def contains(self, line: int) -> bool:
        return self.lineno <= line <= self.end_lineno

    @property
    def span(self) -> int:
        return self.end_lineno - self.lineno


@dataclass
class Edge:
    """A call site: caller invokes callee."""

    caller: str
    callee: str
    confidence: str = EXACT
    lineno: int = 0


@dataclass
class CallGraph:
    functions: Dict[str, FuncDef] = field(default_factory=dict)
    edges: List[Edge] = field(default_factory=list)
    unresolved: int = 0   # call sites the analysis genuinely could not pin down
    external: int = 0     # calls into stdlib / third-party code — correctly outside the graph
    files_parsed: int = 0
    parse_errors: List[str] = field(default_factory=list)

    # Populated during the build so later stages never re-parse the repo.
    trees: Dict[str, Any] = field(default_factory=dict)          # module -> ast.Module
    modules: Dict[str, str] = field(default_factory=dict)        # module -> repo-relative file
    imports: Dict[str, Dict[str, str]] = field(default_factory=dict)  # module -> {local: target}
    decorators: Dict[str, List[str]] = field(default_factory=dict)    # qualname -> decorator srcs
    classes: Dict[str, List[str]] = field(default_factory=dict)       # class qualname -> methods

    def adjacency(self) -> Dict[str, List[Edge]]:
        """caller qualname -> outgoing edges."""
        out: Dict[str, List[Edge]] = {}
        for e in self.edges:
            out.setdefault(e.caller, []).append(e)
        return out

    def entry_points(self) -> List[FuncDef]:
        return [f for f in self.functions.values() if f.is_entry]

    def enclosing(self, file: str, line: int) -> Optional[FuncDef]:
        """Innermost function containing file:line, or None for module-level code."""
        best: Optional[FuncDef] = None
        for f in self.functions.values():
            if f.file == file and f.contains(line):
                if best is None or f.span < best.span:
                    best = f
        return best


@dataclass
class Verdict:
    """A finding plus the reachability answer."""

    finding: Finding
    status: str
    sink: str = ""
    path: List[str] = field(default_factory=list)
    confidence: str = EXACT
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding": self.finding.to_dict(),
            "status": self.status,
            "sink": self.sink,
            "path": self.path,
            "confidence": self.confidence,
            "reason": self.reason,
        }
