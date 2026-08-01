"""Phase 2 — build the call graph with the standard library `ast` module.

Two passes over the repo:

  1. Parse every file, register every function, record imports and decorators.
  2. Walk each function body again and resolve its call sites into edges.

The second pass needs the complete function index from the first, which is why a call in
`a.py` to a function defined in `z.py` resolves regardless of file order.

Resolution is heuristic and says so. See `_resolve` for the precedence order. When a call
cannot be pinned to one target, the fallback matches on the short name across the whole repo
and labels the edge NAME confidence. That over-approximates on purpose: an extra edge makes
something look reachable when it is not, which is far less harmful than hiding a live bug.
"""

from __future__ import annotations

import ast
import os
from typing import Dict, List, Optional, Set, Tuple

from .models import CallGraph, Edge, EXACT, FuncDef, NAME

# Directories that never contain first-party code worth analyzing.
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".tox", ".nox", ".venv", "venv", "env",
    "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache",
    "site-packages", "dist", "build", ".eggs", ".idea", ".vscode",
}

# A very common short name can match dozens of definitions. Past this many candidates the
# fallback carries no information, so the call is counted unresolved instead.
MAX_NAME_CANDIDATES = 10


def iter_python_files(repo: str):
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        for name in files:
            if name.endswith(".py"):
                yield os.path.join(root, name)


def module_name(path: str, repo: str) -> str:
    """Repo-relative dotted module name. `pkg/util/__init__.py` -> `pkg.util`."""
    rel = os.path.relpath(path, repo).replace("\\", "/")
    if rel.endswith(".py"):
        rel = rel[:-3]
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def rel_path(path: str, repo: str) -> str:
    return os.path.relpath(path, repo).replace("\\", "/")


def _decorator_src(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - unparse is best effort only
        return ""


class _Collector(ast.NodeVisitor):
    """Pass 1 — register functions, imports and decorators for one module."""

    def __init__(self, graph: CallGraph, module: str, file: str):
        self.graph = graph
        self.module = module
        self.file = file
        self.stack: List[str] = []
        self.class_stack: List[str] = []

    def _qual(self, name: str) -> str:
        prefix = ".".join([p for p in [self.module] + self.stack if p])
        return "%s.%s" % (prefix, name) if prefix else name

    # -- imports ----------------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        table = self.graph.imports.setdefault(self.module, {})
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            target = alias.name
            table[local] = target
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        table = self.graph.imports.setdefault(self.module, {})
        base = self._resolve_relative(node.module or "", node.level or 0)
        for alias in node.names:
            if alias.name == "*":
                continue
            local = alias.asname or alias.name
            table[local] = "%s.%s" % (base, alias.name) if base else alias.name
        self.generic_visit(node)

    def _resolve_relative(self, mod: str, level: int) -> str:
        """`from ..pkg import x` inside `a.b.c` -> `a.pkg`."""
        if level == 0:
            return mod
        parts = self.module.split(".") if self.module else []
        # A package's __init__ is its own module path; a submodule drops its last segment.
        is_pkg = self.graph.modules.get(self.module, "").endswith("__init__.py")
        if not is_pkg and parts:
            parts = parts[:-1]
        if level > 1:
            parts = parts[: -(level - 1)] if level - 1 <= len(parts) else []
        return ".".join([p for p in parts + ([mod] if mod else []) if p])

    # -- definitions ------------------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.graph.classes.setdefault(self._qual(node.name), [])
        self.stack.append(node.name)
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()
        self.stack.pop()

    def visit_FunctionDef(self, node) -> None:
        qual = self._qual(node.name)
        self.graph.functions[qual] = FuncDef(
            qualname=qual,
            file=self.file,
            lineno=node.lineno,
            end_lineno=getattr(node, "end_lineno", node.lineno) or node.lineno,
            is_method=bool(self.class_stack),
        )
        decs = [_decorator_src(d) for d in node.decorator_list]
        if decs:
            self.graph.decorators[qual] = [d for d in decs if d]
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef


class _Resolver(ast.NodeVisitor):
    """Pass 2 — turn call sites inside each function into edges."""

    def __init__(
        self,
        graph: CallGraph,
        module: str,
        short_index: Dict[str, List[str]],
        first_party: Set[str],
    ):
        self.graph = graph
        self.module = module
        self.short = short_index
        self.first_party = first_party
        self.imports = graph.imports.get(module, {})
        self.stack: List[str] = []
        self.class_stack: List[str] = []
        self.seen: Set[Tuple[str, str]] = set()
        self.call_func_nodes: Set[int] = set()

    def _is_external(self, dotted: str) -> bool:
        """True for stdlib and third-party targets. Those are not analysis failures — they are
        correctly outside a first-party call graph, and conflating the two makes the tool look
        far blinder than it is."""
        return dotted.split(".")[0] not in self.first_party

    def _qual(self, name: str) -> str:
        prefix = ".".join([p for p in [self.module] + self.stack if p])
        return "%s.%s" % (prefix, name) if prefix else name

    @property
    def current(self) -> Optional[str]:
        if not self.stack:
            return None
        return ".".join([p for p in [self.module] + self.stack if p])

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.stack.append(node.name)
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()
        self.stack.pop()

    def visit_FunctionDef(self, node) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> None:
        caller = self.current
        self.call_func_nodes.add(id(node.func))
        if caller and caller in self.graph.functions:
            for callee, conf in self._resolve(node.func):
                self._add(caller, callee, conf, node.lineno)
        self.generic_visit(node)

    # -- function references ----------------------------------------------------
    #
    # `parser.set_defaults(func=run)`, `handlers = {"x": foo}`, `Thread(target=work)` and
    # every decorator registration pass a function without calling it at that site. Something
    # calls it later, through a value the analysis cannot follow.
    #
    # Ignoring these produces false UNREACHABLE verdicts on live code, which is the one error
    # this tool must not make: it tells someone to ignore a real bug. So a reference to a known
    # first-party function counts as an edge, at NAME confidence.

    def visit_Name(self, node: ast.Name) -> None:
        if id(node) not in self.call_func_nodes and isinstance(node.ctx, ast.Load):
            self._reference(self._lookup_name(node.id), node.lineno)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if id(node) not in self.call_func_nodes and isinstance(node.ctx, ast.Load):
            self._reference(self._lookup_attr(node), node.lineno)
        self.generic_visit(node)

    def _reference(self, callees: List[str], lineno: int) -> None:
        caller = self.current
        if not caller or caller not in self.graph.functions:
            return
        for callee in callees:
            self._add(caller, callee, NAME, lineno)

    def _lookup_name(self, name: str) -> List[str]:
        local = "%s.%s" % (self.module, name) if self.module else name
        for cand in (local, self.imports.get(name)):
            if cand and cand in self.graph.functions:
                return [cand]
            if cand and cand in self.graph.classes:
                return self._methods(cand)
        return []

    def _lookup_attr(self, node: ast.Attribute) -> List[str]:
        if not isinstance(node.value, ast.Name):
            return []
        if node.value.id in ("self", "cls") and self.class_stack:
            owner = ".".join([p for p in [self.module] + self.class_stack if p])
            cand = "%s.%s" % (owner, node.attr)
            return [cand] if cand in self.graph.functions else []
        target = self.imports.get(node.value.id)
        if not target:
            return []
        cand = "%s.%s" % (target, node.attr)
        if cand in self.graph.functions:
            return [cand]
        if cand in self.graph.classes:
            return self._methods(cand)
        return []

    def _methods(self, cls: str) -> List[str]:
        """Constructing or referencing a class makes every one of its methods callable.

        Instance calls (`obj.method()`) are precisely what static resolution cannot follow, so
        without this rule ordinary object-oriented code reads as dead. Over-approximating here
        is the correct trade: the alternative is telling someone a live bug is unreachable."""
        return self.graph.classes.get(cls, [])

    def _add(self, caller: str, callee: str, conf: str, lineno: int) -> None:
        key = (caller, callee)
        if key in self.seen or callee == caller:
            return
        self.seen.add(key)
        self.graph.edges.append(
            Edge(caller=caller, callee=callee, confidence=conf, lineno=lineno)
        )

    # -- the heuristic ----------------------------------------------------------

    def _resolve(self, func: ast.AST) -> List[Tuple[str, str]]:
        """Return [(callee_qualname, confidence)]. Empty means unresolved."""
        fns = self.graph.functions

        if isinstance(func, ast.Name):
            name = func.id

            # A function defined in this same module wins over anything imported.
            local = "%s.%s" % (self.module, name) if self.module else name
            if local in fns:
                return [(local, EXACT)]
            if local in self.graph.classes:
                return [(m, NAME) for m in self._methods(local)]

            target = self.imports.get(name)
            if target:
                if target in fns:
                    return [(target, EXACT)]
                if target in self.graph.classes:
                    return [(m, NAME) for m in self._methods(target)]
                if self._is_external(target):
                    self.graph.external += 1
                    return []

            return self._by_short_name(name)

        if isinstance(func, ast.Attribute):
            attr = func.attr
            value = func.value

            if isinstance(value, ast.Name):
                # self.foo() / cls.foo() inside a class body.
                if value.id in ("self", "cls") and self.class_stack:
                    owner = ".".join([p for p in [self.module] + self.class_stack if p])
                    cand = "%s.%s" % (owner, attr)
                    if cand in fns:
                        return [(cand, EXACT)]

                # module.foo() where `module` was imported.
                target = self.imports.get(value.id)
                if target:
                    cand = "%s.%s" % (target, attr)
                    if cand in fns:
                        return [(cand, EXACT)]
                    if cand in self.graph.classes:
                        return [(m, NAME) for m in self._methods(cand)]
                    if self._is_external(target):
                        self.graph.external += 1
                        return []

            # Anything else is a runtime value. Fall back to the name.
            return self._by_short_name(attr)

        self.graph.unresolved += 1
        return []

    def _by_short_name(self, name: str) -> List[Tuple[str, str]]:
        cands = self.short.get(name, [])
        if not cands or len(cands) > MAX_NAME_CANDIDATES:
            self.graph.unresolved += 1
            return []
        return [(c, NAME) for c in cands]


def _short_index(functions: Dict[str, FuncDef]) -> Dict[str, List[str]]:
    idx: Dict[str, List[str]] = {}
    for qual in functions:
        idx.setdefault(qual.rsplit(".", 1)[-1], []).append(qual)
    return idx


def build(repo: str, log=None) -> CallGraph:
    log = log or (lambda *_a, **_k: None)
    graph = CallGraph()

    # Pass 1
    for path in iter_python_files(repo):
        mod = module_name(path, repo)
        rel = rel_path(path, repo)
        try:
            # utf-8-sig, not utf-8: a leading BOM survives as ﻿ and makes ast.parse raise
            # SyntaxError, so every BOM-prefixed file was silently dropped from the graph.
            # Windows editors write them routinely, and a missing file means missing functions,
            # which means findings inside it wrongly report as unreachable.
            with open(path, encoding="utf-8-sig", errors="replace") as fh:
                tree = ast.parse(fh.read(), filename=rel)
        except (SyntaxError, ValueError, OSError) as exc:
            graph.parse_errors.append("%s: %s" % (rel, exc))
            continue

        graph.files_parsed += 1
        graph.modules[mod] = rel
        graph.trees[mod] = tree
        _Collector(graph, mod, rel).visit(tree)

    log("parsed %d files, %d functions" % (graph.files_parsed, len(graph.functions)))

    # Attach each class its own methods, so instantiating a class can pull them in.
    for cls in graph.classes:
        graph.classes[cls] = [
            q for q in graph.functions if q.rsplit(".", 1)[0] == cls
        ]

    # Pass 2
    short = _short_index(graph.functions)
    first_party = {m.split(".")[0] for m in graph.modules if m}
    for mod, tree in graph.trees.items():
        _Resolver(graph, mod, short, first_party).visit(tree)

    log(
        "resolved %d edges, %d external calls, %d call sites unresolved"
        % (len(graph.edges), graph.external, graph.unresolved)
    )
    return graph
