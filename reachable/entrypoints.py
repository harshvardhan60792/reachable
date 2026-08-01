"""Phase 3 — mark which functions can be invoked from outside the program.

Reachability is only meaningful relative to a starting set. Miss an entry point and live code
looks dead, which is the one failure mode that actually hides bugs. So this errs toward marking
too much rather than too little.

Mutates `FuncDef.is_entry` / `.entry_reason` in place.
"""

from __future__ import annotations

import ast
import os
import re
from typing import Dict, List, Optional

from .models import CallGraph, FuncDef

# Decorator source fragments that mean "a framework calls this for you".
ROUTE_PATTERNS = (
    r"\.route\b",
    r"\.(get|post|put|delete|patch|head|options)\s*\(",
    r"\bapp\.",
    r"\brouter\.",
    r"\bblueprint\.",
    r"\bbp\.",
    r"@?task\b",
    r"\bshared_task\b",
    r"\bcelery\.",
    r"\bclick\.command\b",
    r"\bclick\.group\b",
    r"\btyper\b",
    r"\bcommand\s*\(",
    r"\breceiver\b",
    r"\bevent\.",
    r"\bon_event\b",
    r"\bwebsocket\b",
)
ROUTE_RE = re.compile("|".join(ROUTE_PATTERNS))

# Names a serverless platform or WSGI server invokes directly.
MAGIC_NAMES = {
    "handler", "lambda_handler", "main", "handle", "application", "app",
}

SCRIPT_RE = re.compile(r"['\"]?\s*=\s*['\"]?([\w\.]+)\s*:\s*([\w\.]+)")


def _mark(fn: Optional[FuncDef], reason: str) -> None:
    if fn is not None and not fn.is_entry:
        fn.is_entry = True
        fn.entry_reason = reason


def _lookup(graph: CallGraph, module: str, name: str) -> Optional[FuncDef]:
    qual = "%s.%s" % (module, name) if module else name
    return graph.functions.get(qual)


# ------------------------------------------------------------------ decorator based

def _from_decorators(graph: CallGraph) -> None:
    for qual, decs in graph.decorators.items():
        fn = graph.functions.get(qual)
        if fn is None:
            continue
        for dec in decs:
            if ROUTE_RE.search(dec):
                _mark(fn, "decorator: @%s" % dec.split("(")[0].lstrip("@"))
                break


# ------------------------------------------------------------------ __main__ blocks

def _is_main_guard(node: ast.AST) -> bool:
    if not isinstance(node, ast.If):
        return False
    test = node.test
    if not isinstance(test, ast.Compare):
        return False
    left = test.left
    return isinstance(left, ast.Name) and left.id == "__name__"


def _from_main_blocks(graph: CallGraph) -> None:
    for module, tree in graph.trees.items():
        for node in getattr(tree, "body", []):
            if not _is_main_guard(node):
                continue
            imports = graph.imports.get(module, {})
            for call in ast.walk(node):
                if not isinstance(call, ast.Call):
                    continue
                target = _call_target(call.func, graph, module, imports)
                _mark(target, "called from __main__ in %s" % module)


def _call_target(func: ast.AST, graph: CallGraph, module: str, imports: Dict[str, str]):
    if isinstance(func, ast.Name):
        fn = _lookup(graph, module, func.id)
        if fn:
            return fn
        target = imports.get(func.id)
        return graph.functions.get(target) if target else None
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        target = imports.get(func.value.id)
        if target:
            return graph.functions.get("%s.%s" % (target, func.attr))
    return None


# ------------------------------------------------------------------ django urlpatterns

def _from_urlpatterns(graph: CallGraph) -> None:
    for module, tree in graph.trees.items():
        imports = graph.imports.get(module, {})
        for node in getattr(tree, "body", []):
            names = []
            if isinstance(node, ast.Assign):
                names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names = [node.target.id]
            if "urlpatterns" not in names:
                continue
            for ref in ast.walk(node):
                if isinstance(ref, ast.Name):
                    fn = _lookup(graph, module, ref.id)
                    if fn is None:
                        target = imports.get(ref.id)
                        fn = graph.functions.get(target) if target else None
                    _mark(fn, "django urlpatterns in %s" % module)
                elif isinstance(ref, ast.Attribute) and isinstance(ref.value, ast.Name):
                    target = imports.get(ref.value.id)
                    if target:
                        _mark(
                            graph.functions.get("%s.%s" % (target, ref.attr)),
                            "django urlpatterns in %s" % module,
                        )


# ------------------------------------------------------------------ packaging metadata

def _from_packaging(repo: str, graph: CallGraph) -> None:
    """Pull `module:function` console_script targets out of pyproject.toml / setup.py.

    Deliberately regex based rather than a TOML parse: `tomllib` only exists on 3.11+, and the
    entry point syntax is distinctive enough that a regex is both adequate and dependency free.
    """
    for name in ("pyproject.toml", "setup.py", "setup.cfg"):
        path = os.path.join(repo, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for mod, func in SCRIPT_RE.findall(text):
            fn = graph.functions.get("%s.%s" % (mod, func))
            _mark(fn, "console_script in %s" % name)


# ------------------------------------------------------------------ library surface

def _from_public_api(graph: CallGraph) -> None:
    """Functions exported from an `__init__.py` are callable by any consumer of the library."""
    for module, rel in graph.modules.items():
        if not rel.endswith("__init__.py"):
            continue
        tree = graph.trees.get(module)
        if tree is None:
            continue

        exported = _dunder_all(tree)
        imports = graph.imports.get(module, {})

        for node in getattr(tree, "body", []):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("_"):
                    continue
                if exported is not None and node.name not in exported:
                    continue
                _mark(graph.functions.get("%s.%s" % (module, node.name)), "public API of %s" % module)

        for local, target in imports.items():
            if local.startswith("_"):
                continue
            if exported is not None and local not in exported:
                continue
            _mark(graph.functions.get(target), "re-exported from %s" % module)


def _dunder_all(tree: ast.AST) -> Optional[List[str]]:
    for node in getattr(tree, "body", []):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, SyntaxError):
            return None
        if isinstance(value, (list, tuple)):
            return [str(v) for v in value]
    return None


# ------------------------------------------------------------------ magic names

def _from_module_level_refs(graph: CallGraph) -> None:
    """Functions named in a module-level table are invoked through that table.

    `SCANNERS = (("semgrep", run_semgrep), ...)` and every plugin registry, URL map, handler
    dict and callback list share this shape: the reference lives at module scope, so no
    enclosing function owns it and the call-site rule never fires. Without this, whole
    subsystems come back dead.
    """
    for module, tree in graph.trees.items():
        imports = graph.imports.get(module, {})
        for node in getattr(tree, "body", []):
            # Definitions and imports are declarations, not registrations.
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                 ast.Import, ast.ImportFrom)):
                continue
            for ref in ast.walk(node):
                fn = None
                if isinstance(ref, ast.Name) and isinstance(ref.ctx, ast.Load):
                    fn = _lookup(graph, module, ref.id)
                    if fn is None and ref.id in imports:
                        fn = graph.functions.get(imports[ref.id])
                elif isinstance(ref, ast.Attribute) and isinstance(ref.value, ast.Name):
                    target = imports.get(ref.value.id)
                    if target:
                        fn = graph.functions.get("%s.%s" % (target, ref.attr))
                _mark(fn, "referenced in a module-level table in %s" % module)


def _from_magic_names(graph: CallGraph) -> None:
    for qual, fn in graph.functions.items():
        short = qual.rsplit(".", 1)[-1]
        if short in MAGIC_NAMES and not fn.is_method:
            _mark(fn, "conventional entry point name '%s'" % short)


def detect(repo: str, graph: CallGraph, log=None) -> None:
    log = log or (lambda *_a, **_k: None)
    _from_decorators(graph)
    _from_main_blocks(graph)
    _from_urlpatterns(graph)
    _from_packaging(repo, graph)
    _from_public_api(graph)
    _from_module_level_refs(graph)
    _from_magic_names(graph)
    log("found %d entry points" % len(graph.entry_points()))
