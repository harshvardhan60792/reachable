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

# Top-level directories that carry an __init__.py but are never shipped to consumers.
# `requests/tests/` is an importable package, yet nothing outside the repo imports it, so
# counting it as public API turned every dead test fixture into UNKNOWN.
NON_DISTRIBUTED = {
    "tests", "test", "testing", "docs", "doc", "examples", "example",
    "benchmarks", "bench", "scripts", "tools", "ci", "build", "dist",
}


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

            # Record the span so findings sitting directly inside the guard can be resolved
            # as reachable rather than falling through to the module-level UNKNOWN rule.
            rel = graph.modules.get(module, "")
            if rel:
                end = getattr(node, "end_lineno", node.lineno) or node.lineno
                graph.main_blocks.setdefault(rel, []).append((node.lineno, end))

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
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name.startswith("_"):
                    continue
                if exported is not None and node.name not in exported:
                    continue
                _mark_api(graph, "%s.%s" % (module, node.name), "public API of %s" % module)

        for local, target in imports.items():
            if local.startswith("_"):
                continue
            if exported is not None and local not in exported:
                continue
            _mark_api(graph, target, "re-exported from %s" % module)


def _mark_api(graph: CallGraph, qual: str, reason: str) -> None:
    """A public name may be a function or a class. Classes were being dropped.

    `requests/__init__.py` re-exports `Session`, `Response` and `PreparedRequest` -- classes,
    not functions -- so looking only in `graph.functions` marked nothing and left most of the
    library's real surface looking dead.
    """
    fn = graph.functions.get(qual)
    if fn is not None:
        _mark(fn, reason)
        return
    for method in graph.classes.get(qual, []):
        if method.rsplit(".", 1)[-1].startswith("_") and not method.endswith(".__init__"):
            continue
        _mark(graph.functions.get(method), reason)


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
    """Functions named in a module- or class-level table are invoked through that table.

    `SCANNERS = (("semgrep", run_semgrep), ...)` and every plugin registry, URL map, handler
    dict and callback list share this shape: the reference lives at module scope, so no
    enclosing function owns it and the call-site rule never fires.

    Class bodies count too, and missing them caused a real false UNREACHABLE. Flask signs
    every session cookie with `_lazy_sha1`, wired up as `digest_method = staticmethod(
    _lazy_sha1)` in a class body. Skipping ClassDef reported that live crypto path as dead.
    The same shape covers Django's `form_class`, DRF's `serializer_class`, and most
    configure-by-class-attribute frameworks.
    """
    for module, tree in graph.trees.items():
        imports = graph.imports.get(module, {})
        for node in _registration_stmts(getattr(tree, "body", [])):
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
                _mark(fn, "referenced in a module- or class-level table in %s" % module)


def _registration_stmts(body):
    """Statements that can register a callable, at module scope or inside a class body.

    Descends through ClassDef but never into a function: a reference inside a function body
    already has an enclosing caller, and the call-graph rules own it.
    """
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(node, ast.ClassDef):
            for inner in _registration_stmts(node.body):
                yield inner
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        yield node


# ------------------------------------------------------------------ configured by string

#: A dotted path, or setuptools' `module:attr` form. At least one separator is required, so a
#: bare word can never match a same-named function. Anchored, so it matches a string that is
#: *only* a path -- prose that happens to mention one does not count.
DOTTED_RE = re.compile(r"^[A-Za-z_]\w*(?:[.:][A-Za-z_]\w*)+$")

MAX_DOTTED = 200


def _from_dotted_strings(graph: CallGraph) -> None:
    """A class or function named as a string literal is wired up by name at runtime.

    Found by scanning gunicorn, where the entire ASGI subsystem came back UNREACHABLE --
    including the live WebSocket handshake -- because the worker is selected by string:

        SUPPORTED_WORKERS = {"asgi": "gunicorn.workers.gasgi.ASGIWorker", ...}

    resolved through `util.load_class` at runtime. The call graph had every edge from
    `ASGIWorker._serve` onward; nothing reached `ASGIWorker` itself, so a whole live
    subsystem read as dead code. That is a false UNREACHABLE, the one verdict this tool
    must never produce.

    The shape is everywhere once you look: Django `MIDDLEWARE` and `AUTHENTICATION_BACKENDS`,
    DRF's `DEFAULT_*_CLASSES`, Scrapy `ITEM_PIPELINES` and `DOWNLOADER_MIDDLEWARES`, Celery
    `task_cls`, logging `dictConfig` handlers, and every `setuptools` entry point.

    Only an *exact* match against a first-party function or class counts. Resolving partial
    or fuzzy names would mark half the repo, and the lesson from the public-API rule is that
    an entry point rule which over-fires destroys the filtering the tool exists for.
    """
    for module, tree in graph.trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            text = node.value.strip()
            if not text or len(text) > MAX_DOTTED or not DOTTED_RE.match(text):
                continue
            qual = text.replace(":", ".")
            if qual in graph.functions or qual in graph.classes:
                _mark_api(graph, qual, "named as a string literal in %s" % module)


def _from_magic_names(graph: CallGraph) -> None:
    for qual, fn in graph.functions.items():
        short = qual.rsplit(".", 1)[-1]
        if short in MAGIC_NAMES and not fn.is_method:
            _mark(fn, "conventional entry point name '%s'" % short)


def _find_package_roots(repo: str, graph: CallGraph) -> None:
    """Locate packages this repo actually ships, if any.

    Only a *distributed* package has an outside caller. Any directory with an `__init__.py`
    would be far too broad -- an application's internal packages are not an API, and treating
    them as one turns real dead code into UNKNOWN and destroys the filtering this tool exists
    for. So packaging metadata is required, and only top-level packages (at the repo root or
    under `src/`) count.
    """
    if not any(os.path.isfile(os.path.join(repo, n))
               for n in ("pyproject.toml", "setup.py", "setup.cfg")):
        return

    roots = []
    for rel in graph.modules.values():
        if rel.rsplit("/", 1)[-1] != "__init__.py":
            continue
        directory = rel.rsplit("/", 1)[0] if "/" in rel else ""
        if not directory:
            continue
        parent, _, name = directory.rpartition("/")
        if parent in ("", "src") and name.lower() not in NON_DISTRIBUTED:
            roots.append(directory)
    graph.package_roots = sorted(set(roots))


def detect(repo: str, graph: CallGraph, log=None) -> None:
    log = log or (lambda *_a, **_k: None)
    _find_package_roots(repo, graph)
    _from_decorators(graph)
    _from_main_blocks(graph)
    _from_urlpatterns(graph)
    _from_packaging(repo, graph)
    _from_public_api(graph)
    _from_module_level_refs(graph)
    _from_dotted_strings(graph)
    _from_magic_names(graph)
    log("found %d entry points" % len(graph.entry_points()))
