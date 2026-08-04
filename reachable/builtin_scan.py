"""A small built-in Python security scanner, used when Semgrep is not available.

This is deliberately *not* trying to replace Semgrep. It covers a short list of high-signal,
low-false-positive patterns so the tool produces meaningful output on a machine with nothing
installed — which matters more than it sounds. Requiring three external binaries before anyone
can see what the tool does is the kind of friction that stops people trying it at all.

When Semgrep is installed it runs too, and both sets of findings flow through the same
reachability analysis.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional

from .callgraph import iter_python_files, rel_path
from .models import Finding

# Words that mean "this holds a credential", matched against whole identifier segments.
# Substring matching was a mistake: `auth` fired on `__author__` and on Sphinx's `author =
# "..."`, flagging every project's byline as a leaked secret.
SECRET_WORDS = {
    "password", "passwd", "pwd", "secret", "token", "apikey", "accesskey",
    "privatekey", "auth", "credential", "credentials", "passphrase", "apisecret",
    "clientsecret", "authtoken", "sessionkey",
}

_CAMEL = re.compile(r"([a-z0-9])([A-Z])")
_SPLIT = re.compile(r"[^a-z0-9]+")
# Obvious placeholders that are not real leaks. Docs, templates and test fixtures are full of
# these, and flagging them trains people to ignore the tool -- which costs more than the one
# real key it might catch.
PLACEHOLDER = re.compile(
    r"""^(
        | x+ | \.{3} | -+ | \*+
        | none | null | nil | true | false
        | changeme | change_me | placeholder | redacted | insert[\w-]*
        | example[\w-]* | dummy[\w-]* | fake[\w-]* | sample[\w-]*
        | test[\w-]* | todo[\w-]* | foo[\w-]* | bar[\w-]*
        | secret | password | token | api[-_]?key
        | (your|my|our|the|some)[\w-]*
        | <[^>]*>                 # <token>
        | \{\{.*\}\}              # {{ jinja }}
        | \{[^}]*\}               # {placeholder}
        | \$\{[^}]*\}             # ${ENV_VAR}
        | %\(.*\)s                # %(old_style)s
        | \$[A-Z_]+               # $ENV_VAR
    )$""",
    re.I | re.X,
)

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"


class _Rules(ast.NodeVisitor):
    def __init__(self, path: str):
        self.path = path
        self.out: List[Finding] = []
        # `alias -> module` from `import x` / `import x as y`, and `local name -> module.attr`
        # from `from x import y`. A rule that names a stdlib function has to know whether the
        # thing before the dot is that module or some unrelated object that happens to expose
        # a method with the same name.
        self.modules: Dict[str, str] = {}
        self.imported: Dict[str, str] = {}

    # -- imports ----------------------------------------------------------------

    def run(self, tree: ast.AST) -> None:
        """Collect imports across the whole file, then apply the rules.

        Two passes, because a function body executes later than the module text: a function
        defined above a module-level `import tempfile` still calls the imported module.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.visit_Import(node)
            elif isinstance(node, ast.ImportFrom):
                self.visit_ImportFrom(node)
        self.visit(tree)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self.modules[alias.asname] = alias.name
            else:
                # `import xml.etree.ElementTree` binds `xml`, and calls through it stay dotted.
                head = alias.name.split(".", 1)[0]
                self.modules[head] = head
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # Relative imports name a module in the repo under scan, not a stdlib one.
        if node.module and not node.level:
            for alias in node.names:
                self.imported[alias.asname or alias.name] = "%s.%s" % (node.module, alias.name)
        self.generic_visit(node)

    def _resolve(self, name: str) -> str:
        """Rewrite a call's dotted source through this file's imports.

        `tf.mktemp` becomes `tempfile.mktemp` under `import tempfile as tf`, and a bare
        `mktemp` becomes `tempfile.mktemp` under `from tempfile import mktemp`. A receiver
        that is not an imported module -- `tmp_path_factory.mktemp` -- is left alone, which
        is the whole point: it is not tempfile's.
        """
        head, dot, rest = name.partition(".")
        if not dot:
            return self.imported.get(head, head)
        if head in self.modules:
            return "%s.%s" % (self.modules[head], rest)
        return name

    def _add(self, node: ast.AST, rule: str, severity: str, message: str) -> None:
        self.out.append(
            Finding(
                id="",
                tool="builtin",
                severity=severity,
                message=message,
                file=self.path,
                line=getattr(node, "lineno", 0),
                end_line=getattr(node, "end_lineno", 0) or getattr(node, "lineno", 0),
                rule_id="builtin.%s" % rule,
            )
        )

    # -- calls ------------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        name = _src(node.func)
        full = self._resolve(name)
        short = name.rsplit(".", 1)[-1]
        kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}

        if short in ("run", "call", "check_call", "check_output", "Popen"):
            if _is_true(kwargs.get("shell")):
                self._add(node, "subprocess-shell-true", HIGH,
                          "subprocess called with shell=True; a tainted argument becomes "
                          "command injection")

        # `platform.system()` returns the OS name and is completely harmless. Matching the
        # bare short name flagged it in both requests and httpie, so the module must match:
        # either an explicit `os.` prefix, or an undotted call from `from os import system`.
        if full in ("os.system", "os.popen") or (short in ("system", "popen") and "." not in name):
            self._add(node, "os-system", HIGH,
                      "os.system passes its argument to a shell")

        if short in ("eval", "exec") and not _all_literal(node.args):
            self._add(node, "eval-exec", HIGH,
                      "%s() on a non-literal value executes arbitrary code" % short)

        if short in ("loads", "load") and full.startswith("pickle"):
            self._add(node, "pickle-load", HIGH,
                      "pickle deserialization executes arbitrary code on untrusted input")

        if short == "load" and "yaml" in full:
            loader = kwargs.get("Loader")
            if loader is None or "safe" not in _src(loader).lower():
                self._add(node, "yaml-unsafe-load", HIGH,
                          "yaml.load without SafeLoader can construct arbitrary objects")

        if short in ("md5", "sha1"):
            self._add(node, "weak-hash", MEDIUM,
                      "%s is not collision resistant; unsuitable for signatures or "
                      "password storage" % short)

        if _is_false(kwargs.get("verify")):
            self._add(node, "tls-verify-disabled", HIGH,
                      "TLS certificate verification disabled")

        if _is_true(kwargs.get("debug")) and short == "run":
            self._add(node, "debug-enabled", MEDIUM,
                      "debug mode exposes an interactive console if it reaches production")

        # `tmp_path_factory.mktemp()` is pytest's, creates the directory itself, and is safe.
        # The bare short name flagged it in edgecheck, so the receiver has to resolve to
        # tempfile before this fires.
        if full == "tempfile.mktemp":
            self._add(node, "insecure-temp", MEDIUM,
                      "tempfile.mktemp is race-prone; use mkstemp or NamedTemporaryFile")

        if name.startswith("xml.etree") or short in ("fromstring", "parse"):
            if "etree" in name or "ElementTree" in name:
                self._add(node, "xml-parse", LOW,
                          "stdlib XML parsing is vulnerable to entity expansion on "
                          "untrusted input; consider defusedxml")

        self.generic_visit(node)

    # -- assignments ------------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            name = _src(target)
            if not _looks_like_credential(name):
                continue
            value = node.value
            if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                continue
            if PLACEHOLDER.match(value.value.strip()) or len(value.value.strip()) < 8:
                continue
            self._add(node, "hardcoded-secret", HIGH,
                      "credential-looking literal assigned to '%s'" % name)
        self.generic_visit(node)


def _looks_like_credential(name: str) -> bool:
    """Match whole segments of an identifier, never substrings.

    `api_key` and `apiKey` both split to {api, key} and join to `apikey`; `__author__` splits
    to {author} and matches nothing.
    """
    parts = [p for p in _SPLIT.split(_CAMEL.sub(r"\1_\2", name).lower()) if p]
    if set(parts) & SECRET_WORDS:
        return True
    return any(parts[i] + parts[i + 1] in SECRET_WORDS for i in range(len(parts) - 1))


def _src(node: Optional[ast.AST]) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _is_true(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _all_literal(args: List[ast.AST]) -> bool:
    return all(isinstance(a, ast.Constant) for a in args)


def scan(repo: str, log=None) -> List[Finding]:
    log = log or (lambda *_a, **_k: None)
    findings: List[Finding] = []

    for path in iter_python_files(repo):
        rel = rel_path(path, repo)
        try:
            with open(path, encoding="utf-8-sig", errors="replace") as fh:
                tree = ast.parse(fh.read(), filename=rel)
        except (SyntaxError, ValueError, OSError):
            continue
        rules = _Rules(rel)
        rules.run(tree)
        findings.extend(rules.out)

    for i, f in enumerate(findings):
        f.id = "builtin-%d" % i

    log("  builtin -> %d findings" % len(findings))
    return findings
