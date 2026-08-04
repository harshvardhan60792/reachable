# PLAN.md — phase status and roadmap

**Source of truth for project status. Update this when a phase moves.**

Last updated: 2026-08-04

---

## Status at a glance

| Phase | Name | Status |
|---|---|---|
| 1 | Scanner runner | DONE |
| 1b | Built-in rule scanner | DONE (added after Phase 1) |
| 2 | Call graph | DONE |
| 3 | Entry point detection | DONE |
| 4 | Reachability engine | DONE |
| 5 | Report output | DONE |
| 6 | GitHub Action | DONE |
| 7 | Fix suggestion | NOT STARTED (optional) |
| 8 | Compliance evidence | NOT STARTED (optional, low priority) |

Phases 1-5 are the MVP. Shipping them alone is a complete, defensible tool.

26 tests pass. Validated end to end against two real repositories — see **Validation** below.

---

## Phase 1 — Scanner runner — DONE

Subprocess-wrap three free scanners and normalize their wildly different JSON shapes into one
`Finding` dataclass.

- `semgrep --config=p/python --config=p/security-audit --config=p/secrets --metrics=off --json`
  (not `--config=auto`, which Semgrep refuses when metrics are off — see VERIFICATION.md,
  defect 8)
- `osv-scanner --format json -r .`
- `gitleaks detect --report-format json`

Each is optional: a missing binary logs a warning and is skipped. Raw output is cached to
`out/findings.raw.json` so re-runs during development can skip the slow Semgrep pass.

Implemented in `reachable/scanners.py`.

---

## Phase 1b — Built-in rule scanner — DONE

Added because none of the three external scanners was installed on the development machine.
OSV-Scanner and Gitleaks are separate binary installs. Semgrep was assumed unavailable on
Windows; that turned out to be wrong -- `pip install semgrep` gives a working 1.172.0 -- but
the reason for this phase stands: requiring three external tools before anyone can see what
this does is enough friction to stop people trying it at all.

A small AST scanner covering high-signal, low-false-positive patterns: `shell=True`,
`os.system`, `eval`/`exec` on non-literals, pickle loads, unsafe `yaml.load`, MD5/SHA1,
`verify=False`, `debug=True`, `mktemp`, stdlib XML parsing, and hardcoded-credential literals.

It runs alongside the external scanners rather than instead of them; everything flows through
the same reachability analysis. Disable with `--no-builtin`.

The credential rule carries a deliberately broad placeholder filter (`changeme`, `your-api-key`,
`{{ jinja }}`, `${ENV_VAR}`, ...). A rule that cries wolf on every template gets switched off,
which costs more than the one real key it might have caught.

Implemented in `reachable/builtin_scan.py`.

---

## Phase 2 — Call graph — DONE

The core. Walks every `.py` file with stdlib `ast` and builds:

- `FuncDef` per function/method, with qualified name and line range
- `Edge` per call site, with a confidence label

Resolution order for a call:
1. `self.foo()` -> current class method
2. bare `foo()` -> local module function
3. bare `foo()` where `foo` was imported -> import target
4. `mod.foo()` where `mod` was imported -> `<import target>.foo`
5. anything else -> fall back to short-name index across the repo, `confidence="name"`
6. call into stdlib or a third-party package -> counted in `CallGraph.external`, no edge
7. genuinely unresolvable -> counted in `CallGraph.unresolved`, no edge

Rules 6 and 7 are reported separately on purpose. Lumping them together made the tool look
blind — a self-scan showed "392 unresolved" when ~355 of those were ordinary `os.path.join`
and `json.dump` calls that a first-party call graph *should* not contain.

### Three rules added after the first real run

The first self-scan reached only 6 of 97 functions. Each cause was a class of false
UNREACHABLE, which is the one error this tool must not make — it tells someone to ignore a
live bug.

- **Function references are edges.** `parser.set_defaults(func=run)`, `Thread(target=work)`,
  handler dicts, callback lists. The reference is passed at one site and called from another
  the analysis cannot follow. Any reference to a known first-party function now creates a
  NAME-confidence edge.
- **Instantiating a class reaches all its methods.** `obj.method()` on a runtime value is
  exactly the unresolvable case, so ordinary object-oriented code read as dead. Constructing
  or referencing a class now pulls in every method it defines.
- **Module-level tables are entry points.** `SCANNERS = (("semgrep", run_semgrep), ...)` and
  every plugin registry or URL map puts the reference at module scope, where no enclosing
  function owns it. Handled in `entrypoints.py`.

After all three: 88 of 105 functions reachable on a self-scan, and every remaining unreached
function is a test (pytest collects those dynamically) or deliberately dead fixture code.

Implemented in `reachable/callgraph.py`.

---

## Phase 3 — Entry point detection — DONE

Marks which functions can actually be invoked from outside. Detects:

- `if __name__ == "__main__":` blocks
- Web route decorators — Flask `@app.route`, FastAPI `@app.get/post/put/delete/patch`,
  and generic `@*.route`
- Django `urlpatterns` references
- `console_scripts` / `[project.scripts]` in `pyproject.toml` and `setup.py`
- AWS Lambda `handler` / `lambda_handler`
- Celery `@task` / `@shared_task`
- Public functions re-exported from `__init__.py` (library surface)

Implemented in `reachable/entrypoints.py`.

---

## Phase 4 — Reachability engine — DONE

1. Map each `Finding` (`file:line`) to its innermost enclosing `FuncDef`.
2. BFS from every entry point across the call graph to get the reachable set.
3. Emit a `Verdict` per finding.

Verdict values:

- `REACHABLE` — enclosing function is in the reachable set; the shortest call path is recorded
- `UNREACHABLE` — enclosing function exists but nothing reaches it
- `UNKNOWN` — no enclosing function (module-level code), or a dependency finding with no
  resolvable symbol, or the path depends on a low-confidence edge

Module-level findings deliberately resolve to `UNKNOWN` rather than `REACHABLE`: module bodies
execute on import, but whether the module is ever imported is a separate question. Erring
toward `UNKNOWN` is the honest call.

Implemented in `reachable/reachability.py`.

---

## Phase 5 — Report output — DONE

Three artifacts written to the output directory:

- `findings.json` — machine-readable, full verdict list
- `report.md` — grouped by verdict, reachable first, call paths rendered as arrows
- `report.html` — single self-contained static file, no server, no external assets

Implemented in `reachable/report.py`.

---

## Phase 6 — GitHub Action — DONE

`.github/workflows/reachable.yml` runs on pull request, uploads the full report as an
artifact, and posts `report.md` as a comment. The comment is keyed by an HTML marker so
subsequent pushes update it in place instead of stacking new comments.

Scanner installation is `continue-on-error`, so a broken upstream installer degrades the
report rather than failing the job — the built-in rules always run.

Free tier covers this: public repos get unlimited Actions minutes.

**Not yet executed on real CI** — the workflow is written but has never run, since the project
is not yet in a GitHub repository. Verify it on a real pull request before relying on it.

---

## Phase 7 — Fix suggestion — NOT STARTED (optional)

Only ever run against `REACHABLE` findings — that is the point of the triage.

Constraints:
- Runs through the Claude Code CLI the user already pays for. **No metered API key.**
- Output is a diff for human review. Never auto-commit, never auto-push, never auto-open a PR.

The human-review rule is not optional. A fix the submitter cannot explain is worse than no fix:
it wastes a maintainer's time and, in an interview, it collapses.

---

## Phase 8 — Compliance evidence — NOT STARTED (optional, low priority)

Static JSON table mapping scanner rule IDs to SOC2 / ISO 27001 control IDs, rendered to a
Markdown evidence report and optionally to PDF via `weasyprint` (MIT licensed, free).

Deprioritized: it is a different product for a different buyer, and it dilutes the reachability
pitch. Build it only if a specific judge or org asks for the enterprise angle.

---

## Validation

Five real repositories, every verdict hand-audited against source. Full write-up in
**VERIFICATION.md** — read that before trusting these numbers or changing the resolution rules.

| Repo | Findings | REACHABLE | UNREACHABLE | UNKNOWN | Functions | Entry points | Runtime |
|---|---|---|---|---|---|---|---|
| pallets/flask | 6 | 3 | 3 | 0 | 1428 | 560 | 3.4s |
| adeyosemanputra/pygoat | 15 | 12 | 0 | 3 | 180 | 134 | 1.1s |
| psf/requests | 17 | 0 | 13 | 4 | 691 | 59 | 1.8s |
| httpie/cli | 4 | 2 | 0 | 2 | 1062 | 100 | 5.5s |
| pallets/click | 0 | 0 | 0 | 0 | 1698 | 680 | 3.6s |

The spread is the useful result. Something that merely suppressed findings would cut every
repo equally. This filters `requests` down to zero reachable, confirms 12 of 15 on a
deliberately vulnerable app, and finds a genuine `verify=False` on a live network call in
httpie with a verified 5-hop path.

**The audit found six defects, four of them false UNREACHABLE.** Two more turned up later,
from pointing the tool at a sixth repository and from installing Semgrep for the first time.
See VERIFICATION.md. Summary:

1. Class-body registrations (`digest_method = staticmethod(_lazy_sha1)`) were invisible —
   reported Flask's session-signing hash as dead code.
2. `__main__` guard bodies fell through to UNKNOWN instead of REACHABLE.
3. Re-exported *classes* in `__init__.py` marked nothing, understating library API surface.
4. A library's public API was judged only against internal callers. `requests.auth`
   genuinely has no in-repo caller — consumers are the caller. Now UNKNOWN, not UNREACHABLE.
5. `auth` matched as a substring of `author`, flagging every project's byline as a secret.
6. Bare `system` matched `platform.system()`, flagging 5 harmless OS checks as shell execution.
7. Bare `mktemp` matched pytest's `tmp_path_factory.mktemp()`, which creates the directory it
   names and is safe. Found on `edgecheck`, reproduced on `cve-bin-tool`. The builtin scanner
   now resolves a call's receiver through the file's own imports before matching a stdlib name,
   which also picked up `import os as o; o.system(c)` and `import pickle as p; p.loads(b)`.
8. **Semgrep never ran, and that was reported as `semgrep -> 0 findings`.** `--config=auto`
   and `--metrics=off` are mutually exclusive; Semgrep exited 2 and printed nothing, and an
   empty stdout became an empty finding list. Rulesets are now named explicitly, and a scanner
   that dies raises `ScannerFailed` instead of returning nothing. The worst defect found so
   far: a dead scanner looked exactly like a clean scan.

Every one has a regression test.

## Security review

Also in VERIFICATION.md, Part 2. The tool parses untrusted source and untrusted scanner JSON,
and the Action posts its report as a PR comment — which makes report content a security
boundary. Six issues found and fixed:

1. **Report forgery via newline injection** (the serious one). Finding text is
   attacker-influenced and was written into `report.md` unmodified, so a crafted string could
   inject markdown headings and fabricate or bury findings in the report reviewing that same
   PR. All untrusted fields now pass through `_clean()`.
2. BOM-prefixed files raised `SyntaxError` and vanished from the graph — silent false
   negatives, and common on Windows. Now read as `utf-8-sig`.
3. Workflow installed OSV-Scanner via `curl | sh` from a branch URL. Now pinned releases.
4. Semgrep uploaded usage metrics by default. Now `--metrics=off` — which turned out to be
   incompatible with the `--config=auto` already in place and silently disabled Semgrep
   entirely. See defect 8.
5. Fork PRs get a read-only token, so the comment step would fail. Marked
   `continue-on-error` rather than switching to the more dangerous `pull_request_target`.
6. `load_raw` crashed on unexpected keys in a cached findings file.

Reviewed and sound: HTML escaping, no shell invocation, path traversal inert, symlinks not
followed, cycles terminate, no third-party dependencies. Self-scan is clean — the only
findings are the deliberately vulnerable test fixtures.

76 tests pass.

## Next steps, in order

1. **Exercise OSV-Scanner and Gitleaks.** Semgrep is now done: it runs on Windows via pip
   (`pip install semgrep`, 1.172.0), and the first live run immediately exposed defect 8 and
   then produced a correct REACHABLE verdict on `edgecheck` with a three-hop path. OSV and
   Gitleaks are Go binaries and still have never been run against live output, so
   `parse_osv`, `parse_gitleaks` and `_dep_verdict` remain unexercised — `_dep_verdict` is
   the least-tested path in the codebase and no OSV verdict has ever been checked. Run the
   pipeline on Linux, or in the Phase 6 Action.
2. **Carry scanner failures into the report, not just the log.** Defect 8 is fixed at the
   CLI — `report.md` and `report.html` still render a failed run identically to a clean one.
   The honest version needs `report.write` to know which scanners ran, which changes its
   signature.
3. Decide how test code should be treated. Right now pytest functions come back UNREACHABLE
   because pytest collects them dynamically. Arguably correct for triage — a vulnerability
   only reachable from tests is not production-exploitable — but it is currently an accident
   of the implementation rather than a decision. Make it explicit, probably a `--tests`
   flag with a documented default.
4. Run the Phase 6 workflow on a real pull request.
5. Expand `tests/fixtures/sample_app/` with adversarial cases: decorator indirection, dynamic
   dispatch through `getattr`, deep call chains, dead-but-imported modules.
6. Try a much larger repo (10k+ functions), ideally Django or async-heavy where dynamic
   dispatch is densest. Current largest sample is 1698 functions at 3.6s.

## Deliberately not doing

- No database. Output is files.
- No web server or hosted dashboard. The HTML report is a static file.
- No account system, no telemetry, no network calls beyond what the scanners themselves do.
- No auto-submitted pull requests.
