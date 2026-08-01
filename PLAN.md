# PLAN.md — phase status and roadmap

**Source of truth for project status. Update this when a phase moves.**

Last updated: 2026-08-01

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

- `semgrep --config=auto --json`
- `osv-scanner --format json -r .`
- `gitleaks detect --report-format json`

Each is optional: a missing binary logs a warning and is skipped. Raw output is cached to
`out/findings.raw.json` so re-runs during development can skip the slow Semgrep pass.

Implemented in `reachable/scanners.py`.

---

## Phase 1b — Built-in rule scanner — DONE

Added because none of the three external scanners could be installed on the development
machine: Semgrep has no native Windows support, and OSV-Scanner and Gitleaks are separate
binary installs. Requiring three external tools before anyone can see what this does is enough
friction to stop people trying it at all.

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

Run against two real repositories, chosen to sit at opposite ends of the quality range:

| Repo | Files | Functions | Entry points | Reachable functions | Findings | Reachable |
|---|---|---|---|---|---|---|
| pallets/flask | 83 | 1428 | 504 | 815 (57%) | 6 | 2 |
| adeyosemanputra/pygoat | 80 | 180 | 134 | 168 (93%) | 18 | 13 |

The contrast is the useful result, and it is the number to quote. A tool that merely
suppressed findings would cut both equally. This one filters two thirds of a well-audited
library's findings and confirms most of an intentionally vulnerable app's — it discriminates
rather than just deletes.

Spot-checked paths from the PyGoat run are correct, including multi-hop
(`mitre_lab_17_api -> command_out`) and both Django `urlpatterns` and Flask `@app.route`
entry detection.

## Next steps, in order

1. **Hand-verify a sample of verdicts.** The runs above were spot-checked, not audited. Pick
   ~20 findings across both repos and confirm each verdict by reading the code. The entire
   claim rests on the verdicts being right, and no amount of passing tests substitutes for it.
2. Decide how test code should be treated. Right now pytest functions come back UNREACHABLE
   because pytest collects them dynamically. Arguably correct for triage — a vulnerability
   only reachable from tests is not production-exploitable — but it is currently an accident
   of the implementation rather than a decision. Make it explicit, probably a `--tests`
   flag with a documented default.
3. Run the Phase 6 workflow on a real pull request.
4. Expand `tests/fixtures/sample_app/` with adversarial cases: decorator indirection, dynamic
   dispatch through `getattr`, deep call chains, dead-but-imported modules.
5. Try a much larger repo (10k+ functions) and record the runtime. Nothing in the design is
   superlinear, but this has not been measured.

## Deliberately not doing

- No database. Output is files.
- No web server or hosted dashboard. The HTML report is a static file.
- No account system, no telemetry, no network calls beyond what the scanners themselves do.
- No auto-submitted pull requests.
