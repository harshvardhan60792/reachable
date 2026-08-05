# Roadmap

Where the project stands and what is planned. Verified behaviour and the defects found along
the way are recorded in [VERIFICATION.md](VERIFICATION.md).

## Shipped

- **Scanner runner** — Semgrep, OSV-Scanner and Gitleaks normalized into one `Finding` shape.
  Each is optional; a missing binary is skipped with a warning, and a scanner that *fails* is
  reported as a failure rather than as zero findings.
- **Built-in rule set** — a small AST scanner covering high-signal patterns (`shell=True`,
  `os.system`, `eval`/`exec` on non-literals, pickle, unsafe `yaml.load`, MD5/SHA1,
  `verify=False`, `debug=True`, `mktemp`, stdlib XML parsing, hardcoded credentials) so the
  tool produces useful output with nothing installed.
- **Call graph** — stdlib `ast` walk over every `.py` file, two passes, heuristic name
  resolution with per-edge confidence.
- **Entry point detection** — `__main__` guards, Flask/FastAPI/Django routes, `console_scripts`,
  Lambda handlers, Celery tasks, the public surface of `__init__.py`, and framework wiring by
  dotted string.
- **Reachability engine** — BFS from entry points, each finding mapped to its enclosing
  function, verdicts carrying the call path that proves them.
- **Reports** — `findings.json`, `report.md`, and a self-contained `report.html`, with
  plain-language explanations of every rule and verdict.
- **GitHub Action** — triage on each pull request, posted as a comment that updates in place.
- **Live scanner coverage in CI** — a job that builds a repository engineered to trip Semgrep,
  OSV-Scanner and Gitleaks, then asserts per tool that each produced findings. Asserting per
  tool rather than in total is what caught defects 8 and 10, both of which were scanners that
  never ran reporting as clean scans.

## Planned

1. **Hand-check a dependency verdict.** `_dep_verdict` now runs on every push and returns
   findings, but no OSV verdict has been confirmed by opening the source — the same audit that
   found ten defects in the reachability engine has never been applied to the dependency path.
2. **Decide how test code is treated.** Pytest functions currently come back `UNREACHABLE`
   because pytest collects them dynamically. That is arguably the right answer for triage — a
   vulnerability reachable only from tests is not production-exploitable — but today it is an
   accident of the implementation rather than a decision. Make it explicit, likely a `--tests`
   flag with a documented default.
3. **Run the Action on a real pull request.** The workflow is written and has never executed.
4. **Adversarial fixtures.** Extend `tests/fixtures/sample_app/` with decorator indirection,
   `getattr` dispatch, deep call chains, and dead-but-imported modules.
5. **Automated fix suggestion (optional).** Only ever against `REACHABLE` findings. Shells out
   to a coding-agent CLI already installed locally — no metered API. Output is a diff for human
   review: never auto-commit, never auto-push, never auto-open a pull request. A fix the
   submitter cannot explain is worse than no fix.
6. **Compliance evidence (optional, low priority).** Mapping rule IDs to SOC 2 / ISO 27001
   controls. Deprioritized: it is a different product for a different audience and it dilutes
   the reachability story.

## Deliberately not doing

- No database. Output is files.
- No web server or hosted dashboard. The HTML report is a static file.
- No account system, no telemetry, no network calls beyond what the scanners themselves make.
- No auto-submitted pull requests.
