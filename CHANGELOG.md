# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-08-05

First public release.

### Added

- Call-graph reachability triage for Python repositories: findings are classified `REACHABLE`,
  `UNREACHABLE` or `UNKNOWN`, and every reachable finding carries the call path that proves it.
- Scanner integration for Semgrep, OSV-Scanner and Gitleaks. Each is optional and independently
  skippable.
- A built-in AST rule set covering eleven high-signal patterns, so the tool produces useful
  output with no external scanner installed and no third-party dependencies.
- Entry point detection for `__main__` guards, Flask/FastAPI/Django routes, `console_scripts`,
  Lambda handlers, Celery tasks, `__init__.py` public API, and framework wiring by dotted string
  (`SUPPORTED_WORKERS`, Django `MIDDLEWARE`, Scrapy `ITEM_PIPELINES`, setuptools entry points).
- Three output formats: `findings.json`, `report.md`, and a self-contained `report.html`.
- Plain-language explanations for every rule and verdict, including steps to verify a finding by
  hand. Disable with `--brief`.
- GitHub Action that triages each pull request and posts the report as a comment, updating it in
  place on subsequent pushes.
- Verified against a 22-repository corpus with Semgrep live: 1,415 findings, 455 reachable.

### Fixed

Ten correctness defects and six security issues found by hand-auditing verdicts against real
source, and by running the scanners in CI — not by the test suite, which stayed green
throughout. Five of the ten were false `UNREACHABLE`, the one error class this tool must not
make; two more were scanners that never ran at all, reporting as clean scans. All are written
up in [VERIFICATION.md](VERIFICATION.md).

[0.1.0]: https://github.com/harshvardhan60792/reachable/releases/tag/v0.1.0
