# Contributing

## Getting set up

```bash
git clone https://github.com/<your-fork>/reachable
cd reachable
python -m pip install -e ".[dev]"
python -m pytest tests -q
```

The core has no third-party runtime dependencies and is meant to stay that way. `pytest` is the
only development dependency.

## Running it while developing

```bash
# skip the slow external scanners, analyze the call graph only
python -m reachable scan . --out ./out --no-scan

# reuse a previous scanner run instead of re-running Semgrep
python -m reachable scan . --out ./out --findings ./out/findings.raw.json
```

## The rule that matters most

This tool over-approximates on purpose. When resolution is ambiguous, the answer is
`REACHABLE` or `UNKNOWN` — never `UNREACHABLE`.

A false `REACHABLE` costs someone a few minutes reviewing a finding that turns out to be fine.
A false `UNREACHABLE` tells them to ignore a live bug. Five of the nine defects recorded in
[VERIFICATION.md](VERIFICATION.md) were false `UNREACHABLE`, and several came from tightening
name resolution in the name of precision. If a change makes resolution stricter, it needs a
regression test in both directions and a run across real repositories, not just a green suite.

## Standards for a change

- Python 3.9+ (the code uses `ast.end_lineno` and `ast.unparse`).
- Stdlib only in the core. A new runtime dependency needs a written justification.
- Dataclasses, not dicts, for anything crossing a module boundary.
- Qualified names are dotted and rooted at the repo: `pkg.module.Class.method`.
- No `print` in library code — `cli.py` owns all user-facing output.
- Every bug fix gets a regression test. Every new scanner rule gets a plain-English
  explanation in `explain.py`; the suite fails if one is missing.
- Do not commit scan output. `out/` is gitignored.

Tests run on Python 3.9/3.11/3.13 across Linux and Windows. Windows is not incidental — two of
the recorded defects were Windows-only.

## Scope of use

Scan public repositories, or repositories you own. Do not point this at a third party's private
code, and do not use it against a bug bounty target outside that program's published scope.

## Reporting a vulnerability in this tool

The tool parses untrusted source and untrusted scanner JSON, and the Action posts its output as
a pull request comment — which makes report content a security boundary. If you find a way to
forge a report or to execute code through a crafted input, please open a private security
advisory rather than a public issue.
