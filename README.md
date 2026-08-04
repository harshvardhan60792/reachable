# reachable

Security scanners tell you *what* is wrong. `reachable` tells you what is **actually reachable**.

Point it at a Python repo. It runs Semgrep, OSV-Scanner, and Gitleaks, builds a call graph of
the codebase, then traces from real entry points — HTTP routes, CLI commands, `__main__` blocks,
Lambda handlers — to every finding.

Findings nothing can reach get filed away. Findings something *can* reach come back with the
exact call path that proves it.

```
REACHABLE   app.routes.upload -> app.storage.save -> app.util.run_cmd:41
            command injection via unsanitized filename        [semgrep]

UNREACHABLE tests.fixtures.legacy.parse_xml:88
            XXE in dead test fixture                          [semgrep]
```

## Why

A mid-size repo produces hundreds to thousands of findings. Most of them sit in dead code, test
fixtures, or paths nothing ever calls. Teams drown in the list and stop reading it.

Reachability analysis is the fix, and it is normally locked behind commercial tooling that costs
thousands per year. This does it with the standard library.

## Does it actually work

**22 real repositories, 1,415 findings, 455 reachable.** Semgrep live on every run, and a
sample of verdicts hand-checked against the source — see [VERIFICATION.md](VERIFICATION.md).

| Repo | Findings | REACHABLE | UNREACHABLE | UNKNOWN | Functions |
|---|---|---|---|---|---|
| django/django | 637 | 144 | 115 | 378 | 32,438 |
| sqlmapproject/sqlmap | 133 | 92 | 28 | 13 | 7,695 |
| celery/celery | 118 | **13** | 3 | 102 | 7,854 |
| OWASP/pygoat *(deliberately vulnerable)* | 99 | **57** | 0 | 42 | 180 |
| benoitc/gunicorn | 57 | 16 | 36 | 5 | 4,587 |
| scrapy/scrapy | 57 | 32 | 16 | 9 | 5,558 |
| aio-libs/aiohttp | 43 | 11 | 31 | 1 | 6,440 |
| pypa/pip | 41 | 15 | 19 | 7 | 7,541 |
| psf/black | 40 | 12 | 9 | 19 | 1,607 |
| tornadoweb/tornado | 31 | 9 | 0 | 22 | 3,177 |
| pallets/jinja | 30 | 15 | 5 | 10 | 1,568 |
| mitmproxy/mitmproxy | 26 | 10 | 4 | 12 | 4,985 |
| psf/requests | 25 | **0** | 12 | 13 | 691 |
| locustio/locust | 17 | 4 | 2 | 11 | 2,031 |
| fastapi/fastapi | 17 | 11 | 0 | 6 | 4,959 |
| encode/httpx | 15 | **0** | 14 | 1 | 1,122 |
| pallets/flask | 9 | 6 | 3 | 0 | 1,428 |
| httpie/cli | 8 | 5 | 0 | 3 | 1,062 |

The spread is the point. Something that merely suppressed findings would cut every repo
equally. This clears `requests` and `httpx` to zero, keeps 57 of 99 on a deliberately
vulnerable app, and leaves 92 standing on `sqlmap` — a tool that executes payloads for a
living and *should* light up.

Read the UNKNOWN column honestly: on `celery`, 102 of 118 findings resolve to UNKNOWN. That is
not filtering, it is the tool declining to guess about dynamically dispatched tasks. A verdict
it will not defend is reported as one it will not defend.

The httpie result is a genuine one: `requests.get(PACKAGE_INDEX_LINK, verify=False)` — TLS
verification disabled on a live network call, in production code, reached only through a dict:

```
DAEMONIZED_TASKS = {'fetch_updates': _fetch_updates}   # daemon_runner.py
DAEMONIZED_TASKS[options.task_id](env)
```

No caller names that function anywhere. Dynamic dispatch through a registry is exactly what a
plain scanner cannot rank and what this tool exists to resolve.

The audit also found nine defects in this tool, five of them false UNREACHABLE. All fixed, all
with regression tests. They are written up honestly in VERIFICATION.md rather than quietly
patched — the failure modes are the most useful thing to know about a tool like this. Two of
the nine were found only by running it over unfamiliar code; the test suite passed throughout.

## Install

Requires Python 3.9+. **No third-party dependencies, and no scanners required** — a built-in
rule set runs out of the box.

```bash
git clone <this repo>
cd reachable
python -m reachable scan /path/to/repo
```

For deeper coverage, install any of the external scanners. Anything missing is skipped with a
warning and the rest still runs.

```bash
pip install semgrep
brew install osv-scanner gitleaks    # or see each project's install docs
```

## Use

```bash
python -m reachable scan /path/to/repo --out ./out
```

Writes three files to `./out`:

| File | For |
|---|---|
| `findings.json` | machines — full verdict list |
| `report.md` | humans and pull request comments |
| `report.html` | a browser — self-contained, no server |

### Options

```
--out DIR             output directory (default: ./out)
--no-scan             skip all scanners, analyze the call graph only
--no-builtin          skip the built-in rules
--findings FILE       reuse a cached raw scanner run instead of re-running
--include-unknown     show UNKNOWN verdicts in the Markdown report
--fail-on-reachable   exit 1 if anything is reachable, for CI gating
--quiet               errors only
```

### In CI

`.github/workflows/reachable.yml` runs the triage on every pull request and posts the report
as a comment, updating it in place on each push. Public repositories get unlimited Actions
minutes, so it costs nothing.

## How it decides

1. **Call graph** — every `.py` file is parsed with the stdlib `ast` module. Function
   definitions become nodes; call sites become edges.
2. **Entry points** — functions reachable from outside the program are marked: `__main__`
   blocks, Flask/FastAPI/Django routes, `console_scripts`, Lambda handlers, Celery tasks, the
   public surface of `__init__.py`, and anything a framework names as a dotted string rather
   than calls in code — gunicorn's `SUPPORTED_WORKERS`, Django `MIDDLEWARE`, Scrapy
   `ITEM_PIPELINES`, setuptools entry points.
3. **Traversal** — breadth-first search from every entry point produces the reachable set.
4. **Verdict** — each finding is mapped to its enclosing function, and that function is looked
   up in the reachable set.

## Honest limits

Static analysis of a dynamic language cannot be exact, and this tool does not pretend otherwise.

Everything below pushes errors toward *false positives* — claiming something is reachable when
it is not. That is deliberate. The opposite error tells someone to ignore a live bug.

- `obj.method()` on a runtime value cannot be resolved precisely. It falls back to matching the
  method name across the repo, labelled `name` confidence rather than `exact`.
- Constructing a class marks every one of its methods callable, because instance calls are
  exactly what cannot be traced.
- `getattr`-style dispatch and framework magic produce no edges at all. Findings behind them
  return `UNKNOWN`, never `UNREACHABLE`.
- Module-level findings return `UNKNOWN`. Module bodies run on import, but whether anything
  imports the module is a separate question.
- Dependency findings resolve at package granularity unless the advisory names a specific
  symbol.
- Test functions come back `UNREACHABLE` — pytest collects them dynamically. Usually the
  useful answer for triage, but know that it is happening.

Every verdict carries its confidence. `UNREACHABLE` is a claim the tool is willing to defend;
`UNKNOWN` is it telling you it does not know.

## Scope of use

Scan public repositories, or repositories you own. Do not point this at a third party's private
code, and do not use it against a bug bounty target outside that program's published scope.

## License

MIT
