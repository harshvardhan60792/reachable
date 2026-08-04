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

Five real repositories. **Every verdict was hand-checked against the source** — see
[VERIFICATION.md](VERIFICATION.md).

| Repo | Findings | REACHABLE | UNREACHABLE | UNKNOWN |
|---|---|---|---|---|
| pallets/flask | 6 | 3 | 3 | 0 |
| adeyosemanputra/pygoat *(deliberately vulnerable)* | 15 | **12** | 0 | 3 |
| psf/requests | 17 | **0** | 13 | 4 |
| httpie/cli | 4 | 2 | 0 | 2 |
| pallets/click | 0 | 0 | 0 | 0 |

The spread is the point. Something that just suppressed findings would cut every repo equally.

The httpie result is a genuine one: `requests.get(PACKAGE_INDEX_LINK, verify=False)` — TLS
verification disabled on a live network call — reached by a verified five-hop path:

```
httpie.core.main -> core.program -> client.collect_messages
  -> client.build_requests_session -> ssl_.HTTPieHTTPSAdapter.get_default_ciphers_names
```

The audit also found nine defects in this tool, five of them false UNREACHABLE. All fixed, all
with regression tests. They are written up honestly in VERIFICATION.md rather than quietly
patched — the failure modes are the most useful thing to know about a tool like this.

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
   blocks, Flask/FastAPI/Django routes, `console_scripts`, Lambda handlers, Celery tasks, and
   the public surface of `__init__.py`.
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
