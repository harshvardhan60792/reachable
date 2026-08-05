# Architecture

What the tool is, how its stages fit together, and which limits are deliberate.

## What this is

`reachable` — a security-finding triage tool. It runs free OSS scanners (Semgrep, OSV-Scanner,
Gitleaks) against a Python repo, then answers the question those scanners can't:

> **Is this finding actually reachable from a real entry point?**

Output: findings split into `REACHABLE` / `UNREACHABLE` / `UNKNOWN`, with the exact call path
(`entrypoint -> f1 -> f2 -> vulnerable line`) rendered as proof for every reachable one.

## Why it exists

Scanners are noise machines. A mid-size repo produces 500-3000 findings; >90% sit in dead code,
test fixtures, or code paths nothing ever calls. Teams drown and stop looking.

Commercial tools (Semgrep Pro, Endor Labs, Socket) charge thousands per year for reachability
analysis. Open source has almost nothing usable. **That gap is the whole product.**

In one line: *"1,847 findings became 12. Here is the call path for each."*

Anything that does not serve that line is secondary. Wrapping scanners is the commodity part;
the call-graph reachability engine is what makes this worth using.

## Design constraints

1. **Zero cost.** No paid APIs, no hosted services, no API keys, no database, no server.
   Everything is local CLI + Python stdlib + free GitHub Actions tier.
2. **No network calls in the core.** Reachability is pure static analysis, offline and
   deterministic. If automated fix suggestion is ever added, it shells out to a coding-agent
   CLI already installed locally, never a metered API.
3. **Honest confidence.** Python call graphs cannot be exact — dynamic dispatch, getattr,
   duck typing, and monkeypatching all defeat static resolution. Every edge and verdict carries
   a confidence level, and unresolved calls are counted and reported. Never present a guess as
   certainty. Overstated precision is the fastest way to lose credibility with a maintainer.
4. **Python targets only, for now.** Stdlib `ast` means zero parsing dependencies. JS/TS via
   tree-sitter would be a later addition, and is optional.

## Architecture

Single pass, five stages, each a separate module with no circular imports:

```
  repo path
      |
      v
[1] scanners.py     run semgrep / osv-scanner / gitleaks, normalize to Finding[]
      |
      v
[2] callgraph.py    ast-walk every .py -> FuncDef[] + Edge[]  (the call graph)
      |
      v
[3] entrypoints.py  mark which FuncDefs are entry points (routes, main, console_scripts...)
      |
      v
[4] reachability.py BFS from entry points; map each Finding to its enclosing function;
      |             emit Verdict[] with call path
      v
[5] report.py       findings.json + report.md + report.html (static, no server)
```

`models.py` holds the dataclasses shared across all stages. `cli.py` wires them together.

### Data flow contract

- `scanners.scan(repo) -> list[Finding]`
- `callgraph.build(repo) -> CallGraph` (`.functions: dict[qualname, FuncDef]`, `.edges: list[Edge]`,
  `.unresolved: int`)
- `entrypoints.detect(repo, graph) -> None` (mutates `FuncDef.is_entry` / `.entry_reason` in place)
- `reachability.analyze(findings, graph) -> list[Verdict]`
- `report.write(verdicts, graph, out_dir) -> None`

Keep these signatures stable. Changing one means touching `cli.py` and the tests.

## File map

| Path | Role |
|---|---|
| `reachable/models.py` | dataclasses: `Finding`, `FuncDef`, `Edge`, `CallGraph`, `Verdict` |
| `reachable/scanners.py` | Phase 1 — subprocess wrappers + output normalization |
| `reachable/builtin_scan.py` | Phase 1b — built-in AST rules, so the tool works with nothing installed |
| `reachable/callgraph.py` | Phase 2 — the core AST walker and name resolver |
| `reachable/entrypoints.py` | Phase 3 — entry point detection |
| `reachable/reachability.py` | Phase 4 — BFS + finding-to-function mapping |
| `reachable/report.py` | Phase 5 — JSON / Markdown / HTML output |
| `reachable/cli.py` | argparse entry point, wires stages together |
| `tests/` | pytest; `tests/fixtures/sample_app/` is a tiny repo with known reachable/dead code |
| `ROADMAP.md` | what is shipped and what is planned |
| `README.md` | human-facing usage |

## How to run

```bash
python -m reachable scan /path/to/repo --out ./out
```

Useful flags while developing:

```bash
# skip the slow external scanners, analyze the call graph only
python -m reachable scan . --out ./out --no-scan

# reuse a previous scanner run instead of re-running semgrep
python -m reachable scan . --out ./out --findings ./out/findings.raw.json
```

Tests:

```bash
python -m pytest tests -q
```

The external scanners are optional at runtime. If a binary is missing, that scanner is skipped
with a warning and the rest of the pipeline still works — this keeps the tool usable on a
machine with nothing installed, and keeps tests hermetic.

## Known limitations

- **Name resolution is heuristic.** `obj.method()` where `obj` is a runtime value cannot be
  resolved statically. Falls back to matching on the short method name across the whole repo,
  tagged `confidence="name"`. This over-approximates: it can create edges that do not exist,
  which makes reachability err toward false-positive (safe direction — better than missing a
  real bug).
- **Dynamic dispatch is invisible.** `getattr(mod, name)()`, plugin registries, and framework
  magic produce no edges. Findings behind them come back `UNKNOWN`, never `UNREACHABLE`.
- **Decorators that wrap and re-export** may hide the real call site.
- **Cross-language calls** (Python calling into a JS worker, subprocess, RPC) are not modeled.
- **OSV dep findings** are mapped at package granularity unless the advisory names a symbol;
  reachability then means "some reachable function imports or uses this package."

The correct engineering response to all of these is a confidence label, not a silent guess.

### The error that matters

These limits are all handled by over-approximating: when in doubt, call it reachable. That is
not laziness, it is the correct direction. A false REACHABLE wastes someone's time reviewing a
finding that turns out to be fine. A false UNREACHABLE tells them to ignore a live bug. The
second failure is the one that ends the project's credibility, so every ambiguous case must
resolve toward REACHABLE or UNKNOWN.

Three of the resolution rules exist purely because an early build got this wrong — it reached
6 of 97 functions and called the rest dead. Function references passed as values, methods of
an instantiated class, and module-level registration tables all had to become edges before the
numbers meant anything. Tightening resolution for precision tends to reintroduce that failure;
`VERIFICATION.md` records five separate false `UNREACHABLE` defects found this way.

## Conventions

- Python 3.9+ (uses `ast.end_lineno`, `ast.unparse`).
- Stdlib only for the core. `pytest` for tests. No runtime third-party deps.
- Dataclasses over dicts for anything crossing a module boundary.
- Qualified names are dotted and rooted at the repo: `pkg.module.Class.method`.
- No `print` in library code — `cli.py` owns all user-facing output.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
