# VERIFICATION.md — hand-audit of verdicts against real source

PLAN.md listed this as next step #1: the entire claim rests on the verdicts being right, and
passing tests do not substitute for reading the code.

Every verdict below was checked by opening the file at the reported line and tracing the
claimed path by hand. **Eight defects were found and fixed.** Four of them were false
`UNREACHABLE` — the one error class this tool must never make, because it tells someone to
ignore live code. Defect 8 is worse than any of them: Semgrep was never running at all, and
the run reported that as zero findings.

Audited: 5 repositories, 42 findings, every verdict. Defects 7 and 8 came later, from pointing
the tool at a sixth repository and from installing Semgrep for the first time.

---

## Defects found and fixed

### 1. Class-body registrations were invisible → false UNREACHABLE

**Found on:** `flask/src/flask/sessions.py:281`, reported UNREACHABLE.

`_lazy_sha1` has no caller by name. It is wired in as a class attribute:

```python
class SecureCookieSessionInterface(SessionInterface):
    digest_method = staticmethod(_lazy_sha1)     # sessions.py:293
```

and used at line 319 to sign **every Flask session cookie**. Live crypto code, reported dead.

Cause: `_from_module_level_refs` skipped `ast.ClassDef` entirely. Fix: descend into class
bodies (never into functions — those already have an enclosing caller). This shape is
everywhere: Django `form_class`, DRF `serializer_class`, and most configure-by-class-attribute
frameworks.

Now REACHABLE. Regression test: `test_class_body_reference_is_an_entry_point`.

### 2. `__main__` guard bodies fell through to UNKNOWN

**Found on:** `pygoat/dockerized_labs/broken_auth_lab/app.py:123`, reported UNKNOWN.

```python
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

That is not "might run on import" — it is exactly what runs when you execute the file. It hit
the module-level UNKNOWN rule because no function encloses it.

Fix: record `__main__` guard line spans during entry point detection; findings inside one
resolve REACHABLE. Regression test: `test_finding_inside_main_guard_is_reachable`.

### 3. Re-exported classes marked nothing → library surface understated

**Found on:** `requests`, which detected only 15 entry points for a 691-function library.

`requests/__init__.py` re-exports `Session`, `Response`, `Request`, `PreparedRequest` — all
**classes**. `_from_public_api` looked them up in `graph.functions` only, found nothing, and
marked nothing. Fix: `_mark_api` falls back to `graph.classes` and marks the public methods.

Entry points went 15 → 59.

### 4. A library's public API judged only against internal callers → false UNREACHABLE

**Found on:** `requests/src/requests/auth.py:179,187,237` (MD5 and SHA-1 in HTTP Digest Auth),
reported UNREACHABLE.

`HTTPDigestAuth` is documented public API, but it is **not** re-exported from
`requests/__init__.py`, and nothing inside the requests source ever constructs it. Consumers
write `requests.get(url, auth=HTTPDigestAuth(u, p))`, and `PreparedRequest.prepare_auth` then
calls it through a runtime value.

So "no internal caller" is genuinely true — and completely the wrong conclusion. For a
distributed library, the outside caller is the point.

Fix: a public symbol inside a shipped package with no internal path resolves **UNKNOWN**, not
UNREACHABLE. UNREACHABLE has to be earned.

**Scoping this correctly took two attempts, and the first was wrong in an instructive way.**
Treating any directory with an `__init__.py` as public API made the test fixture's
deliberately-dead code UNKNOWN — which would have destroyed the filtering the tool exists for.
Narrowed to: packaging metadata must exist (`pyproject.toml` / `setup.py` / `setup.cfg`), the
package must be top-level (repo root or `src/`), and conventional non-shipped directories
(`tests`, `docs`, `examples`, ...) are excluded. Without that last exclusion, `requests/tests/`
— which has an `__init__.py` — counted as public API and every dead test fixture became
UNKNOWN.

### 5. `auth` matched as a substring of `author` → false-positive secrets

**Found on:** `requests/src/requests/__version__.py:10,11` and `requests/docs/conf.py:62`.

```python
__author__ = "Kenneth Reitz"          # flagged as a leaked credential
author = u"Kenneth Reitz and contributors"
```

The credential-name regex matched `auth` anywhere in the identifier. Every project's byline
was a "hardcoded secret".

Fix: split identifiers into segments (underscore and camelCase aware) and match whole segments.
`api_key` and `apiKey` both still fire; `__author__` does not. Regression test:
`test_author_is_not_a_secret`.

### 6. Bare `system` matched `platform.system()` → false-positive command execution

**Found on:** 5 findings across `pygoat`, `httpie` and `click`.

```python
if platform.system() == 'Windows':    # flagged as os.system shell execution
```

`platform.system()` returns the OS name and touches no shell. Fix: require an explicit `os.`
prefix, or an undotted call (`from os import system`). Verified by grep that no genuine
`os.system(...)` call was lost in the process. Regression test:
`test_platform_system_is_not_os_system`.

### 7. Bare `mktemp` matched `tmp_path_factory.mktemp()` → false-positive insecure temp file

**Found on:** `edgecheck/benchmarks/`, and independently on `cve-bin-tool/test/test_mismatch_cli.py:16`.

```python
db_file = tmpdir_factory.mktemp("data").join("test_mismatch.db")   # flagged as tempfile.mktemp
```

pytest's `tmp_path_factory.mktemp` / `tmpdir_factory.mktemp` **creates** the directory it
names, which is the entire difference from `tempfile.mktemp` — no window, no race. Same shape
as defect 6: the rule matched the method name and never asked what the receiver was.

Fix: the scanner now reads each file's imports into an alias table and resolves a call's
dotted source through it before matching, so `mktemp` fires only when the receiver resolves to
`tempfile`. `import tempfile as tf`, `from tempfile import mktemp as mk`, and an import placed
below the function that uses it all still fire — the pass over imports runs before the pass
over calls, because a function body executes later than the module text. The same resolution
now also catches `import os as o; o.system(c)` and `import pickle as p; p.loads(b)`, which the
bare-name rules missed. Regression tests: `test_pytest_mktemp_is_not_tempfile_mktemp`,
`test_real_mktemp_fires_through_every_import_style`, `test_an_import_below_its_use_still_resolves`.

Worth noting what did **not** go wrong: the verdict on the bad finding was `UNREACHABLE`,
which was correct — the triage layer did its job on top of a wrong rule. The false positive
was in the scanner, and it is exactly the noise the reachability layer exists to absorb.

### 8. Semgrep never ran, and the run reported it as zero findings

**Found on:** the first run with Semgrep actually installed — `edgecheck`.

`run_semgrep` passed `--config=auto` and `--metrics=off` together. Semgrep refuses the
combination:

```
[ERROR]: Cannot create auto config when metrics are off.
```

`auto` is *defined* as "ask the registry what to run for this project", which requires the
upload `--metrics=off` forbids. Semgrep exited 2, wrote the error to stderr, and printed
nothing to stdout. `_run` returned that empty stdout, `if not out: return []` turned it into an
empty finding list, and the run printed:

```
running semgrep ...
  semgrep -> 0 findings
```

**A dead scanner reported as a clean scan.** Worse than any false verdict: the whole pipeline
looked healthy, and the number it printed was indistinguishable from a genuine all-clear. The
two changes that produced it were each individually correct — `--metrics=off` came from the
security review (PLAN.md, security item 4), `--config=auto` from Phase 1 — and no test caught
the combination because the tests are hermetic and never execute a real scanner.

Two fixes, because there are two defects here:

1. **Name the rulesets.** `p/python`, `p/security-audit`, `p/secrets` instead of `auto`. Keeps
   metrics off, and makes the rule set reproducible between runs rather than whatever the
   registry decides today.
2. **Never turn a failure into an empty result.** `ScannerFailed` is raised when a scanner
   exits non-zero *with no stdout at all*, when it cannot start, when it times out, or when
   its output is not JSON. Non-zero *with* output is still findings — scanners exit 1 because
   they found something, which is why exit code alone was never usable. The driver catches it
   per scanner, logs `FAILED ... and that is not a clean result`, and closes the run with
   `warning: semgrep did not complete; this report is incomplete, not clean`.

Regression tests: `test_a_scanner_that_dies_raises_rather_than_returning_nothing` (the literal
metrics error string), `test_a_nonzero_exit_with_output_is_findings_not_failure`,
`test_a_failed_scanner_is_reported_not_counted_as_zero`.

The failure is carried all the way into the artifacts, not just the log — a `ScanFailure` per
dead scanner reaches `report.write`, which puts a banner **above** the counts in `report.md`
and `report.html` and sets `summary.complete: false` plus a `scan_failures` list in
`findings.json`. The report is what a reviewer reads and what the Action posts as a PR comment,
so a run missing a scanner's coverage must not render identically to a run that genuinely found
nothing. `--fail-on-reachable` now also exits 1 on an incomplete scan: a gate that passes
because a scanner died is worse than no gate.

The failure reason is the scanner's own stderr, so it crosses the same untrusted boundary as a
finding message and gets the same `_clean` / `_esc` treatment — tested with the S1 markdown
forgery payload and an HTML injection payload.

After the fix, the same run on `edgecheck` returns **1 finding, REACHABLE**, with the path
`cli.fetch -> StooqSource.fetch -> StooqSource._download` — `p/security-audit`'s
`dynamic-urllib-use-detected` on `urllib.request.urlopen(url)`. The path is correct and the
finding is genuine-but-benign: the host is a hardcoded `https://` literal, so the `file://`
scheme the rule warns about is unreachable. Audit-grade warning, correctly surfaced, correctly
traced.

---

## Verdicts confirmed correct

### flask (6 findings)

| Verdict | Location | Checked |
|---|---|---|
| REACHABLE | `src/flask/cli.py:1023` eval-exec | `eval(compile(f.read(), ...))` inside `shell_command`, decorated `@click.command("shell")` at line 999. Correct. |
| REACHABLE | `src/flask/config.py:209` eval-exec | `exec(compile(config_file.read(), ...))` in `Config.from_pyfile`. Path via `examples/tutorial/flaskr/__init__.py:18`, which calls `app.config.from_pyfile("config.py")`. Correct. |
| REACHABLE | `src/flask/sessions.py:281` weak-hash | Defect 1, above. Correct after fix. |
| UNREACHABLE ×3 | `tests/test_basic.py:1899`, `tests/test_reqctx.py:215`, `tests/test_templating.py:484` | Test-only code. Flask's `tests/` has no `__init__.py`, so it is correctly not treated as shipped. |

### pygoat (15 findings, 12 reachable)

Intentionally vulnerable Django + Flask app. Spot-checked against source and `introduction/urls.py`:

- `introduction/mitre.py:218` `eval(expression)` in `mitre_lab_25_api` — registered at `urls.py:119`. Correct.
- `introduction/mitre.py:233` `subprocess.Popen(command, shell=True)` in `command_out`, called by `mitre_lab_17_api`, registered at `urls.py:122`. **Multi-hop path correct.**
- `introduction/views.py:430` `cmd_lab` — registered at `urls.py:36`. Correct.
- `dockerized_labs/broken_auth_lab/app.py:86` `hashlib.md5` in `reset_password`, `@app.route`. Correct.
- `uninstaller.py:19,79` — were false positives (defect 6), correctly gone.

3 UNKNOWN are module-level Django `SECRET_KEY` assignments in `settings.py`. Honest: they run
on import, but proving the module is imported is a separate question.

### requests (17 findings)

| Verdict | Location | Checked |
|---|---|---|
| UNKNOWN ×3 | `src/requests/auth.py:179,187,237` | Defect 4. Public API, no internal caller. Correct after fix. |
| UNREACHABLE ×13 | `tests/**` | Test-only. Correct. |
| UNKNOWN | `tests/test_utils.py:443` | Module-level constant. Correct. |

### httpie (4 findings, 2 reachable)

- `httpie/internal/update_warnings.py:44` — `requests.get(PACKAGE_INDEX_LINK, verify=False)`.
  **A genuine security finding**: TLS verification disabled on a real network call.
- `httpie/ssl_.py:89` — `cls._create_ssl_context(verify=False)`, reached by a verified 5-hop
  path: `core.main -> core.program -> client.collect_messages -> client.build_requests_session
  -> ssl_.HTTPieHTTPSAdapter.get_default_ciphers_names`. The path is correct. **The finding
  itself is low-severity in context** — the context is built only to enumerate cipher names,
  never to make a request. That is a rule-precision limit, not a reachability error.

### click (0 findings)

All 4 previous findings were `platform.system()` false positives (defect 6). A clean result on
a well-audited library is the right answer.

---

## Results after the audit

| Repo | Findings | REACHABLE | UNREACHABLE | UNKNOWN | Functions | Entry points |
|---|---|---|---|---|---|---|
| pallets/flask | 6 | 3 | 3 | 0 | 1428 | 560 |
| adeyosemanputra/pygoat | 15 | 12 | 0 | 3 | 180 | 134 |
| psf/requests | 17 | 0 | 13 | 4 | 691 | 59 |
| httpie/cli | 4 | 2 | 0 | 2 | 1062 | 100 |
| pallets/click | 0 | 0 | 0 | 0 | 1698 | 680 |

Runtime: 1.8s (requests, 37 files) to 5.5s (httpie, 133 files). Nothing in the design is
superlinear and nothing here suggests otherwise.

33 tests pass, including a regression test for every defect above.

---

# Part 2 — security review and hostile-input testing

The threat model: this tool parses **source it does not trust** and **scanner JSON it does not
control**, then writes a report that a GitHub Action posts as a pull request comment. That last
step makes report content a security boundary, not a formatting concern.

## Vulnerabilities found and fixed

### S1. Report forgery through newline injection — the serious one

`report.md` is posted verbatim as a PR comment. Nothing stripped newlines from finding text,
and finding text is attacker-influenced: the built-in credential rule embeds an identifier
lifted straight from the scanned source, and file paths come from scanner output.

```python
message = "harmless\n\n## REACHABLE (999)\n\n### `fake.py:1`\n\nfabricated critical finding"
```

That renders as real markdown headings. Anyone able to influence a scanned string could
fabricate findings, or bury genuine ones under a forged all-clear — in the very report used to
review their pull request.

Fixed: all untrusted fields pass through `_clean()`, which strips control characters, collapses
whitespace to a single line, and caps length at 500 characters. The text still appears, as
inline prose — suppressing it would hide real content. Markdown structure needs a line start,
and there are no longer any line starts to hijack.

Tests: `test_markdown_report_cannot_be_forged_through_a_finding_message`,
`test_forgery_through_file_path_and_rule_id`, `test_control_characters_are_stripped`,
`test_absurdly_long_message_is_truncated`.

### S2. BOM-prefixed files silently dropped from the graph

Files were read as `utf-8`, so a byte-order mark survived as `﻿` and `ast.parse` raised
`SyntaxError`. The file was recorded as a parse error and vanished from the call graph.

This is a **security** bug, not a cosmetic one: a missing file means missing functions, which
means findings inside it report as unreachable. Silent false negatives, and Windows editors
emit BOMs routinely. Fixed by reading `utf-8-sig`. Test:
`test_bom_prefixed_file_is_parsed`.

### S3. `curl | sh` from a branch URL in the workflow

The CI installed OSV-Scanner by piping a script fetched from a `main` branch URL — executing
whatever that branch happened to contain, with write access to the workspace. Indefensible in
the pipeline of a security tool. Replaced with pinned release binaries at fixed versions.

### S4. Semgrep uploaded usage metrics by default

Semgrep enables metrics reporting by default. This tool promises local-only analysis, so
quietly phoning home about a codebase someone pointed a scanner at breaks that promise. Added
`--metrics=off`. Fetching the rulesets is still a network request; that is a deliberate trade
for rule coverage and is now documented as the only outbound request.

**This fix caused defect 8** — see above. `--metrics=off` is incompatible with the
`--config=auto` that was already there, and the combination silently disabled Semgrep for
every run until someone finally installed it.

### S5. `pull_request` + fork PRs would fail the job

Fork pull requests get a read-only token, so the comment step fails for exactly the PRs most
worth scanning. Using `pull_request_target` would fix the token but hand write scope to
untrusted PR code — the wrong trade. Kept `pull_request`, marked the comment step
`continue-on-error`, and documented it. The report is still uploaded as an artifact.

### S6. `load_raw` crashed on unexpected keys

`Finding(**d)` raises `TypeError` on any extra key, so a findings file from a different version
of the tool became a hard failure with a confusing traceback. Now filters to known fields.

## Reviewed and found sound

- **No XSS in `report.html`.** Every interpolated field goes through `html.escape`. Verified
  by injecting `<script>` and `onerror=` payloads and confirming they render escaped.
  (An earlier draft of the test reported a false positive by substring-matching text that was
  already escaped — the payload string survives escaping, the markup does not.)
- **No command injection.** Scanners are invoked with argument lists, never `shell=True`, and
  no user-controlled string reaches a shell.
- **Path traversal is inert.** A finding reporting `../../../etc/passwd` is only ever printed,
  never opened. Files are read exclusively from the tool's own directory walk.
- **Symlink loops cannot hang the walk.** `os.walk` does not follow symlinks by default.
- **Malformed source degrades gracefully.** Null bytes, pathological nesting and undecodable
  bytes skip the file and record a parse error; other files still process.
- **Cycles terminate.** Circular imports and self-recursive calls are handled by the BFS
  visited-set; verified explicitly.
- **No dependencies to audit.** The core is standard library only, so there is no third-party
  supply chain in the tool itself.
- **Self-scan is clean.** Running the tool on its own source produces 3 findings, all in the
  deliberately vulnerable test fixtures, all correctly classified. No findings in tool code.

## Known residual risk

- **Memory scales with repo size.** Every parsed AST is cached in `CallGraph.trees` so later
  stages need not re-parse. Fine at the sizes tested (1698 functions), but a very large
  monorepo could exhaust memory. Not a crash-safety issue, and no bound is currently enforced.
- **Markdown code spans can still be unbalanced** by a backtick inside a cleaned field. It
  breaks rendering cosmetically; it cannot forge structure.

49 tests pass, including a regression test for every issue above.

---

## What this audit did not cover

- **External scanners were never exercised against live output.** Semgrep has no native
  Windows support, and OSV-Scanner and Gitleaks are separate binaries. Every finding above came
  from the built-in rules. The Semgrep/OSV/Gitleaks parsers are written and unit-shaped but
  have not been run against real scanner JSON.
- **No dependency (OSV) verdict was verified**, since OSV-Scanner never ran. `_dep_verdict` is
  the least-tested path in the codebase.
- **Only Python.** Nothing here says anything about the JS/TS plan.
- Five repositories is a reasonable sample, not a guarantee. The next most useful test is a
  large Django or async-heavy codebase, where dynamic dispatch is densest.
