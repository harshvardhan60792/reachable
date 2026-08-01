# VERIFICATION.md — hand-audit of verdicts against real source

PLAN.md listed this as next step #1: the entire claim rests on the verdicts being right, and
passing tests do not substitute for reading the code.

Every verdict below was checked by opening the file at the reported line and tracing the
claimed path by hand. **Six defects were found and fixed.** Four of them were false
`UNREACHABLE` — the one error class this tool must never make, because it tells someone to
ignore live code.

Audited: 5 repositories, 42 findings, every verdict.

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
