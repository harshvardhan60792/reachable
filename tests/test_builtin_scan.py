"""Rules are only useful if they fire on the bad case and stay quiet on the good one.

Each test asserts both directions. A rule that cannot be silenced is a rule people turn off.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reachable import builtin_scan  # noqa: E402


def scan_src(tmp_path, code, name="mod.py"):
    (tmp_path / name).write_text(code, encoding="utf-8")
    return builtin_scan.scan(str(tmp_path))


def rules(findings):
    return {f.rule_id for f in findings}


def test_shell_true_fires(tmp_path):
    got = scan_src(tmp_path, "import subprocess\ndef f(x):\n    subprocess.run(x, shell=True)\n")
    assert "builtin.subprocess-shell-true" in rules(got)


def test_shell_false_is_quiet(tmp_path):
    got = scan_src(tmp_path, "import subprocess\ndef f(x):\n    subprocess.run([x])\n")
    assert "builtin.subprocess-shell-true" not in rules(got)


def test_eval_on_variable_fires(tmp_path):
    got = scan_src(tmp_path, "def f(x):\n    return eval(x)\n")
    assert "builtin.eval-exec" in rules(got)


def test_eval_on_literal_is_quiet(tmp_path):
    """`eval("1+1")` cannot be influenced by an attacker."""
    got = scan_src(tmp_path, "def f():\n    return eval('1+1')\n")
    assert "builtin.eval-exec" not in rules(got)


def test_pickle_load_fires(tmp_path):
    got = scan_src(tmp_path, "import pickle\ndef f(b):\n    return pickle.loads(b)\n")
    assert "builtin.pickle-load" in rules(got)


def test_yaml_safe_loader_is_quiet(tmp_path):
    got = scan_src(
        tmp_path,
        "import yaml\ndef f(s):\n    return yaml.load(s, Loader=yaml.SafeLoader)\n",
    )
    assert "builtin.yaml-unsafe-load" not in rules(got)


def test_yaml_without_loader_fires(tmp_path):
    got = scan_src(tmp_path, "import yaml\ndef f(s):\n    return yaml.load(s)\n")
    assert "builtin.yaml-unsafe-load" in rules(got)


def test_tls_verify_disabled_fires(tmp_path):
    got = scan_src(tmp_path, "import requests\ndef f(u):\n    requests.get(u, verify=False)\n")
    assert "builtin.tls-verify-disabled" in rules(got)


def test_hardcoded_secret_fires(tmp_path):
    got = scan_src(tmp_path, "API_KEY = 'sk_live_9f3ba21c7d5e4088'\n")
    assert "builtin.hardcoded-secret" in rules(got)


def test_placeholder_secret_is_quiet(tmp_path):
    """Docs, templates and examples are full of these. Flagging them trains people to ignore
    the tool, which is worse than missing one real key."""
    for value in ("", "changeme", "your-api-key", "xxxxxxxxxx", "<token>", "{{ secret }}"):
        got = scan_src(tmp_path, "API_KEY = %r\n" % value)
        assert "builtin.hardcoded-secret" not in rules(got), value


def test_short_secret_is_quiet(tmp_path):
    got = scan_src(tmp_path, "token = 'abc'\n")
    assert "builtin.hardcoded-secret" not in rules(got)


def test_non_secret_name_is_quiet(tmp_path):
    got = scan_src(tmp_path, "greeting = 'hello there friend'\n")
    assert "builtin.hardcoded-secret" not in rules(got)


def test_findings_have_ids_and_locations(tmp_path):
    got = scan_src(tmp_path, "import subprocess\ndef f(x):\n    subprocess.run(x, shell=True)\n")
    assert got
    for f in got:
        assert f.id
        assert f.file.endswith(".py")
        assert f.line > 0
        assert f.tool == "builtin"


def test_syntax_error_file_is_skipped_not_fatal(tmp_path):
    (tmp_path / "broken.py").write_text("def (:\n", encoding="utf-8")
    (tmp_path / "ok.py").write_text("import os\ndef f(c):\n    os.system(c)\n", encoding="utf-8")
    got = builtin_scan.scan(str(tmp_path))
    assert "builtin.os-system" in rules(got)
