"""Leaf helpers. `run_cmd` is the reachable sink the tests assert on."""

import subprocess


def run_cmd(cmd):
    # SINK-REACHABLE: shell=True with caller-controlled input
    return subprocess.run(cmd, shell=True)


def slugify(name):
    return name.strip().lower().replace(" ", "-")
