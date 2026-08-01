"""Middle of the reachable chain: routes -> save -> run_cmd."""

from .util import run_cmd, slugify


def save(filename, data):
    name = slugify(filename)
    run_cmd("cp /tmp/upload " + name)
    return name


def purge():
    """Defined but nothing calls it, and it is not an entry point."""
    run_cmd("rm -rf /tmp/upload")
