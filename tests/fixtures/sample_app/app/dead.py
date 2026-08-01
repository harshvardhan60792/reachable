"""Nothing reaches this module. Every finding inside it should come back UNREACHABLE."""

import pickle

TRUSTED = False


def parse_blob(blob):
    # SINK-UNREACHABLE: insecure deserialization in code nothing calls
    return pickle.loads(blob)


def _helper(blob):
    return parse_blob(blob)
