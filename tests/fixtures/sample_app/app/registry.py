"""Registration shapes that no call site references directly.

Both patterns below defeated the analysis at some point, and both produced a false
UNREACHABLE on code that genuinely runs.
"""

import hashlib


def sign_payload(data):
    # SINK-CLASS-REGISTERED: weak hash, wired in through a class attribute
    return hashlib.md5(data).hexdigest()


class Signer:
    """Nothing calls `sign_payload` by name. It is handed over as a class attribute and
    invoked later through `self.digest`, exactly like Flask's `digest_method`."""

    digest = staticmethod(sign_payload)

    def run(self, data):
        return self.digest(data)


if __name__ == "__main__":
    Signer().run(b"x")
    print("debug", True)  # SINK-MAIN-GUARD
