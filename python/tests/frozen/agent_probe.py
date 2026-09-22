"""The program PyInstaller freezes for the packaging check. Not a pytest module.

It is deliberately the smallest thing that exercises the property #118 broke:
ask the shim for a client and make a real request through the broker. Anything
less — importing the module, calling `flavor()` — would not have caught #118,
because the module imported fine and only the transport was missing.

Run by `check_frozen_bundle.py`, which builds this, stands up a fake broker and
a TLS server, and reads the lines printed here.
"""

import os
import sys

from hawcx_haap import egress


def main() -> int:
    print(f"flavor={egress.flavor()}", flush=True)

    url = os.environ["FROZEN_PROBE_URL"]
    ca = os.environ["FROZEN_PROBE_CA"]
    with egress.client(verify=ca, timeout=30) as http:
        r = http.get(url)
        print(f"status={r.status_code}", flush=True)
        print(f"body={r.text}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
