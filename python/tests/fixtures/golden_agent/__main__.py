"""Golden fixture agent for `hawcx bundle` (agent-delivery WP-F).

The reference agent named in the plan is `hx_crewai_demo`'s `acme_doc_gen`.
It is NOT the golden here, for two reasons, both structural rather than
convenience:

1. It lives in a sibling repo, and this repo's rule is no cross-repo path deps.
2. It could not be bundled as a zipapp anyway -- its dependency closure
   (crewai -> pydantic -> pydantic-core) contains a compiled extension module,
   which `hawcx bundle` refuses by design. Discovering that from the golden
   would have been the point of the golden, so it is recorded here instead.

So the golden is this: the smallest agent that is a real agent -- it imports
the SDK from inside the archive, opens the Assembler UDS, completes the §7
handshake, invokes one tool, and prints what came back. If the bundle is not
self-contained, or the SDK does not survive being imported from a zip, this
fails to reach the socket at all.
"""

from __future__ import annotations

import os
import sys

from hawcx_haap import HawcxAgent, TokenTransport

MARKER = "GOLDEN-OK"


def main() -> int:
    endpoint = os.environ.get("HAWCX_ASSEMBLER_ENDPOINT")
    if not endpoint:
        print("HAWCX_ASSEMBLER_ENDPOINT is not set", file=sys.stderr)
        return 2

    with HawcxAgent.connect(endpoint, principal_allowlist=["alice"]) as agent:
        resp = agent.invoke(
            target_rs_url="https://api.example.com/docs",
            http_method="POST",
            headers={"Content-Type": "application/json"},
            tool="acme.doc.generate",
            action=["write"],
            body=MARKER.encode("ascii"),
            transport=TokenTransport.HTTP_HEADER,
            acting_for_user="alice",
        )

    print(f"{MARKER} status={resp.http_status} body={resp.body.decode('ascii')}")
    # Proof the SDK came out of the archive rather than the ambient
    # site-packages: __file__ of an imported-from-zip module is a path INSIDE
    # the .pyz.
    import hawcx_haap
    print(f"sdk_from={hawcx_haap.__file__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
