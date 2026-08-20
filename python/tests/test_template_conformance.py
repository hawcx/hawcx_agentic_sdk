"""Replay the CANONICAL agent-template vector set through this SDK's validator.

Auto-wrap plan U1/U2 acceptance. ``hawcx_haap.template.validate_v1`` is an
implementation of rules owned elsewhere — the reference validator in
``hx_agent_canonical_spec/spec/conformance/test_vectors_template.py``. A local
unit test can only prove this implementation is self-consistent; it cannot prove
it AGREES with the oracle. This file does that, by driving the oracle's own
vectors through our code and requiring the same accept/deny verdict and the same
error code.

Why the vectors are read from the sibling repo rather than vendored: a vendored
copy is a snapshot, and a snapshot silently stops tracking the oracle the first
time the spec adds a vector. Reading the live file means a new canonical vector
shows up here as a failure — which is the point.

Resolution order for the spec repo:
  1. ``$HAWCX_CANONICAL_SPEC``
  2. the conventional sibling checkout, ``../../hx_agent_canonical_spec``

If neither resolves the module SKIPS rather than passing vacuously, and says so.
"""

from __future__ import annotations

import json
import os
import pathlib

import pytest

from hawcx_haap.template import validate_v1

_VECTOR_REL = pathlib.Path("spec/conformance/vectors/agent-template-v1.json")


def _spec_root() -> pathlib.Path | None:
    """Locate an hx_agent_canonical_spec checkout, or None.

    An explicitly-set `HAWCX_CANONICAL_SPEC` is used EXCLUSIVELY — no silent
    fallback to the sibling. If someone points this at the wrong checkout, the
    right outcome is "not found" (and a skip naming the bad path), not quietly
    validating against a different repo than the one they named.
    """
    env = os.environ.get("HAWCX_CANONICAL_SPEC")
    if env:
        p = pathlib.Path(env)
        return p if (p / _VECTOR_REL).is_file() else None
    # tests/ -> python/ -> repo root -> haap_repos/
    sibling = pathlib.Path(__file__).resolve().parents[3] / "hx_agent_canonical_spec"
    return sibling if (sibling / _VECTOR_REL).is_file() else None


_ROOT = _spec_root()
pytestmark = pytest.mark.skipif(
    _ROOT is None,
    reason=(
        "canonical vector set not found — set HAWCX_CANONICAL_SPEC to an "
        "hx_agent_canonical_spec checkout, or place it as a sibling of this repo. "
        "Skipped, NOT passed: this module is the only cross-repo proof that our "
        "validator agrees with the reference oracle."
    ),
)


def _vectors() -> dict:
    # Returns an empty shell when the spec repo is absent. `pytestmark = skipif`
    # skips TEST FUNCTIONS, but a module-level `@parametrize(..., _manifest_vectors())`
    # argument is evaluated during COLLECTION, before any skip applies — so an
    # unguarded `_ROOT / ...` here is a collection-time TypeError that fails the
    # whole file instead of skipping it. Found in CI, not locally: the sibling
    # checkout exists on a dev machine, so the skip path never ran.
    if _ROOT is None:
        return {"vectors": [], "golden_manifest": {}, "goldens": {}}
    return json.loads((_ROOT / _VECTOR_REL).read_text())


def _strip_notes(doc):
    """Mirror the canonical checker: `_note` is provenance, not schema."""
    return {k: v for k, v in doc.items() if k != "_note"} if isinstance(doc, dict) else doc


def _compose(doc: dict, vector: dict) -> dict:
    """Rebuild the manifest under test exactly as the canonical checker does."""
    inputs = vector.get("inputs") or {}
    name = inputs.get("golden")
    if name:
        # `goldens` landed with the UKG O365/Salesforce goldens (spec #427). A
        # spec checkout predating it simply has no such vectors to replay.
        base = (doc.get("goldens") or {})[name]
    else:
        base = doc["golden_manifest"]
    manifest = json.loads(json.dumps(_strip_notes(base)))
    mutation = inputs.get("mutation")
    if mutation:
        for k in mutation.get("delete", []):
            manifest.pop(k, None)
        manifest.update(mutation.get("set", {}))
    return manifest


def _manifest_vectors():
    doc = _vectors()
    return [v for v in doc["vectors"] if v.get("kind") == "manifest"]


def test_vector_set_is_not_empty():
    """A vector file that parses to zero manifest vectors would make every
    parametrized test below vacuously green."""
    assert len(_manifest_vectors()) >= 10


@pytest.mark.parametrize("vector", _manifest_vectors(), ids=lambda v: v["id"])
def test_matches_reference_verdict(vector):
    doc = _vectors()
    manifest = _compose(doc, vector)
    errors = validate_v1(manifest)
    codes = {c for c, _ in errors}

    if vector["expect"] == "accept":
        assert not errors, f"{vector['id']}: reference accepts, we reject with {errors}"
    else:
        assert errors, f"{vector['id']}: reference denies, we accept"
        want = vector.get("error_code")
        if want:
            assert want in codes, (
                f"{vector['id']}: reference denies with {want}, we emitted {sorted(codes)}"
            )


@pytest.mark.parametrize("vector", _manifest_vectors(), ids=lambda v: v["id"])
def test_deterministic_and_key_order_independent(vector):
    """Canonical property TPL-P2. Key order is not semantic, and a validator that
    short-circuits on the first error can accidentally make it semantic."""
    manifest = _compose(_vectors(), vector)
    reordered = dict(reversed(list(manifest.items())))
    norm = lambda e: sorted(f"{c}@{p}" for c, p in e)  # noqa: E731
    assert norm(validate_v1(manifest)) == norm(validate_v1(manifest))
    assert norm(validate_v1(manifest)) == norm(validate_v1(reordered))


def test_every_golden_in_the_spec_validates_clean():
    """Includes the UKG O365 + Salesforce goldens once spec #427 lands. If the
    spec adds a golden this SDK cannot accept, that is a release blocker, not a
    detail — the scaffolder generates from these."""
    doc = _vectors()
    for name, golden in [("golden_manifest", doc["golden_manifest"]),
                         *sorted((doc.get("goldens") or {}).items())]:
        assert not validate_v1(_strip_notes(golden)), f"{name} must validate clean"
