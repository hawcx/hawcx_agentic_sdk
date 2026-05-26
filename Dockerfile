# syntax=docker/dockerfile:1.7

# hawcx_agentic_sdk image — customer-side release/distribution image.
#
# Topology note (2026-05-21): this repo is a release-only scaffold and
# hosts no Rust source code of its own. The image is built from sibling
# repos that ARE checked out as part of the build context:
#
#   hawcx_agentic_sdk/             (this file; only Dockerfile + workflow + docs)
#   hx_agent_crypto_core/          (shared crypto / wire / haap-sdk-types)
#   hx_agent_client_auth_service/  (the multi-call `hawcx-manager` binary)
#
# The companion `haap-rsv` MCP-server-side verifier binary is shipped from
# its own image at ghcr.io/hawcx/haap-rsv — built out of
# hx_agent_authorizer where the cascade core (haap-core §45.7-ahead)
# lives. See hx_agent_authorizer/Dockerfile.
#
# Phases 3-5 cutover (2026-05-22): this image previously built and shipped
# 7 individual binaries (haap-authenticator, haap-tqs-precompute,
# haap-tqs-jit, haap-assembler, haap-eib, haap-supervisor, haap-sdk).
# It now builds ONE binary, `hawcx-manager`, and installs 7 symlinks
# under the legacy names so existing supervisor fork/exec call sites
# continue to work via argv0 dispatch. See
# /hx_agent_canonical_spec/DESIGN-MEMO-MULTICALL-BINARY.md and
# /hx_agent_canonical_spec/SDK-BUILD-WITH-HAWCX-MANAGER.md.
#
# The release.yml workflow in .github/ arranges the sibling checkout; for
# local builds run from the parent dir containing all three repos:
#   docker build -f hawcx_agentic_sdk/Dockerfile -t hawcx-sdk ~/Projects/

FROM rust:1-bookworm AS builder

WORKDIR /build

# protoc — tonic-build needs it for code generation. Pinned to a specific
# release artifact + SHA-256. The official checksum is published at
#   https://github.com/protocolbuffers/protobuf/releases/tag/v25.1
# Bumping the version REQUIRES updating PROTOC_SHA256 in lockstep. Without
# the hash a compromised mirror or release-asset swap silently slips
# arbitrary code into the build stage (L-2 hardening 2026-05-20).
ARG PROTOC_VERSION=25.1
ARG PROTOC_SHA256=ed8fca87a11c888fed329d6a59c34c7d436165f662a2c875246ddb1ac2b6dd50
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        unzip curl ca-certificates && \
    curl -fsSL -o /tmp/protoc.zip \
        "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip" && \
    echo "${PROTOC_SHA256}  /tmp/protoc.zip" | sha256sum -c - && \
    unzip -o /tmp/protoc.zip -d /usr/local bin/protoc 'include/*' && \
    chmod +x /usr/local/bin/protoc && \
    rm -rf /var/lib/apt/lists/* /tmp/*

# Sibling checkout: the `hawcx-manager` multi-call binary builds out of
# hx_agent_client_auth_service, which path-deps into hx_agent_crypto_core.
# This SDK repo carries no source so there is no `COPY hawcx_agentic_sdk`.
COPY hx_agent_crypto_core /build/hx_agent_crypto_core
COPY hx_agent_client_auth_service /build/hx_agent_client_auth_service

# Phase 3-5 cutover: ONE binary replaces the prior 7-bin build. The
# multi-call binary dispatches by argv[0] (basename) → role; symlinks
# below preserve every legacy exec call site without changing the
# supervisor child-spawn code path.
WORKDIR /build/hx_agent_client_auth_service
RUN cargo build --release --bin hawcx-manager

# Staging stage: place hawcx-manager + legacy symlinks under
# /staging/usr/local/bin so the final distroless COPY brings the
# whole tree across in one shot. Distroless has no shell, so the
# symlinks MUST be generated in the builder (which has bash) and
# COPY-preserved into runtime.
RUN mkdir -p /staging/usr/local/bin && \
    cp /build/hx_agent_client_auth_service/target/release/hawcx-manager \
       /staging/usr/local/bin/hawcx-manager && \
    cd /staging/usr/local/bin && \
    for n in haap-authenticator haap-tqs-precompute haap-tqs-jit \
             haap-assembler haap-eib haap-supervisor haap-sdk; do \
        ln -sf hawcx-manager "$n"; \
    done && \
    ls -la /staging/usr/local/bin/

# Distroless runtime.
FROM gcr.io/distroless/cc-debian12 AS runtime

# Single COPY brings the binary + 7 symlinks across as one tree.
# `COPY --from=builder DIR/ DIR/` preserves symlinks per the OCI
# spec and Docker COPY semantics (verified in Buildx >=0.10).
COPY --from=builder /staging/usr/local/bin/ /usr/local/bin/

# Default entrypoint = haap-supervisor, which is now a symlink to
# hawcx-manager. argv[0] = "haap-supervisor" routes to supervisor mode
# via the multi-call dispatcher. Behavior is byte-identical to the
# pre-cutover supervisor binary.
ENTRYPOINT ["/usr/local/bin/haap-supervisor"]
