# syntax=docker/dockerfile:1.7

# Multi-stage build: requires hx_labs to be checked out as a sibling
# of hx_agentic_sdk in the build context. The release.yml workflow
# arranges this; for local builds run `docker build -f hx_agentic_sdk/Dockerfile .`
# from the parent directory containing both repos.

FROM rust:1-bookworm AS builder

WORKDIR /build

# Build dependencies: protoc (tonic-build needs it for code generation).
#
# protoc is pinned to a specific release artifact + SHA-256. The official
# checksum for protoc-25.1-linux-x86_64.zip is published on the upstream
# release page:
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

# Copy both repos so the SDK's path-deps to ../hx_labs resolve.
COPY hx_labs /build/hx_labs
COPY hx_agentic_sdk /build/hx_agentic_sdk

# Build hx_labs binaries.
WORKDIR /build/hx_labs
RUN cargo build --release \
    --bin haap-authenticator \
    --bin haap-tqs-precompute \
    --bin haap-tqs-jit \
    --bin haap-assembler \
    --bin haap-eib \
    --bin haap-supervisor

# Build SDK binaries.
WORKDIR /build/hx_agentic_sdk
RUN cargo build --release --bin haap-rsv --bin haap-sdk

# Distroless runtime.
FROM gcr.io/distroless/cc-debian12 AS runtime

COPY --from=builder /build/hx_labs/target/release/haap-authenticator /usr/local/bin/
COPY --from=builder /build/hx_labs/target/release/haap-tqs-precompute /usr/local/bin/
COPY --from=builder /build/hx_labs/target/release/haap-tqs-jit /usr/local/bin/
COPY --from=builder /build/hx_labs/target/release/haap-assembler /usr/local/bin/
COPY --from=builder /build/hx_labs/target/release/haap-eib /usr/local/bin/
COPY --from=builder /build/hx_labs/target/release/haap-supervisor /usr/local/bin/
COPY --from=builder /build/hx_agentic_sdk/target/release/haap-rsv /usr/local/bin/
COPY --from=builder /build/hx_agentic_sdk/target/release/haap-sdk /usr/local/bin/

# Default entrypoint = supervisor (most common customer-side deployment).
ENTRYPOINT ["/usr/local/bin/haap-supervisor"]
