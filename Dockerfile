# syntax=docker/dockerfile:1.7

# Multi-stage build: requires hx_labs to be checked out as a sibling
# of hx_agentic_sdk in the build context. The release.yml workflow
# arranges this; for local builds run `docker build -f hx_agentic_sdk/Dockerfile .`
# from the parent directory containing both repos.

FROM rust:1.75 AS builder

WORKDIR /build

# Copy both repos so the SDK's path-deps to ../hx_labs resolve.
COPY hx_labs /build/hx_labs
COPY hx_agentic_sdk /build/hx_agentic_sdk

# Build hx_labs binaries.
WORKDIR /build/hx_labs
RUN cargo build --release \
    --bin haap-auth-bin \
    --bin haap-tqs-precompute-bin \
    --bin haap-tqs-jit-bin \
    --bin haap-assembler-bin \
    --bin haap-supervisor

# Build SDK binaries.
WORKDIR /build/hx_agentic_sdk
RUN cargo build --release --bin haap-rsv --bin haap-sdk

# Distroless runtime.
FROM gcr.io/distroless/cc-debian12

COPY --from=builder /build/hx_labs/target/release/haap-auth-bin /usr/local/bin/
COPY --from=builder /build/hx_labs/target/release/haap-tqs-precompute-bin /usr/local/bin/
COPY --from=builder /build/hx_labs/target/release/haap-tqs-jit-bin /usr/local/bin/
COPY --from=builder /build/hx_labs/target/release/haap-assembler-bin /usr/local/bin/
COPY --from=builder /build/hx_labs/target/release/haap-supervisor /usr/local/bin/
COPY --from=builder /build/hx_agentic_sdk/target/release/haap-rsv /usr/local/bin/
COPY --from=builder /build/hx_agentic_sdk/target/release/haap-sdk /usr/local/bin/

# Default entrypoint = supervisor (most common customer-side deployment).
ENTRYPOINT ["/usr/local/bin/haap-supervisor"]
