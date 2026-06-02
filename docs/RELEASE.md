# Release process

This repo is **release-only** (no Rust source ships from here). The
customer-facing `hawcx-manager` binary is built from
`hx_agent_client_auth_service`, published to the private Kellnr registry
at `cargo.hawcx.com`, and pulled into each release via
`cargo install hawcx-manager --registry hawcx --version =<pin> --locked`.

## Workflows

| Workflow | Trigger | Produces |
|---|---|---|
| `release.yml` | `v*` tag | Per-target tarballs, multi-arch GHCR image, signed `SHA256SUMS`, GitHub Release |
| `release-node.yml` | `node-v*` tag | 6 `@hawcx/*` npm packages (OIDC Trusted Publishing) |
| `release-python.yml` | `python-v*` tag | Platform wheels + sdist to PyPI (OIDC Trusted Publishing) |

`release.yml` can also be run via `workflow_dispatch`.

## Version pinning (INF-01)

The bundled `hawcx-manager` crate version is a single source of truth:
the `HAWCX_MANAGER_VERSION` env var at the top of each release workflow
(currently `0.8.2`). It is decoupled from the SDK git tag
(`v0.1.0-alpha.N`) by design. The install step pins
`--version =${HAWCX_MANAGER_VERSION}` and a post-install step asserts the
installed binary reports exactly that version, so a build of an
already-evaluated tag can never silently pick up a newer (or malicious)
publish from `cargo.hawcx.com`. When bumping `hawcx-manager`, update this
env var in all three workflows AND `CLAUDE.md`.

## Action pinning (INF-02)

Every third-party (and first-party) GitHub Action is pinned to a full
40-char commit SHA with a trailing `# vX.Y.Z` comment. Dependabot
(`.github/dependabot.yml`, `github-actions` ecosystem) bumps the SHAs.
Do not reintroduce a tag/branch ref (`@v3`, `@stable`, `@release/v1`) —
the `no-rust-source`/lint discipline and review must reject it.

## Supply-chain provenance & signing (INF-03)

- The GHCR image is built with `provenance: mode=max` + `sbom: true`
  (SLSA build provenance + SBOM attestation attached to the image).
- The published multi-arch manifest is **cosign keyless-signed by
  digest** (`docker_manifest` job; OIDC identity = this repo's workflow).
- The GitHub Release includes a `SHA256SUMS` over all tarballs, plus its
  cosign signature (`SHA256SUMS.sig`) and certificate (`SHA256SUMS.pem`).

### Verifying a release as a customer

Image (replace `<TAG>`):

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/hawcx/hawcx_agentic_sdk/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/hawcx/hx-agent-sdk:<TAG>

# Inspect the attached SLSA provenance + SBOM attestations:
cosign verify-attestation --type slsaprovenance \
  --certificate-identity-regexp '^https://github.com/hawcx/hawcx_agentic_sdk/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/hawcx/hx-agent-sdk:<TAG>
```

Tarballs:

```bash
# 1. Verify the checksum manifest's signature (binds all tarballs).
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature   SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github.com/hawcx/hawcx_agentic_sdk/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS

# 2. Verify each tarball against the now-trusted manifest.
sha256sum -c SHA256SUMS
```

## Distribution contents

Each tarball (`hx-agent-sdk-<tag>-<target>.tar.gz`) ships ONE real binary
(`hawcx-manager`) plus 7 legacy-name symlinks (Unix) / `.exe` copies
(Windows) that dispatch by `argv[0]`: `haap-authenticator`,
`haap-tqs-precompute`, `haap-tqs-jit`, `haap-assembler`, `haap-eib`,
`haap-supervisor`, `haap-sdk`. See
`hx_agent_canonical_spec/DESIGN-MEMO-MULTICALL-BINARY.md`.

The `haap-rsv` MCP-server-side verifier ships from a **separate** image
(`ghcr.io/hawcx/haap-rsv`) built out of `hx_agent_authorizer`.

## Docker image

`ghcr.io/hawcx/hx-agent-sdk:<tag>` (multi-arch `linux/amd64` +
`linux/arm64`). Prereleases also move the matching channel tag
(`:alpha` / `:beta` / `:rc`); `:latest` is reserved for GA. Built from
`Dockerfile.fast` (registry-installed binary COPY). The repo's
`Dockerfile` is **dev/reference-only** (INF-10) and is NOT the published
build.

Default ENTRYPOINT is `/usr/local/bin/haap-supervisor`.

## Required secrets

- `CARGO_HAWCX_TOKEN` — Kellnr registry token for installing
  `hawcx-manager` (written `chmod 600`).
- `GITHUB_TOKEN` — automatic; GHCR push + cosign signature upload.
- npm / PyPI publishing uses **OIDC Trusted Publishing** — no static
  tokens. Trusted-publisher entries are configured per package on
  npmjs.com / PyPI bound to this repo + workflow + environment.

## Future scope

- Mobile targets (iOS/Android via UniFFI), system packages (`.deb`,
  `.rpm`, Homebrew, scoop/Chocolatey), and a `native-tls` variant.
