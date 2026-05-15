# Release process (Mechanism 2)

## Tag-to-release workflow

The SDK uses GitHub Actions to bundle binaries from two sibling
workspaces (`hx_agentic_sdk` + `hx_labs`) into a unified distribution.

To cut a release:

```bash
git tag -a v0.1.0-alpha.1 -m "alpha.1"
git push origin v0.1.0-alpha.1
```

The `release.yml` workflow triggers automatically and produces:
- Six platform-specific tarballs (or `.zip` on Windows)
- A multi-arch Docker image at `ghcr.io/hawcx/hx-agent-sdk:<tag>`

The same workflow can be triggered manually via the GitHub Actions UI
(`workflow_dispatch`).

## Tier 1 targets (six platforms)

| Target | OS runner | Note |
|---|---|---|
| `x86_64-unknown-linux-gnu` | ubuntu-latest | native |
| `aarch64-unknown-linux-gnu` | ubuntu-latest | cross (cross-rs) |
| `x86_64-apple-darwin` | macos-13 | Intel macOS |
| `aarch64-apple-darwin` | macos-14 | Apple Silicon |
| `x86_64-pc-windows-msvc` | windows-latest | native |
| `aarch64-pc-windows-msvc` | windows-latest | cross (Visual Studio) |

## Distribution contents

Each tarball contains:

```
hx-agent-sdk-<version>-<target>/
├── bin/
│   ├── haap-auth-bin                  (from hx_labs)
│   ├── haap-tqs-precompute-bin        (from hx_labs)
│   ├── haap-tqs-jit-bin               (from hx_labs)
│   ├── haap-assembler-bin             (from hx_labs)
│   ├── haap-supervisor                (from hx_labs)
│   ├── haap-rsv                       (from SDK; crate haap-rsv-bin)
│   └── haap-sdk                       (from SDK; crate haap-sdk-cli)
├── README.md
└── docs/
```

Seven binaries total: five from hx_labs, two from the SDK.

## Docker image

`ghcr.io/hawcx/hx-agent-sdk:<tag>` and `:latest`. Multi-arch
(`linux/amd64` + `linux/arm64`) via buildx. Built from `Dockerfile`
which expects both source trees in the build context.

Default ENTRYPOINT is `/usr/local/bin/haap-supervisor` (the most
common customer-side deployment). Override with `--entrypoint
/usr/local/bin/haap-rsv` to run the RSV sidecar, or
`/usr/local/bin/haap-sdk` for the CLI.

## Required secrets

- **`HX_LABS_READ_TOKEN`** — a PAT (fine-grained or classic) with
  read access to the private `hawcx/hx_labs` repository. The
  workflow checks out `hx_labs` as a sibling via this token.
- `GITHUB_TOKEN` — automatic; used by docker buildx to push to GHCR.

## Future scope

- **Mobile targets** (alpha+1): iOS + Android via UniFFI bindings
  around the SDK's `haap-rsv` library. Requires xcframework / .aar
  artifacts in addition to the platform tarballs.
- **System packages** (post-alpha): `.deb` and `.rpm` for Linux
  distributions, Homebrew tap for macOS, scoop/Chocolatey for
  Windows.
- **Native TLS variants**: today everything uses rustls; adding
  `--features native-tls` for environments that mandate it.
