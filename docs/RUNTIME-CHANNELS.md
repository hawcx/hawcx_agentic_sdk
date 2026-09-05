# Runtime channel matrix

All release workflows pin the **published hawcx-manager 0.11.8** from
`cargo.hawcx.com` with `cargo install --locked --version =0.11.8`.
`haap-unseal-orch` is the same binary invoked by its role name. It is a copy in
npm/PyPI and Windows tarballs, a symlink in Unix tarballs/images. There is no
second orchestrator crate version to synchronize. PR CI checks pin and target
agreement; release execution verifies actual bytes and role dispatch.

| Target | npm platform | Python wheel | Tarball | Native execution in release job |
|---|---|---|---|---|
| Linux x86_64 | linux-x64 | manylinux2014_x86_64 | yes | yes |
| Linux aarch64 | linux-arm64 | manylinux2014_aarch64 | yes | yes |
| macOS arm64 | darwin-arm64 | macosx_11_0_arm64 | yes | yes |
| Windows x86_64 | win32-x64 | win_amd64 | yes | yes |
| Windows arm64 | win32-arm64 | win_arm64 | yes | **unverified: cross-compiled** |

The Docker image covers the two Linux targets. Native laptop PoC use does not
require that image. This table names existing packaging targets, not evidence
that every resulting artifact has executed or passed UKG acceptance. In
particular the existing `manylinux2014` wheel tags are not an ABI certification
of the Ubuntu-built executable; deployment must verify the actual target loader
and libraries. Windows arm64 needs native execution before candidate acceptance.

Before upload, native runners check the exact manager version, identical
orchestrator bytes and a bounded invocation that must reach security-audited,
fail-closed startup without custody configuration. Timeout, missing executable,
linker error, generic help and unexpected startup success fail the check. This
probe does **not** prove successful unlock, pipeline launch or IPC interoperability.
Cache hits run the same check. npm publishes the inspected `.tgz`; wheel checking
reads the final archive and compares both runtime entries with staged bytes.

## Candidate release gate

The 0.11.8 package was independently downloaded on 2026-09-05, not yanked, with
SHA-256 `a933ff9728a93d11241cf9dce59d4aad3c272c8b7765ea5a927e60787187b219`.
Its source contains both `haap-unseal-orch` argv0 and `unseal-orch` subcommand
routes and forwards the role to `run_unseal_orch`. Source verification is not
native execution. Native packaging probes added here still need a release run.

This pin intentionally does **not** claim the unpublished CAS custody safety
batch is included. Before the UKG candidate is released:

1. Publish the reviewed CAS runtime with completed custody integration; select
   its actual **hawcx-manager crate** version, not the workspace or standalone
   orchestrator version. Update all three pins together.
2. Run native package builds, install each candidate wheel/npm package and
   distribution tarball, and invoke the installed runtime. Preserve artifact
   digests and exact embedded versions. A green unit-test job is insufficient.
3. Exercise SDK client interoperability with the candidate Manager/CAS instance:
   enrollment, guardianship unlock, isolated authenticator startup, request and
   response, restart/zeroization, and rejected cross-principal calls.
4. Record signed macOS delivery/notarization and Windows arm64 native results
   separately. Do not count cross-compile byte checks as execution.

No package publication or customer rollout is performed by this change.
