# Official CI 40971 / UAPI5 with SuSFS

This manually dispatched profile builds Android12 GKI 5.10.209 (2024-05) for
an official SukiSU manager whose version code is 40971 and native UAPI is 5.
It produces an AnyKernel3 ZIP and build evidence; it does not flash a device,
publish a Release, or send a notification.

## Source and compatibility

- GKI common: `f0826289c51653ee116c20c1dda9c87ad8a30636`.
- SukiSU builtin: `6c284e957feaa9a388a9f1c37dc4ec80d95e434b`.
- SuSFS Android12-5.10: `9892175b4acec7ee844e113b8d02c0f4d12cdfac` (2.3.0).
- SukiSU patches: `547ae94bcaec53d030398f857950c64662043a5d`.

The pinned builtin source already implements the UAPI3 scoped su-session FD
and the UAPI5 services event result. Its header still advertises UAPI2. The
checked-in patch advertises the implemented contract and adds the UAPI4
Bundled flag declaration. Bundled stays zero because this branch only builds
KernelSU into the kernel. `KSU_VERSION` is separately fixed to 40971; the
upstream Makefile otherwise computes it from the moving main branch.

Su-session FDs can bypass the ordinary permission check only for wrapper FD
creation and disabling escape-to-root. The SuSFS exec hook must first succeed
for an allowed su request and then complete exec successfully before installing
such a descriptor. The profile verifies these existing paths rather than
replacing them with hooks from main.

The existing official manager certificate is retained (DER length 860,
SHA256 `947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef`).
There is no custom manager certificate or disabled signature check.

KPM is disabled in this variant. It is independent of Root and SuSFS, and the
binary KPM injector is not part of this build. Other optional extensions from
SukiSU main are not claimed to have been ported by this header patch.

## Build and verification

Run the **Build official 40971-5 (UAPI5 + SUSFS)** workflow. The profile rejects
incorrect source pins or target tuples and stops on required patch failures.
Each workflow attempt uses its own workspace and verifies the actual patched
source before compiling. The resulting Image and configuration must come from
that attempt.

Local builder checks:

```sh
python3 -m unittest discover -s tests -v
actionlint .github/workflows/kernel-40971-5.yml
```

After applying the patch to the pinned KernelSU checkout:

```sh
python3 tests/test_uapi5_contract.py --source /path/to/KernelSU --host-header
# Optional Android ABI check on a host with the NDK installed:
python3 tests/test_uapi5_contract.py --source /path/to/KernelSU --ndk /path/to/ndk
```

The contract harness extracts the real C dispatch functions. It checks version
and UAPI propagation, the first/repeated/post-fs services sequence, copy faults,
and the two-command scoped-FD whitelist. It rejects the old UAPI2 header and
isolated mutations of both services return values. Its kernel dependencies are
stubbed: these checks do not prove device boot, Root, or SuSFS runtime behavior.
Those require a separately authorized device test after compilation.
