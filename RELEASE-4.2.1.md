# SukiSU v4.2.1 / 40994 release profile

This profile updates the builtin root source to
`ee35e65428054476c279eae59f7f2bba272040b9`, including the dynamic-manager
implementation and its builtin build fixes. It keeps the previously booted
Android12 GKI 5.10.209 base, SuSFS 2.3.0, and disables KPM and KSU_DEBUG.

The official v4.2.1 APK (40994) requires **UAPI5**, including exact equality in
ksud. Current development UAPI6 is a different target. The pinned builtin already
implements scoped su-session descriptors and the first/repeat EVENT_SERVICES
return contract, but its header still advertises UAPI2. The checked header patch
advertises the existing UAPI5 behavior and adds the BUNDLED constant without
setting that flag for builtin mode. The source identity and numeric/full versions
are fixed, and the official certificate authorization is retained.

Run the manual **Build SukiSU release 4.2.1** workflow, or on a Linux build host:

```sh
python3 .github/workflows/scripts/build.py --release-4-2-1 \
  --android android12 --kernel 5.10 --sub-level 209 --os-patch 2024-05 --revision r13 \
  --ksu-commit ee35e65428054476c279eae59f7f2bba272040b9 \
  --susfs-commit 9892175b4acec7ee844e113b8d02c0f4d12cdfac \
  --no-kpm --no-release --workspace /tmp/gki-release421 \
  --output-json /tmp/gki-release421/build-result.json
```

Each build needs fresh output. Real-source C/ABI checks run before compilation;
source hooks, signature, effective generated config, source pins, ZIP contents and
linked machine code are checked separately. The workflow exports a compact ZIP
and evidence only after validation; failed inspection input is explicitly marked
unverified. It does not publish a GitHub Release or send Telegram messages.

The official builtin branch lacks the mainline CPU-spoof ioctl105; that optional
manager tool is unsupported. Uname spoofing uses the retained SuSFS path, rather
than the absent independent UTS ioctl104. A built artifact is not evidence of
boot, root or module behavior on a phone; flashing and runtime acceptance remain
separate user-controlled steps. The old 40971/UAPI5 profile remains available.

References: [official release](https://github.com/SukiSU-Ultra/SukiSU-Ultra/releases/tag/v4.2.1),
[pinned builtin](https://github.com/SukiSU-Ultra/SukiSU-Ultra/commit/ee35e65428054476c279eae59f7f2bba272040b9).
