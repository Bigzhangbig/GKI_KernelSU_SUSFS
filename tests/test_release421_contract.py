"""Check real builtin C sources against the v4.2.1 / 40994 UAPI5 contract.

Reference: SukiSU-Ultra fd2a85151c8312fd9b4237db9ba827dcea692228.
Host stubs exercise dispatch and user-copy branches; they cannot prove boot/root.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile

import test_uapi5_contract as base

VERSION = 40994
CERT = "947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef"

def require_text(path, patterns):
    text = path.read_text(encoding="utf-8-sig")
    for pattern in patterns:
        if re.search(pattern, text, re.S) is None:
            raise AssertionError(f"release421 source contract failed: {path}: {pattern}")
    return text

def header_abi(source, compiler):
    # Values and offsets independently taken from the official release header.
    checks = '''
#include <stdbool.h>
#include <stddef.h>
#include "uapi/supercall.h"
_Static_assert(KERNEL_SU_UAPI_VERSION == 5, "release421 requires UAPI5");
_Static_assert(KSU_IOCTL_GET_INFO == 0x80104b02U, "release GET_INFO ioctl");
_Static_assert(KSU_IOCTL_GET_INFO_LEGACY == 0x80004b02U, "release legacy ioctl");
_Static_assert(KSU_IOCTL_REPORT_EVENT == 0x40004b03U, "release event ioctl");
_Static_assert(KSU_IOCTL_GET_WRAPPER_FD == 0x40004b0fU, "release wrapper ioctl");
_Static_assert(KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT == 0x4b15U, "release scoped ioctl");
_Static_assert(KSU_IOCTL_MANAGER == 0xcd984b6aU, "release manager ioctl106");
_Static_assert(sizeof(struct ksu_get_info_cmd) == 16, "release info size");
_Static_assert(offsetof(struct ksu_get_info_cmd, uapi_version) == 12, "release UAPI offset");
_Static_assert(sizeof(struct ksu_manager_entry) == 204, "release entry size");
_Static_assert(sizeof(struct ksu_manager_cmd) == 3480, "release manager size");
_Static_assert(offsetof(struct ksu_manager_cmd, entries) == 216, "release manager entries offset");
_Static_assert(KSU_MANAGER_GET == 0 && KSU_MANAGER_ADD == 1 && KSU_MANAGER_REMOVE == 2 &&
               KSU_MANAGER_SET_ENABLED == 3 && KSU_MANAGER_CLEAR == 4, "release operations");
'''
    args = compiler + ["-std=c11", "-Werror", "-fsyntax-only", "-x", "c", "-",
                       "-I", str(source / "kernel/include")]
    result = subprocess.run(args, input=checks, capture_output=True, text=True)
    if result.returncode:
        raise AssertionError("official release ABI mismatch:\n" + result.stderr)
    print("official release ABI: UAPI5, GET_INFO and manager ioctl106 sizes/offsets pass")

def manager_harness(source, dispatch):
    declaration = (source / "kernel/include/uapi/manager.h").read_text()
    declaration = re.sub(r"^#include.*$", "", declaration, flags=re.M)
    function = base.c_function(dispatch, "do_manager")
    return '''
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
typedef uint32_t __u32;
#define __user
#define GFP_KERNEL 0
''' + declaration + '''
static bool alloc_fail, read_fail, write_fail;
static int manager_get_calls, manager_set_calls, frees, response;
static void *kzalloc(size_t size, int flags) {
    (void)flags; return alloc_fail ? NULL : calloc(1, size);
}
static void kfree(void *ptr) { ++frees; free(ptr); }
static int copy_from_user(void *to, const void *from, size_t size) {
    if (read_fail) return 1; memcpy(to, from, size); return 0;
}
static int copy_to_user(void *to, const void *from, size_t size) {
    if (write_fail) return 1; memcpy(to, from, size); return 0;
}
static int ksu_dynamic_manager_get(struct ksu_manager_cmd *cmd) {
    ++manager_get_calls; cmd->count = 3; return response;
}
static int ksu_dynamic_manager_set(struct ksu_manager_cmd *cmd) {
    (void)cmd; ++manager_set_calls; return response;
}
''' + function + '''
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "manager CHECK line %d\\n", __LINE__); return 1; } } while (0)
int main(void) {
    struct ksu_manager_cmd cmd = {0};
    alloc_fail = true; CHECK(do_manager(&cmd) == -ENOMEM && frees == 0);
    alloc_fail = false; read_fail = true;
    CHECK(do_manager(&cmd) == -EFAULT && frees == 1 && manager_get_calls == 0 && manager_set_calls == 0);
    read_fail = false; cmd.operation = KSU_MANAGER_GET;
    CHECK(do_manager(&cmd) == 0 && cmd.count == 3 && manager_get_calls == 1 && manager_set_calls == 0);
    write_fail = true; CHECK(do_manager(&cmd) == -EFAULT); write_fail = false;
    response = -EINVAL; CHECK(do_manager(&cmd) == -EINVAL);
    for (unsigned op = KSU_MANAGER_ADD; op <= KSU_MANAGER_CLEAR; ++op) {
        cmd.operation = op; response = 42; CHECK(do_manager(&cmd) == 42);
    }
    CHECK(manager_set_calls == 4 && frees == 8);
    puts("actual manager dispatch: allocation/copy faults, GET response, SET operations pass");
    return 0;
}
'''

def common_contract(source, common):
    kernel = source / "kernel"
    require_text(kernel / "Makefile", [
        r"(?m)^KSU_VERSION\s*:= 40994$", r"(?m)^VERSION_TAG\s*:= 4\.2\.1$",
        r"(?m)^KSU_VERSION_FULL\s*:= v4\.2\.1-ee35e654@builtin$"])
    require_text(kernel / "manager/apk_sign.c", [r'\{\s*0x35c,\s*"' + CERT + r'"\s*\}'])
    require_text(kernel / "supercall/dispatch.c", [
        r"\.cmd = KSU_IOCTL_MANAGER,[^}]*\.handler = do_manager,[^}]*\.perm_check = manager_or_root",
        r"ksu_ioctl_handlers\[i\]\.allow_su_session && ksu_is_su_session_fd\(filp\)"])
    require_text(kernel / "infra/file_wrapper.c", [
        r"old_cred = override_creds\(ksu_cred\);\s*wrapper_file = .*?;\s*revert_creds\(old_cred\);"])
    require_text(kernel / "feature/sucompat.c", [
        r"if \(!\(__ksu_is_allow_uid_for_current\(current_uid\(\)\.val\)\)\)\s*return -EINVAL;",
        r"if \(current_chrooted\(\)\).*?return -EINVAL;",
        r"if \(ret\) \{.*?return -EINVAL;.*?\}\s*return 0;",
        r"int ksu_handle_post_execveat_sucompat\(.*?if \(\*retval >= 0\) \{\s*\(void\)ksu_install_su_fd\(\);"])
    require_text(common / "fs/exec.c", [
        r"bool is_su_session = false;",
        r"if \(likely\(susfs_is_current_proc_no_su\(\)\)\)\s*goto orig_flow;",
        r"if \(static_branch_likely\(&ksu_su_compat_enabled\)\)",
        r"is_su_session = !ksu_handle_execveat\(&fd, &filename, &argv, &envp, &flags\);",
        r"is_su_session = !ksu_handle_execveat_sucompat\(&fd, &filename, &argv, &envp, &flags\);",
        r"retval = bprm_execve\(bprm, fd, filename, flags\);\s*#ifdef CONFIG_KSU_SUSFS\s*if \(unlikely\(is_su_session\)\)\s*\(void\)ksu_handle_post_execveat_sucompat\(&fd, &filename, &argv, &envp, &flags, &retval\);"])
    require_text(common / "include/linux/susfs.h", [r'#define\s+SUSFS_VERSION\s+"v2\.3\.0"'])
    require_text(common / "Makefile", [r"(?m)^VERSION = 5$", r"(?m)^PATCHLEVEL = 10$", r"(?m)^SUBLEVEL = 209$"])
    lines = (common / "arch/arm64/configs/gki_defconfig").read_text().splitlines()
    for key in ("CONFIG_KSU", "CONFIG_KSU_SUSFS"):
        values = [line for line in lines if line.startswith(key + "=")]
        if not values or values[-1] != key + "=y":
            raise AssertionError("release421 requires effective " + key + "=y")
    print("actual common hooks, successful-exec suFD guard, signature, SuSFS and target sources pass")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--common", type=Path)
    parser.add_argument("--host-header", action="store_true")
    parser.add_argument("--ndk", type=Path, default=Path(os.environ.get("ANDROID_NDK_HOME", "")))
    args = parser.parse_args()
    source = args.source.resolve()
    if args.common is not None:
        common_contract(source, args.common.resolve())
        return
    header = (source / "kernel/include/uapi/supercall.h").read_text(encoding="utf-8-sig")
    dispatch = (source / "kernel/supercall/dispatch.c").read_text()
    entries = base.table_entries(base.c_table(dispatch))
    if "KSU_IOCTL_MANAGER" not in entries or ".perm_check = manager_or_root" not in entries["KSU_IOCTL_MANAGER"]:
        raise AssertionError("manager ioctl must remain restricted to manager/root")
    compiler, label = base.header_compiler(args.ndk, args.host_header)
    with tempfile.TemporaryDirectory(prefix="release421-contract-") as tmp:
        directory = Path(tmp)
        header_abi(source, compiler)
        base.compile_and_run_host(base.host_harness(header, dispatch, VERSION), directory, "real_source_40994", True)
        base.compile_and_run_host(manager_harness(source, dispatch), directory, "real_manager_dispatch", True)
        old = subprocess.run(["git", "show", "HEAD:kernel/include/uapi/supercall.h"], cwd=source,
                             check=True, capture_output=True, text=True).stdout
        old_include = directory / "kernel/include/uapi"
        old_include.mkdir(parents=True)
        (old_include / "supercall.h").write_text(old)
        base.header_check(source, directory, compiler, label, False)
        for which, value in (("first", "return 0;"), ("repeat", "return 1;")):
            mutated = base.mutate_services(dispatch, value, which)
            base.compile_and_run_host(base.host_harness(header, mutated, VERSION), directory, "wrong_services_" + which, False)
    print("release421 real C contract passed; runtime boot/root remain untested")

if __name__ == "__main__":
    main()
