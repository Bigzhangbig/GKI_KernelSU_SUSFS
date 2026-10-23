"""Check the audited Release ABI and actual builtin C source behavior."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".github/workflows/scripts"))
from release_target import load_release_target
import contract_helpers as base
from test_mount_hide_contract import check_source as check_mount_hide_source

TARGET = load_release_target()

def require_text(path, patterns):
    text = path.read_text(encoding="utf-8-sig")
    for pattern in patterns:
        if re.search(pattern, text, re.S) is None:
            raise AssertionError(f"Release source contract failed: {path}: {pattern}")
    return text

def preinit_contract(source):
    makefile = require_text(source / "kernel/Makefile", [r"(?m)^ccflags-y \+= -DKSU_NO_PREINIT$"])
    if re.search(r"(?m)^ksu-y\s*\+=.*preinit/|^targets\s*\+=.*preinit/", makefile):
        raise AssertionError("Release must disable the unconnected preinit runner unconditionally")


def header_abi(source, compiler):
    if TARGET.uapi != 6:
        raise AssertionError("No audited header ABI recipe for this Release UAPI")
    # Values and offsets independently taken from the official release header.
    checks = '''
#include <stdbool.h>
#include <stddef.h>
#include "uapi/supercall.h"
#include "uapi/extension.h"
#define KERNEL_VERSION(a, b, c) (((a) << 16) | ((b) << 8) | (c))
#define LINUX_VERSION_CODE KERNEL_VERSION(5, 10, 209)
#include "uapi/feature.h"
_Static_assert(KERNEL_SU_UAPI_VERSION == 6, "Release requires UAPI6");
_Static_assert(KSU_FEATURE_MAX == 17, "Release feature ceiling");
_Static_assert(KSU_GET_INFO_FLAG_LKM == 1 && KSU_GET_INFO_FLAG_MANAGER == 2 &&
               KSU_GET_INFO_FLAG_LATE_LOAD == 4 && KSU_GET_INFO_FLAG_PR_BUILD == 8 &&
               KSU_GET_INFO_FLAG_BUNDLED == 16 && KSU_GET_INFO_FLAG_PREINIT == 32, "Release flags");
_Static_assert(EVENT_POST_FS_DATA == 1 && EVENT_BOOT_COMPLETED == 2 &&
               EVENT_MODULE_MOUNTED == 3 && EVENT_SERVICES == 4, "Release event numbers");
_Static_assert(KSU_IOCTL_GET_INFO == 0x80104b02U, "release GET_INFO ioctl");
_Static_assert(KSU_IOCTL_GET_INFO_LEGACY == 0x80004b02U, "release legacy ioctl");
_Static_assert(KSU_IOCTL_REPORT_EVENT == 0x40004b03U, "release event ioctl");
_Static_assert(KSU_IOCTL_GET_WRAPPER_FD == 0x40004b0fU, "release wrapper ioctl");
_Static_assert(KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT == 0x4b15U, "release scoped ioctl");
_Static_assert(KSU_IOCTL_LOOKUP_SYMBOLS == 0x40184b16U, "release lookup ioctl22");
/* The official _IOC nr=300 crosses the eight-bit nr field: preserve its ABI. */
_Static_assert(KSU_IOCTL_EXTENSION == 0xc0204b2cU, "release extension ioctl300");
_Static_assert(sizeof(struct ksu_lookup_symbols_cmd) == 24, "release lookup size");
_Static_assert(offsetof(struct ksu_lookup_symbols_cmd, names) == 0 &&
               offsetof(struct ksu_lookup_symbols_cmd, addrs) == 8 &&
               offsetof(struct ksu_lookup_symbols_cmd, count) == 16 &&
               offsetof(struct ksu_lookup_symbols_cmd, flags) == 20, "release lookup offsets");
_Static_assert(KSU_LOOKUP_SYMBOLS_MAX == 1024, "release lookup limit");
_Static_assert(sizeof(struct ksu_extension_cmd) == 32, "release extension size");
_Static_assert(offsetof(struct ksu_extension_cmd, value) == 16 &&
               offsetof(struct ksu_extension_cmd, user_ptr) == 24, "release extension offsets");
_Static_assert(KSU_EXTENSION_DYNAMIC_MANAGER == 3 && KSU_EXTENSION_MAX == 5,
               "release extension ids");
_Static_assert(KSU_EXTENSION_GET == 1 && KSU_EXTENSION_SET == 2 &&
               KSU_EXTENSION_IO == 3 && KSU_EXTENSION_WIPE == 4 &&
               KSU_EXTENSION_FLAG_FORCED == 128, "release extension operations");
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
    print("official release ABI: UAPI6, feature17, GET_INFO, lookup22 and extension300 sizes/offsets pass")

def manager_harness(source):
    declaration = (source / "kernel/include/uapi/manager.h").read_text()
    declaration = re.sub(r"^#include.*$", "", declaration, flags=re.M)
    dynamic = (source / "kernel/extension/dynamic_manager.c").read_text()
    function = base.c_function(dynamic, "ksu_extension_dynamic_manager_io")
    return '''
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
typedef uint32_t __u32;
typedef uint32_t u32;
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
#define do_manager(arg) ksu_extension_dynamic_manager_io(3, arg)
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
    puts("actual dynamic-manager extension IO: allocation/copy faults, GET response, SET operations pass");
    return 0;
}
'''

def lookup_harness(header, dispatch):
    declaration = re.search(r"struct ksu_lookup_symbols_cmd \{.*?\n\};", header, re.S).group()
    function = base.c_function(dispatch, "do_lookup_symbols")
    return r'''
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
typedef uint32_t __u32;
typedef uint32_t u32;
typedef uint64_t __aligned_u64;
typedef uint64_t u64;
#define __user
#define GFP_KERNEL 0
#define KSYM_NAME_LEN 128
#define KSU_LOOKUP_SYMBOLS_MAX 1024
#define pr_err(...) ((void)0)
#define ERR_PTR(x) ((void *)(intptr_t)(x))
#define IS_ERR(x) ((uintptr_t)(x) >= (uintptr_t)-4095)
#define PTR_ERR(x) ((intptr_t)(x))
static bool read_fail, get_fail, put_fail, name_fail;
static int allocation, alloc_fail_at, allocated, freed, resolver_error, resolver_calls;
static int copy_from_user(void *to, const void *from, size_t size) {
    if (read_fail) return 1; memcpy(to, from, size); return 0;
}
#define get_user(out, ptr) (get_fail ? 1 : ((out) = *(ptr), 0))
#define put_user(value, ptr) (put_fail ? 1 : (*(ptr) = (value), 0))
static void *kvcalloc(size_t count, size_t size, int flags) {
    (void)flags; ++allocation;
    if (allocation == alloc_fail_at) return NULL;
    ++allocated; return calloc(count, size);
}
static void kvfree(void *ptr) { if (ptr) ++freed; free(ptr); }
static void kfree(void *ptr) { kvfree(ptr); }
static char *strndup_user(const char *str, size_t max) {
    if (name_fail) return ERR_PTR(-EFAULT);
    size_t len = strlen(str);
    if (len >= max) return ERR_PTR(-EINVAL);
    char *out = malloc(len + 1); ++allocated; memcpy(out, str, len + 1); return out;
}
static int ksu_lookup_kernel_symbols(const char *const *names, unsigned long *addrs, u32 count) {
    ++resolver_calls;
    if (resolver_error) return resolver_error;
    int found = 0;
    for (u32 i = 0; i < count; ++i) {
        if (names[i] && !strcmp(names[i], "known")) { addrs[i] = 0x12345678; ++found; }
    }
    return found;
}
''' + declaration + '\n' + function + r'''
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "lookup CHECK line %d: %s\n", __LINE__, #x); return 1; } } while (0)
int main(void) {
    char long_name[129]; memset(long_name, 'x', 128); long_name[128] = 0;
    u64 names[] = {(u64)(uintptr_t)"known", (u64)(uintptr_t)"missing",
                   (u64)(uintptr_t)"", (u64)(uintptr_t)long_name};
    u64 addrs[] = {99, 99, 99, 99};
    struct ksu_lookup_symbols_cmd cmd = {(u64)(uintptr_t)names, (u64)(uintptr_t)addrs, 4, 0};
    read_fail = true; CHECK(do_lookup_symbols(&cmd) == -EFAULT && resolver_calls == 0);
    read_fail = false; cmd.flags = 1; CHECK(do_lookup_symbols(&cmd) == -EINVAL);
    cmd.flags = 0; cmd.count = 0; CHECK(do_lookup_symbols(&cmd) == -EINVAL);
    cmd.count = 1025; CHECK(do_lookup_symbols(&cmd) == -EINVAL); cmd.count = 4;
    for (int fault = 1; fault <= 2; ++fault) {
        allocation = 0; alloc_fail_at = fault;
        CHECK(do_lookup_symbols(&cmd) == -ENOMEM && allocated == freed);
    }
    alloc_fail_at = 0; get_fail = true;
    CHECK(do_lookup_symbols(&cmd) == -EFAULT && allocated == freed); get_fail = false;
    name_fail = true; CHECK(do_lookup_symbols(&cmd) == -EFAULT && allocated == freed); name_fail = false;
    CHECK(do_lookup_symbols(&cmd) == 1 && addrs[0] == 0x12345678 && addrs[1] == 0 &&
          addrs[2] == 0 && addrs[3] == 0 && allocated == freed);
    put_fail = true; CHECK(do_lookup_symbols(&cmd) == -EFAULT && allocated == freed); put_fail = false;
    resolver_error = -EIO; CHECK(do_lookup_symbols(&cmd) == -EIO && allocated == freed);
    puts("actual lookup22: flags/count limits, copy/allocation/resolver faults, missing symbols, cleanup pass");
    return 0;
}
'''


def extension_harness(header, dispatch):
    declaration = re.search(r"enum ksu_extension_id \{.*?\n\};", header, re.S).group()
    declaration += '\n' + re.search(r"struct ksu_extension_cmd \{.*?\n\};", header, re.S).group()
    function = base.c_function(dispatch, "do_extension")
    return r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef uint32_t u32;
typedef uint64_t u64;
#define __user
#define KSU_EXTENSION_GET 1
#define KSU_EXTENSION_SET 2
#define KSU_EXTENSION_IO 3
#define KSU_EXTENSION_WIPE 4
#define KSU_FEATURE_FLAG_SUPPORTED 1
#define KSU_EXTENSION_FLAG_FORCED 128
static bool read_fail, write_fail, supported = true, forced;
static int error, calls_get, calls_set, calls_io, calls_wipe;
static u32 seen_id;
static void *seen_pointer;
static u64 stored_value = 9;
static int copy_from_user(void *to, const void *from, size_t size) {
    if (read_fail) return 1; memcpy(to, from, size); return 0;
}
static int copy_to_user(void *to, const void *from, size_t size) {
    if (write_fail) return 1; memcpy(to, from, size); return 0;
}
static int ksu_extension_ioctl(u32 id, void *arg) {
    ++calls_io; seen_id = id; seen_pointer = arg; return error;
}
static int ksu_extension_wipe(u32 id) { ++calls_wipe; seen_id = id; return error; }
static int ksu_extension_set(u32 id, u64 value) {
    ++calls_set; seen_id = id; if (!error) stored_value = value; return error;
}
static int ksu_extension_get(u32 id, u64 *value, bool *out_supported) {
    ++calls_get; seen_id = id; *value = stored_value; *out_supported = supported; return error;
}
static bool ksu_extension_is_forced(u32 id) { seen_id = id; return forced; }
''' + declaration + '\n' + function + r'''
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "extension CHECK line %d: %s\n", __LINE__, #x); return 1; } } while (0)
int main(void) {
    struct ksu_extension_cmd cmd = {.id = KSU_EXTENSION_DYNAMIC_MANAGER, .op = KSU_EXTENSION_GET};
    read_fail = true; CHECK(do_extension(&cmd) == -EFAULT && calls_get == 0); read_fail = false;
    cmd.id = KSU_EXTENSION_MAX; CHECK(do_extension(&cmd) == -EINVAL && calls_get == 0);
    cmd.id = KSU_EXTENSION_DYNAMIC_MANAGER;
    CHECK(do_extension(&cmd) == 0 && seen_id == 3 && cmd.value == 9 && cmd.supported == 1);
    forced = true; CHECK(do_extension(&cmd) == 0 && cmd.supported == 129); forced = false;
    supported = false; CHECK(do_extension(&cmd) == -EOPNOTSUPP); supported = true;
    error = -EIO; CHECK(do_extension(&cmd) == -EIO); error = 0;
    write_fail = true; CHECK(do_extension(&cmd) == -EFAULT); write_fail = false;
    cmd.op = KSU_EXTENSION_SET; cmd.value = 42; forced = true;
    CHECK(do_extension(&cmd) == 0 && calls_set == 1 && cmd.value == 42 && cmd.supported == 129);
    error = -EPERM; CHECK(do_extension(&cmd) == -EPERM && calls_set == 2); error = 0;
    write_fail = true; CHECK(do_extension(&cmd) == -EFAULT && stored_value == 42); write_fail = false;
    cmd.op = KSU_EXTENSION_IO; cmd.user_ptr = 0x1234;
    CHECK(do_extension(&cmd) == 0 && calls_io == 1 && seen_pointer == (void *)(uintptr_t)0x1234);
    error = -EIO; CHECK(do_extension(&cmd) == -EIO && calls_io == 2); error = 0;
    cmd.op = KSU_EXTENSION_WIPE; CHECK(do_extension(&cmd) == 0 && calls_wipe == 1);
    error = -EPERM; CHECK(do_extension(&cmd) == -EPERM && calls_wipe == 2);
    puts("actual extension300: manager routing, GET/SET state/forced flags, IO pointers, WIPE and faults pass");
    return 0;
}
'''


def common_contract(source, common):
    kernel = source / "kernel"
    require_text(kernel / "Makefile", [
        rf"(?m)^KSU_VERSION\s*:= {TARGET.version}$",
        rf"(?m)^VERSION_TAG\s*:= {re.escape(TARGET.backend_tag.removeprefix('v'))}$",
        rf"(?m)^KSU_VERSION_FULL\s*:= {re.escape(TARGET.full_version)}$",
        r"(?m)^ccflags-y \+= -DKSU_NO_PREINIT$"])
    require_text(kernel / "manager/apk_sign.c", [r'\{\s*0x35c,\s*"' + TARGET.manager_certificate_sha256 + r'"\s*\}'])
    require_text(kernel / "supercall/dispatch.c", [
        r"\.cmd = KSU_IOCTL_EXTENSION,[^}]*\.handler = do_extension,[^}]*\.perm_check = manager_or_root",
        r"\.cmd = KSU_IOCTL_LOOKUP_SYMBOLS,[^}]*\.handler = do_lookup_symbols,[^}]*\.perm_check = only_root",
        r"ksu_ioctl_handlers\[i\]\.allow_su_session && ksu_is_su_session_fd\(filp\)"])
    require_text(kernel / "infra/file_wrapper.c", [
        r"old_cred = override_creds\(ksu_cred\);\s*wrapper_file = .*?;\s*revert_creds\(old_cred\);"])
    require_text(kernel / "feature/sucompat.c", [
        r"bool ksu_su_compat_enabled __read_mostly = true;",
        r"if \(likely\(!__ksu_is_allow_uid_for_current\(current_uid\(\)\.val\)\)\)\s*return -EINVAL;",
        r"if \(current_chrooted\(\)\).*?return -EINVAL;",
        r"if \(ret\) \{.*?return -EINVAL;.*?\}\s*return 0;",
        r"int ksu_handle_post_execveat_sucompat\(.*?if \(\*retval >= 0\) \{\s*\(void\)ksu_install_su_fd\(\);"])
    require_text(common / "fs/exec.c", [
        r"bool is_su_session = false;",
        r"if \(likely\(susfs_is_current_proc_no_su\(\)\)\)\s*goto orig_flow;",
        r"if \(likely\(READ_ONCE\(ksu_su_compat_enabled\)\)\)",
        r"is_su_session = !ksu_handle_execveat\(&fd, &filename, &argv, &envp, &flags\);",
        r"is_su_session = !ksu_handle_execveat_sucompat\(&fd, &filename, &argv, &envp, &flags\);",
        r"retval = bprm_execve\(bprm, fd, filename, flags\);\s*#ifdef CONFIG_KSU_SUSFS\s*if \(unlikely\(is_su_session\)\)\s*\(void\)ksu_handle_post_execveat_sucompat\(&fd, &filename, &argv, &envp, &flags, &retval\);"])
    for relative in ("fs/exec.c", "fs/open.c", "fs/stat.c"):
        hooks = require_text(common / relative, [r"extern bool ksu_su_compat_enabled;",
                                                r"if \(likely\(READ_ONCE\(ksu_su_compat_enabled\)\)\)"])
        if re.search(r"static_branch_\w+\(&ksu_su_compat_enabled\)", hooks):
            raise AssertionError("bool sucompat flag must never be used as a static key: " + relative)
    require_text(kernel / "runtime/ksud.c", [
        r"int ksu_handle_sys_read\(unsigned int fd, char __user \*\*buf_ptr, size_t \*count_ptr\)"])
    reads = require_text(common / "fs/read_write.c", [
        r"extern int ksu_handle_sys_read\(unsigned int fd, char __user \*\*buf_ptr, size_t \*count_ptr\);",
        r"if \(static_branch_unlikely\(&ksu_is_init_rc_hook_enabled\)\)\s*\(void\)ksu_handle_sys_read\(fd, &buf, &count\);"])
    if re.search(r"void ksu_handle_sys_read|ksu_handle_sys_read\(fd\);", reads):
        raise AssertionError("read hook must match the builtin three-argument ABI")
    require_text(common / "include/linux/susfs.h", [r'#define\s+SUSFS_VERSION\s+"v' + re.escape(TARGET.susfs_version) + r'"'])
    major, minor = TARGET.kernel_tuple[1].split(".")
    require_text(common / "Makefile", [rf"(?m)^VERSION = {major}$",
        rf"(?m)^PATCHLEVEL = {minor}$", rf"(?m)^SUBLEVEL = {TARGET.kernel_tuple[2]}$"])
    lines = (common / "arch/arm64/configs/gki_defconfig").read_text().splitlines()
    for key in ("CONFIG_KSU", "CONFIG_KSU_SUSFS"):
        values = [line for line in lines if line.startswith(key + "=")]
        if not values or values[-1] != key + "=y":
            raise AssertionError("Release requires effective " + key + "=y")
    with tempfile.TemporaryDirectory(prefix="Release-common-contract-") as tmp:
        directory = Path(tmp)
        base.compile_and_run_host(base.common_hook_harness(source, common), directory, "real_common_hooks", True)
        original = (common / "fs/exec.c").read_text()
        mutated, changed = re.subn(r"if \(likely\(susfs_is_current_proc_no_su\(\)\)\)", "if (false)", original)
        if changed != 1:
            raise AssertionError("expected one no-su guard for mutation test")
        base.compile_and_run_host(base.common_hook_harness(source, common, mutated), directory, "wrong_common_no_su", False)
    print("actual common hooks, successful-exec suFD guard, signature, SuSFS and target sources pass")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--common", type=Path)
    parser.add_argument("--host-header", action="store_true")
    parser.add_argument("--ndk", type=Path, default=Path(os.environ.get("ANDROID_NDK_HOME", "")))
    args = parser.parse_args()
    source = args.source.resolve()
    # This pinned SuSFS integration has no preinit hook; never advertise it.
    preinit_contract(source)
    check_mount_hide_source((source / "kernel/feature/mount_hide.c").read_text())
    if args.common is not None:
        common_contract(source, args.common.resolve())
        return
    header = (source / "kernel/include/uapi/supercall.h").read_text(encoding="utf-8-sig")
    dispatch = (source / "kernel/supercall/dispatch.c").read_text()
    entries = base.table_entries(base.c_table(dispatch))
    for cmd, permission in (("KSU_IOCTL_EXTENSION", "manager_or_root"),
                            ("KSU_IOCTL_LOOKUP_SYMBOLS", "only_root")):
        if cmd not in entries or not re.search(r"\.perm_check\s*=\s*" + permission + r"\b", entries[cmd]):
            raise AssertionError(cmd + " must remain restricted to " + permission)
    compiler, label = base.header_compiler(args.ndk, args.host_header)
    with tempfile.TemporaryDirectory(prefix="Release-contract-") as tmp:
        directory = Path(tmp)
        header_abi(source, compiler)
        base.compile_and_run_host(base.host_harness(header, dispatch, TARGET.version, TARGET.uapi, TARGET.features), directory, "preinit_branch", True)
        base.compile_and_run_host(base.host_harness(header, dispatch, TARGET.version, TARGET.uapi,
                                                  TARGET.features, False), directory, "release_no_preinit", True)
        base.compile_and_run_host(manager_harness(source), directory, "real_manager_dispatch", True)
        base.compile_and_run_host(lookup_harness(header, dispatch), directory, "real_lookup", True)
        extension = (source / "kernel/include/uapi/extension.h").read_text()
        base.compile_and_run_host(extension_harness(extension, dispatch), directory, "real_extension", True)
        # A controlled UAPI5 rollback must fail even when all other declarations
        # are current; it must not fail merely because an old git object is absent.
        old, changed = re.subn(r"DECLARE\(__u32,\s*KERNEL_SU_UAPI_VERSION,\s*6\);",
                               "DECLARE(__u32, KERNEL_SU_UAPI_VERSION, 5);", header)
        if changed != 1:
            raise AssertionError("expected one native UAPI6 declaration")
        old_include = directory / "kernel/include/uapi"
        old_include.mkdir(parents=True)
        (old_include / "supercall.h").write_text(old)
        base.header_check(source, directory, compiler, label, False, TARGET.uapi)
        for which, value in (("first", "return 0;"), ("repeat", "return 1;")):
            mutated = base.mutate_services(dispatch, value, which)
            base.compile_and_run_host(base.host_harness(header, mutated, TARGET.version, TARGET.uapi, TARGET.features), directory, "wrong_services_" + which, False)
        wrong_flags = dispatch.replace("cmd.flags |= KSU_GET_INFO_FLAG_PREINIT;",
                                       "cmd.flags |= 0;", 1)
        if wrong_flags == dispatch:
            raise AssertionError("PREINIT branch missing")
        base.compile_and_run_host(base.host_harness(header, wrong_flags, TARGET.version, TARGET.uapi,
                                                   TARGET.features), directory, "wrong_preinit_flag", False)
        wrong_count = dispatch.replace("!cmd.count || cmd.count > KSU_LOOKUP_SYMBOLS_MAX",
                                       "cmd.count > KSU_LOOKUP_SYMBOLS_MAX", 1)
        if wrong_count == dispatch:
            raise AssertionError("lookup count guard missing")
        base.compile_and_run_host(lookup_harness(header, wrong_count), directory, "wrong_lookup_count", False)
        wrong_pointer = dispatch.replace("(void __user *)(uintptr_t)cmd.user_ptr", "NULL", 1)
        if wrong_pointer == dispatch:
            raise AssertionError("extension user pointer forwarding missing")
        base.compile_and_run_host(extension_harness(extension, wrong_pointer), directory, "wrong_extension_pointer", False)
    print("Release real C contract passed; runtime boot/root remain untested")

if __name__ == "__main__":
    main()
