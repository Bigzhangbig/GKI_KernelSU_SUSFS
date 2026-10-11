"""Exercise the patched KernelSU UAPI using its actual C header and dispatch functions.

Run after applying the pinned patch, for example:
    python3 tests/test_uapi5_contract.py --source /path/to/KernelSU --ndk /path/to/android-ndk
    python3 tests/test_uapi5_contract.py --source /path/to/KernelSU --host-header

The host harness stubs kernel/user-copy and lifecycle dependencies. It tests
branches and ABI declarations, not boot, root privileges, or SuSFS on a device.
"""

import argparse
import os
import re
import subprocess
import tempfile
from pathlib import Path


INFO_STRUCTS = ("ksu_get_info_cmd", "ksu_get_info_legacy_cmd", "ksu_report_event_cmd")
UAPI_NAMES = (
    "KERNEL_SU_UAPI_VERSION", "EVENT_POST_FS_DATA", "EVENT_BOOT_COMPLETED",
    "EVENT_MODULE_MOUNTED", "EVENT_SERVICES", "KSU_GET_INFO_FLAG_MANAGER",
    "KSU_GET_INFO_FLAG_BUNDLED",
)
FUNCTION_NAMES = ("do_get_info", "do_get_info_legacy", "do_report_event")
ALLOWED_SESSION_CMDS = {"KSU_IOCTL_GET_WRAPPER_FD", "KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT"}


def c_function(source: str, name: str) -> str:
    match = re.search(r"\b(?:static\s+)?(?:int|long)\s+" + re.escape(name)
                      + r"\s*\([^;]*?\)\s*\{", source, re.S)
    if not match:
        raise AssertionError(f"actual function {name} missing")
    start = match.start()
    depth = 0
    for index in range(match.end() - 1, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError(f"unterminated function {name}")


def c_table(source: str) -> str:
    match = re.search(r"static const struct ksu_ioctl_cmd_map\s+ksu_ioctl_handlers\[\]\s*=\s*\{",
                      source)
    if not match:
        raise AssertionError("actual ioctl dispatch table missing")
    depth = 0
    for index in range(match.end() - 1, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start():index + 2]  # include semicolon
    raise AssertionError("unterminated ioctl table")


def header_declarations(header: str) -> str:
    declarations = []
    for name in UAPI_NAMES:
        match = re.search(r"^DECLARE\(__u32,\s*" + re.escape(name) + r",[^\n]+;",
                          header, re.M)
        if not match:
            raise AssertionError(f"actual UAPI declaration {name} missing")
        declarations.append(match.group())
    for name in INFO_STRUCTS:
        match = re.search(r"^struct\s+" + name + r"\s*\{.*?^\};", header, re.M | re.S)
        if not match:
            raise AssertionError(f"actual UAPI struct {name} missing")
        declarations.append(match.group())
    return "\n".join(declarations)


def table_entries(table: str) -> dict[str, str]:
    entries = {}
    for block in re.findall(r"\{\s*\.cmd\s*=\s*KSU_IOCTL_.*?\}", table, re.S):
        cmd = re.search(r"\.cmd\s*=\s*(KSU_IOCTL_\w+)", block).group(1)
        if cmd in entries:
            raise AssertionError(f"duplicate ioctl table command: {cmd}")
        entries[cmd] = block
    if not entries:
        raise AssertionError("ioctl table has no command entries")
    actual = {name for name, block in entries.items()
              if re.search(r"\.allow_su_session\s*=\s*true\b", block)}
    if actual != ALLOWED_SESSION_CMDS:
        raise AssertionError(f"su-session permission whitelist {actual} != {ALLOWED_SESSION_CMDS}")
    return entries


def host_harness(header: str, dispatch: str) -> str:
    declarations = header_declarations(header)
    functions = "\n\n".join(c_function(dispatch, name) for name in FUNCTION_NAMES)
    dispatcher = c_function(dispatch, "ksu_supercall_handle_ioctl")
    table = c_table(dispatch)
    entries = table_entries(table)
    handler_names = set(re.findall(r"\.handler\s*=\s*(\w+)", table)) - set(FUNCTION_NAMES) - {"NULL"}
    permission_names = set(re.findall(r"\.perm_check\s*=\s*(\w+)", table)) - {"NULL"}
    handlers = "\n".join(f"static int {name}(void *arg) {{ (void)arg; return 123; }}"
                         for name in sorted(handler_names))
    permissions = "\n".join(f"static bool {name}(void) {{ return permission_allowed; }}"
                            for name in sorted(permission_names))
    commands = "enum { " + ", ".join(f"{name} = {1000 + i}" for i, name in
                                   enumerate(entries)) + " };"
    return f"""
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
typedef uint32_t __u32;
#define DECLARE(type, name, val) enum {{ name = val }}
#define __user
#define __init
#define KERNEL_SU_VERSION 40971
#define KSU_FEATURE_MAX 37
#define pr_info(...) ((void)0)
#define pr_warn(...) ((void)0)
#define pr_err(...) ((void)0)
{declarations}
_Static_assert(sizeof(struct ksu_get_info_cmd) == 16, "get_info ABI size");
static bool manager, fail_copy_from, fail_copy_to, permission_allowed, session_fd;
static bool is_manager(void) {{ return manager; }}
static int copy_from_user(void *to, const void *from, size_t size) {{
    if (fail_copy_from) return 1;
    memcpy(to, from, size); return 0;
}}
static int copy_to_user(void *to, const void *from, size_t size) {{
    if (fail_copy_to) return 1;
    memcpy(to, from, size); return 0;
}}
static void on_post_fs_data(void) {{}}
static void on_boot_completed(void) {{}}
static void on_module_mounted(void) {{}}
{functions}
{commands}
struct file {{ int unused; }};
static bool ksu_is_su_session_fd(const struct file *file) {{ (void)file; return session_fd; }}
{handlers}
{permissions}
struct ksu_ioctl_cmd_map {{
    unsigned int cmd;
    const char *name;
    int (*handler)(void *);
    bool (*perm_check)(void);
    bool allow_su_session;
}};
{table}
{dispatcher}
#define CHECK(cond) do {{ if (!(cond)) {{ \
    fprintf(stderr, "CHECK failed at line %d: %s\\n", __LINE__, #cond); return 1; \
}} }} while (0)
int main(void) {{
    struct ksu_report_event_cmd event = {{ .event = EVENT_SERVICES }};
    struct ksu_get_info_cmd info;
    struct ksu_get_info_legacy_cmd legacy;
    struct file file = {{ 0 }};
    CHECK(KERNEL_SU_UAPI_VERSION == 5);
    CHECK(KSU_GET_INFO_FLAG_BUNDLED == 16);
    CHECK(do_report_event(&event) == 1);
    CHECK(do_report_event(&event) == 0);
    event.event = EVENT_POST_FS_DATA;
    CHECK(do_report_event(&event) == 0);
    event.event = EVENT_SERVICES;
    CHECK(do_report_event(&event) == 1);
    fail_copy_from = true;
    CHECK(do_report_event(&event) == -EFAULT);
    fail_copy_from = false;
    for (int is_manager_app = 0; is_manager_app <= 1; ++is_manager_app) {{
        manager = is_manager_app;
        memset(&info, 0xa5, sizeof(info));
        CHECK(do_get_info(&info) == 0);
        CHECK(info.version == 40971 && info.uapi_version == 5);
        CHECK(info.features == KSU_FEATURE_MAX);
        CHECK(info.flags == (is_manager_app ? KSU_GET_INFO_FLAG_MANAGER : 0));
        CHECK((info.flags & KSU_GET_INFO_FLAG_BUNDLED) == 0);
        CHECK(do_get_info_legacy(&legacy) == 0);
        CHECK(legacy.version == 40971 && legacy.features == KSU_FEATURE_MAX);
        CHECK(legacy.flags == (is_manager_app ? KSU_GET_INFO_FLAG_MANAGER : 0));
    }}
    fail_copy_to = true;
    CHECK(do_get_info(&info) == -EFAULT);
    CHECK(do_get_info_legacy(&legacy) == -EFAULT);
    fail_copy_to = false;
    permission_allowed = false;
    session_fd = true;
    for (size_t i = 0; ksu_ioctl_handlers[i].handler; ++i) {{
        int allowed = ksu_ioctl_handlers[i].cmd == KSU_IOCTL_GET_WRAPPER_FD ||
                      ksu_ioctl_handlers[i].cmd == KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT;
        CHECK(ksu_supercall_handle_ioctl(&file, ksu_ioctl_handlers[i].cmd, NULL) ==
              (allowed ? 123 : -EPERM));
    }}
    session_fd = false;
    CHECK(ksu_supercall_handle_ioctl(&file, KSU_IOCTL_GET_WRAPPER_FD, NULL) == -EPERM);
    CHECK(ksu_supercall_handle_ioctl(&file, KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT, NULL) == -EPERM);
    puts("actual dispatch functions: UAPI5, event transitions, copy faults, built-in flags, scoped FD");
    return 0;
}}
"""


def compile_and_run_host(source: str, directory: Path, label: str, expect_success: bool) -> None:
    path = directory / f"{label}.c"
    binary = directory / label
    path.write_text(source)
    built = subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Werror", "-Wno-unused-function",
                            "-o", str(binary), str(path)], capture_output=True, text=True)
    if built.returncode:
        raise AssertionError(f"{label} host harness did not compile:\n{built.stderr}")
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    if (result.returncode == 0) != expect_success:
        raise AssertionError(f"{label}: unexpected exit {result.returncode}:\n{result.stdout}{result.stderr}")
    print(f"{label}: {'pass' if expect_success else 'failure detected'}")


def header_check(source_root: Path, directory: Path, compiler: list[str],
                 label: str, expect_success: bool) -> None:
    header_test = """#include <stdbool.h>
#include "uapi/supercall.h"
_Static_assert(KERNEL_SU_UAPI_VERSION == 5, "UAPI must be 5");
_Static_assert(KSU_GET_INFO_FLAG_BUNDLED == (1U << 4), "BUNDLED bit");
_Static_assert(sizeof(struct ksu_get_info_cmd) == 16, "GET_INFO C ABI");
int event_case(int x) {
    switch (x) { case EVENT_POST_FS_DATA: return 0; case EVENT_SERVICES: return 1; default: return -1; }
}
"""
    result = subprocess.run(compiler + ["-std=c11", "-Werror", "-fsyntax-only", "-x", "c", "-",
                             "-I", str(directory / "kernel/include"),
                             "-I", str(source_root / "kernel/include")],
                            input=header_test, capture_output=True, text=True)
    if (result.returncode == 0) != expect_success:
        raise AssertionError(f"{label} header check exit {result.returncode}:\n{result.stderr}")
    if not expect_success and not ("UAPI must be 5" in result.stderr and
                                   "KSU_GET_INFO_FLAG_BUNDLED" in result.stderr):
        raise AssertionError(f"old header failed for the wrong reason:\n{result.stderr}")
    print(f"{label} header: {'pass' if expect_success else 'old UAPI rejected'}")


def header_compiler(ndk: Path, host_header: bool) -> tuple[list[str], str]:
    if host_header:
        # Linux userspace UAPI headers may leave the kernel pointer annotation
        # undefined; Android's NDK linux/compiler.h already makes it empty.
        return [os.environ.get("CC", "cc"), "-D__user="], "Host"
    clang_candidates = list((ndk / "toolchains/llvm/prebuilt").glob("*/bin/clang"))
    if not clang_candidates:
        raise FileNotFoundError(f"Android NDK clang missing under {ndk}")
    return [str(clang_candidates[0]), "--target=aarch64-linux-android26"], "Android"


def mutate_services(dispatch: str, replacement: str, which: str) -> str:
    original = c_function(dispatch, "do_report_event")
    if original.count("case EVENT_SERVICES:") != 1 or original.count("default:") != 1:
        raise AssertionError("EVENT_SERVICES case missing")
    case = original.split("case EVENT_SERVICES:", 1)[1].split("default:", 1)[0]
    needle = "return 1;" if which == "first" else "return 0;"
    if case.count(needle) != 1:
        raise AssertionError(f"expected exactly one {needle} in services case")
    changed = case.replace(needle, replacement, 1)
    return dispatch.replace(original, original.replace(case, changed, 1), 1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="patched KernelSU source root")
    parser.add_argument("--ndk", type=Path, default=Path(os.environ.get("ANDROID_NDK_HOME", "")),
                        help="Android NDK root (or ANDROID_NDK_HOME)")
    parser.add_argument("--host-header", action="store_true",
                        help="compile the actual UAPI header with the Linux host C compiler")
    args = parser.parse_args()
    source_root = args.source.resolve()
    header_path = source_root / "kernel/include/uapi/supercall.h"
    dispatch_path = source_root / "kernel/supercall/dispatch.c"
    header, dispatch = header_path.read_text(), dispatch_path.read_text()
    compiler, label = header_compiler(args.ndk, args.host_header)
    with tempfile.TemporaryDirectory(prefix="uapi5-contract-") as temp:
        directory = Path(temp)
        header_check(source_root, source_root, compiler, label, True)
        compile_and_run_host(host_harness(header, dispatch), directory, "real_source", True)

        # Red test against the pinned clean checkout's actual pre-patch header.
        old = subprocess.run(["git", "show", "HEAD:kernel/include/uapi/supercall.h"],
                             cwd=source_root, capture_output=True, text=True, check=True).stdout
        old_include = directory / "kernel/include/uapi"
        old_include.mkdir(parents=True)
        (old_include / "supercall.h").write_text(old)
        header_check(source_root, directory, compiler, label, False)

        # Isolated mutations prove the event assertions reject both wrong returns.
        always_zero = mutate_services(dispatch, "return 0;", "first")
        compile_and_run_host(host_harness(header, always_zero), directory, "services_always_zero", False)
        always_one = mutate_services(dispatch, "return 1;", "repeat")
        compile_and_run_host(host_harness(header, always_one), directory, "services_always_one", False)


if __name__ == "__main__":
    main()
