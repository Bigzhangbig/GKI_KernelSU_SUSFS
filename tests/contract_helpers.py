"""Compile and exercise actual C declarations and dispatch functions."""
import os
import re
import subprocess
from pathlib import Path


INFO_STRUCTS = ("ksu_get_info_cmd", "ksu_get_info_legacy_cmd", "ksu_report_event_cmd")
UAPI_NAMES = (
    "KERNEL_SU_UAPI_VERSION", "EVENT_POST_FS_DATA", "EVENT_BOOT_COMPLETED",
    "EVENT_MODULE_MOUNTED", "EVENT_SERVICES", "KSU_GET_INFO_FLAG_MANAGER",
    "KSU_GET_INFO_FLAG_BUNDLED", "KSU_GET_INFO_FLAG_PREINIT",
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


def host_harness(header: str, dispatch: str, kernel_version: int,
                 uapi: int = 6, features: int = 17, preinit: bool = True) -> str:
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
#define KERNEL_SU_VERSION {kernel_version}
#define KSU_FEATURE_MAX {features}
#define CONFIG_KSU_SUSFS 1
{"" if preinit else "#define KSU_NO_PREINIT 1"}
#define pr_info(...) ((void)0)
#define pr_warn(...) ((void)0)
#define pr_err(...) ((void)0)
{declarations}
_Static_assert(sizeof(struct ksu_get_info_cmd) == 16, "get_info ABI size");
static bool manager, fail_copy_from, fail_copy_to, permission_allowed, session_fd;
static bool preinit_enabled;
static int post_fs_calls, boot_calls, mounted_calls, monitor_calls;
static bool ksu_preinit_enabled_param(void) {{ return preinit_enabled; }}
static bool is_manager(void) {{ return manager; }}
static int copy_from_user(void *to, const void *from, size_t size) {{
    if (fail_copy_from) return 1;
    memcpy(to, from, size); return 0;
}}
static int copy_to_user(void *to, const void *from, size_t size) {{
    if (fail_copy_to) return 1;
    memcpy(to, from, size); return 0;
}}
static void on_post_fs_data(void) {{ ++post_fs_calls; }}
static void on_boot_completed(void) {{ ++boot_calls; }}
static void on_module_mounted(void) {{ ++mounted_calls; }}
static void susfs_start_sdcard_monitor_fn(void) {{ ++monitor_calls; }}
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
    CHECK(KERNEL_SU_UAPI_VERSION == {uapi});
    CHECK(KSU_GET_INFO_FLAG_PREINIT == 32);
    CHECK(KSU_GET_INFO_FLAG_BUNDLED == 16);
    CHECK(do_report_event(&event) == 1);
    CHECK(do_report_event(&event) == 0);
    event.event = EVENT_POST_FS_DATA;
    CHECK(do_report_event(&event) == 0);
    CHECK(do_report_event(&event) == 0 && post_fs_calls == 1);
    event.event = EVENT_BOOT_COMPLETED;
    CHECK(do_report_event(&event) == 0 && boot_calls == 1 && monitor_calls == 1);
    CHECK(do_report_event(&event) == 0 && boot_calls == 1 && monitor_calls == 1);
    event.event = EVENT_MODULE_MOUNTED;
    CHECK(do_report_event(&event) == 0 && mounted_calls == 1);
    CHECK(do_report_event(&event) == 0 && mounted_calls == 2);
    event.event = 999;
    CHECK(do_report_event(&event) == 0);
    event.event = EVENT_SERVICES;
    CHECK(do_report_event(&event) == 1);
    fail_copy_from = true;
    CHECK(do_report_event(&event) == -EFAULT);
    fail_copy_from = false;
    for (int enabled = 0; enabled <= 1; ++enabled) {{
    preinit_enabled = enabled;
    for (int is_manager_app = 0; is_manager_app <= 1; ++is_manager_app) {{
        manager = is_manager_app;
        memset(&info, 0xa5, sizeof(info));
        CHECK(do_get_info(&info) == 0);
        CHECK(info.version == {kernel_version} && info.uapi_version == {uapi});
        CHECK(info.features == KSU_FEATURE_MAX);
        CHECK(info.flags == ((is_manager_app ? KSU_GET_INFO_FLAG_MANAGER : 0) |
              ((enabled && {1 if preinit else 0}) ? KSU_GET_INFO_FLAG_PREINIT : 0)));
        CHECK((info.flags & KSU_GET_INFO_FLAG_BUNDLED) == 0);
        CHECK(do_get_info_legacy(&legacy) == 0);
        CHECK(legacy.version == {kernel_version} && legacy.features == KSU_FEATURE_MAX);
        CHECK(legacy.flags == (is_manager_app ? KSU_GET_INFO_FLAG_MANAGER : 0));
    }}
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
    permission_allowed = true;
    CHECK(ksu_supercall_handle_ioctl(&file, KSU_IOCTL_LOOKUP_SYMBOLS, NULL) == 123);
    CHECK(ksu_supercall_handle_ioctl(&file, KSU_IOCTL_EXTENSION, NULL) == 123);
    CHECK(ksu_supercall_handle_ioctl(&file, 0xffffffffU, NULL) == -ENOTTY);
    puts("actual dispatch: UAPI{uapi}, event callbacks/transitions, copy faults, PREINIT flags, scoped FD");
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
                 label: str, expect_success: bool, uapi: int = 6) -> None:
    header_test = """#include <stdbool.h>
#include "uapi/supercall.h"
_Static_assert(KERNEL_SU_UAPI_VERSION == EXPECTED_UAPI, "UAPI version mismatch");
_Static_assert(KSU_GET_INFO_FLAG_BUNDLED == (1U << 4), "BUNDLED bit");
_Static_assert(sizeof(struct ksu_get_info_cmd) == 16, "GET_INFO C ABI");
int event_case(int x) {
    switch (x) { case EVENT_POST_FS_DATA: return 0; case EVENT_SERVICES: return 1; default: return -1; }
}
"""
    header_test = header_test.replace("EXPECTED_UAPI", str(uapi))
    result = subprocess.run(compiler + ["-std=c11", "-Werror", "-fsyntax-only", "-x", "c", "-",
                             "-I", str(directory / "kernel/include"),
                             "-I", str(source_root / "kernel/include")],
                            input=header_test, capture_output=True, text=True)
    if (result.returncode == 0) != expect_success:
        raise AssertionError(f"{label} header check exit {result.returncode}:\n{result.stderr}")
    if not expect_success and "UAPI version mismatch" not in result.stderr:
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


def common_hook_harness(source: Path, common: Path, exec_override: str | None = None) -> str:
    """Exercise the exact added common hook blocks, with kernel services stubbed."""
    def prehook(text):
        blocks = re.findall(r"if \([^\n]+\)\s*goto orig_flow;.*?orig_flow:", text, re.S)
        if len(blocks) != 1:
            raise AssertionError("expected one actual no-su hook block")
        return blocks[0]

    exec_source = exec_override if exec_override is not None else (common / "fs/exec.c").read_text()
    exec_hook = prehook(exec_source)
    access_hook = prehook((common / "fs/open.c").read_text())
    stat_hook = prehook((common / "fs/stat.c").read_text())
    post_hook = re.search(r"if \(unlikely\(is_su_session\)\)\s*\(void\)ksu_handle_post_execveat_sucompat\([^;]+;",
                          exec_source).group()
    read_hook = re.search(r"if \(static_branch_unlikely\(&ksu_is_init_rc_hook_enabled\)\)\s*\(void\)ksu_handle_sys_read\([^;]+;",
                          (common / "fs/read_write.c").read_text()).group()
    sucompat = (source / "kernel/feature/sucompat.c").read_text()
    combined = c_function(sucompat, "ksu_handle_execveat")
    post = c_function(sucompat, "ksu_handle_post_execveat_sucompat")
    return r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#define __user
#define CONFIG_KSU_SUSFS 1
#define KSU_COMPAT_USE_STATIC_KEY 1
#define likely(x) (x)
#define unlikely(x) (x)
#define READ_ONCE(x) (x)
#define static_branch_unlikely(key) ((key)->enabled)
struct static_key_true { bool enabled; };
struct filename { const char *name; };
struct user_arg_ptr { int unused; };
struct uid { unsigned val; };
static struct static_key_true susfs_is_sdcard_android_data_not_decrypted, is_first_zygote;
static struct static_key_true ksu_is_init_rc_hook_enabled;
static bool no_su, ksu_su_compat_enabled, uid_allowed, bad_arguments;
static int ksud_calls, su_calls, access_calls, stat_calls, read_calls, installed_fds;
static int su_result, exec_result;
static char read_buffer[8];
static bool susfs_is_current_proc_no_su(void) { return no_su; }
static bool __ksu_is_allow_uid_for_current(unsigned uid) { (void)uid; return uid_allowed; }
static struct uid current_uid(void) { return (struct uid){10001}; }
static int ksu_handle_execveat_ksud(int *fd, struct filename **name, void *argv, void *envp, int *flags) {
    (void)fd; (void)name; (void)argv; (void)envp; (void)flags; ++ksud_calls; return 0;
}
static int ksu_handle_execveat_sucompat(int *fd, struct filename **name, void *argv, void *envp, int *flags) {
    (void)fd; (void)name; (void)argv; (void)envp; (void)flags; ++su_calls; return su_result;
}
static int ksu_install_su_fd(void) { ++installed_fds; return 0; }
static int ksu_handle_faccessat(int *fd, struct filename **name, int *mode, int *flags) {
    ++access_calls;
    if (*fd != 9 || !*name || *mode != 4 || flags != NULL) bad_arguments = true;
    return 0;
}
static int ksu_handle_stat(int *fd, struct filename **name, int *flags) {
    ++stat_calls;
    if (*fd != 9 || !*name || *flags != 5) bad_arguments = true;
    return 0;
}
static int ksu_handle_sys_read(unsigned int fd, char **buf, size_t *count) {
    ++read_calls;
    if (fd != 9 || *buf != read_buffer || *count != 8) bad_arguments = true;
    *buf += 1; --*count;
    return 0;
}
''' + combined + '\n' + post + r'''
static void run_exec(void) {
    int fd = 9, flags = 0, retval;
    struct filename name = {"/system/bin/su"}, *filename = &name;
    struct user_arg_ptr argv = {0}, envp = {0};
    bool is_su_session = false;
''' + exec_hook + r'''
    retval = exec_result;
''' + post_hook + r'''
}
static void run_access(void) {
    int dfd = 9, mode = 4;
    struct filename name = {"/system/bin/su"}, *fname = &name;
''' + access_hook + r'''
    return;
}
static void run_stat(void) {
    int dfd = 9, flags = 5;
    struct filename name = {"/system/bin/su"}, *fname = &name;
''' + stat_hook + r'''
    return;
}
static bool run_read(void) {
    unsigned int fd = 9;
    char *buf = read_buffer;
    size_t count = sizeof(read_buffer);
''' + read_hook + r'''
    return buf == read_buffer + 1 && count == 7;
}
static void reset(void) {
    ksud_calls = su_calls = access_calls = stat_calls = read_calls = installed_fds = 0;
    no_su = false; ksu_su_compat_enabled = uid_allowed = true;
    su_result = exec_result = 0; bad_arguments = false;
    is_first_zygote.enabled = susfs_is_sdcard_android_data_not_decrypted.enabled = true;
}
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "common hooks CHECK line %d: %s\n", __LINE__, #x); return 1; } } while (0)
int main(void) {
    for (int gate = 0; gate < 2; ++gate) {
        reset(); if (gate) no_su = true; else ksu_su_compat_enabled = false;
        run_exec(); run_access(); run_stat();
        CHECK(ksud_calls == 0 && su_calls == 0 && access_calls == 0 && stat_calls == 0 && installed_fds == 0);
    }
    reset(); run_exec(); CHECK(ksud_calls == 1 && su_calls == 1 && installed_fds == 1);
    reset(); is_first_zygote.enabled = false; run_exec();
    CHECK(ksud_calls == 0 && su_calls == 1 && installed_fds == 1);
    reset(); susfs_is_sdcard_android_data_not_decrypted.enabled = false; run_exec();
    CHECK(ksud_calls == 0 && su_calls == 1 && installed_fds == 1);
    reset(); su_result = -EINVAL; run_exec(); CHECK(installed_fds == 0);
    reset(); exec_result = -EIO; run_exec(); CHECK(installed_fds == 0);
    reset(); uid_allowed = false; run_access(); run_stat(); CHECK(access_calls == 0 && stat_calls == 0);
    reset(); run_access(); run_stat(); CHECK(access_calls == 1 && stat_calls == 1 && !bad_arguments);
    ksu_is_init_rc_hook_enabled.enabled = false; CHECK(!run_read() && read_calls == 0);
    ksu_is_init_rc_hook_enabled.enabled = true; CHECK(run_read() && read_calls == 1 && !bad_arguments);
    puts("actual common hooks: no-su/feature/UID gates, decrypt and first-zygote routing, exec-result suFD, read argument flow pass");
    return 0;
}
'''
