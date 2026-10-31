"""Check the real common-to-builtin SELinux routing boundary.

The C harness exercises actual common wrappers with their callees replaced by
argument-recording stubs. It proves routing and return propagation, not the
correctness of SELinux policy decisions inside those callees.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile


WRAPPERS = ("handle_selinux_setprocattr", "handle_sel_write_context", "handle_sel_write_access")


def function(source, name):
    match = re.search(r"\b(?:static\s+)?(?:int|ssize_t)\s+" + re.escape(name)
                      + r"\s*\([^;]*?\)\s*\{", source, re.S)
    if not match:
        raise AssertionError("missing actual SELinux helper: " + name)
    depth = 0
    for index in range(match.end() - 1, len(source)):
        depth += (source[index] == "{") - (source[index] == "}")
        if depth == 0:
            return source[match.start():index + 1]
    raise AssertionError("unterminated actual SELinux helper: " + name)


def reject_fake_state(text, label):
    code = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
    if re.search(r"\bfake_state\b", code):
        raise AssertionError("obsolete or fabricated fake_state in " + str(label))


def check_declarations(builtin, hooks, filesystem):
    for name, signature, common in (
        ("my_setprocattr", r"int my_setprocattr\(const char \*name, void \*value, size_t size\)", hooks),
        ("my_write_context", r"ssize_t my_write_context\(struct file \*file, char \*buf, size_t size\)", filesystem),
        ("my_write_access", r"ssize_t my_write_access\(struct file \*file, char \*buf, size_t size\)", filesystem),
    ):
        if not re.search(r"(?m)^" + signature + r"\s*\{", builtin):
            raise AssertionError("builtin must export the real SELinux entry: " + name)
        if not re.search(r"\bextern\s+" + signature + r";", common):
            raise AssertionError("common prototype must match builtin: " + name)
        if re.search(r"\bstatic\s+" + signature, common):
            raise AssertionError("common must delegate instead of shadowing builtin: " + name)
    if not re.search(r"#ifdef CONFIG_KSU_SUSFS\s*LSM_HOOK_INIT\(setprocattr, handle_selinux_setprocattr\),\s*"
                     r"#else\s*LSM_HOOK_INIT\(setprocattr, selinux_setprocattr\)", hooks):
        raise AssertionError("LSM setprocattr must register the gated wrapper and original fallback")
    for operation in ("ACCESS", "CONTEXT"):
        suffix = operation.lower()
        if not re.search(r"#ifdef CONFIG_KSU_SUSFS\s*\[SEL_" + operation + r"\]\s*=\s*handle_sel_write_" + suffix
                         + r",\s*#else\s*\[SEL_" + operation + r"\]\s*=\s*sel_write_" + suffix, filesystem):
            raise AssertionError("SEL_" + operation + " must register the gated wrapper and original fallback")


def harness(wrappers):
    return r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#define likely(x) (x)
struct file { int unused; };
struct kuid { unsigned val; };
static struct kuid uid;
static struct kuid current_uid(void) { return uid; }
static bool ksu_selinux_hide_running, bad_arguments;
static int delegated[3], fallback[3];
static int set_result;
static ssize_t write_result;
static const char *expected_name;
static void *expected_value;
static struct file *expected_file;
static size_t expected_size;
static int selinux_setprocattr(const char *name, void *value, size_t size) {
    ++fallback[0];
    if (name != expected_name || value != expected_value || size != expected_size) bad_arguments = true;
    return set_result;
}
static int my_setprocattr(const char *name, void *value, size_t size) {
    ++delegated[0];
    if (name != expected_name || value != expected_value || size != expected_size) bad_arguments = true;
    return set_result;
}
static ssize_t record_write(int index, bool delegate, struct file *file, char *buf, size_t size) {
    if (delegate) ++delegated[index]; else ++fallback[index];
    if (file != expected_file || buf != expected_value || size != expected_size) bad_arguments = true;
    return write_result;
}
static ssize_t sel_write_context(struct file *file, char *buf, size_t size) { return record_write(1, false, file, buf, size); }
static ssize_t my_write_context(struct file *file, char *buf, size_t size) { return record_write(1, true, file, buf, size); }
static ssize_t sel_write_access(struct file *file, char *buf, size_t size) { return record_write(2, false, file, buf, size); }
static ssize_t my_write_access(struct file *file, char *buf, size_t size) { return record_write(2, true, file, buf, size); }
''' + wrappers + r'''
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "SELinux routing CHECK line %d: %s\n", __LINE__, #x); return 1; } } while (0)
int main(void) {
    struct file file = {7};
    char value[] = "u:r:untrusted_app:s0\n";
    const char original[] = "u:r:untrusted_app:s0\n";
    const char *names[] = {"current", "exec", "prev", "fscreate", "current.extra"};
    unsigned uids[] = {0, 9999, 10000, 101000};
    size_t sizes[] = {0, sizeof(value)};
    int results[] = {-13, 0, 37};
    for (size_t u = 0; u < sizeof(uids) / sizeof(uids[0]); ++u)
    for (int running = 0; running <= 1; ++running)
    for (size_t n = 0; n < sizeof(names) / sizeof(names[0]); ++n)
    for (size_t z = 0; z < sizeof(sizes) / sizeof(sizes[0]); ++z)
    for (size_t r = 0; r < sizeof(results) / sizeof(results[0]); ++r) {
        memset(delegated, 0, sizeof(delegated)); memset(fallback, 0, sizeof(fallback));
        bad_arguments = false;
        uid.val = uids[u]; ksu_selinux_hide_running = running;
        expected_name = names[n]; expected_value = value; expected_file = &file; expected_size = sizes[z];
        set_result = results[r]; write_result = results[r];
        bool write_delegate = uids[u] >= 10000 && running;
        bool set_delegate = write_delegate && n == 0;
        CHECK(handle_selinux_setprocattr(names[n], value, sizes[z]) == results[r]);
        CHECK(handle_sel_write_context(&file, value, sizes[z]) == results[r]);
        CHECK(handle_sel_write_access(&file, value, sizes[z]) == results[r]);
        CHECK(delegated[0] == set_delegate && fallback[0] == !set_delegate);
        CHECK(delegated[1] == write_delegate && fallback[1] == !write_delegate);
        CHECK(delegated[2] == write_delegate && fallback[2] == !write_delegate);
        CHECK(!bad_arguments && memcmp(value, original, sizeof(value)) == 0);
    }
    puts("actual SELinux wrappers: UID/running/current gates, original fallbacks, builtin arguments/returns pass");
    return 0;
}
'''


def run_harness(wrappers, directory, label, success=True):
    c_file, binary = directory / (label + ".c"), directory / label
    c_file.write_text(harness(wrappers))
    compiled = subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Werror", "-Wno-unused-function",
                               str(c_file), "-o", str(binary)], capture_output=True, text=True)
    if compiled.returncode:
        raise AssertionError(label + " did not compile:\n" + compiled.stderr)
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    if (result.returncode == 0) != success:
        raise AssertionError(label + " unexpected result:\n" + result.stdout + result.stderr)
    print(result.stdout.strip() if success else label + ": failure detected")


def check_sources(source, common):
    for root in (source / "kernel", common / "security/selinux"):
        for path in root.rglob("*"):
            if path.suffix in (".c", ".h") and path.is_file():
                reject_fake_state(path.read_text(encoding="utf-8-sig"), path)
    builtin = (source / "kernel/feature/selinux_hide.c").read_text()
    hooks = (common / "security/selinux/hooks.c").read_text()
    filesystem = (common / "security/selinux/selinuxfs.c").read_text()
    check_declarations(builtin, hooks, filesystem)
    wrappers = "\n".join((function(hooks, WRAPPERS[0]), *(function(filesystem, name) for name in WRAPPERS[1:])))
    with tempfile.TemporaryDirectory(prefix="sukisu-selinux-routing-") as tmp:
        directory = Path(tmp)
        run_harness(wrappers, directory, "actual_selinux_routing")
        for label, old, new in (
            ("wrong_running_gate", "ksu_selinux_hide_running", "false"),
            ("wrong_uid_boundary", ">= 10000", ">= 9999"),
            ("wrong_current_gate", '!strcmp(name, "current")', "false"),
            ("wrong_delegate_size", "my_write_access(file, buf, size)", "my_write_access(file, buf, size + 1)"),
            ("wrong_delegate_return", "return my_setprocattr(name, value, size);", "(void)my_setprocattr(name, value, size); return 0;"),
        ):
            if old not in wrappers:
                raise AssertionError("missing exact mutation target: " + label)
            run_harness(wrappers.replace(old, new, 1), directory, label, False)
    try:
        reject_fake_state("extern struct selinux_state fake_state;", "old ABI negative sample")
    except AssertionError:
        print("obsolete fake_state declaration: failure detected")
    else:
        raise AssertionError("old SELinux ABI must be rejected")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--common", type=Path, required=True)
    args = parser.parse_args()
    check_sources(args.source, args.common)


if __name__ == "__main__":
    main()
