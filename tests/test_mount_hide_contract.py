"""Compile actual mount-hide helpers and check first-read/content contracts.

Host stand-ins supply kernel objects and UID policy. The separate mount-list and
dentry-root predicates are disabled; the classifier, permission hook, UID gate,
wrappers and marker filter execute actual C source. Kernel LSM wiring, object
layout, mount-list/root filtering and device acceptance need separate checks.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile


def function(source, name):
    match = re.search(r"\b(?:static\s+)?(?:bool|int|enum\s+ksu_mount_file)\s+"
                      r"(?:__nocfi\s+)?" + re.escape(name)
                      + r"\s*\([^;]*?\)\s*\{", source, re.S)
    if not match:
        raise AssertionError("missing actual helper: " + name)
    depth = 0
    for index in range(match.end() - 1, len(source)):
        depth += (source[index] == "{") - (source[index] == "}")
        if depth == 0:
            return source[match.start():index + 1]
    raise AssertionError("unterminated actual helper: " + name)


def declaration(source, pattern):
    match = re.search(pattern, source, re.S)
    if not match:
        raise AssertionError("actual mount filter declaration missing: " + pattern)
    return match.group()


def harness(source):
    if re.search(r"\bksu_mount_hide_file_open\s*\([^;]*?\)\s*\{", source, re.S):
        raise AssertionError("mount hiding must not restore the file_open rejection")
    declarations = "\n".join(declaration(source, pattern) for pattern in (
        r"struct ksu_proc_mounts\s*\{.*?\};",
        r"typedef int \(\*ksu_show_fn\).*?;",
        r"static const char \*const ksu_mount_markers\[\]\s*=\s*\{.*?\};",
        r"enum ksu_mount_file\s*\{.*?\};",
    ))
    helpers = "\n".join(function(source, name) for name in (
        "ksu_region_contains", "ksu_region_has_marker",
        "ksu_should_hide_mount_for_current", "ksu_filter_show",
        "ksu_show_vfsmnt", "ksu_show_mountinfo", "ksu_show_vfsstat",
        "ksu_mount_file_type", "ksu_mount_hide_file_permission",
    ))
    return r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef unsigned int uid_t;
#define PROC_SUPER_MAGIC 0x9fa0
#define EXT4_SUPER_MAGIC 0xef53
#define F2FS_SUPER_MAGIC 0xf2f52010
#define MAY_READ 4
#define MAY_WRITE 2
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define unlikely(x) (x)
#define __nocfi
#define pr_warn_once(...) ((void)0)
struct super_block { unsigned long s_magic; };
struct qstr { const char *name; };
struct dentry { struct qstr d_name; struct super_block *d_sb; };
struct path { struct dentry *dentry; };
struct file { struct path f_path; void *private_data; };
struct vfsmount { int unused; };
struct seq_file { char *buf; size_t count; void *private; bool overflow; };
static bool seq_has_overflowed(struct seq_file *m) { return m->overflow; }
struct kuid { uid_t val; };
static struct kuid test_uid = {10001};
static struct kuid current_uid(void) { return test_uid; }
static bool is_isolated_process(uid_t uid) {
    return uid % 100000 >= 90000 && uid % 100000 <= 99999;
}
static bool is_appuid(uid_t uid) {
    return uid % 100000 >= 10000 && uid % 100000 <= 19999;
}
static bool should_umount = true;
static bool ksu_uid_should_umount(uid_t uid) { (void)uid; return should_umount; }
static bool ksu_mount_hide_running = true, ksu_mount_hide_enabled = true;
/* Independent kernel-dependent predicates are outside this host contract. */
static bool ksu_region_has_mount_list(const char *buf, size_t len) {
    (void)buf; (void)len; return false;
}
static bool ksu_mnt_root_hidden(struct vfsmount *mnt) { (void)mnt; return false; }
''' + declarations + r'''
static ksu_show_fn ksu_orig_show_vfsmnt;
static ksu_show_fn ksu_orig_show_mountinfo;
static ksu_show_fn ksu_orig_show_vfsstat;
''' + helpers + r'''
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "mount filter check failed at %d: %s\n", __LINE__, #condition); \
    return 1; } } while (0)
static const char *record;
static int original_result, original_calls, original_kind;
static int emit_record(struct seq_file *m, struct vfsmount *mnt) {
    (void)mnt;
    original_calls++;
    if (m) {
        size_t len = strlen(record);
        memcpy(m->buf + m->count, record, len);
        m->count += len;
    }
    return original_result;
}
static int original_mounts(struct seq_file *m, struct vfsmount *mnt) {
    original_kind = 0;
    return emit_record(m, mnt);
}
static int original_mountinfo(struct seq_file *m, struct vfsmount *mnt) {
    original_kind = 1;
    return emit_record(m, mnt);
}
static int original_mountstats(struct seq_file *m, struct vfsmount *mnt) {
    original_kind = 2;
    return emit_record(m, mnt);
}
int main(void) {
    struct super_block sb = {EXT4_SUPER_MAGIC};
    struct dentry dentry = {{"mountinfo"}, &sb};
    char buffer[2048];
    struct ksu_proc_mounts proc = {0};
    struct seq_file seq = {buffer, 0, &proc, false};
    struct file file = {{&dentry}, &seq};
    const char *targets[] = {"mounts", "mountinfo", "mountstats"};
    unsigned long other_fs[] = {EXT4_SUPER_MAGIC, F2FS_SUPER_MAGIC};
    ksu_show_fn originals[] = {original_mounts, original_mountinfo, original_mountstats};
    ksu_show_fn filters[] = {ksu_show_vfsmnt, ksu_show_mountinfo, ksu_show_vfsstat};
    ksu_orig_show_vfsmnt = original_mounts;
    ksu_orig_show_mountinfo = original_mountinfo;
    ksu_orig_show_vfsstat = original_mountstats;
    for (size_t fs = 0; fs < ARRAY_SIZE(other_fs); fs++) {
        sb.s_magic = other_fs[fs];
        for (size_t n = 0; n < ARRAY_SIZE(targets); n++) {
            dentry.d_name.name = targets[n];
            proc.show = originals[n];
            CHECK(ksu_mount_hide_file_permission(&file, MAY_READ) == 0);
            CHECK(proc.show == originals[n]);
        }
    }
    sb.s_magic = PROC_SUPER_MAGIC;
    for (size_t n = 0; n < ARRAY_SIZE(targets); n++) {
        dentry.d_name.name = targets[n];
        proc.show = originals[n];
        CHECK(ksu_mount_hide_file_permission(&file, 0) == 0);
        CHECK(proc.show == originals[n]);
        CHECK(ksu_mount_hide_file_permission(&file, MAY_WRITE) == 0);
        CHECK(proc.show == originals[n]);
        file.private_data = NULL;
        CHECK(ksu_mount_hide_file_permission(&file, MAY_READ) == 0);
        CHECK(proc.show == originals[n]);
        file.private_data = &seq;
        seq.private = NULL;
        CHECK(ksu_mount_hide_file_permission(&file, MAY_READ) == 0);
        CHECK(proc.show == originals[n]);
        seq.private = &proc;
        proc.show = originals[(n + 1) % ARRAY_SIZE(originals)];
        CHECK(ksu_mount_hide_file_permission(&file, MAY_READ) == 0);
        CHECK(proc.show == originals[(n + 1) % ARRAY_SIZE(originals)]);
        proc.show = NULL;
        CHECK(ksu_mount_hide_file_permission(&file, MAY_READ) == 0);
        CHECK(proc.show == NULL);
        proc.show = originals[n];
        CHECK(ksu_mount_hide_file_permission(&file, MAY_READ | MAY_WRITE) == 0);
        CHECK(proc.show == filters[n]);
        CHECK(ksu_mount_hide_file_permission(&file, MAY_READ) == 0);
        CHECK(proc.show == filters[n]);
        /* All three files remain readable; preceding records are preserved. */
        const char *markers[] = {"/adb/module", "/DATA/ADB/module", "KernelSU",
                                 "MaGiSk", "ZyGiSk", "/debug_ramdisk/file"};
        for (size_t marker = 0; marker < ARRAY_SIZE(markers); marker++) {
            strcpy(buffer, "previous record\n");
            seq.count = strlen(buffer);
            record = markers[marker];
            original_calls = 0;
            CHECK(proc.show(&seq, NULL) == 0);
            CHECK(original_calls == 1);
            CHECK(original_kind == (int)n);
            CHECK(seq.count == strlen("previous record\n"));
            CHECK(memcmp(buffer, "previous record\n", seq.count) == 0);
        }
        /* A marker in an earlier record must not erase this normal record. */
        strcpy(buffer, "previous magisk record\n");
        seq.count = strlen(buffer);
        record = "tmpfs /mnt/user tmpfs rw 0 0\n";
        CHECK(proc.show(&seq, NULL) == 0);
        CHECK(seq.count == strlen("previous magisk record\n") + strlen(record));
        CHECK(memcmp(buffer + strlen("previous magisk record\n"), record,
                     strlen(record)) == 0);
        for (int outcome = 0; outcome < 2; outcome++) {
            original_result = outcome ? 1 : -EIO; /* SEQ_SKIP and original error */
            seq.count = 0;
            record = "magisk record\n";
            CHECK(proc.show(&seq, NULL) == original_result);
            CHECK(seq.count == strlen(record));
            CHECK(proc.show(NULL, NULL) == original_result);
        }
        original_result = 0;
        seq.count = 0;
        seq.overflow = true;
        CHECK(proc.show(&seq, NULL) == 0);
        CHECK(seq.count == strlen(record));
        seq.overflow = false;
        seq.count = 0;
        record = "";
        CHECK(proc.show(&seq, NULL) == 0);
        CHECK(seq.count == 0);
    }
    dentry.d_name.name = "mountinfo";
    proc.show = original_mountinfo;
    ksu_mount_hide_enabled = false;
    CHECK(ksu_mount_hide_file_permission(&file, MAY_READ) == 0);
    CHECK(proc.show == original_mountinfo);
    ksu_mount_hide_enabled = true;
    ksu_mount_hide_running = false;
    CHECK(ksu_mount_hide_file_permission(&file, MAY_READ) == 0);
    CHECK(proc.show == original_mountinfo);
    ksu_mount_hide_running = true;
    uid_t excluded[] = {0, 9999, 20000};
    for (size_t n = 0; n < ARRAY_SIZE(excluded); n++) {
        test_uid.val = excluded[n];
        CHECK(ksu_mount_hide_file_permission(&file, MAY_READ) == 0);
        CHECK(proc.show == original_mountinfo);
    }
    test_uid.val = 10001;
    should_umount = false;
    CHECK(ksu_mount_hide_file_permission(&file, MAY_READ) == 0);
    CHECK(proc.show == original_mountinfo);
    uid_t isolated[] = {90000, 98999, 99000, 99999, 199000};
    for (size_t n = 0; n < ARRAY_SIZE(isolated); n++) {
        test_uid.val = isolated[n];
        proc.show = original_mountinfo;
        CHECK(ksu_mount_hide_file_permission(&file, MAY_READ) == 0);
        CHECK(proc.show == ksu_show_mountinfo);
    }
    test_uid.val = 110001;
    should_umount = true;
    proc.show = original_mountinfo;
    CHECK(ksu_mount_hide_file_permission(&file, MAY_READ) == 0);
    CHECK(proc.show == ksu_show_mountinfo);
    const char *other_names[] = {"status", "mountinfo.backup", "mount", "", NULL};
    for (size_t n = 0; n < ARRAY_SIZE(other_names); n++) {
        dentry.d_name.name = other_names[n];
        proc.show = original_mountinfo;
        CHECK(ksu_mount_hide_file_permission(&file, MAY_READ) == 0);
        CHECK(proc.show == original_mountinfo);
    }
    dentry.d_name.name = "mountinfo";
    CHECK(ksu_mount_hide_file_permission(NULL, MAY_READ) == 0);
    file.f_path.dentry = NULL;
    CHECK(ksu_mount_hide_file_permission(&file, MAY_READ) == 0);
    CHECK(proc.show == original_mountinfo);
    puts("actual mount filter: procfs first-read wrappers, ext4/f2fs exclusions, valid seq/show, UID/feature gates, marker/normal/error records pass");
    return 0;
}
'''


def check_source(source):
    with tempfile.TemporaryDirectory(prefix="sukisu-mount-filter-") as directory:
        root = Path(directory)
        c_file, binary = root / "mount_filter.c", root / "mount_filter"
        c_file.write_text(harness(source))
        compiled = subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Werror",
                                   "-Wno-unused-function", str(c_file), "-o", str(binary)],
                                  capture_output=True, text=True)
        if compiled.returncode:
            raise AssertionError("actual mount filter did not compile:\n" + compiled.stderr)
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        if result.returncode:
            raise AssertionError("actual mount filter contract failed:\n" + result.stderr)
        print(result.stdout.strip())


def check_mutations(source):
    mutations = (
        ("missing show installation", "p->show = filter;", "p->show = expected;"),
        ("lost procfs boundary", "file->f_path.dentry->d_sb->s_magic != PROC_SUPER_MAGIC",
         "false"),
        ("leaked marker record", "m->count = start; /* erase the record */",
         "m->count = m->count; /* injected leak */"),
    )
    for name, old, new in mutations:
        if source.count(old) != 1:
            raise AssertionError("mutation target is not unique: " + name)
        try:
            check_source(source.replace(old, new, 1))
        except AssertionError as error:
            if "actual mount filter contract failed:" not in str(error):
                raise AssertionError("mutation must fail at runtime: " + name) from error
            print("mutation rejected: " + name)
        else:
            raise AssertionError("mutation escaped contract: " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--check-mutations", action="store_true")
    args = parser.parse_args()
    source = (args.source / "kernel/feature/mount_hide.c").read_text()
    check_source(source)
    if args.check_mutations:
        check_mutations(source)


if __name__ == "__main__":
    main()
