"""Compile the actual builtin mount filter and check filesystem boundaries.

Run with --source after applying the pinned kernel patch. This host harness
checks the actual helpers, while kernel and device acceptance remain separate.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile


def function(source, name):
    match = re.search(r"\b(?:static\s+)?(?:bool|int)\s+" + re.escape(name)
                      + r"\s*\([^;]*?\)\s*\{", source, re.S)
    if not match:
        raise AssertionError("missing actual helper: " + name)
    depth = 0
    for index in range(match.end() - 1, len(source)):
        depth += (source[index] == "{") - (source[index] == "}")
        if depth == 0:
            return source[match.start():index + 1]
    raise AssertionError("unterminated actual helper: " + name)


def harness(source):
    names = re.search(r"static const char \*const ksu_proc_magic_names\[\]\s*=\s*\{.*?\};",
                      source, re.S)
    maximum = re.search(r"^#define KSU_PROC_MAGIC_NAME_MAX\s+\d+", source, re.M)
    if not names or not maximum:
        raise AssertionError("actual mount filter name declarations missing")
    helpers = "\n".join(function(source, name) for name in (
        "ksu_path_is_proc_mount_file", "ksu_should_hide_mount_for_current",
        "ksu_mount_hide_file_open"))
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
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
struct super_block { unsigned long s_magic; };
struct inode { struct super_block *i_sb; };
struct qstr { const char *name; };
struct dentry { struct qstr d_name; };
struct file { struct { struct dentry *dentry; } f_path; struct inode *inode; };
static struct inode *file_inode(struct file *file) { return file->inode; }
struct kuid { uid_t val; };
static struct kuid test_uid = {10001};
static struct kuid current_uid(void) { return test_uid; }
static bool is_isolated_process(uid_t uid) { return uid % 100000 >= 90000; }
static bool is_appuid(uid_t uid) { return uid % 100000 >= 10000; }
static bool should_umount = true;
static bool ksu_uid_should_umount(uid_t uid) { (void)uid; return should_umount; }
static bool ksu_mount_hide_running = true, ksu_mount_hide_enabled = true;
''' + maximum.group() + "\n" + names.group() + "\n" + helpers + r'''
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "mount filter check failed at %d: %s\n", __LINE__, #condition); \
    return 1; } } while (0)
int main(void) {
    struct super_block sb = {EXT4_SUPER_MAGIC};
    struct inode inode = {&sb};
    struct dentry dentry = {{"mountinfo"}};
    struct file file = {{&dentry}, &inode};
    const char *targets[] = {"mountinfo", "mounts", "mountstats"};
    unsigned long other_fs[] = {EXT4_SUPER_MAGIC, F2FS_SUPER_MAGIC};
    for (size_t fs = 0; fs < ARRAY_SIZE(other_fs); fs++) {
        sb.s_magic = other_fs[fs];
        for (size_t n = 0; n < ARRAY_SIZE(targets); n++) {
            dentry.d_name.name = targets[n];
            CHECK(ksu_mount_hide_file_open(&file) == 0);
        }
    }
    sb.s_magic = PROC_SUPER_MAGIC;
    for (size_t n = 0; n < ARRAY_SIZE(targets); n++) {
        dentry.d_name.name = targets[n];
        CHECK(ksu_mount_hide_file_open(&file) == -ENOENT);
    }
    dentry.d_name.name = "status";
    CHECK(ksu_mount_hide_file_open(&file) == 0);
    dentry.d_name.name = "mountinfo.backup";
    CHECK(ksu_mount_hide_file_open(&file) == 0);
    dentry.d_name.name = NULL;
    CHECK(ksu_mount_hide_file_open(&file) == 0);
    dentry.d_name.name = "mountinfo";
    CHECK(ksu_mount_hide_file_open(NULL) == 0);
    file.f_path.dentry = NULL;
    CHECK(ksu_mount_hide_file_open(&file) == 0);
    file.f_path.dentry = &dentry;
    file.inode = NULL;
    CHECK(ksu_mount_hide_file_open(&file) == 0);
    file.inode = &inode;
    inode.i_sb = NULL;
    CHECK(ksu_mount_hide_file_open(&file) == 0);
    inode.i_sb = &sb;
    should_umount = false;
    CHECK(ksu_mount_hide_file_open(&file) == 0);
    test_uid.val = 99001;
    CHECK(ksu_mount_hide_file_open(&file) == -ENOENT);
    ksu_mount_hide_enabled = false;
    CHECK(ksu_mount_hide_file_open(&file) == 0);
    ksu_mount_hide_enabled = true;
    ksu_mount_hide_running = false;
    CHECK(ksu_mount_hide_file_open(&file) == 0);
    puts("actual mount filter: procfs targets, ext4/f2fs exclusions, invalid objects, feature and UID gates pass");
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    check_source((args.source / "kernel/feature/mount_hide.c").read_text())


if __name__ == "__main__":
    main()
