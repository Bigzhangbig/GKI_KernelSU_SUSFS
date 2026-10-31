"""Compile the real, provenance-bound r2 AVC backport and exercise its lifecycle.

Kernel services are fault-injection stubs. Probe tests use the real builtin
ARM64 register macros and check audit-register changes, not SELinux decisions.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

BACKPORT_COMMIT = "ff7dfe2dbc39f78a08ee6fcff23bc615b0f54ea2"
OFFICIAL_C_SHA256 = "abc0b2fd9e344e140bcc41a56b55e9f739f9b39ee765f79ee02e095d1fa2de83"
OFFICIAL_H_SHA256 = "72504f30f70e8ce8d3a246e29a26ce78375c8d152db241694a336d836e4e89e0"
REMOVED_INCLUDE = '#include "runtime/ksud_boot.h"\n'
RENAMES = {
    "su_sid": "avc_su_sid", "ksu_sid": "avc_ksu_sid", "priv_app_sid": "avc_priv_app_sid",
    "disable_spoof": "avc_disable_spoof", "ksu_avc_spoof_enabled": "avc_spoof_enabled",
    "boot_completed": "avc_boot_completed", "slow_avc_audit_kp": "avc_slow_audit_kp",
    "slow_avc_audit_pre_handler": "avc_slow_audit_pre_handler", "init_avc_kprobe": "avc_init_kprobe",
    "destroy_avc_kprobe": "avc_destroy_kprobe", "get_avc_sids": "avc_get_sids",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def reverse_adaptation(text):
    if REMOVED_INCLUDE in text:
        raise AssertionError("builtin must remove the unused, unavailable ksud_boot header")
    for original, adapted in RENAMES.items():
        text = re.sub(r"\b" + adapted + r"\b", original, text)
    anchor = '#include "klog.h"\n'
    if text.count(anchor) != 1:
        raise AssertionError("official include anchor missing")
    return text.replace(anchor, anchor + REMOVED_INCLUDE)


def function(text, name):
    match = re.search(r"\b(?:static\s+)?(?:void|int)\s+(?:__init\s+)?" + name + r"\([^;]*?\)\s*\{", text, re.S)
    if not match:
        raise AssertionError("missing actual C function: " + name)
    depth = 0
    for i in range(match.end() - 1, len(text)):
        depth += (text[i] == "{") - (text[i] == "}")
        if not depth:
            return text[match.start():i + 1]
    raise AssertionError("unterminated C function: " + name)


def source_contract(source, commit=BACKPORT_COMMIT):
    if commit != BACKPORT_COMMIT:
        raise AssertionError("AVC contract must be bound to the audited official commit")
    c_path = source / "kernel/feature/avc_spoof.c"
    h_path = source / "kernel/feature/avc_spoof.h"
    if not c_path.is_file() or not h_path.is_file():
        raise AssertionError("official AVC feature implementation is missing")
    text = c_path.read_text()
    restored = reverse_adaptation(text).encode()
    if digest(restored) != OFFICIAL_C_SHA256 or digest(h_path.read_bytes()) != OFFICIAL_H_SHA256:
        raise AssertionError("AVC implementation differs from official source beyond audited names/include adaptation")
    main = (source / "kernel/ksu_main.c").read_text()
    for suffix in ("h", "c"):
        if main.count('#include "feature/avc_spoof.' + suffix + '"') != 1:
            raise AssertionError("unity build must include the AVC " + suffix + " once")
    init = function(main, "kernelsu_init")
    if init.count("ksu_avc_spoof_init();") != 1 or not (
            init.index("ksu_feature_init();") < init.index("ksu_avc_spoof_init();") < init.index("ksu_feature_apply_forced();")):
        raise AssertionError("AVC registration must follow feature initialization and precede forced settings")
    boot = function((source / "kernel/runtime/ksud.c").read_text(), "on_boot_completed")
    if boot.count("ksu_avc_spoof_late_init();") != 1:
        raise AssertionError("boot completion must activate the configured AVC feature once")
    feature = (source / "kernel/include/uapi/feature.h").read_text()
    if not re.search(r"KSU_FEATURE_AVC_SPOOF\s*=\s*10003\s*,\s*KSU_FEATURE_MAX", feature):
        raise AssertionError("official AVC ID10003 must set the feature ceiling to 10004")
    if '[KSU_FEATURE_AVC_SPOOF] = "avc_spoof"' not in (source / "kernel/policy/feature.c").read_text():
        raise AssertionError("AVC feature configuration name is missing")
    arch = (source / "kernel/include/arch.h").read_text()
    if not re.search(r"#if defined\(__aarch64__\).*?#define __PT_PARM3_REG regs\[2\]", arch, re.S):
        raise AssertionError("ARM64 probe argument 3 must address regs[2]")
    return text, boot, arch, feature



def check_common(common):
    audit = (common / "security/selinux/avc.c").read_text()
    if not re.search(r"noinline int slow_avc_audit\(struct selinux_state \*state,\s*"
                     r"u32 ssid, u32 tsid, u16 tclass,", audit):
        raise AssertionError("the pinned kernel audit ABI must keep tsid as argument 3")


def harness(text, boot, arch, feature, probes=True):
    text = re.sub(r"^#include[^\n]*\n", "", text, flags=re.M)
    arch = re.sub(r"^#include[^\n]*\n", "", arch, flags=re.M)
    return r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
typedef uint64_t u64;
#define __init
#define __exit
#define GFP_KERNEL 0
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#define LINUX_VERSION_CODE KERNEL_VERSION(5,10,209)
#ifndef __aarch64__
#define __aarch64__ 1
#endif
#define pr_info(...) ((void)0)
#define pr_info_ratelimited(...) ((void)0)
#define pr_err(...) ((void)0)
#define pr_warn(...) ((void)0)
''' + ("#define CONFIG_KPROBES 1\n" if probes else "") + feature + '\n' + arch + r'''
struct pt_regs { uint64_t regs[31], sp, pc, pstate; };
typedef struct { int counter; } atomic_t;
#define ATOMIC_INIT(x) {x}
static int atomic_read(const atomic_t *v) { return v->counter; }
static void atomic_set(atomic_t *v, int x) { v->counter = x; }
struct kprobe;
typedef int (*kprobe_pre_handler_t)(struct kprobe *, struct pt_regs *);
struct kprobe { const char *symbol_name; kprobe_pre_handler_t pre_handler; };
struct ksu_feature_handler {
    u32 feature_id; const char *name; int (*get_handler)(u64 *); int (*set_handler)(u64);
};
static int resolve_calls, resolve_fail_at, allocations, allocation_fail, frees;
static int probe_register_calls, probe_unregister_calls, sync_calls, probe_error;
static int feature_register_calls, feature_unregister_calls, feature_error;
static bool bad_context, bad_probe, ksu_boot_completed;
static int throne_calls, drop_backup_calls;
static const struct ksu_feature_handler *feature_handler;
static int security_secctx_to_secid(const char *context, size_t length, u32 *sid) {
    ++resolve_calls;
    if (resolve_fail_at == resolve_calls) return -ENOENT;
    if (length != strlen(context)) bad_context = true;
    if (!strcmp(context, "u:r:su:s0")) *sid = 11;
    else if (!strcmp(context, "u:r:ksu:s0")) *sid = 22;
    else if (!strcmp(context, "u:r:priv_app:s0:c512,c768")) *sid = 33;
    else { bad_context = true; return -EINVAL; }
    return 0;
}
static void *kzalloc(size_t size, int flags) {
    (void)flags; ++allocations;
    return allocation_fail ? NULL : calloc(1, size);
}
static void kfree(void *ptr) { if (ptr) ++frees; free(ptr); }
static int register_kprobe(struct kprobe *kp) {
    ++probe_register_calls;
    if (strcmp(kp->symbol_name, "slow_avc_audit") || !kp->pre_handler) bad_probe = true;
    return probe_error;
}
static void unregister_kprobe(struct kprobe *kp) { (void)kp; ++probe_unregister_calls; }
static void synchronize_rcu(void) { ++sync_calls; }
static int ksu_register_feature_handler(const struct ksu_feature_handler *handler) {
    ++feature_register_calls;
    if (feature_error) return feature_error;
    feature_handler = handler; return 0;
}
static int ksu_unregister_feature_handler(u32 id) {
    if (id != KSU_FEATURE_AVC_SPOOF) return -EINVAL;
    ++feature_unregister_calls; feature_handler = NULL; return 0;
}
static void track_throne(bool load) { if (load) ++throne_calls; }
static void ksu_selinux_hide_drop_backup_if_unused(void) { ++drop_backup_calls; }
''' + text + '\n' + boot + r'''
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "AVC CHECK line %d: %s\n", __LINE__, #x); return 1; } } while (0)
#ifdef CONFIG_KPROBES
static bool check_probe(u32 tsid, bool enabled) {
    struct pt_regs regs, expected;
    for (size_t i = 0; i < sizeof(regs) / sizeof(uint64_t); ++i)
        ((uint64_t *)&regs)[i] = 0xa1b2000000000000ULL + i;
    regs.regs[2] = 0xa1b2000000000000ULL | tsid;
    expected = regs;
    if (enabled && (tsid == 11 || tsid == 22))
        expected.regs[2] = 0xa1b2000000000000ULL | 33;
    if (avc_slow_audit_pre_handler(avc_slow_audit_kp, &regs) != 0) return false;
    return memcmp(&regs, &expected, sizeof(regs)) == 0;
}
#endif
int main(int argc, char **argv) {
    const char *scenario = argc > 1 ? argv[1] : "normal";
    u64 value = 999;
    CHECK(KSU_FEATURE_AVC_SPOOF == 10003 && KSU_FEATURE_MAX == 10004);
#ifndef CONFIG_KPROBES
    ksu_avc_spoof_init();
    CHECK(feature_register_calls == 0 && feature_handler == NULL);
    on_boot_completed();
    CHECK(atomic_read(&avc_disable_spoof) == 1 && probe_register_calls == 0 && allocations == 0);
    CHECK(avc_spoof_feature_get(&value) == 0 && value == 1);
    ksu_avc_spoof_exit(); CHECK(feature_unregister_calls == 0);
    puts("actual AVC without KPROBES: no advertised handler or active probe");
    return 0;
#else
    if (!strcmp(scenario, "feature-registration")) feature_error = -EEXIST;
    ksu_avc_spoof_init();
    CHECK(feature_register_calls == 1);
    if (feature_error) {
        CHECK(feature_handler == NULL);
        ksu_avc_spoof_exit(); CHECK(feature_unregister_calls == 0);
        return 0;
    }
    CHECK(feature_handler != NULL && feature_handler->feature_id == 10003 && !strcmp(feature_handler->name, "avc_spoof"));
    CHECK(feature_handler->get_handler(&value) == 0 && value == 1);
    CHECK(atomic_read(&avc_disable_spoof) == 1 && resolve_calls == 0 && allocations == 0);
    CHECK(feature_handler->set_handler(0) == 0);
    CHECK(feature_handler->get_handler(&value) == 0 && value == 0);
    CHECK(feature_handler->set_handler(0) == 0 && resolve_calls == 0);
    if (strcmp(scenario, "normal")) {
        on_boot_completed();
        CHECK(ksu_boot_completed && avc_boot_completed && resolve_calls == 0 && allocations == 0);
        if (!strcmp(scenario, "sid-su")) resolve_fail_at = 1;
        else if (!strcmp(scenario, "sid-ksu")) resolve_fail_at = 2;
        else if (!strcmp(scenario, "sid-priv-app")) resolve_fail_at = 3;
        else if (!strcmp(scenario, "allocation")) allocation_fail = true;
        else if (!strcmp(scenario, "probe-registration")) probe_error = -EIO;
        else CHECK(false);
        CHECK(feature_handler->set_handler(1) == 0);
        CHECK(feature_handler->get_handler(&value) == 0 && value == 1);
        CHECK(atomic_read(&avc_disable_spoof) == 1 && avc_slow_audit_kp == NULL);
        CHECK(check_probe(11, false) && check_probe(22, false) && check_probe(0, false));
        if (resolve_fail_at) CHECK(resolve_calls == resolve_fail_at && allocations == 0 && probe_register_calls == 0);
        if (allocation_fail) CHECK(allocations == 1 && probe_register_calls == 0 && frees == 0);
        if (probe_error) CHECK(probe_register_calls == 1 && frees == 1 && probe_unregister_calls == 0);
        int calls_before_repeat = resolve_calls, allocations_before_repeat = allocations;
        CHECK(feature_handler->set_handler(1) == 0);
        CHECK(resolve_calls == calls_before_repeat && allocations == allocations_before_repeat);
        CHECK(atomic_read(&avc_disable_spoof) == 1 && feature_handler->get_handler(&value) == 0 && value == 1);
        ksu_avc_spoof_exit(); CHECK(feature_unregister_calls == 1);
        return 0;
    }
    CHECK(feature_handler->set_handler(2) == 0);
    CHECK(feature_handler->set_handler(UINT64_MAX) == 0 && resolve_calls == 0 && allocations == 0);
    on_boot_completed();
    CHECK(ksu_boot_completed && avc_boot_completed && throne_calls == 1 && drop_backup_calls == 1);
    CHECK(resolve_calls == 3 && probe_register_calls == 1 && atomic_read(&avc_disable_spoof) == 0 && !bad_context && !bad_probe);
    CHECK(avc_slow_audit_kp && avc_slow_audit_kp->pre_handler == avc_slow_audit_pre_handler);
    CHECK(check_probe(11, true) && check_probe(22, true));
    CHECK(check_probe(33, true) && check_probe(0, true) && check_probe(UINT32_MAX, true) && check_probe(23, true));
    CHECK(feature_handler->set_handler(1) == 0 && probe_register_calls == 1 && resolve_calls == 3);
    CHECK(feature_handler->set_handler(0) == 0);
    CHECK(feature_handler->get_handler(&value) == 0 && value == 0);
    CHECK(probe_unregister_calls == 1 && sync_calls == 1 && frees == 1 && avc_slow_audit_kp == NULL);
    CHECK(atomic_read(&avc_disable_spoof) == 1 && check_probe(11, false) && check_probe(22, false));
    CHECK(feature_handler->set_handler(0) == 0 && probe_unregister_calls == 1);
    CHECK(feature_handler->set_handler(UINT64_MAX) == 0);
    CHECK(probe_register_calls == 2 && atomic_read(&avc_disable_spoof) == 0 && check_probe(11, true));
    ksu_avc_spoof_exit();
    CHECK(probe_unregister_calls == 2 && sync_calls == 2 && frees == 2 && feature_unregister_calls == 1);
    puts("actual AVC: boot/config lifecycle, GET, exact ARM64 tsid register, disable/exit cleanup pass");
    return 0;
#endif
}
'''


def run_c(code, directory, label, scenarios=("normal",), success=True):
    path, binary = directory / (label + ".c"), directory / label
    path.write_text(code)
    compiled = subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Werror", "-Wno-unused-function",
                               str(path), "-o", str(binary)], capture_output=True, text=True)
    if compiled.returncode:
        raise AssertionError(label + " did not compile:\n" + compiled.stderr)
    for scenario in scenarios:
        result = subprocess.run([str(binary), scenario], capture_output=True, text=True, timeout=10)
        if (result.returncode == 0) != success:
            raise AssertionError(label + "/" + scenario + " unexpected result:\n" + result.stdout + result.stderr)
    print(label + ": " + ("pass (" + ", ".join(scenarios) + ")" if success else "failure detected"))


def force_unity_harness(source, feature_override=None):
    feature = feature_override if feature_override is not None else (source / "kernel/policy/feature.c").read_text()
    extension = (source / "kernel/extension/extension.c").read_text()
    masks = re.findall(r"static DECLARE_BITMAP\((\w+), KSU_FEATURE_MAX\);", feature)
    if len(masks) != 2:
        raise AssertionError("actual feature force bitmap declarations missing")
    def without_includes(text):
        return re.sub(r"^#include[^\n]*\n", "", text, flags=re.M)
    headers = without_includes((source / "kernel/policy/feature.h").read_text())
    headers += without_includes((source / "kernel/extension/extension.h").read_text())
    umount = re.search(r"struct ksu_add_try_umount_cmd \{.*?\n\};",
                       (source / "kernel/include/uapi/supercall.h").read_text(), re.S).group()
    extension_uapi = without_includes((source / "kernel/include/uapi/extension.h").read_text())
    return r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint8_t __u8;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef uint64_t __aligned_u64;
#define __init
#define __exit
#define __user
#define __read_mostly
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#define LINUX_VERSION_CODE KERNEL_VERSION(5,10,209)
#define _IOC_NRBITS 8
#define _IOC_TYPEBITS 8
#define _IOC_SIZEBITS 14
#define _IOC_DIRBITS 2
#define _IOC_NONE 0U
#define _IOC_WRITE 1U
#define _IOC_READ 2U
#define _IOC_NRSHIFT 0
#define _IOC_TYPESHIFT (_IOC_NRSHIFT+_IOC_NRBITS)
#define _IOC_SIZESHIFT (_IOC_TYPESHIFT+_IOC_TYPEBITS)
#define _IOC_DIRSHIFT (_IOC_SIZESHIFT+_IOC_SIZEBITS)
#define _IOC(dir,type,nr,size) (((dir) << _IOC_DIRSHIFT) | ((type) << _IOC_TYPESHIFT) | \
                                ((nr) << _IOC_NRSHIFT) | ((size) << _IOC_SIZESHIFT))
#define _IOC_TYPECHECK(t) (sizeof(t))
#define _IO(type,nr) _IOC(_IOC_NONE,(type),(nr),0)
#define _IOR(type,nr,size) _IOC(_IOC_READ,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOW(type,nr,size) _IOC(_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOWR(type,nr,size) _IOC(_IOC_READ|_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
#define KSU_FEATURE_FLAG_SUPPORTED 1
static ssize_t strscpy(char *dest, const char *src, size_t count) {
    size_t len = 0;
    if (!count) return -E2BIG;
    while (len + 1 < count && src[len]) { dest[len] = src[len]; ++len; }
    dest[len] = '\0';
    return src[len] ? (ssize_t)-E2BIG : (ssize_t)len;
}
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
#define pr_warn(...) ((void)0)
#define pr_debug(...) ((void)0)
#define DEFINE_MUTEX(name) int name
#define mutex_lock(ptr) ((void)(ptr))
#define mutex_unlock(ptr) ((void)(ptr))
#define DECLARE_BITMAP(name,bits) unsigned long name[((bits)+63)/64]
#define set_bit(bit,map) ((map)[(bit)/64] |= 1UL << ((bit)%64))
#define clear_bit(bit,map) ((map)[(bit)/64] &= ~(1UL << ((bit)%64)))
#define test_bit(bit,map) (((map)[(bit)/64] >> ((bit)%64)) & 1UL)
#define for_each_set_bit(bit,map,size) for ((bit)=0;(bit)<(size);++(bit)) if(test_bit(bit,map))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,value) ((x)=(value))
#define WARN_ON_ONCE(x) (x)
#define smp_wmb() ((void)0)
#define KERNEL_PARAM_OPS_FL_NOARG 1
#define module_param_cb(...)
struct kernel_param { int unused; };
struct kernel_param_ops { int flags; int (*set)(const char *,const struct kernel_param *); };
static char *host_strchrnul(const char *p,int c) { const char *end=strchr(p,c);return (char *)(end ? end : p+strlen(p)); }
#define strchrnul host_strchrnul
static int kstrtou64(const char *s,unsigned base,u64 *out) {
    char *end; errno=0;
    if (!s || !*s || *s=='-') return -EINVAL;
    unsigned long long value=strtoull(s,&end,base);
    if (errno || *end) return -EINVAL;
    *out=value; return 0;
}
static int kstrtou32(const char *s,unsigned base,u32 *out) {
    u64 value; int ret=kstrtou64(s,base,&value);
    if (ret || value>UINT32_MAX) return -EINVAL;
    *out=(u32)value; return 0;
}
''' + (source / "kernel/include/uapi/feature.h").read_text() + '\n' + umount + '\n' + extension_uapi + '\n' + headers + r'''
static u64 low_feature_value, avc_feature_value, extension_value;
static int low_feature_calls, avc_feature_calls, extension_calls;
static bool fail_feature, fail_extension;
static int get_low(u64 *value) { *value=low_feature_value; return 0; }
static int get_avc(u64 *value) { *value=avc_feature_value; return 0; }
static int set_low(u64 value) { ++low_feature_calls; low_feature_value=value; return 0; }
static int set_avc(u64 value) { ++avc_feature_calls; if(fail_feature)return -EAGAIN; avc_feature_value=value;return 0; }
static int extension_get_stub(u32 id,u64 *value) { (void)id; *value=extension_value; return 0; }
static int extension_set_stub(u32 id,u64 value) { if(id!=3)return -EINVAL; ++extension_calls;if(fail_extension)return -EIO;extension_value=value;return 0; }
static int extension_io_stub(u32 id,void *arg) { (void)id;(void)arg;return 0; }
static void extension_force_stub(u32 id,u64 value) { (void)id;(void)value; }
static int extension_wipe_stub(u32 id) { (void)id;return 0; }
static const struct ksu_extension_handler_ops ksu_extension_kpm_ops={extension_get_stub,extension_set_stub};
static const struct ksu_extension_handler_ops ksu_extension_dynamic_manager_ops={extension_get_stub,extension_set_stub};
static const struct ksu_extension_handler_ops ksu_extension_susfs_ops={extension_get_stub,NULL};
#define ksu_extension_kpm_io extension_io_stub
#define ksu_extension_kpm_apply_forced extension_force_stub
#define ksu_extension_cpu_spoof_io extension_io_stub
#define ksu_extension_umount_paths_io extension_io_stub
#define ksu_extension_umount_paths_wipe extension_wipe_stub
#define ksu_extension_dynamic_manager_io extension_io_stub
#define ksu_extension_version_spoof_io extension_io_stub
#define ksu_extension_version_spoof_wipe extension_wipe_stub
''' + without_includes(extension) + '\n' + without_includes(feature) + r'''
_Static_assert(sizeof(unsigned long)==8,"target and host must use 64-bit bitmap words");
_Static_assert(sizeof(FEATURE_MASK)==157*sizeof(unsigned long),"feature bitmap must cover AVC10003");
_Static_assert(sizeof(forced_mask)==sizeof(unsigned long),"extension bitmap stays at six IDs");
#define CHECK(x) do { if(!(x)){fprintf(stderr,"force unity CHECK line %d: %s\n",__LINE__,#x);return 1;} } while(0)
int main(int argc,char **argv) {
    const char *scenario=argc>1?argv[1]:"normal";
    const struct ksu_feature_handler low={3,"adb_root",get_low,set_low};
    const struct ksu_feature_handler avc={10003,"avc_spoof",get_avc,set_avc};
    ksu_feature_init();ksu_extension_init();ksu_extension_register_all();
    CHECK(ksu_register_feature_handler(&low)==0 && ksu_register_feature_handler(&avc)==0);
    CHECK((void *)FEATURE_MASK!=(void *)forced_mask && (void *)FEATURE_PENDING!=(void *)forced_pending);
    CHECK(!ksu_feature_is_forced(3) && !ksu_extension_is_forced(3));
    if(!strcmp(scenario,"feature-low")) {
        CHECK(force_feature_param_set("3:101",NULL)==0);
        CHECK(ksu_feature_is_forced(3) && !ksu_extension_is_forced(3));
        CHECK(test_bit(3,FEATURE_PENDING) && !test_bit(3,forced_pending));
        CHECK(ksu_extension_set(3,KSU_EXTENSION_API_VERSION,202)==0 && ksu_set_feature(3,404)==-EPERM);
        ksu_feature_apply_forced();
        CHECK(low_feature_value==101 && !test_bit(3,FEATURE_PENDING) && extension_value==202);
        ksu_extension_apply_forced();CHECK(low_feature_calls==1 && extension_calls==1);
        return 0;
    }
    if(!strcmp(scenario,"extension-low")) {
        CHECK(force_extension_param_set("3:202",NULL)==0);
        CHECK(ksu_extension_is_forced(3) && !ksu_feature_is_forced(3));
        CHECK(test_bit(3,forced_pending) && !test_bit(3,FEATURE_PENDING));
        CHECK(ksu_set_feature(3,101)==0 && ksu_extension_set(3,KSU_EXTENSION_API_VERSION,404)==-EPERM);
        ksu_extension_apply_forced();
        CHECK(extension_value==202 && !test_bit(3,forced_pending) && low_feature_value==101);
        ksu_feature_apply_forced();CHECK(low_feature_calls==1 && extension_calls==1);
        return 0;
    }
    CHECK(force_feature_param_set("avc_spoof:111",NULL)==0);
    CHECK(ksu_feature_is_forced(10003) && test_bit(10003,FEATURE_PENDING));
    CHECK(!ksu_extension_is_forced(3) && !test_bit(3,forced_pending));
    CHECK(force_extension_param_set("dynamic_manager:222",NULL)==0);
    CHECK(ksu_extension_is_forced(3) && !ksu_feature_is_forced(3));
    CHECK(ksu_set_feature(3,999)==0 && low_feature_value==999);
    CHECK(ksu_set_feature(10003,999)==-EPERM && ksu_extension_set(3,KSU_EXTENSION_API_VERSION,999)==-EPERM);
    CHECK(force_feature_param_set("3:333",NULL)==0);
    ksu_feature_apply_forced();
    CHECK(avc_feature_value==111 && low_feature_value==333 && extension_calls==0);
    CHECK(!test_bit(10003,FEATURE_PENDING) && !test_bit(3,FEATURE_PENDING) && test_bit(3,forced_pending));
    ksu_extension_apply_forced();
    CHECK(extension_value==222 && extension_calls==1 && !test_bit(3,forced_pending));
    CHECK(ksu_feature_is_forced(10003) && ksu_feature_is_forced(3) && ksu_extension_is_forced(3));
    CHECK(force_extension_param_set("3:444",NULL)==0);ksu_feature_apply_forced();
    CHECK(test_bit(3,forced_pending));ksu_extension_apply_forced();CHECK(extension_value==444);
    CHECK(force_feature_param_set("3:555",NULL)==0);ksu_extension_apply_forced();
    CHECK(test_bit(3,FEATURE_PENDING));ksu_feature_apply_forced();CHECK(low_feature_value==555);
    fail_feature=true;CHECK(force_feature_param_set("10003:666",NULL)==0);ksu_feature_apply_forced();
    CHECK(test_bit(10003,FEATURE_PENDING) && avc_feature_value==111);
    ksu_extension_apply_forced();CHECK(test_bit(10003,FEATURE_PENDING));
    fail_feature=false;ksu_feature_apply_forced();CHECK(!test_bit(10003,FEATURE_PENDING) && avc_feature_value==666);
    fail_extension=true;CHECK(force_extension_param_set("3:777",NULL)==0);ksu_extension_apply_forced();
    CHECK(test_bit(3,forced_pending) && extension_value==444);
    ksu_feature_apply_forced();CHECK(test_bit(3,forced_pending));
    fail_extension=false;ksu_extension_apply_forced();CHECK(!test_bit(3,forced_pending) && extension_value==777);
    u64 value=0;bool supported=false;u32 caps=0;
    CHECK(ksu_get_feature(10003,&value,&supported)==0 && supported && value==666);
    CHECK(ksu_extension_get(3,KSU_EXTENSION_API_VERSION,&value,&caps)==0 &&
          (caps&KSU_FEATURE_FLAG_SUPPORTED) && (caps&KSU_EXTENSION_FLAG_STICKY) && value==777);
    puts("actual feature+extension unity: 157/1-word declarations, AVC10003/shared-low3 force masks and replay queues isolated");
    return 0;
}
'''.replace("FEATURE_MASK", masks[0]).replace("FEATURE_PENDING", masks[1])


def check_force_unity(source, directory):
    code = force_unity_harness(source)
    run_c(code, directory, "actual_force_unity", ("normal", "feature-low", "extension-low"))
    old = code.replace("forced_feature_mask", "forced_mask").replace("forced_feature_pending", "forced_pending")
    old_path = directory / "old_force_unity.c"
    old_path.write_text(old)
    compiled = subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-fsyntax-only", str(old_path)], capture_output=True, text=True)
    if compiled.returncode == 0 or not all(name in compiled.stderr for name in ("forced_mask", "forced_pending")) or not re.search(r"different type|conflicting types", compiled.stderr):
        raise AssertionError("old 10004/5 unity collision must fail for both bitmap types:\n" + compiled.stderr)
    print("original 10004/5 unity bitmap declarations: type conflict detected")
    feature = (source / "kernel/policy/feature.c").read_text()
    for label, before, after in (
        ("wrong_feature_force_mask", "test_bit(feature_id, forced_feature_mask)", "test_bit(feature_id, forced_mask)"),
        ("wrong_feature_pending_queue", "clear_bit(id, forced_feature_pending)", "clear_bit(id, forced_pending)"),
    ):
        if before not in feature:
            raise AssertionError("actual feature isolation mutation target missing: " + label)
        run_c(force_unity_harness(source, feature.replace(before, after)), directory, label, ("feature-low",), False)


def check_source(source, commit=BACKPORT_COMMIT):
    text, boot, arch, feature = source_contract(source, commit)
    with tempfile.TemporaryDirectory(prefix="sukisu-avc-contract-") as tmp:
        directory = Path(tmp)
        check_force_unity(source, directory)
        run_c(harness(text, boot, arch, feature), directory, "actual_avc", (
            "normal", "sid-su", "sid-ksu", "sid-priv-app", "allocation", "probe-registration", "feature-registration"))
        run_c(harness(text, boot, arch, feature, False), directory, "actual_avc_no_kprobes")
        for label, before, after, scenario in (
            ("wrong_arm64_argument", "tsid = (u32 *)&PT_REGS_PARM3(regs);", "tsid = (u32 *)&PT_REGS_PARM2(regs);", "normal"),
            ("wrong_sid_filter", "*tsid == avc_su_sid || *tsid == avc_ksu_sid", "*tsid == avc_su_sid", "normal"),
            ("wrong_disabled_guard", "if (atomic_read(&avc_disable_spoof))", "if (false)", "normal"),
            ("wrong_probe_failure", "atomic_set(&avc_disable_spoof, 1);\n            pr_err", "atomic_set(&avc_disable_spoof, 0);\n            pr_err", "probe-registration"),
            ("wrong_get_configuration", "*value = avc_spoof_enabled ? 1 : 0;", "*value = 0;", "normal"),
        ):
            if before not in text:
                raise AssertionError("actual AVC mutation target missing: " + label)
            run_c(harness(text.replace(before, after, 1), boot, arch, feature), directory, label, (scenario,), False)
    print("official AVC source/hash contract passed; no claim of device runtime or SELinux policy changes")


def write_evidence(source, official_repo, directory):
    source_contract(source)
    directory.mkdir(parents=True, exist_ok=True)
    evidence = {"official_commit": BACKPORT_COMMIT, "adaptation": RENAMES,
                "removed_unused_include": REMOVED_INCLUDE.strip(), "files": {}}
    for suffix, expected in (("c", OFFICIAL_C_SHA256), ("h", OFFICIAL_H_SHA256)):
        path = "kernel/feature/avc_spoof." + suffix
        official = subprocess.run(["git", "show", BACKPORT_COMMIT + ":" + path], cwd=official_repo,
                                  check=True, capture_output=True).stdout
        if digest(official) != expected:
            raise AssertionError("official object/hash differs: " + path)
        (directory / ("official-avc_spoof." + suffix)).write_bytes(official)
        evidence["files"][path] = {"official_sha256": expected, "backport_sha256": digest((source / path).read_bytes())}
    evidence["restored_c_sha256"] = digest(reverse_adaptation((source / "kernel/feature/avc_spoof.c").read_text()).encode())
    (directory / "source-provenance.json").write_text(json.dumps(evidence, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--commit", default=BACKPORT_COMMIT)
    parser.add_argument("--official-repo", type=Path)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    check_source(args.source, args.commit)
    if args.official_repo is not None and args.evidence is not None:
        write_evidence(args.source, args.official_repo, args.evidence)


if __name__ == "__main__":
    main()
