"""Execute the actual SELinux generation helper and policy publication tails.

This contract covers the >= 5.10 policy-object path, including both reset API
signatures. Stubs check publication/lifetime ordering and notification arguments;
they do not model kernel RCU concurrency or prove an on-device SELinux decision.
The retained < 5.10 in-place policy path is intentionally outside this release's
supported generation-tracking scope.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile


def _without_comments(source):
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)


def _function(source, name):
    match = re.search(r"\b(?:static\s+)?(?:void|int)\s+" + re.escape(name)
                      + r"\s*\([^;]*?\)\s*\{", source, re.S)
    if not match:
        raise AssertionError("missing actual policy-generation function: " + name)
    depth = 1
    for index in range(match.end(), len(source)):
        depth += (source[index] == "{") - (source[index] == "}")
        if depth == 0:
            return source[match.start():index + 1], source[match.end():index]
    raise AssertionError("unterminated policy-generation function: " + name)


def _actual_parts(source):
    source = _without_comments(source)
    helper, _ = _function(source, "reset_avc_cache")
    if not re.search(r"reset_avc_cache\s*\(\s*u32\s+seqno\s*\)", helper):
        raise AssertionError("reset_avc_cache must accept the policy generation (u32 seqno)")
    _, apply = _function(source, "apply_kernelsu_rules")
    anchor = re.search(r"apply_kernelsu_rules_fn\s*\(\s*\(void\s*\*\)\s*db\s*\)\s*;", apply)
    if not anchor:
        raise AssertionError("missing actual apply_kernelsu_rules publication boundary")
    apply_tail = apply[anchor.end():].split("\n#else\n", 1)[0]
    _, handle = _function(source, "handle_sepolicy")
    anchor = re.search(r"cmd_index\s*\+\+\s*;\s*\}", handle)
    if not anchor:
        raise AssertionError("missing actual handle_sepolicy publication boundary")
    handle_tail = handle[anchor.end():]
    for name, tail in (("apply_kernelsu_rules", apply_tail), ("handle_sepolicy", handle_tail)):
        if "rcu_assign_pointer" not in tail or "reset_avc_cache" not in tail:
            raise AssertionError("missing actual publication tail: " + name)
    # Legacy paths modify policydb in place and have no `pol` to read. Keep them
    # syntactically compatible without claiming the new contract covers them.
    if len(re.findall(r"reset_avc_cache\s*\(\s*0\s*\)\s*;", source)) != 2:
        raise AssertionError("both retained <5.10 reset call sites must explicitly pass 0")
    return helper, apply_tail, handle_tail


def _harness(helper, apply_tail, handle_tail):
    return r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint32_t u32;
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#define CONFIG_KSU_SUSFS 1
struct selinux_avc { int unused; };
struct selinux_policy { u32 latest_granting; };
static struct selinux_avc test_avc;
static struct { struct selinux_policy *policy; struct selinux_avc *avc; int policy_mutex; } selinux_state;
static struct selinux_policy previous, replacement;
static u32 old_generation, expected_generation;
static int stage, applying, successes, payload_marker;
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "generation CHECK line %d: %s (stage=%d)\n", __LINE__, #x, stage); exit(1); } } while (0)
static void publish(struct selinux_policy **slot, struct selinux_policy *policy) {
    REQUIRE(stage == 0 && slot == &selinux_state.policy && *slot == &previous);
    REQUIRE(policy == &replacement && policy->latest_granting == expected_generation);
    REQUIRE(previous.latest_granting == old_generation);
    *slot = policy; ++stage;
}
#define rcu_assign_pointer(slot, policy) publish(&(slot), (policy))
static void synchronize_rcu(void) {
    REQUIRE(stage == 1 && selinux_state.policy == &replacement); ++stage;
}
static void ksu_destroy_sepolicy(struct selinux_policy *policy) {
    REQUIRE(stage == 2 && policy == &previous && selinux_state.policy == &replacement);
    REQUIRE(previous.latest_granting == old_generation); ++stage;
}
#if ((!defined(KSU_COMPAT_USE_SELINUX_STATE)) || LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0))
static int avc_ss_reset(u32 seqno) {
#else
static int avc_ss_reset(struct selinux_avc *avc, u32 seqno) {
    REQUIRE(avc == &test_avc);
#endif
    REQUIRE(stage == 3 && seqno == expected_generation); ++stage; return 0;
}
static void selnl_notify_policyload(u32 seqno) {
    REQUIRE(stage == 4 && seqno == expected_generation); ++stage;
}
#if ((!defined(KSU_COMPAT_USE_SELINUX_STATE)) || LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0))
static void selinux_status_update_policyload(u32 seqno) {
#else
static void selinux_status_update_policyload(void *state, u32 seqno) {
    REQUIRE(state == &selinux_state);
#endif
    REQUIRE(stage == 5 && seqno == expected_generation); ++stage;
}
static void selinux_xfrm_notify_policyload(void) { REQUIRE(stage == 6); ++stage; }
static void susfs_set_batch_sid(void) { REQUIRE(applying && stage == 7); ++stage; }
static void mutex_unlock(void *mutex) {
    REQUIRE(mutex == &selinux_state.policy_mutex && stage == (applying ? 8 : 7)); ++stage;
}
static void kvfree(void *payload) { REQUIRE(!applying && stage == 8 && payload == &payload_marker); ++stage; }
''' + helper + r'''
static void actual_apply_publication(void) {
    struct selinux_policy *pol = &replacement, *old_pol = &previous;
''' + apply_tail + r'''
}
static int actual_handle_publication(void) {
    struct selinux_policy *pol = &replacement, *old_pol = &previous;
    void *payload = &payload_marker;
    int ret = -999, success_cmd_count = successes;
''' + handle_tail + r'''
}
static void prepare(u32 generation, int apply) {
    old_generation = generation; expected_generation = generation + 1U;
    previous.latest_granting = generation;
    replacement.latest_granting = generation; /* Same generation as a real clone. */
    selinux_state.policy = &previous; selinux_state.avc = &test_avc;
    stage = 0; applying = apply;
}
int main(void) {
    u32 generations[] = {0U, 41U, UINT32_MAX};
    int counts[] = {0, 1, 7};
    for (unsigned g = 0; g < sizeof(generations) / sizeof(generations[0]); ++g) {
        prepare(generations[g], 1);
        actual_apply_publication();
        REQUIRE(stage == 9 && selinux_state.policy == &replacement);
        REQUIRE(replacement.latest_granting == expected_generation);
        for (unsigned c = 0; c < sizeof(counts) / sizeof(counts[0]); ++c) {
            prepare(generations[g], 0); successes = counts[c];
            REQUIRE(actual_handle_publication() == counts[c]);
            REQUIRE(stage == 9 && selinux_state.policy == &replacement);
            REQUIRE(replacement.latest_granting == expected_generation);
        }
    }
    puts("actual generation helper/publication tails: increment, RCU/lifetime order, notifications and return pass");
    return 0;
}
'''


def check_source(source_text):
    """Raise AssertionError unless the actual builtin >=5.10 generation path passes."""
    harness = _harness(*_actual_parts(source_text))
    # Exercise both kernel APIs, including the version override when compat-state
    # is defined. This is host compilation of extracted logic, not kernel builds.
    with tempfile.TemporaryDirectory(prefix="sukisu-policy-generation-") as tmp:
        directory = Path(tmp)
        source = directory / "generation.c"
        source.write_text(harness)
        for version, state in (("5,10,0", False), ("5,10,0", True),
                               ("6,4,0", False), ("6,4,0", True)):
            label = version.replace(",", "_") + ("_state" if state else "_global")
            binary = directory / label
            command = [os.environ.get("CC", "cc"), "-std=c11", "-Werror",
                       "-DLINUX_VERSION_CODE=KERNEL_VERSION(" + version + ")"]
            if state:
                command.append("-DKSU_COMPAT_USE_SELINUX_STATE=1")
            compiled = subprocess.run(command + [str(source), "-o", str(binary)],
                                      capture_output=True, text=True)
            if compiled.returncode:
                raise AssertionError(label + " actual generation code did not compile:\n" + compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            if result.returncode:
                raise AssertionError(label + " generation contract failed:\n" + result.stdout + result.stderr)


def _check_mutations(source):
    mutations = (
        ("missing apply generation increment",
         r"pol->latest_granting\s*=\s*old_pol->latest_granting\s*\+\s*1\s*;", "", 0),
        ("missing handle generation increment",
         r"pol->latest_granting\s*=\s*old_pol->latest_granting\s*\+\s*1\s*;", "", 1),
        ("zero global AVC generation", r"avc_ss_reset\(seqno\)", "avc_ss_reset(0)", 0),
        ("zero state AVC generation", r"avc_ss_reset\(avc, seqno\)", "avc_ss_reset(avc, 0)", 0),
        ("zero global policyload notification", r"selnl_notify_policyload\(seqno\)",
         "selnl_notify_policyload(0)", 0),
        ("zero state policyload notification", r"selnl_notify_policyload\(seqno\)",
         "selnl_notify_policyload(0)", 1),
        ("zero global status generation", r"selinux_status_update_policyload\(seqno\)",
         "selinux_status_update_policyload(0)", 0),
        ("zero state status generation", r"selinux_status_update_policyload\(&selinux_state, seqno\)",
         "selinux_status_update_policyload(&selinux_state, 0)", 0),
        ("destroy before RCU grace period", r"synchronize_rcu\(\);\s*ksu_destroy_sepolicy\(old_pol\);",
         "ksu_destroy_sepolicy(old_pol);\n    synchronize_rcu();", 0),
        ("lost success count return", r"ret = success_cmd_count;\s*goto out_unlock;",
         "ret = 0;\n    goto out_unlock;", 0),
    )
    for label, pattern, replacement, occurrence in mutations:
        matches = list(re.finditer(pattern, source))
        if len(matches) <= occurrence:
            raise AssertionError("could not construct mutation: " + label)
        match = matches[occurrence]
        mutated = source[:match.start()] + replacement + source[match.end():]
        try:
            check_source(mutated)
        except AssertionError as error:
            # These mutations remain valid C. Require a failed runtime assertion,
            # so a broken extraction or compiler error cannot stand in for red.
            if "generation contract failed:" not in str(error):
                raise AssertionError(label + " did not reach the runtime contract: " + str(error)) from error
            print(label + ": failure detected")
        else:
            raise AssertionError("generation contract accepted mutation: " + label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path,
                        help="builtin source tree or its kernel/selinux/rules.c")
    args = parser.parse_args()
    path = args.source / "kernel/selinux/rules.c" if args.source.is_dir() else args.source
    source = path.read_text()
    check_source(source)
    print("generation contract: actual >=5.10 publication logic passes all 4 reset API configurations")
    _check_mutations(source)


if __name__ == "__main__":
    main()
