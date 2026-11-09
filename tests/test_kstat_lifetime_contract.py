"""Execute the complete actual SUSFS KSTAT block against host kernel-service doubles.

This checks inode-reference ownership, rule matching and retirement ordering. It
does not emulate kernel memory ordering, filesystem reclaim, or Linux RCU internals;
real device/kernel acceptance remains separate. No SUSFS algorithm is reimplemented.
The fixed GPL source fixture permits offline baseline red/patch green experiments.
"""
import argparse
import base64
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest


FIXTURE_SHA256 = "87d9b91d8abeaeab023d8cb5176ae7db9cdb9ed5e58fb7cb84b6afa451203ec9"
BASELINE_SHA256 = {
    "fs/susfs.c": "eb192f62a9ec70b0c00b0e800d5734a7e51f357bb3d001e10d1e3be9f76e9b0d",
    "fs/super.c": "59ce3744779d09265de591ac972440ec870ca535fba519f39879c5bffb89ec9c",
    "include/linux/susfs.h": "1dbe8e9d31211bf07eacf5c28054b7f3bb27d034565b88f1ddff371c356c4dd6",
}
# The source archive contains fs/susfs.c and include/linux/susfs.h fetched
# byte-for-byte from SUSFS 2.4.0 commit 45a05753, plus unpatched common super.c.
# Byte-for-byte fs/super.c diff extracted from
# https://github.com/ShirkNeko/susfs4ksu/blob/45a057536ddba12fd59fb583a8f5375f83be703e/kernel_patches/50_add_susfs_in_gki-android12-5.10.patch
# Applied to common f0826289c51653ee116c20c1dda9c87ad8a30636, exactly as CI does
# before the local lifetime patch. The bundled source files already contain the
# 2.4.0 SUSFS implementation/header at that exact commit; upstream's only additional fixture input here
# is the complete super.c diff, including its mount logic hunks.
UPSTREAM_SUPER_SHA256 = "ee43f7878f0f1c811df2f3d6977f0c88525938d5d11b0313c0018df77c886e28"
STACKED_SUPER_SHA256 = "b4ce36f5cf17b4e8eb258b8b0f1471754899348bf266f3c37309cce11bb0ba33"
# Exact failing include hunk shipped in local commit 3d110b2 and rejected by
# real CI run 42353276390. Keep it as a negative integration example: upstream
# inserts susfs_def.h between fs_context.h and uapi/linux/mount.h.
FAILED_INCLUDE_HUNK = '''--- a/fs/super.c
+++ b/fs/super.c
@@ -39,6 +39,9 @@
 #include <linux/fs_context.h>
 #include <uapi/linux/mount.h>
 #include "internal.h"
+#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
+#include <linux/susfs.h>
+#endif
\x20
 static int thaw_super_locked(struct super_block *sb);
\x20
'''


def _block(text, marker, end):
    start = text.index(marker)
    finish = text.index(end, start) + len(end)
    return text[start:finish]


def harness(common):
    common = Path(common)
    source = (common / "fs/susfs.c").read_text()
    header = (common / "include/linux/susfs.h").read_text()
    end = "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_KSTAT"
    body = _block(source, "/* sus_kstat */", end)
    types = _block(header, "#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT", end)
    lifetime = "void susfs_drop_sus_kstat_for_sb(" in body
    return PREAMBLE.replace("@HAS_LIFETIME@", str(int(lifetime))) + types + SERVICES + body + SCENARIOS


PREAMBLE = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#define HAS_LIFETIME @HAS_LIFETIME@
#define CONFIG_KSU_SUSFS_SUS_KSTAT 1
#define __user
#define SUSFS_MAX_LEN_PATHNAME 256
#define GFP_KERNEL 0
#define AS_FLAGS_SUS_KSTAT 35
#define FUSE_SUPER_MAGIC 0x65735546
#define F2FS_SUPER_MAGIC 0xf2f52010
#define SB_ACTIVE 1UL
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#define LINUX_VERSION_CODE KERNEL_VERSION(5,10,209)
#define STATX_SUS_KSTAT 0x10000000
#define STATX_SUS_KSTAT_FUSE 0x20000000
#define SUSFS_LOGI(...) ((void)0)
#define SUSFS_LOGE(...) ((void)0)
#define old_decode_dev(x) (x)
#define huge_decode_dev(x) (x)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
typedef uint32_t u32;
struct address_space { unsigned long flags; };
struct super_block { unsigned long s_magic, s_flags; dev_t s_dev; };
struct fuse_inode;
struct inode {
    struct address_space *i_mapping;
    struct super_block *i_sb;
    unsigned long i_ino;
    long long i_size;
    int refs, path_refs;
    unsigned long retired_seq;
    struct fuse_inode *fuse;
};
struct fuse_inode { struct inode inode; unsigned long long nodeid; };
struct dentry { struct inode *inode; int refs; };
struct vfsmount { struct dentry *mnt_root; int refs, id; };
struct path { struct dentry *dentry; struct vfsmount *mnt; };
struct kstatfs { long f_type, f_flags, f_blocks; };
struct ktimespec { long tv_sec, tv_nsec; };
struct kstat {
    unsigned long ino, dev, nlink, blksize;
    long long size, blocks;
    struct ktimespec atime, mtime, ctime;
    int mnt_id;
};
struct hlist_node { struct hlist_node *next, **pprev; };
struct hlist_head { struct hlist_node *first; };
static void host_visit(struct hlist_node *n);
static void host_publishing(struct hlist_node *n);
#define DEFINE_HASHTABLE(name,bits) struct hlist_head name[1U << (bits)]
#define HASH_SIZE(t) (sizeof(t)/sizeof((t)[0]))
/* The real Linux 64-bit multiplicative bucket function (14-bit production table). */
static size_t bucket(unsigned long key) {
    return (key * 0x61c8864680b583ebUL) >> (64-14);
}
#define hash_for_each_possible(t,o,m,k) \
    for (struct hlist_node *_hn=(t)[bucket(k)].first; \
         _hn && (host_visit(_hn),(o)=container_of(_hn,__typeof__(*(o)),m),1); _hn=_hn->next)
#define hash_for_each_possible_rcu hash_for_each_possible
#define hash_for_each_possible_safe(t,o,n,m,k) \
    for (struct hlist_node *_hn=(t)[bucket(k)].first; \
         _hn && ((n)=_hn->next,(o)=container_of(_hn,__typeof__(*(o)),m),1); _hn=(n))
#define hash_for_each(t,b,o,m) \
    for ((b)=0;(b)<(int)HASH_SIZE(t);(b)++) hash_for_each_possible_bucket(t,b,o,m)
#define hash_for_each_possible_bucket(t,b,o,m) \
    for (struct hlist_node *_hn=(t)[b].first; \
         _hn && ((o)=container_of(_hn,__typeof__(*(o)),m),1); _hn=_hn->next)
#define hash_for_each_safe(t,b,n,o,m) \
    for ((b)=0;(b)<(int)HASH_SIZE(t);(b)++) \
    for (struct hlist_node *_hn=(t)[b].first; \
         _hn && ((n)=_hn->next,(o)=container_of(_hn,__typeof__(*(o)),m),1); _hn=(n))
static void hash_add_impl(struct hlist_head *t,struct hlist_node *n,unsigned long key) {
    host_publishing(n);
    struct hlist_head *h=&t[bucket(key)]; n->next=h->first; n->pprev=&h->first;
    if(n->next)n->next->pprev=&n->next; h->first=n;
}
#define hash_add_rcu(t,n,k) hash_add_impl(t,n,k)
static void hash_del_rcu(struct hlist_node *n);
struct list_head { struct list_head *next,*prev; };
#define LIST_HEAD(n) struct list_head n={&(n),&(n)}
static int list_empty(struct list_head *h) { return h->next==h; }
static void list_add_tail(struct list_head *n,struct list_head *h) {
    n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;
}
static void list_del(struct list_head *n) {n->prev->next=n->next;n->next->prev=n->prev;}
#define list_for_each_entry_safe(o,n,h,m) \
    for (struct list_head *_ln=(h)->next,*_next; \
         _ln!=(h) && (_next=_ln->next,(o)=container_of(_ln,__typeof__(*(o)),m), \
         (n)=_next==(h)?NULL:container_of(_next,__typeof__(*(n)),m),1);_ln=_next)
static _Thread_local int table_depth, rcu_depth;
static _Thread_local int thread_role;
struct mutex { pthread_mutex_t native; const char *name; };
#define DEFINE_MUTEX(n) struct mutex n={PTHREAD_MUTEX_INITIALIZER,#n}
static pthread_mutex_t gate_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cond=PTHREAD_COND_INITIALIZER;
static int gate_enabled, grace_entered, release_grace, drop_attempted, drop_acquired, drop_finished, drop_blocked;
static int reader_ready, reader_release, reader_done, active_readers;
static struct hlist_node *held_reader_node, *held_reader_next;
static void require(int ok,const char *what) {
    if(!ok) {fprintf(stderr,"KSTAT CONTRACT FAIL: %s\n",what);exit(1);}
}
static int is_table(struct mutex *m) {return !strcmp(m->name,"susfs_mutex_lock_sus_kstat");}
static int is_lifecycle(struct mutex *m) {return strstr(m->name,"_lifecycle")!=NULL;}
static void mutex_lock(struct mutex *m) {
    if(thread_role==2 && is_lifecycle(m)) {
        int attempt=pthread_mutex_trylock(&m->native);
        require(attempt==0 || attempt==EBUSY,"host lifecycle trylock outcome");
        pthread_mutex_lock(&gate_lock);drop_attempted=1;drop_blocked=attempt==EBUSY;
        drop_acquired=attempt==0;pthread_cond_broadcast(&gate_cond);pthread_mutex_unlock(&gate_lock);
        if(attempt==EBUSY)pthread_mutex_lock(&m->native);
    } else {
        pthread_mutex_lock(&m->native);
    }
    if(is_table(m))table_depth++;
    if(thread_role==2 && is_lifecycle(m)) {
        pthread_mutex_lock(&gate_lock);drop_acquired=1;pthread_cond_broadcast(&gate_cond);pthread_mutex_unlock(&gate_lock);
    }
}
static void mutex_unlock(struct mutex *m) {if(is_table(m))table_depth--;pthread_mutex_unlock(&m->native);}
static unsigned long removal_seq, grace_seq;
static int sync_count, iput_count, live_allocations, fail_alloc, fail_copy_from, fail_copy_to;
static int fail_lookup, fail_statfs, fail_igrab, fail_non_sus;
static void *kzalloc(size_t n,int flags) {
    (void)flags;if(fail_alloc){fail_alloc=0;return NULL;}
    void *p=calloc(1,n);require(p!=NULL,"host allocation");live_allocations++;return p;
}
static void kfree(void *p) {if(p){live_allocations--;free(p);}}
static int copy_from_user(void *d,const void *s,size_t n) {
    if(fail_copy_from){fail_copy_from=0;return 1;}memcpy(d,s,n);return 0;
}
static int copy_to_user(void *d,const void *s,size_t n) {
    if(fail_copy_to){fail_copy_to=0;return 1;}memcpy(d,s,n);return 0;
}
static void rcu_read_lock(void) {pthread_mutex_lock(&gate_lock);active_readers++;rcu_depth++;pthread_mutex_unlock(&gate_lock);}
static void rcu_read_unlock(void) {pthread_mutex_lock(&gate_lock);require(rcu_depth>0,"balanced RCU reader");active_readers--;rcu_depth--;pthread_cond_broadcast(&gate_cond);pthread_mutex_unlock(&gate_lock);}
static void host_visit(struct hlist_node *n) {
    if(thread_role!=3 || reader_ready)return;
    pthread_mutex_lock(&gate_lock);held_reader_node=n;held_reader_next=n->next;
    require(held_reader_next!=NULL,"reader starts on a real nonempty old hash chain");
    reader_ready=1;pthread_cond_broadcast(&gate_cond);
    while(!reader_release)pthread_cond_wait(&gate_cond,&gate_lock);
    require(held_reader_node->next==held_reader_next,"retirement preserves old hlist node.next for existing RCU reader");
    pthread_mutex_unlock(&gate_lock);
}
static void synchronize_rcu(void) {
    require(!rcu_depth && !table_depth,"RCU grace outside reader/table lock");
    pthread_mutex_lock(&gate_lock);
    if(gate_enabled && thread_role==1) {
        grace_entered=1;pthread_cond_broadcast(&gate_cond);
        while(!release_grace)pthread_cond_wait(&gate_cond,&gate_lock);
    }
    while(active_readers)pthread_cond_wait(&gate_cond,&gate_lock);
    sync_count++;grace_seq=removal_seq;
    pthread_mutex_unlock(&gate_lock);
}
static void set_bit(int bit,unsigned long *flags) {*flags|=1UL<<bit;}
static int test_bit(int bit,const unsigned long *flags) {return !!(*flags&(1UL<<bit));}
static struct inode *d_backing_inode(struct dentry *d) {return d->inode;}
static struct fuse_inode *get_fuse_inode(struct inode *i) {return i->fuse;}
#define real_mount(m) (m)
static int susfs_get_non_sus_mnt_id_from_mnt(struct vfsmount *m) {return m->id;}
static struct inode *igrab(struct inode *i) {
    require(!table_depth && !rcu_depth,"igrab outside table/RCU");
    if(fail_igrab){fail_igrab=0;return NULL;}if(i)i->refs++;return i;
}
static void iput(struct inode *i) {
    if(!i)return;
    require(!table_depth && !rcu_depth,"iput outside table/RCU lock");
    require(i->retired_seq<=grace_seq,"iput after matching RCU grace period");
    require(i->refs>0,"inode reference underflow");i->refs--;iput_count++;
}
struct file_slot { const char *name; struct inode inode; struct address_space mapping;
                   struct dentry dentry; struct vfsmount mount; };
static struct file_slot slots[16];
static int slot_count;
static struct file_slot *make_file(const char *name,struct super_block *sb,unsigned long ino) {
    struct file_slot *s=&slots[slot_count++];require(slot_count<=16,"host slot capacity");
    memset(s,0,sizeof(*s));s->name=name;s->inode.i_sb=sb;s->inode.i_ino=ino;
    s->inode.i_size=123;s->inode.i_mapping=&s->mapping;s->dentry.inode=&s->inode;
    s->mount.mnt_root=&s->dentry;s->mount.id=50+slot_count;return s;
}
static int kern_path(const char *name,int flags,struct path *p) {
    (void)flags;require(!HAS_LIFETIME || (!table_depth && !rcu_depth),"lookup outside table/RCU lock");
    if(fail_lookup){fail_lookup=0;return -ENOENT;}
    for(int n=slot_count-1;n>=0;n--)if(!strcmp(name,slots[n].name)) {
        p->dentry=&slots[n].dentry;p->mnt=&slots[n].mount;
        p->dentry->refs++;p->mnt->refs++;p->dentry->inode->path_refs++;return 0;
    }return -ENOENT;
}
static void dput(struct dentry *d) {require(d->refs>0,"dentry reference balance");d->refs--;}
static void mntput(struct vfsmount *m) {require(m->refs>0,"mount reference balance");m->refs--;}
static void path_put(struct path *p) {p->dentry->inode->path_refs--;dput(p->dentry);mntput(p->mnt);}
static struct vfsmount *susfs_get_non_sus_vfsmnt_from_vfsmnt(struct vfsmount *m) {
    if(fail_non_sus){fail_non_sus=0;return NULL;}m->refs++;m->mnt_root->refs++;return m;
}
int statfs_by_dentry_wrapper(struct dentry *d,struct kstatfs *b) {
    require(!HAS_LIFETIME || (!table_depth && !rcu_depth),"statfs callback outside table/RCU lock");
    if(fail_statfs){fail_statfs=0;return -EIO;}
    b->f_type=d->inode->i_sb->s_magic;b->f_blocks=d->inode->i_ino+1000;return 0;
}
int calculate_f_flags_wrapper(struct vfsmount *m) {(void)m;return 77;}
'''


SERVICES = r'''
static void host_publishing(struct hlist_node *n) {
#if HAS_LIFETIME
    struct st_susfs_sus_kstat_hlist *e=container_of(n,struct st_susfs_sus_kstat_hlist,node);
    int held=0;
    for(int i=0;i<slot_count;i++)if(&slots[i].inode==e->pinned_inode ||
        (slots[i].inode.fuse && &slots[i].inode.fuse->inode==e->pinned_inode))
        held|=slots[i].dentry.refs>0 && slots[i].mount.refs>0 && slots[i].inode.path_refs>0;
    require(held,"staging lookup path retains mount through publication");
#endif
}
static void hash_del_rcu(struct hlist_node *n) {
    *n->pprev=n->next;if(n->next)n->next->pprev=n->pprev;
    /* Like hlist_del_rcu, preserve next for pre-existing readers. */
#if HAS_LIFETIME
    struct st_susfs_sus_kstat_hlist *e=container_of(n,struct st_susfs_sus_kstat_hlist,node);
    e->pinned_inode->retired_seq=++removal_seq;
#endif
}
'''


SCENARIOS = r'''
static struct super_block sb_a={F2FS_SUPER_MAGIC,SB_ACTIVE,11};
static struct super_block sb_b={F2FS_SUPER_MAGIC,SB_ACTIVE,22};
static struct super_block sb_f={FUSE_SUPER_MAGIC,SB_ACTIVE,33};
static struct super_block sb_under={F2FS_SUPER_MAGIC,SB_ACTIVE,44};
static struct st_susfs_sus_kstat request(struct file_slot *s,long long spoof_size) {
    struct st_susfs_sus_kstat r={0};r.target_ino=s->inode.i_ino;
    strcpy(r.target_pathname,s->name);r.spoofed_ino=7001;r.spoofed_dev=90;
    r.spoofed_size=spoof_size;r.spoofed_nlink=3;r.spoofed_blocks=7;r.spoofed_blksize=4096;
    r.spoofed_atime_tv_sec=10;r.spoofed_atime_tv_nsec=11;
    r.spoofed_mtime_tv_sec=12;r.spoofed_mtime_tv_nsec=13;
    r.spoofed_ctime_tv_sec=14;r.spoofed_ctime_tv_nsec=15;r.flags=0xfff;return r;
}
static void add(struct st_susfs_sus_kstat *r) {void *p=r;susfs_add_sus_kstat(&p);}
static void update(struct st_susfs_sus_kstat *r) {void *p=r;susfs_update_sus_kstat(&p);}
static struct kstat getattr_stat(struct inode *i) {
    struct kstat out={0};bool fuse=false;
    if(susfs_is_inode_sus_kstat(i,&fuse))
        susfs_sus_kstat_spoof_generic_fillattr(i,&out,fuse?STATX_SUS_KSTAT_FUSE:STATX_SUS_KSTAT);
    return out;
}
static void reclaim(struct inode *i) {if(!i->refs && !i->path_refs)i->i_mapping->flags=0;}
static void balanced_paths(void) {
    for(int n=0;n<slot_count;n++)require(!slots[n].dentry.refs && !slots[n].mount.refs && !slots[n].inode.path_refs,"temporary path/mount references released");
}
static int entries(void) {int n=0,b;struct st_susfs_sus_kstat_hlist *e;
    hash_for_each(SUS_KSTAT_HLIST,b,e,node)n++;return n;}
static void cache_reclaim(void) {
    struct file_slot *s=make_file("/lifetime",&sb_a,900);
    struct st_susfs_sus_kstat r=request(s,999);add(&r);
    require(r.err==0,"add 900 succeeds");
    require(test_bit(35,&s->mapping.flags),"add sets actual inode marker");
    require(getattr_stat(&s->inode).size==999,"spoof visible immediately after add");
    balanced_paths();reclaim(&s->inode);
    require(getattr_stat(&s->inode).size==999,"cache reclaim must preserve marker and spoof (baseline loses bit 35)");
    require(s->inode.refs==1,"one durable inode pin per rule");
    puts("PASS cache reclaim: actual add/marker/getattr retain inode 900");
}
#if HAS_LIFETIME
static void drop(struct super_block *sb) {sb->s_flags&=~SB_ACTIVE;susfs_drop_sus_kstat_for_sb(sb);}
static void replacement_update(void) {
    struct file_slot *old=&slots[0];int allocations=live_allocations;
    struct st_susfs_sus_kstat r=request(old,1001);add(&r);
    require(!r.err && entries()==1,"same-path add replaces existing rule");
    require(old->inode.refs==1 && live_allocations==allocations,"same-path replacement releases prior pin/allocation");
    struct file_slot *fresh=make_file("/lifetime",&sb_a,901);r=request(fresh,2002);add(&r);
    require(!r.err && entries()==1,"new inode at same path replaces across hash buckets");
    require(!old->inode.refs && fresh->inode.refs==1,"path recreation transfers owned pin");
    require(getattr_stat(&old->inode).size==0 && getattr_stat(&fresh->inode).size==2002,"recreated path has only new rule");
    fresh->inode.i_size=4321;r=request(fresh,9999);r.spoofed_ino=1;r.flags=KSTAT_SPOOF_SIZE;update(&r);
    struct kstat stat=getattr_stat(&fresh->inode);
    require(!r.err && stat.size==4321,"update refreshes actual size");
    require(stat.ino==7001 && stat.dev==90 && stat.nlink==3 && stat.atime.tv_sec==10 && stat.atime.tv_nsec==11 && stat.mtime.tv_sec==12 && stat.mtime.tv_nsec==13 && stat.ctime.tv_sec==14 && stat.ctime.tv_nsec==15 && stat.blocks==7 && stat.blksize==4096,"update preserves prior dynamic spoof fields and flags");
    require(fresh->inode.refs==1 && entries()==1,"update retains exactly one pin");
    puts("PASS duplicate/recreated path replacement and dynamic update");
}
static void errors(void) {
    struct file_slot *s=&slots[1];struct st_susfs_sus_kstat r;
    int allocations=live_allocations, refs=s->inode.refs;
    int *failures[]={&fail_lookup,&fail_statfs,&fail_igrab,&fail_alloc,&fail_copy_from,&fail_non_sus};
    for(unsigned n=0;n<sizeof(failures)/sizeof(failures[0]);n++) {
        for(int updating=0;updating<2;updating++) {
            r=request(s,8080);*failures[n]=1;if(updating)update(&r);else add(&r);
            require(r.err<0,"injected preparation/copy/allocation failure reported");
            require(live_allocations==allocations && s->inode.refs==refs && entries()==1,"failed add/update keeps old rule without reference/allocation leaks");
            require(getattr_stat(&s->inode).size==4321,"failed replacement preserves old spoof");balanced_paths();
        }
    }
    r=request(s,8080);r.target_ino++;add(&r);
    require(r.err==-ESTALE && s->inode.refs==refs && live_allocations==allocations,"stale userspace inode rejected without leaked pin");
    r=request(s,8080);r.target_pathname[0]=0;add(&r);
    require(r.err==-EINVAL && live_allocations==allocations,"empty path rejected");
    /* copy_to_user can fail after the operation committed: retain one valid rule. */
    r=request(s,7654);r.err=1234;fail_copy_to=1;add(&r);
    require(r.err==1234 && getattr_stat(&s->inode).size==7654,"copy-to failure does not undo a committed rule");
    require(s->inode.refs==refs && live_allocations==allocations,"copy-to failure leaks no replacement pin/allocation");
    sb_a.s_flags&=~SB_ACTIVE;r=request(s,111);add(&r);
    require(r.err==-ESHUTDOWN && getattr_stat(&s->inode).size==7654,"inactive sb rejects publication and retains prior entry");
    require(s->inode.refs==refs && live_allocations==allocations,"inactive sb releases staging pin");sb_a.s_flags|=SB_ACTIVE;
    struct file_slot *missing=make_file("/not-added",&sb_a,902);r=request(missing,1);update(&r);
    require(r.err==-ENOENT && !missing->inode.refs && live_allocations==allocations,"update absent rule releases prepared pin");
    balanced_paths();puts("PASS add/update failure ownership, stale/inactive sb and copy-to commit semantics");
}
static unsigned long collision(unsigned long key) {for(unsigned long n=key+1;n<key+1000000;n++)if(bucket(n)==bucket(key))return n;require(0,"find actual hash bucket collision");return 0;}
static void full_keys_and_fuse(void) {
    struct file_slot *s=&slots[1];unsigned long other_ino=collision(s->inode.i_ino);
    struct file_slot *collider=make_file("/collision",&sb_a,other_ino);
    struct st_susfs_sus_kstat r=request(collider,2222);r.spoofed_ino=8002;r.spoofed_dev=91;add(&r);require(!r.err,"collision rule added");
    require(getattr_stat(&s->inode).size==7654,"complete ino key excludes same-bucket different ino");
    dev_t dev=0;unsigned long ino=0;susfs_sus_kstat_spoof_show_map_vma(&s->inode,&dev,&ino);
    require(dev==90 && ino==7001,"map lookup includes complete ino key");
    struct kstatfs fs={0};bool fuse=false;
    require(!susfs_sus_kstat_spoof_vfs_statfs(&s->inode,&fs,&fuse) && fs.f_blocks==1901,"statfs lookup includes full ino key");
    ino=s->inode.i_ino;dev=sb_a.s_dev;susfs_sus_kstat_spoof_inotify_fdinfo(&ino,&dev);
    require(ino==7001 && dev==90,"inotify lookup includes full ino key");
    int mount_id=0;ino=s->inode.i_ino;susfs_sus_kstat_spoof_proc_fd_seq_show(&mount_id,&ino,sb_a.s_dev);
    require(ino==7001 && mount_id==s->mount.id,"proc fd lookup includes full ino key");
    struct file_slot *otherdev=make_file("/otherdev",&sb_b,s->inode.i_ino);r=request(otherdev,3333);add(&r);
    require(!r.err && getattr_stat(&s->inode).size==7654 && getattr_stat(&otherdev->inode).size==3333,"same ino on different dev remains separate");
    /* FUSE wrapper and marked embedded inode deliberately have distinct mappings and devs. */
    struct file_slot *f=make_file("/fuse",&sb_f,777);static struct fuse_inode fi;static struct address_space fm;
    fi.inode.i_mapping=&fm;fi.inode.i_ino=s->inode.i_ino;fi.inode.i_sb=&sb_under;fi.nodeid=77;f->inode.fuse=&fi;
    r=request(f,4444);r.target_ino=fi.inode.i_ino;add(&r);
    require(!r.err && fi.inode.refs==1 && !f->inode.refs,"FUSE pins actual marked embedded inode");
    require(test_bit(35,&fm.flags) && !test_bit(35,&f->mapping.flags),"FUSE marks correct mapping");
    require(getattr_stat(&f->inode).size==4444,"FUSE getattr uses actual marked inode key");
    fuse=true;memset(&fs,0,sizeof(fs));require(!susfs_sus_kstat_spoof_vfs_statfs(&f->inode,&fs,&fuse) && fs.f_blocks==1777,"FUSE statfs compares actual embedded inode dev");
    /* Same (ino,dev), distinct is_fuse: collision cannot cross the FUSE key. */
    struct file_slot *ordinary=make_file("/ordinary-key",&sb_under,fi.inode.i_ino);r=request(ordinary,5555);r.spoofed_ino=9003;r.spoofed_dev=92;add(&r);
    require(!r.err && getattr_stat(&f->inode).size==4444 && getattr_stat(&ordinary->inode).size==5555,"getattr complete FUSE discriminator");
    dev=0;ino=0;susfs_sus_kstat_spoof_show_map_vma(&f->inode,&dev,&ino);require(ino==7001 && dev==90,"FUSE map lookup remains keyed");
    fuse=true;memset(&fs,0,sizeof(fs));require(!susfs_sus_kstat_spoof_vfs_statfs(&f->inode,&fs,&fuse) && fs.f_blocks==1777,"statfs complete FUSE discriminator");
    balanced_paths();puts("PASS complete ino/dev/FUSE keys through all public readers and actual FUSE marker");
}
struct worker_request {struct st_susfs_sus_kstat info;};
static void *replace_worker(void *arg) {thread_role=1;add(&((struct worker_request *)arg)->info);return NULL;}
static void *reader_worker(void *arg) {
    thread_role=3;struct kstat stat=getattr_stat(arg);
    require(stat.size==7654,"in-flight actual public RCU reader sees intact retired rule");
    pthread_mutex_lock(&gate_lock);reader_done=1;pthread_cond_broadcast(&gate_cond);pthread_mutex_unlock(&gate_lock);return NULL;
}
static void *drop_worker(void *arg) {
    thread_role=2;susfs_drop_sus_kstat_for_sb(arg);
    pthread_mutex_lock(&gate_lock);drop_finished=1;pthread_cond_broadcast(&gate_cond);pthread_mutex_unlock(&gate_lock);return NULL;
}
static void retirement_shutdown(void) {
    /* Pause a real replacement at synchronize_rcu, then drive real drop concurrently. */
    struct file_slot *s=&slots[1];struct st_susfs_sus_kstat head=request(s,7654);add(&head);
    require(!head.err,"reinsert target at head of real collision chain");
    struct worker_request w={request(s,6060)};
    pthread_t replacement,shutdown,reader;int before=iput_count;
    require(!pthread_create(&reader,NULL,reader_worker,&s->inode),"actual public reader starts");
    pthread_mutex_lock(&gate_lock);while(!reader_ready)pthread_cond_wait(&gate_cond,&gate_lock);pthread_mutex_unlock(&gate_lock);
    gate_enabled=1;require(!pthread_create(&replacement,NULL,replace_worker,&w),"replacement thread starts");
    pthread_mutex_lock(&gate_lock);while(!grace_entered)pthread_cond_wait(&gate_cond,&gate_lock);
    require(s->inode.refs==2 && iput_count==before,"retired pin stays owned until RCU grace completes");
    sb_a.s_flags&=~SB_ACTIVE;
    require(!pthread_create(&shutdown,NULL,drop_worker,&sb_a),"shutdown thread starts");
    while(!drop_attempted)pthread_cond_wait(&gate_cond,&gate_lock);
    require(drop_blocked && !drop_acquired && !drop_finished,"shutdown cannot pass a retirement still waiting for grace/iput");
    reader_release=1;pthread_cond_broadcast(&gate_cond);
    while(!reader_done)pthread_cond_wait(&gate_cond,&gate_lock);
    release_grace=1;pthread_cond_broadcast(&gate_cond);pthread_mutex_unlock(&gate_lock);
    require(!pthread_join(reader,NULL) && !pthread_join(replacement,NULL) && !pthread_join(shutdown,NULL),"deterministic workers finish");gate_enabled=0;
    require(!w.info.err && drop_acquired && drop_finished,"replacement/shutdown complete under lifecycle serialization");
    require(!s->inode.refs && !slots[3].inode.refs,"shutdown drops every rule on target superblock");
    require(slots[4].inode.refs==1 && getattr_stat(&slots[4].inode).size==3333,"shutdown preserves another superblock");
    drop(&sb_b);drop(&sb_f);drop(&sb_under);drop(&sb_a);
    require(entries()==0 && live_allocations==0,"all shutdowns release all entries and pins");
    for(int n=0;n<slot_count;n++)require(!slots[n].inode.refs,"no final inode pin leak");
    require(sync_count>0,"retirement executes real RCU barrier");balanced_paths();
    puts("PASS deterministic retirement/grace/iput versus shutdown; other sb preserved; no final leaks");
}
#endif
int main(void) {
    alarm(15);cache_reclaim();
#if HAS_LIFETIME
    replacement_update();errors();full_keys_and_fuse();retirement_shutdown();
#else
    require(0,"baseline cannot claim completed lifecycle support");
#endif
    puts("actual complete SUSFS KSTAT block: all host behavior contracts pass");return 0;
}
'''


def check_common(common, hostcc=None):
    """Compile and execute actual KSTAT implementation from a common-kernel root."""
    with tempfile.TemporaryDirectory(prefix="susfs-kstat-contract-") as directory:
        root = Path(directory)
        c_file, binary = root / "kstat_contract.c", root / "kstat_contract"
        c_file.write_text(harness(common))
        cc = hostcc or os.environ.get("HOSTCC", "cc")
        result = subprocess.run([cc, "-std=gnu11", "-pthread", "-Werror",
                                 "-Wno-unused-function", str(c_file), "-o", str(binary)],
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError("actual KSTAT block did not compile:\n" + result.stderr)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise AssertionError("actual KSTAT runtime contract failed:\n" + result.stdout + result.stderr)
        print(result.stdout.strip())
    check_superhook((Path(common) / "fs/super.c").read_text())


def check_superhook(source):
    """Static integration contract: the full kernel shutdown cannot run on host."""
    start = source.index("void generic_shutdown_super(")
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        depth += (source[index] == "{") - (source[index] == "}")
        if not depth:
            body = source[opening:index + 1]
            break
    else:
        raise AssertionError("unterminated generic_shutdown_super")
    cleared = re.search(r"sb->s_flags\s*&=\s*~SB_ACTIVE\s*;", body)
    hook = re.search(r"#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT\s+"
                     r"susfs_drop_sus_kstat_for_sb\(sb\);\s+#endif", body)
    evict = re.search(r"\bevict_inodes\(sb\);", body)
    if not (cleared and hook and evict and cleared.start() < hook.start() < evict.start()
            and body.count("susfs_drop_sus_kstat_for_sb(sb);") == 1):
        raise AssertionError("KSTAT shutdown integration requires CONFIG guard and clear SB_ACTIVE < drop hook < evict_inodes")
    print("PASS static generic_shutdown_super: CONFIG guard, clear SB_ACTIVE < drop < evict_inodes")


def check_mutations(common, hostcc=None):
    """Require defect-directed mutations to compile and fail in real C execution."""
    common = Path(common)
    source = (common / "fs/susfs.c").read_text()
    header = (common / "include/linux/susfs.h").read_text()
    mutations = (
        ("missing igrab", "entry->pinned_inode = igrab(marked_inode);",
         "entry->pinned_inode = marked_inode;", "susfs_prepare_sus_kstat"),
        ("missing iput", "iput(entry->pinned_inode);", "(void)entry->pinned_inode;", "susfs_kstat_entry_put"),
        ("missing RCU grace", "synchronize_rcu();", "(void)0;", "susfs_kstat_drain_retired"),
        ("getattr missing ino key", "if (entry->target_ino == target_ino &&",
         "if (true &&", "susfs_sus_kstat_spoof_generic_fillattr"),
        ("map missing ino key", "if (entry->target_ino == target_ino &&",
         "if (true &&", "susfs_sus_kstat_spoof_show_map_vma"),
        ("statfs missing ino key", "if (entry->target_ino == target_inode->i_ino &&",
         "if (true &&", "susfs_sus_kstat_spoof_vfs_statfs"),
        ("inotify missing ino key", "if (entry->target_ino == *out_target_ino &&",
         "if (true &&", "susfs_sus_kstat_spoof_inotify_fdinfo"),
        ("proc fd missing ino key", "if (entry->target_ino == *out_target_ino &&",
         "if (true &&", "susfs_sus_kstat_spoof_proc_fd_seq_show"),
        ("getattr missing dev key", "entry->target_dev == target_dev &&", "true &&",
         "susfs_sus_kstat_spoof_generic_fillattr"),
        ("getattr missing FUSE key", "entry->is_fuse == is_fuse)", "true)",
         "susfs_sus_kstat_spoof_generic_fillattr"),
        ("retirement corrupts reader next", "hash_del_rcu(&entry->node);",
         "hash_del_rcu(&entry->node); entry->node.next = NULL;", "susfs_kstat_retire_path_locked"),
        ("publication omits lifecycle lock", "mutex_lock(&susfs_mutex_lock_sus_kstat_lifecycle);",
         "(void)0;", "susfs_publish_sus_kstat"),
    )
    with tempfile.TemporaryDirectory(prefix="susfs-kstat-mutations-") as directory:
        root = Path(directory)
        (root / "fs").mkdir()
        (root / "include/linux").mkdir(parents=True)
        (root / "include/linux/susfs.h").write_text(header)
        super_source = (common / "fs/super.c").read_text()
        (root / "fs/super.c").write_text(super_source)
        for name, old, new, function_name in mutations:
            # Restrict mutation to the actual KSTAT block; other SUSFS features
            # also use synchronize_rcu, and must remain byte-for-byte unchanged.
            end = "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_KSTAT"
            block = _block(source, "/* sus_kstat */", end)
            start = block.index(function_name + "(")
            finish = block.index("\n}", start) + 2
            function = block[start:finish]
            if function.count(old) != 1:
                raise AssertionError("mutation target missing: " + name)
            changed = source.replace(function, function.replace(old, new, 1), 1)
            (root / "fs/susfs.c").write_text(changed)
            try:
                check_common(root, hostcc)
            except AssertionError as error:
                if "actual KSTAT runtime contract failed:" not in str(error):
                    raise AssertionError("mutation must compile and fail at runtime: " + name) from error
                print("mutation rejected at runtime: " + name + " -> " + str(error).splitlines()[-1])
            else:
                raise AssertionError("mutation escaped runtime contract: " + name)
        hook = "susfs_drop_sus_kstat_for_sb(sb);"
        guarded_hook = re.search(r"#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT\s+"
                                 r"susfs_drop_sus_kstat_for_sb\(sb\);\s+#endif",
                                 super_source).group()
        static_mutations = {
            "missing shutdown hook": super_source.replace(hook, "/* removed */", 1),
            "shutdown hook before SB_ACTIVE clear": super_source.replace(guarded_hook, "", 1).replace(
                "sb->s_flags &= ~SB_ACTIVE;", guarded_hook + "\n\tsb->s_flags &= ~SB_ACTIVE;", 1),
            "shutdown hook after evict_inodes": super_source.replace(guarded_hook, "", 1).replace(
                "evict_inodes(sb);", "evict_inodes(sb);\n" + guarded_hook, 1),
        }
        for name, changed in static_mutations.items():
            try:
                check_superhook(changed)
            except AssertionError:
                print("mutation rejected by static shutdown contract: " + name)
            else:
                raise AssertionError("mutation escaped static shutdown contract: " + name)


def _extract_fixture(common):
    fixture = Path(__file__).parent / "fixtures/susfs-kstat-baseline.tar.gz"
    if not fixture.is_file():
        raise AssertionError("required fixed KSTAT source fixture missing: " + str(fixture))
    if hashlib.sha256(fixture.read_bytes()).hexdigest() != FIXTURE_SHA256:
        raise AssertionError("fixed KSTAT source archive identity changed")
    with tarfile.open(fixture, "r:gz") as archive:
        expected = {"fs/susfs.c", "fs/super.c", "include/linux/susfs.h"}
        if set(archive.getnames()) != expected or any(not m.isfile() for m in archive):
            raise AssertionError("unexpected KSTAT fixture members")
        archive.extractall(common, filter="data")
    for name, expected_hash in BASELINE_SHA256.items():
        if hashlib.sha256((common / name).read_bytes()).hexdigest() != expected_hash:
            raise AssertionError("fixed baseline source identity changed: " + name)


def _strict_apply(common, patch, label):
    for checking in (True, False):
        command = ["git", "apply"] + (["--check"] if checking else []) + [str(Path(patch).resolve())]
        applied = subprocess.run(command, cwd=common, capture_output=True, text=True, timeout=30)
        if applied.returncode:
            raise AssertionError(label + " failed strict " + ("check" if checking else "apply")
                                 + ":\n" + applied.stderr)


def check_fixture(patch, hostcc=None, mutations=True):
    """Run offline baseline red -> real patch apply -> same contract green."""
    with tempfile.TemporaryDirectory(prefix="susfs-kstat-fixture-") as directory:
        common = Path(directory)
        _extract_fixture(common)
        try:
            check_common(common, hostcc)
        except AssertionError as error:
            if "KSTAT CONTRACT FAIL: cache reclaim must preserve marker and spoof" not in str(error):
                raise AssertionError("baseline must fail at runtime for the inode reclaim defect") from error
            print("baseline red (compiled and executed): " + str(error).splitlines()[-1])
        else:
            raise AssertionError("baseline unexpectedly passed inode reclaim contract")
        _strict_apply(common, patch, "actual KSTAT patch against raw fixed fixture")
        check_common(common, hostcc)
        if mutations:
            check_mutations(common, hostcc)


def check_stacked_fixture(patch, hostcc=None):
    """Reproduce the actual upstream SUSFS -> local lifetime patch composition."""
    encoded = Path(__file__).parent / "fixtures/upstream-susfs-45a05753-super.patch.b64"
    if not encoded.is_file():
        raise AssertionError("required exact 45a05753 upstream super.c diff fixture missing")
    upstream_bytes = base64.b64decode(encoded.read_bytes().strip(), validate=True)
    if hashlib.sha256(upstream_bytes).hexdigest() != UPSTREAM_SUPER_SHA256:
        raise AssertionError("required exact 45a05753 upstream super.c diff missing or changed")
    with tempfile.TemporaryDirectory(prefix="susfs-kstat-stacked-fixture-") as directory:
        common = Path(directory)
        _extract_fixture(common)
        upstream = common / "upstream-susfs-45a05753-super.patch"
        upstream.write_bytes(upstream_bytes)
        _strict_apply(common, upstream, "exact 45a05753 upstream SUSFS super.c diff")
        if hashlib.sha256((common / "fs/super.c").read_bytes()).hexdigest() != STACKED_SUPER_SHA256:
            raise AssertionError("upstream-stacked common super.c identity changed")
        broken = common / "old-lifetime-include.patch"
        broken.write_text(FAILED_INCLUDE_HUNK)
        red = subprocess.run(["git", "apply", "--check", str(broken)], cwd=common,
                             capture_output=True, text=True, timeout=30)
        if red.returncode != 1 or "patch failed: fs/super.c:39" not in red.stderr:
            raise AssertionError("old include hunk must fail strict apply on the actual upstream stack:\n" + red.stderr)
        if hashlib.sha256((common / "fs/super.c").read_bytes()).hexdigest() != STACKED_SUPER_SHA256:
            raise AssertionError("failed old-patch check mutated the stacked source")
        print("stack integration red: old include hunk fails strict apply at fs/super.c:39")
        _strict_apply(common, patch, "local KSTAT patch after exact upstream SUSFS stack")
        check_common(common, hostcc)
        print("PASS offline actual stack: f082 common -> exact 45a05753 upstream super.c -> strict local patch -> host contract")


class KstatLifetimeContractTests(unittest.TestCase):
    def test_fixed_baseline_real_patch_and_runtime_mutations(self):
        patch = Path(__file__).resolve().parents[1] / ".github/workflows/patches/susfs-kstat-lifetime.patch"
        check_fixture(patch)

    def test_exact_upstream_stack_then_strict_local_patch(self):
        patch = Path(__file__).resolve().parents[1] / ".github/workflows/patches/susfs-kstat-lifetime.patch"
        check_stacked_fixture(patch)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--common", type=Path)
    target.add_argument("--fixture-patch", type=Path)
    parser.add_argument("--hostcc")
    parser.add_argument("--check-mutations", action="store_true")
    args = parser.parse_args()
    if args.fixture_patch:
        check_fixture(args.fixture_patch, args.hostcc)
        check_stacked_fixture(args.fixture_patch, args.hostcc)
    else:
        check_common(args.common, args.hostcc)
        if args.check_mutations:
            check_mutations(args.common, args.hostcc)


if __name__ == "__main__":
    main()
