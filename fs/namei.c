#include <linux/init.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/filelock.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/sched/mm.h>
#include <linux/fsnotify.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/ima.h>
#include <linux/syscalls.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/device_cgroup.h>
#include <linux/fs_struct.h>
#include <linux/posix_acl.h>
#include <linux/hash.h>
#include <linux/bitops.h>
#include <linux/init_task.h>
#include <linux/uaccess.h>

#include "internal.h"
#include "mount.h"

#define __getname()     kmem_cache_alloc(names_cachep, GFP_KERNEL)
#define EMBEDDED_NAME_MAX	(PATH_MAX - offsetof(struct filename, iname))
#define ND_ROOT_PRESET 1
#define ND_ROOT_GRABBED 2
#define ND_JUMPED 4
#define EMBEDDED_LEVELS 2

#define read_seqcount_retry(s, start)                   \
    do_read_seqcount_retry(seqprop_ptr(s), start)

enum {WALK_TRAILING = 1, WALK_MORE = 2, WALK_NOFOLLOW = 4};

struct nameidata {
    struct path path;
    struct qstr last;
    struct path root;
    struct inode *inode; /* path.dentry.d_inode */
    unsigned int flags, state;
    unsigned seq, next_seq, m_seq, r_seq;
    int last_type;
    unsigned depth;
    int total_link_count;
    struct saved {
        struct path link;
        struct delayed_call done;
        const char *name;
        unsigned seq;
    } *stack, internal[EMBEDDED_LEVELS];
    struct filename *name;
    struct nameidata *saved;
    unsigned root_seq;
    int dfd;
    vfsuid_t dir_vfsuid;
    umode_t dir_mode;
} __randomize_layout;

struct icc_req {
    struct hlist_node req_node;
    struct icc_node *node;
    struct device *dev;
    bool enabled;
    u32 tag;
    u32 avg_bw;
    u32 peak_bw;
};

struct icc_path {
    const char *name;
    size_t num_nodes;
    struct icc_req reqs[] __counted_by(num_nodes);
};

extern int do_tmpfile(struct nameidata *nd, unsigned flags, const struct open_flags *op, struct file *file);
extern int do_o_path(struct nameidata *nd, unsigned flags, struct file *file);
extern void terminate_walk(struct nameidata *nd); 
extern void set_nameidata(struct nameidata *p, int dfd, struct filename *name, const struct path *root);
extern void restore_nameidata(void);
extern struct file *alloc_empty_file(int flags, const struct cred *cred);
extern int do_open(struct nameidata *nd, struct file *file, const struct open_flags *op);
extern int nd_jump_root(struct nameidata *nd);
extern unsigned long __fdget_raw(unsigned int fd);
extern inline void mnt_add_count(struct mount *mnt, int n);
extern inline int do_read_seqcount_retry(const seqcount_t *s, unsigned start);
extern const char *pick_link(struct nameidata *nd, struct path *link, struct inode *inode, int flags);
extern inline void lock_mount_hash(void);
extern void drop_links(struct nameidata *nd);
extern bool try_to_unlazy_next(struct nameidata *nd, struct dentry *dentry); 
extern inline int d_revalidate(struct dentry *dentry, unsigned int flags);
extern inline int handle_mounts(struct nameidata *nd, struct dentry *dentry, struct path *path);
extern inline void put_link(struct nameidata *nd);
extern const char *handle_dots(struct nameidata *nd, int type); 
extern struct dentry *lookup_slow(const struct qstr *name, struct dentry *dir, unsigned int flags);
extern inline int may_lookup(struct mnt_idmap *idmap, struct nameidata *nd);
extern inline void unlock_mount_hash(void);
extern void leave_rcu(struct nameidata *nd);
extern inline u64 hash_name(const void *salt, const char *name);
extern struct dentry *__d_lookup_rcu(const struct dentry *parent, const struct qstr *name, unsigned *seqp);
extern struct dentry *__d_lookup(const struct dentry *parent, const struct qstr *name);
extern int mnt_want_write(struct vfsmount *m);
extern struct dentry *atomic_open(struct nameidata *nd, struct dentry *dentry, struct file *file, int open_flag, umode_t mode);
extern int may_o_create(struct mnt_idmap *idmap, const struct path *dir, struct dentry *dentry, umode_t mode);
extern inline umode_t vfs_prepare_mode(struct mnt_idmap *idmap, const struct inode *dir, umode_t mode, umode_t mask_perms, umode_t type);

/* must be paired with terminate_walk() */
static const char *my_path_init(struct nameidata *nd, unsigned flags)
{
	int error;
	const char *s = nd->name->name;

	/* LOOKUP_CACHED requires RCU, ask caller to retry */
	if ((flags & (LOOKUP_RCU | LOOKUP_CACHED)) == LOOKUP_CACHED)
		return ERR_PTR(-EAGAIN);

	if (!*s)
		flags &= ~LOOKUP_RCU;
	if (flags & LOOKUP_RCU)
		rcu_read_lock();
	else
		nd->seq = nd->next_seq = 0;

	nd->flags = flags;
	nd->state |= ND_JUMPED;

	nd->m_seq = __read_seqcount_begin(&mount_lock.seqcount);
	nd->r_seq = __read_seqcount_begin(&rename_lock.seqcount);
	smp_rmb();

	if (nd->state & ND_ROOT_PRESET) {
		struct dentry *root = nd->root.dentry;
		struct inode *inode = root->d_inode;
		if (*s && unlikely(!d_can_lookup(root)))
			return ERR_PTR(-ENOTDIR);
		nd->path = nd->root;
		nd->inode = inode;
		if (flags & LOOKUP_RCU) {
			nd->seq = read_seqcount_begin(&nd->path.dentry->d_seq);
			nd->root_seq = nd->seq;
		} else {
			path_get(&nd->path);
		}
		return s;
	}

	nd->root.mnt = NULL;

	/* Absolute pathname -- fetch the root (LOOKUP_IN_ROOT uses nd->dfd). */
	if (*s == '/' && !(flags & LOOKUP_IN_ROOT)) {
		error = nd_jump_root(nd);
		if (unlikely(error))
			return ERR_PTR(error);
		return s;
	}

	if (nd->dfd == AT_FDCWD) {
        if (flags & LOOKUP_RCU) {
            struct fs_struct *fs = current->fs;
            unsigned seq;

            do {
                seq = read_seqcount_begin(&fs->seq);
                nd->path = fs->pwd;
                nd->inode = nd->path.dentry->d_inode;
                nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
            } while (read_seqcount_retry(&fs->seq, seq));
        } else {
            get_fs_pwd(current->fs, &nd->path);
            nd->inode = nd->path.dentry->d_inode;
        }
    } else {
        /* Caller must check execute permissions on the starting path component */
        struct fd f = fdget_raw(nd->dfd);
        struct dentry *dentry;

        if (!f.file)
            return ERR_PTR(-EBADF);

        dentry = f.file->f_path.dentry;

        if (*s && unlikely(!d_can_lookup(dentry))) {
            fdput(f);
            return ERR_PTR(-ENOTDIR);
        }

        nd->path = f.file->f_path;
        if (flags & LOOKUP_RCU) {
            nd->inode = nd->path.dentry->d_inode;
            nd->seq = read_seqcount_begin(&nd->path.dentry->d_seq);
        } else {
            path_get(&nd->path);
            nd->inode = nd->path.dentry->d_inode;
        }
        fdput(f);
    }

    /* For scoped-lookups we need to set the root to the dirfd as well. */
    if (flags & LOOKUP_IS_SCOPED) {
        nd->root = nd->path;
        if (flags & LOOKUP_RCU) {
            nd->root_seq = nd->seq;
        } else {
            path_get(&nd->root);
            nd->state |= ND_ROOT_GRABBED;
        }
    }
    return s;
}

/* call under rcu_read_lock */
int __my_legitimize_mnt(struct vfsmount *bastard, unsigned seq)
{
    struct mount *mnt;
    if (read_seqretry(&mount_lock, seq))
        return 1;
    if (bastard == NULL)
        return 0;
    mnt = real_mount(bastard);
    mnt_add_count(mnt, 1);
    smp_mb();           // see mntput_no_expire()
    if (likely(!read_seqretry(&mount_lock, seq)))
        return 0;
    if (bastard->mnt_flags & MNT_SYNC_UMOUNT) {
        mnt_add_count(mnt, -1);
        return 1;
    }
    lock_mount_hash();
    if (unlikely(bastard->mnt_flags & MNT_DOOMED)) {
        mnt_add_count(mnt, -1);
        unlock_mount_hash();
        return 1;
    }
    unlock_mount_hash();
    /* caller will mntput() */
    return -1;
}

/* path_put is needed afterwards regardless of success or failure */
static bool __my_legitimize_path(struct path *path, unsigned seq, unsigned mseq)
{
    int res = __my_legitimize_mnt(path->mnt, mseq);
    if (unlikely(res)) {
        if (res > 0)
            path->mnt = NULL;
        path->dentry = NULL;
        return false;
    }
    if (unlikely(!lockref_get_not_dead(&path->dentry->d_lockref))) {
        path->dentry = NULL;
        return false;
    }
    return !read_seqcount_retry(&path->dentry->d_seq, seq);
}

static inline bool my_legitimize_path(struct nameidata *nd,
                struct path *path, unsigned seq)
{
    return __my_legitimize_path(path, seq, nd->m_seq);
}

static bool my_legitimize_root(struct nameidata *nd)
{
    /* Nothing to do if nd->root is zero or is managed by the VFS user. */
    if (!nd->root.mnt || (nd->state & ND_ROOT_PRESET))
        return true;
    nd->state |= ND_ROOT_GRABBED;
    return my_legitimize_path(nd, &nd->root, nd->root_seq);
}

static bool my_legitimize_links(struct nameidata *nd)
{
    int i;
    if (unlikely(nd->flags & LOOKUP_CACHED)) {
        drop_links(nd);
        nd->depth = 0;
        return false;
    }
    for (i = 0; i < nd->depth; i++) {
        struct saved *last = nd->stack + i;
        if (unlikely(!my_legitimize_path(nd, &last->link, last->seq))) {
            drop_links(nd);
            nd->depth = i + 1;
            return false;
        }
    }
    return true;
}

static bool my_try_to_unlazy(struct nameidata *nd)
{
    struct dentry *parent = nd->path.dentry;

    BUG_ON(!(nd->flags & LOOKUP_RCU));

    if (unlikely(!my_legitimize_links(nd)))
        goto out1;
    if (unlikely(!my_legitimize_path(nd, &nd->path, nd->seq)))
        goto out;
    if (unlikely(!my_legitimize_root(nd)))
        goto out;
    leave_rcu(nd);
    BUG_ON(nd->inode != parent->d_inode);
    return true;

out1:
    nd->path.mnt = NULL;
    nd->path.dentry = NULL;
out:
    leave_rcu(nd);
    return false;
}

static struct dentry *my_lookup_fast(struct nameidata *nd)
{
    struct dentry *dentry, *parent = nd->path.dentry;
    int status = 1;

    /*
     * Rename seqlock is not required here because in the off chance
     * of a false negative due to a concurrent rename, the caller is
     * going to fall back to non-racy lookup.
     */
    if (nd->flags & LOOKUP_RCU) {
        printk("[%s]: parent=%s\n", __func__, parent->d_name.name);
        printk("[%s]: nd->last.hash_len=%u\n", __func__, hashlen_len(nd->last.hash_len));
        printk("[%s]: nd->next_seq=%u\n", __func__, nd->next_seq);
        dentry = __d_lookup_rcu(parent, &nd->last, &nd->next_seq);
        if (unlikely(!dentry)) {
            if (!my_try_to_unlazy(nd))
                return ERR_PTR(-ECHILD);
            return NULL;
        }

        /*
         * This sequence count validates that the parent had no
         * changes while we did the lookup of the dentry above.
         */
        if (read_seqcount_retry(&parent->d_seq, nd->seq))
            return ERR_PTR(-ECHILD);

        status = d_revalidate(dentry, nd->flags);
        if (likely(status > 0))
            return dentry;
        if (!try_to_unlazy_next(nd, dentry))
            return ERR_PTR(-ECHILD);
        if (status == -ECHILD)
            /* we'd been told to redo it in non-rcu mode */
            status = d_revalidate(dentry, nd->flags);
    } else {
        dentry = __d_lookup(parent, &nd->last);
        if (unlikely(!dentry))
            return NULL;
        status = d_revalidate(dentry, nd->flags);
    }
    if (unlikely(status <= 0)) {
        if (!status)
            d_invalidate(dentry);
        dput(dentry);
        return ERR_PTR(status);
    }
    return dentry;
}

static const char *my_step_into(struct nameidata *nd, int flags,
             struct dentry *dentry)
{
    struct path path;
    struct inode *inode;
    int err = handle_mounts(nd, dentry, &path);

    if (err < 0)
        return ERR_PTR(err);
    inode = path.dentry->d_inode;
    if (likely(!d_is_symlink(path.dentry)) ||
       ((flags & WALK_TRAILING) && !(nd->flags & LOOKUP_FOLLOW)) ||
       (flags & WALK_NOFOLLOW)) {
        /* not a symlink or should not follow */
        if (nd->flags & LOOKUP_RCU) {
            if (read_seqcount_retry(&path.dentry->d_seq, nd->next_seq))
                return ERR_PTR(-ECHILD);
            if (unlikely(!inode))
                return ERR_PTR(-ENOENT);
        } else {
            dput(nd->path.dentry);
            if (nd->path.mnt != path.mnt)
                mntput(nd->path.mnt);
        }
        nd->path = path;
        nd->inode = inode;
        nd->seq = nd->next_seq;
        return NULL;
    }
    if (nd->flags & LOOKUP_RCU) {
        /* make sure that d_is_symlink above matches inode */
        if (read_seqcount_retry(&path.dentry->d_seq, nd->next_seq))
            return ERR_PTR(-ECHILD);
    } else {
        if (path.mnt == nd->path.mnt)
            mntget(path.mnt);
    }
    return pick_link(nd, &path, inode, flags);
}

static const char *my_walk_component(struct nameidata *nd, int flags)
{
    struct dentry *dentry;
    /*
     * "." and ".." are special - ".." especially so because it has
     * to be able to know about the current root directory and
     * parent relationships.
     */
    if (unlikely(nd->last_type != LAST_NORM)) {
        if (!(flags & WALK_MORE) && nd->depth)
            put_link(nd);
        return handle_dots(nd, nd->last_type);
    }
    dentry = my_lookup_fast(nd);
    if (IS_ERR(dentry))
        return ERR_CAST(dentry);
    if (unlikely(!dentry)) {
        dentry = lookup_slow(&nd->last, nd->path.dentry, nd->flags);
        if (IS_ERR(dentry))
            return ERR_CAST(dentry);
    }
    if (!(flags & WALK_MORE) && nd->depth)
        put_link(nd);
    return my_step_into(nd, flags, dentry);
}

int my_link_path_walk(const char *name, struct nameidata *nd)
{
    int depth = 0; // depth <= nd->depth
    int err;

    nd->last_type = LAST_ROOT;
    nd->flags |= LOOKUP_PARENT;
    if (IS_ERR(name))
        return PTR_ERR(name);
    while (*name=='/')
        name++;
    if (!*name) {
        nd->dir_mode = 0; // short-circuit the 'hardening' idiocy
        return 0;
    }

    /* At this point we know we have a real path component. */
    for(;;) {
        struct mnt_idmap *idmap;
        const char *link;
        u64 hash_len;
        int type;

        idmap = mnt_idmap(nd->path.mnt);
        err = may_lookup(idmap, nd);
        if (err)
            return err;

        hash_len = hash_name(nd->path.dentry, name);

        type = LAST_NORM;
        if (name[0] == '.') switch (hashlen_len(hash_len)) {
            case 2:
                if (name[1] == '.') {
                    type = LAST_DOTDOT;
                    nd->state |= ND_JUMPED;
                }
                break;
            case 1:
                type = LAST_DOT;
        }
        if (likely(type == LAST_NORM)) {
            struct dentry *parent = nd->path.dentry;
            nd->state &= ~ND_JUMPED;
            if (unlikely(parent->d_flags & DCACHE_OP_HASH)) {
                struct qstr this = { { .hash_len = hash_len }, .name = name };
                err = parent->d_op->d_hash(parent, &this);
                if (err < 0)
                    return err;
                hash_len = this.hash_len;
                name = this.name;
            }
        }

        nd->last.hash_len = hash_len;
        printk("[%s]: nd->last.hash_len=%llu\n", __func__, (long long unsigned int)nd->last.hash_len);
        nd->last.name = name;
        printk("[%s]: nd->last.name=%s", __func__, nd->last.name);
        nd->last_type = type;
        printk("[%s]: nd->last_type=%d", __func__, nd->last_type);

        name += hashlen_len(hash_len);
        if (!*name)
            goto OK;
        /*
         * If it wasn't NUL, we know it was '/'. Skip that
         * slash, and continue until no more slashes.
         */
        do {
            name++;
        } while (unlikely(*name == '/'));
        if (unlikely(!*name)) {
OK:
            /* pathname or trailing symlink, done */
            if (!depth) {
                nd->dir_vfsuid = i_uid_into_vfsuid(idmap, nd->inode);
                nd->dir_mode = nd->inode->i_mode;
                nd->flags &= ~LOOKUP_PARENT;
                return 0;
            }
            /* last component of nested symlink */
            name = nd->stack[--depth].name;
            link = my_walk_component(nd, 0);
        } else {
            /* not the last component */
            link = my_walk_component(nd, WALK_MORE);
        }
        if (unlikely(link)) {
            if (IS_ERR(link))
                return PTR_ERR(link);
            /* a symlink to follow */
            nd->stack[depth++].name = name;
            name = link;
            continue;
        }
        if (unlikely(!d_can_lookup(nd->path.dentry))) {
            if (nd->flags & LOOKUP_RCU) {
                if (!my_try_to_unlazy(nd))
                    return -ECHILD;
            }
            return -ENOTDIR;
        }
    }
}

static struct dentry *my_lookup_open(struct nameidata *nd, struct file *file,
                  const struct open_flags *op,
                  bool got_write)
{
    struct mnt_idmap *idmap;
    struct dentry *dir = nd->path.dentry;
    struct inode *dir_inode = dir->d_inode;
    int open_flag = op->open_flag;
    struct dentry *dentry;
    int error, create_error = 0;
    umode_t mode = op->mode;
    DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wq);

    if (unlikely(IS_DEADDIR(dir_inode)))
        return ERR_PTR(-ENOENT);

    file->f_mode &= ~FMODE_CREATED;
    dentry = d_lookup(dir, &nd->last);
    printk("[%s]: dentry=%s\n", __func__, dentry->d_name.name);
    for (;;) {
        if (!dentry) {
            dentry = d_alloc_parallel(dir, &nd->last, &wq);
            if (IS_ERR(dentry))
                return dentry;
        }
        if (d_in_lookup(dentry))
            break;

        error = d_revalidate(dentry, nd->flags);
        if (likely(error > 0))
            break;
        if (error)
            goto out_dput;
        d_invalidate(dentry);
        dput(dentry);
        dentry = NULL;
    }
    if (dentry->d_inode) {
        /* Cached positive dentry: will open in f_op->open */
        return dentry;
    }

    /*
     * Checking write permission is tricky, bacuse we don't know if we are
     * going to actually need it: O_CREAT opens should work as long as the
     * file exists.  But checking existence breaks atomicity.  The trick is
     * to check access and if not granted clear O_CREAT from the flags.
     *
     * Another problem is returing the "right" error value (e.g. for an
     * O_EXCL open we want to return EEXIST not EROFS).
     */
    if (unlikely(!got_write))
        open_flag &= ~O_TRUNC;
    idmap = mnt_idmap(nd->path.mnt);
    if (open_flag & O_CREAT) {
        if (open_flag & O_EXCL)
            open_flag &= ~O_TRUNC;
        mode = vfs_prepare_mode(idmap, dir->d_inode, mode, mode, mode);
        if (likely(got_write))
            create_error = may_o_create(idmap, &nd->path,
                            dentry, mode);
        else
            create_error = -EROFS;
    }
    if (create_error)
        open_flag &= ~O_CREAT;
    if (dir_inode->i_op->atomic_open) {
        dentry = atomic_open(nd, dentry, file, open_flag, mode);
        if (unlikely(create_error) && dentry == ERR_PTR(-ENOENT))
            dentry = ERR_PTR(create_error);
        return dentry;
    }

    if (d_in_lookup(dentry)) {
        struct dentry *res = dir_inode->i_op->lookup(dir_inode, dentry,
                                 nd->flags);
        d_lookup_done(dentry);
        if (unlikely(res)) {
            if (IS_ERR(res)) {
                error = PTR_ERR(res);
                goto out_dput;
            }
            dput(dentry);
            dentry = res;
        }
    }
    /* Negative dentry, just create the file */
    if (!dentry->d_inode && (open_flag & O_CREAT)) {
        file->f_mode |= FMODE_CREATED;
        audit_inode_child(dir_inode, dentry, AUDIT_TYPE_CHILD_CREATE);
        if (!dir_inode->i_op->create) {
            error = -EACCES;
            goto out_dput;
        }

        error = dir_inode->i_op->create(idmap, dir_inode, dentry,
                        mode, open_flag & O_EXCL);
        if (error)
            goto out_dput;
    }
    if (unlikely(create_error) && !dentry->d_inode) {
        error = create_error;
        goto out_dput;
    }
    return dentry;

out_dput:
    dput(dentry);
    return ERR_PTR(error);
}

const char *my_open_last_lookups(struct nameidata *nd,
           struct file *file, const struct open_flags *op)
{
    struct dentry *dir = nd->path.dentry;
    int open_flag = op->open_flag;
    bool got_write = false;
    struct dentry *dentry;
    const char *res;

    printk("[%s]: nd->path.dentry=%s\n", __func__, nd->path.dentry->d_name.name);
    printk("[%s]: nd->last.hash_len=%llu\n", __func__, nd->last.hash_len);
    printk("[%s]: nd->last.name=%s\n", __func__, nd->last.name);
    
    nd->flags |= op->intent;

    if (nd->last_type != LAST_NORM) {
        if (nd->depth)
            put_link(nd);
        return handle_dots(nd, nd->last_type);
    }

    if (!(open_flag & O_CREAT)) {
        if (nd->last.name[nd->last.len])
            nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
        /* we _can_ be in RCU mode here */
        dentry = my_lookup_fast(nd);
        if (IS_ERR(dentry))
            return ERR_CAST(dentry);
        if (likely(dentry))
            goto finish_lookup;

        BUG_ON(nd->flags & LOOKUP_RCU);
    } else {
        /* create side of things */
        if (nd->flags & LOOKUP_RCU) {
            if (!my_try_to_unlazy(nd))
                return ERR_PTR(-ECHILD);
        }
        audit_inode(nd->name, dir, AUDIT_INODE_PARENT);
        /* trailing slashes? */
        if (unlikely(nd->last.name[nd->last.len]))
            return ERR_PTR(-EISDIR);
    }

    if (open_flag & (O_CREAT | O_TRUNC | O_WRONLY | O_RDWR)) {
        got_write = !mnt_want_write(nd->path.mnt);
        /*
         * do _not_ fail yet - we might not need that or fail with
         * a different error; let lookup_open() decide; we'll be
         * dropping this one anyway.
         */
    }
    if (open_flag & O_CREAT)
        inode_lock(dir->d_inode);
    else
        inode_lock_shared(dir->d_inode);
    dentry = my_lookup_open(nd, file, op, got_write);
    printk("[%s]: dentry(my_lookup_open()'s result)= %s\n", __func__, dentry->d_name.name);
    if (!IS_ERR(dentry) && (file->f_mode & FMODE_CREATED))
        fsnotify_create(dir->d_inode, dentry);
    if (open_flag & O_CREAT)
        inode_unlock(dir->d_inode);
    else
        inode_unlock_shared(dir->d_inode);

    if (got_write)
        mnt_drop_write(nd->path.mnt);

    if (IS_ERR(dentry))
        return ERR_CAST(dentry);

    if (file->f_mode & (FMODE_OPENED | FMODE_CREATED)) {
        dput(nd->path.dentry);
        nd->path.dentry = dentry;
        return NULL;
    }

finish_lookup:
    if (nd->depth)
        put_link(nd);
    res = my_step_into(nd, WALK_TRAILING, dentry);
    printk("[%s]: nd->path.dentry=%s\n", __func__, nd->path.dentry->d_name.name);
    if (unlikely(res))
        nd->flags &= ~(LOOKUP_OPEN|LOOKUP_CREATE|LOOKUP_EXCL);
    return res;
}

// obtains the file object corresponding to the incoming pathname
// searches the file along a path and return the file
struct file* my_path_openat(struct nameidata *nd, const struct open_flags *op, unsigned flags)
{
    printk("[%s]: my_path_openat()\n", __func__);
	struct file *file;
	int error;

	file = alloc_empty_file(op->open_flag, current_cred()); // allocate memory to the struct file
	if (IS_ERR(file))
		return file;

	if (unlikely(file->f_flags & __O_TMPFILE)) {
		error = do_tmpfile(nd, flags, op, file);
	} else if (unlikely(file->f_flags & O_PATH)) {
		error = do_o_path(nd, flags, file);
	} else {
		const char *s = my_path_init(nd, flags); // initialize the nameidata structure
        printk("[%s]: the initialized nameidata: %c\n", __func__, *s);
		while (!(error = my_link_path_walk(s, nd)) &&
		       (s = my_open_last_lookups(nd, file, op)) != NULL)
			;
		if (!error)
			error = do_open(nd, file, op);
		terminate_walk(nd);
	}
	if (likely(!error)) {
		if (likely(file->f_mode & FMODE_OPENED))
			return file;
		WARN_ON(1);
		error = -EINVAL;
	}
	fput(file);
	if (error == -EOPENSTALE) {
		if (flags & LOOKUP_RCU)
			error = -ECHILD;
		else
			error = -ESTALE;
	}
	return ERR_PTR(error);
}
EXPORT_SYMBOL(my_path_openat);

// gets the file struct corresponding to the filename
// parameters:
// return: file struct
struct file *my_do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op)
{
    printk("[%s]: start my_do_filp_open", __func__);
    struct nameidata nd;
    int flags = op->lookup_flags;
    struct file *filp;

    set_nameidata(&nd, dfd, pathname, NULL);
    printk("[%s]: (set_nameidate)total_link_count: %d\n", __func__, nd.total_link_count);
    filp = my_path_openat(&nd, op, flags | LOOKUP_RCU);
    if (unlikely(filp == ERR_PTR(-ECHILD)))
        filp = my_path_openat(&nd, op, flags);
    if (unlikely(filp == ERR_PTR(-ESTALE)))
        filp = my_path_openat(&nd, op, flags | LOOKUP_REVAL);
    restore_nameidata();
    printk("[%s]: finished restore_nameidata(): ", __func__);
    return filp;
}
EXPORT_SYMBOL(my_do_filp_open);
