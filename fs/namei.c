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

struct nameidata {
    struct path path;
    struct qstr last;
    struct path root;
    struct inode    *inode; /* path.dentry.d_inode */
    unsigned int    flags, state;
    unsigned    seq, next_seq, m_seq, r_seq;
    int     last_type;
    unsigned    depth;
    int     total_link_count;
    struct saved {
        struct path link;
        struct delayed_call done;
        const char *name;
        unsigned seq;
    } *stack, internal[EMBEDDED_LEVELS];
    struct filename *name;
    struct nameidata *saved;
    unsigned    root_seq;
    int     dfd;
    vfsuid_t    dir_vfsuid;
    umode_t     dir_mode;
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
extern int link_path_walk(const char *name, struct nameidata *nd);
extern const char *open_last_lookups(struct nameidata *nd, struct file *file, const struct open_flags *op);
extern void terminate_walk(struct nameidata *nd); 
extern void set_nameidata(struct nameidata *p, int dfd, struct filename *name, const struct path *root);
extern void restore_nameidata(void);
extern struct file *alloc_empty_file(int flags, const struct cred *cred);
extern int do_open(struct nameidata *nd, struct file *file, const struct open_flags *op);
extern int nd_jump_root(struct nameidata *nd);
extern unsigned long __fdget_raw(unsigned int fd);

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
		while (!(error = link_path_walk(s, nd)) &&
		       (s = open_last_lookups(nd, file, op)) != NULL)
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
