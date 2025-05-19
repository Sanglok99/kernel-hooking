#include <linux/string.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fsnotify.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/rcupdate.h>
#include <linux/audit.h>
#include <linux/falloc.h>
#include <linux/fs_struct.h>
#include <linux/ima.h>
#include <linux/dnotify.h>
#include <linux/compat.h>
#include <linux/mnt_idmapping.h>
#include <linux/filelock.h>

#include "internal.h"

extern inline void set_nameidata(struct nameidata *p, int dfd, struct filename *name, const struct path *root);
extern struct file *path_openat(struct nameidata *nd, const struct open_flags *op, unsigned flags);
extern void restore_nameidata(void);
extern int my_get_unused_fd_flags(unsigned flags);
extern int do_tmpfile(struct nameidata *nd, unsigned flags, const struct open_flags *op, struct file *file);
extern int do_o_path(struct nameidata *nd, unsigned flags, struct file *file);
extern int link_path_walk(const char *name, struct nameidata *nd);
extern const char *path_init(struct nameidata *nd, unsigned flags);
extern const char *open_last_lookups(struct nameidata *nd, struct file *file, const struct open_flags *op);
extern void terminate_walk(struct nameidata *nd);
extern struct file *my_do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op);
extern struct file* my_path_openat(struct nameidata *nd, const struct open_flags *op, unsigned flags);


static long my_do_sys_openat2(int dfd, const char __user *filename, struct open_how *how)
{
    printk("[%s]: start my_do_sys_openat2\n", __func__); // success
    struct open_flags op;
    int fd = build_open_flags(how, &op);
    struct filename *tmp;

    if (fd)
        return fd;

    tmp = getname(filename);
    printk("[%s]: filename: %s\n", __func__, tmp->name);

    if (IS_ERR(tmp))
        return PTR_ERR(tmp);

    fd = my_get_unused_fd_flags(how->flags); // the "EXPORT_SYMBOL(get_unused_fd_flags);" code exists in the kernel source code, but how is this valid when there is no "extern int get_unused_fd_flags(unsigned flags);"?
    printk("[%s]: fd: %d\n", __func__, fd);

    if (fd >= 0) {
        struct file *f = my_do_filp_open(dfd, tmp, &op); // convert to a custum function
        if (IS_ERR(f)) {
            put_unused_fd(fd);
            fd = PTR_ERR(f);
        } else {
            fd_install(fd, f);
        }
    }
    putname(tmp);
    return fd;
}

#define VALID_OPEN_FLAGS \
    (O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | \
     O_APPEND | O_NDELAY | O_NONBLOCK | __O_SYNC | O_DSYNC | \
     FASYNC | O_DIRECT | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | \
     O_NOATIME | O_CLOEXEC | O_PATH | __O_TMPFILE)

#define S_IALLUGO (S_ISUID|S_ISGID|S_ISVTX|S_IRWXUGO)

#define O_PATH_FLAGS (O_DIRECTORY | O_NOFOLLOW | O_PATH | O_CLOEXEC)

#define WILL_CREATE(flags) (flags & (O_CREAT | __O_TMPFILE))

struct open_how my_build_open_how(int flags, umode_t mode)
{
    struct open_how how = {
        .flags = flags & VALID_OPEN_FLAGS,
        .mode = mode & S_IALLUGO,
    };

    printk("[%s]: raw flags = %#x, masked flags = %#llx\n", __func__, flags, how.flags);
    printk("[%s]: raw mode = %#x, masked mode = %#llx\n", __func__, mode, how.mode);

    /* O_PATH beats everything else. */
    if (how.flags & O_PATH)
        how.flags &= O_PATH_FLAGS;
    /* Modes should only be set for create-like flags. */
    if (!WILL_CREATE(how.flags))
        how.mode = 0;
                            
    return how;
}

long my_do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode)
{
    printk("[%s]: start module\n", __func__);
    struct open_how how = my_build_open_how(flags, mode);
    return my_do_sys_openat2(dfd, filename, &how);
}
