#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/close_range.h>
#include <net/sock.h>

#include "internal.h"

extern int expand_files(struct files_struct *files, unsigned int nr);
extern inline void __set_close_on_exec(unsigned int fd, struct fdtable *fdt);
extern inline void __clear_close_on_exec(unsigned int fd, struct fdtable *fdt);

inline void __my_set_open_fd(unsigned int fd, struct fdtable *fdt)
{
	__set_bit(fd, fdt->open_fds);
	fd /= BITS_PER_LONG;
	if (!~fdt->open_fds[fd])
		__set_bit(fd, fdt->full_fds_bits);
}

unsigned int my_find_next_fd(struct fdtable *fdt, unsigned int start)
{
	unsigned int maxfd = fdt->max_fds;
	unsigned int maxbit = maxfd / BITS_PER_LONG;
	unsigned int bitbit = start / BITS_PER_LONG;

	bitbit = find_next_zero_bit(fdt->full_fds_bits, maxbit, bitbit) * BITS_PER_LONG;
	if (bitbit > maxfd)
		return maxfd;
	if (bitbit > start)
		start = bitbit;
	return find_next_zero_bit(fdt->open_fds, maxfd, start);
}

int my_alloc_fd(unsigned start, unsigned end, unsigned flags)
{
    printk("[%s]: my_alloc_fd start", __func__);
    struct files_struct *files = current->files;
	unsigned int fd;
	int error;
	struct fdtable *fdt;

    spin_lock(&files->file_lock);
repeat:
	fdt = files_fdtable(files);
	fd = start;
    printk("[%s]: fd(start): %d\n", __func__, fd);
	
    if (fd < files->next_fd)
		fd = files->next_fd;
        printk("[%s]: fd(1): %d\n", __func__, fd);
	if (fd < fdt->max_fds)
		fd = my_find_next_fd(fdt, fd);
        printk("[%s]: fd(2): %d\n", __func__, fd);
	/*
	 * N.B. For clone tasks sharing a files structure, this test
	 * will limit the total number of files that can be opened.
	 */
	error = -EMFILE;
	if (fd >= end)
		goto out;

	error = expand_files(files, fd);
	if (error < 0)
		goto out;

	/*
	 * If we needed to expand the fs array we
	 * might have blocked - try again.
	 */
	if (error)
		goto repeat;

	if (start <= files->next_fd)
		files->next_fd = fd + 1;

	__my_set_open_fd(fd, fdt);
	if (flags & O_CLOEXEC)
		__set_close_on_exec(fd, fdt);
	else
		__clear_close_on_exec(fd, fdt);
	error = fd;
#if 1
	/* Sanity check */
	if (rcu_access_pointer(fdt->fd[fd]) != NULL) {
		printk(KERN_WARNING "alloc_fd: slot %d not NULL!\n", fd);
		rcu_assign_pointer(fdt->fd[fd], NULL);
	}
#endif

out:
	spin_unlock(&files->file_lock);
	return error;
}

int __my_get_unused_fd_flags(unsigned flags, unsigned long nofile)
{
	return my_alloc_fd(0, nofile, flags);
}

int my_get_unused_fd_flags(unsigned flags)
{
    printk("[%s]: __get_unused_fd_flags function executed", __func__);
    return __my_get_unused_fd_flags(flags, rlimit(RLIMIT_NOFILE));
}
EXPORT_SYMBOL(my_get_unused_fd_flags);
