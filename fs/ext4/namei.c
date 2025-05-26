#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/time.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include <linux/bio.h>
#include <linux/iversion.h>
#include <linux/unicode.h>
#include "ext4.h"
#include "ext4_jbd2.h"

#include "xattr.h"
#include "acl.h"

#include <trace/events/ext4.h>
/*
 * define how far ahead to read directories while searching them.
 */
#define NAMEI_RA_CHUNKS  2
#define NAMEI_RA_BLOCKS  4
#define NAMEI_RA_SIZE        (NAMEI_RA_CHUNKS * NAMEI_RA_BLOCKS)

#define my_ext4_new_inode_start_handle(idmap, dir, mode, qstr, goal, owner, type, nblocks) \
        __my_ext4_new_inode((idmap), NULL, (dir), (mode), (qstr), (goal), (owner), 0, (type), __LINE__, (nblocks))

extern int find_group_orlov(struct super_block *sb, struct inode *parent, ext4_group_t *group, umode_t mode, const struct qstr *qstr);
extern int ext4_add_nondir(handle_t *handle, struct dentry *dentry, struct inode **inodep);
extern int ext4_xattr_credits_for_new_inode(struct inode *dir, mode_t mode, bool encrypt);
extern int recently_deleted(struct super_block *sb, ext4_group_t group, int ino); 
extern int ext4_validate_inode_bitmap(struct super_block *sb, struct ext4_group_desc *desc, ext4_group_t block_group, struct buffer_head *bh);

static inline struct ext4_sb_info *my_EXT4_SB(struct super_block *sb)
{
    return sb->s_fs_info;
}

static inline ext4_group_t my_ext4_get_groups_count(struct super_block *sb)
{
    ext4_group_t ngroups = my_EXT4_SB(sb)->s_groups_count;

    smp_rmb();
    return ngroups;
}

struct ext4_group_desc * my_ext4_get_group_desc(struct super_block *sb,
                         ext4_group_t block_group,
                         struct buffer_head **bh)
{
    unsigned int group_desc;
    unsigned int offset;
    ext4_group_t ngroups = my_ext4_get_groups_count(sb);
    struct ext4_group_desc *desc;
    struct ext4_sb_info *sbi = my_EXT4_SB(sb);
    struct buffer_head *bh_p;

    if (block_group >= ngroups) {
        ext4_error(sb, "block_group >= groups_count - block_group = %u,"
               " groups_count = %u", block_group, ngroups);

        return NULL;
    }

    group_desc = block_group >> EXT4_DESC_PER_BLOCK_BITS(sb);
    offset = block_group & (EXT4_DESC_PER_BLOCK(sb) - 1);
    bh_p = sbi_array_rcu_deref(sbi, s_group_desc, group_desc);
    /*
     * sbi_array_rcu_deref returns with rcu unlocked, this is ok since
     * the pointer being dereferenced won't be dereferenced again. By
     * looking at the usage in add_new_gdb() the value isn't modified,
     * just the pointer, and so it remains valid.
     */
    if (!bh_p) {
        ext4_error(sb, "Group descriptor not loaded - "
               "block_group = %u, group_desc = %u, desc = %u",
               block_group, group_desc, offset);
        return NULL;
    }

    desc = (struct ext4_group_desc *)(
        (__u8 *)bh_p->b_data +
        offset * EXT4_DESC_SIZE(sb));
    if (bh)
        *bh = bh_p;
    return desc;
}

static int my_find_group_other(struct super_block *sb, struct inode *parent,
			    ext4_group_t *group, umode_t mode)
{
	ext4_group_t parent_group = EXT4_I(parent)->i_block_group;
	ext4_group_t i, last, ngroups = my_ext4_get_groups_count(sb);
	struct ext4_group_desc *desc;
	int flex_size = ext4_flex_bg_size(my_EXT4_SB(sb));

	/*
	 * Try to place the inode is the same flex group as its
	 * parent.  If we can't find space, use the Orlov algorithm to
	 * find another flex group, and store that information in the
	 * parent directory's inode information so that use that flex
	 * group for future allocations.
	 */
	if (flex_size > 1) {
		int retry = 0;

	try_again:
		parent_group &= ~(flex_size-1);
		last = parent_group + flex_size;
		if (last > ngroups)
			last = ngroups;
		for  (i = parent_group; i < last; i++) {
			desc = my_ext4_get_group_desc(sb, i, NULL);
			if (desc && ext4_free_inodes_count(sb, desc)) {
				*group = i;
				return 0;
			}
		}
		if (!retry && EXT4_I(parent)->i_last_alloc_group != ~0) {
			retry = 1;
			parent_group = EXT4_I(parent)->i_last_alloc_group;
			goto try_again;
		}
		/*
		 * If this didn't work, use the Orlov search algorithm
		 * to find a new flex group; we pass in the mode to
		 * avoid the topdir algorithms.
		 */
		*group = parent_group + flex_size;
		if (*group > ngroups)
			*group = 0;
		return find_group_orlov(sb, parent, group, mode, NULL);
	}

	/*
	 * Try to place the inode in its parent directory
	 */
	*group = parent_group;
	desc = my_ext4_get_group_desc(sb, *group, NULL);
	if (desc && ext4_free_inodes_count(sb, desc) &&
	    ext4_free_group_clusters(sb, desc))
		return 0;

	/*
	 * We're going to place this inode in a different blockgroup from its
	 * parent.  We want to cause files in a common directory to all land in
	 * the same blockgroup.  But we want files which are in a different
	 * directory which shares a blockgroup with our parent to land in a
	 * different blockgroup.
	 *
	 * So add our directory's i_ino into the starting point for the hash.
	 */
	*group = (*group + parent->i_ino) % ngroups;

	/*
	 * Use a quadratic hash to find a group with a free inode and some free
	 * blocks.
	 */
	for (i = 1; i < ngroups; i <<= 1) {
		*group += i;
		if (*group >= ngroups)
			*group -= ngroups;
		desc = my_ext4_get_group_desc(sb, *group, NULL);
		if (desc && ext4_free_inodes_count(sb, desc) &&
		    ext4_free_group_clusters(sb, desc))
			return 0;
	}

	/*
	 * That failed: try linear search for a free inode, even if that group
	 * has no free blocks.
	 */
	*group = parent_group;
	for (i = 0; i < ngroups; i++) {
		if (++*group >= ngroups)
			*group = 0;
		desc = my_ext4_get_group_desc(sb, *group, NULL);
		if (desc && ext4_free_inodes_count(sb, desc))
			return 0;
	}

	return -1;
}

static struct buffer_head *
ext4_read_inode_bitmap(struct super_block *sb, ext4_group_t block_group)
{
	struct ext4_group_desc *desc;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct buffer_head *bh = NULL;
	ext4_fsblk_t bitmap_blk;
	int err;

	desc = ext4_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return ERR_PTR(-EFSCORRUPTED);

	bitmap_blk = ext4_inode_bitmap(sb, desc);
	if ((bitmap_blk <= le32_to_cpu(sbi->s_es->s_first_data_block)) ||
	    (bitmap_blk >= ext4_blocks_count(sbi->s_es))) {
		ext4_error(sb, "Invalid inode bitmap blk %llu in "
			   "block_group %u", bitmap_blk, block_group);
		ext4_mark_group_bitmap_corrupted(sb, block_group,
					EXT4_GROUP_INFO_IBITMAP_CORRUPT);
		return ERR_PTR(-EFSCORRUPTED);
	}
	bh = sb_getblk(sb, bitmap_blk);
	if (unlikely(!bh)) {
		ext4_warning(sb, "Cannot read inode bitmap - "
			     "block_group = %u, inode_bitmap = %llu",
			     block_group, bitmap_blk);
		return ERR_PTR(-ENOMEM);
	}
	if (bitmap_uptodate(bh))
		goto verify;

	lock_buffer(bh);
	if (bitmap_uptodate(bh)) {
		unlock_buffer(bh);
		goto verify;
	}

	ext4_lock_group(sb, block_group);
	if (ext4_has_group_desc_csum(sb) &&
	    (desc->bg_flags & cpu_to_le16(EXT4_BG_INODE_UNINIT))) {
		if (block_group == 0) {
			ext4_unlock_group(sb, block_group);
			unlock_buffer(bh);
			ext4_error(sb, "Inode bitmap for bg 0 marked "
				   "uninitialized");
			err = -EFSCORRUPTED;
			goto out;
		}
		memset(bh->b_data, 0, (EXT4_INODES_PER_GROUP(sb) + 7) / 8);
		ext4_mark_bitmap_end(EXT4_INODES_PER_GROUP(sb),
				     sb->s_blocksize * 8, bh->b_data);
		set_bitmap_uptodate(bh);
		set_buffer_uptodate(bh);
		set_buffer_verified(bh);
		ext4_unlock_group(sb, block_group);
		unlock_buffer(bh);
		return bh;
	}
	ext4_unlock_group(sb, block_group);

	if (buffer_uptodate(bh)) {
		/*
		 * if not uninit if bh is uptodate,
		 * bitmap is also uptodate
		 */
		set_bitmap_uptodate(bh);
		unlock_buffer(bh);
		goto verify;
	}
	/*
	 * submit the buffer_head for reading
	 */
	trace_ext4_load_inode_bitmap(sb, block_group);
	ext4_read_bh(bh, REQ_META | REQ_PRIO, ext4_end_bitmap_read);
	ext4_simulate_fail_bh(sb, bh, EXT4_SIM_IBITMAP_EIO);
	if (!buffer_uptodate(bh)) {
		put_bh(bh);
		ext4_error_err(sb, EIO, "Cannot read inode bitmap - "
			       "block_group = %u, inode_bitmap = %llu",
			       block_group, bitmap_blk);
		ext4_mark_group_bitmap_corrupted(sb, block_group,
				EXT4_GROUP_INFO_IBITMAP_CORRUPT);
		return ERR_PTR(-EIO);
	}

verify:
	err = ext4_validate_inode_bitmap(sb, desc, block_group, bh);
	if (err)
		goto out;
	return bh;
out:
	put_bh(bh);
	return ERR_PTR(err);
}

struct ext4_group_desc * ext4_get_group_desc(struct super_block *sb,
                         ext4_group_t block_group,
                         struct buffer_head **bh)
{
    unsigned int group_desc;
    unsigned int offset;
    ext4_group_t ngroups = my_ext4_get_groups_count(sb);
    struct ext4_group_desc *desc;
    struct ext4_sb_info *sbi = my_EXT4_SB(sb);
    struct buffer_head *bh_p;

    if (block_group >= ngroups) {
        ext4_error(sb, "block_group >= groups_count - block_group = %u,"
               " groups_count = %u", block_group, ngroups);

        return NULL;
    }

    group_desc = block_group >> EXT4_DESC_PER_BLOCK_BITS(sb);
    offset = block_group & (EXT4_DESC_PER_BLOCK(sb) - 1);
    bh_p = sbi_array_rcu_deref(sbi, s_group_desc, group_desc);
    /*
     * sbi_array_rcu_deref returns with rcu unlocked, this is ok since
     * the pointer being dereferenced won't be dereferenced again. By
     * looking at the usage in add_new_gdb() the value isn't modified,
     * just the pointer, and so it remains valid.
     */
    if (!bh_p) {
        ext4_error(sb, "Group descriptor not loaded - "
               "block_group = %u, group_desc = %u, desc = %u",
               block_group, group_desc, offset);
        return NULL;
    }

    desc = (struct ext4_group_desc *)(
        (__u8 *)bh_p->b_data +
        offset * EXT4_DESC_SIZE(sb));
    if (bh)
        *bh = bh_p;
    return desc;
}

static int find_inode_bit(struct super_block *sb, ext4_group_t group,
			  struct buffer_head *bitmap, unsigned long *ino)
{
	bool check_recently_deleted = my_EXT4_SB(sb)->s_journal == NULL;
	unsigned long recently_deleted_ino = EXT4_INODES_PER_GROUP(sb);

next:
	*ino = ext4_find_next_zero_bit((unsigned long *)
				       bitmap->b_data,
				       EXT4_INODES_PER_GROUP(sb), *ino);
	if (*ino >= EXT4_INODES_PER_GROUP(sb))
		goto not_found;

	if (check_recently_deleted && recently_deleted(sb, group, *ino)) {
		recently_deleted_ino = *ino;
		*ino = *ino + 1;
		if (*ino < EXT4_INODES_PER_GROUP(sb))
			goto next;
		goto not_found;
	}
	return 1;
not_found:
	if (recently_deleted_ino >= EXT4_INODES_PER_GROUP(sb))
		return 0;
	/*
	 * Not reusing recently deleted inodes is mostly a preference. We don't
	 * want to report ENOSPC or skew allocation patterns because of that.
	 * So return even recently deleted inode if we could find better in the
	 * given range.
	 */
	*ino = recently_deleted_ino;
	return 1;
}

struct inode *__my_ext4_new_inode(struct mnt_idmap *idmap,
			       handle_t *handle, struct inode *dir,
			       umode_t mode, const struct qstr *qstr,
			       __u32 goal, uid_t *owner, __u32 i_flags,
			       int handle_type, unsigned int line_no,
			       int nblocks)
{
	struct super_block *sb;
	struct buffer_head *inode_bitmap_bh = NULL;
	struct buffer_head *group_desc_bh;
	ext4_group_t ngroups, group = 0;
	unsigned long ino = 0;
	struct inode *inode;
	struct ext4_group_desc *gdp = NULL;
	struct ext4_inode_info *ei;
	struct ext4_sb_info *sbi;
	int ret2, err;
	struct inode *ret;
	ext4_group_t i;
	ext4_group_t flex_group;
	struct ext4_group_info *grp = NULL;
	bool encrypt = false;

	/* Cannot create files in a deleted directory */
	if (!dir || !dir->i_nlink)
		return ERR_PTR(-EPERM);

	sb = dir->i_sb;
	sbi = my_EXT4_SB(sb);

	if (unlikely(ext4_forced_shutdown(sb)))
		return ERR_PTR(-EIO);

	ngroups = my_ext4_get_groups_count(sb);
	trace_ext4_request_inode(dir, mode);
	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	ei = EXT4_I(inode);

	/*
	 * Initialize owners and quota early so that we don't have to account
	 * for quota initialization worst case in standard inode creating
	 * transaction
	 */
	if (owner) {
		inode->i_mode = mode;
		i_uid_write(inode, owner[0]);
		i_gid_write(inode, owner[1]);
	} else if (test_opt(sb, GRPID)) {
		inode->i_mode = mode;
		inode_fsuid_set(inode, idmap);
		inode->i_gid = dir->i_gid;
	} else
		inode_init_owner(idmap, inode, dir, mode);

	if (ext4_has_feature_project(sb) &&
	    ext4_test_inode_flag(dir, EXT4_INODE_PROJINHERIT))
		ei->i_projid = EXT4_I(dir)->i_projid;
	else
		ei->i_projid = make_kprojid(&init_user_ns, EXT4_DEF_PROJID);

	if (!(i_flags & EXT4_EA_INODE_FL)) {
		err = fscrypt_prepare_new_inode(dir, inode, &encrypt);
		if (err)
			goto out;
	}

	err = dquot_initialize(inode);
	if (err)
		goto out;

	if (!handle && sbi->s_journal && !(i_flags & EXT4_EA_INODE_FL)) {
		ret2 = ext4_xattr_credits_for_new_inode(dir, mode, encrypt);
		if (ret2 < 0) {
			err = ret2;
			goto out;
		}
		nblocks += ret2;
	}

	if (!goal)
		goal = sbi->s_inode_goal;

	if (goal && goal <= le32_to_cpu(sbi->s_es->s_inodes_count)) {
		group = (goal - 1) / EXT4_INODES_PER_GROUP(sb);
		ino = (goal - 1) % EXT4_INODES_PER_GROUP(sb);
		ret2 = 0;
		goto got_group;
	}

	if (S_ISDIR(mode))
		ret2 = find_group_orlov(sb, dir, &group, mode, qstr);
	else
		ret2 = my_find_group_other(sb, dir, &group, mode);

got_group:
	EXT4_I(dir)->i_last_alloc_group = group;
	err = -ENOSPC;
	if (ret2 == -1)
		goto out;

	/*
	 * Normally we will only go through one pass of this loop,
	 * unless we get unlucky and it turns out the group we selected
	 * had its last inode grabbed by someone else.
	 */
	for (i = 0; i < ngroups; i++, ino = 0) {
		err = -EIO;

		gdp = my_ext4_get_group_desc(sb, group, &group_desc_bh);
		if (!gdp)
			goto out;

		/*
		 * Check free inodes count before loading bitmap.
		 */
		if (ext4_free_inodes_count(sb, gdp) == 0)
			goto next_group;

		if (!(sbi->s_mount_state & EXT4_FC_REPLAY)) {
			grp = ext4_get_group_info(sb, group);
			/*
			 * Skip groups with already-known suspicious inode
			 * tables
			 */
			if (!grp || EXT4_MB_GRP_IBITMAP_CORRUPT(grp))
				goto next_group;
		}

		brelse(inode_bitmap_bh);
		inode_bitmap_bh = ext4_read_inode_bitmap(sb, group);
		/* Skip groups with suspicious inode tables */
		if (((!(sbi->s_mount_state & EXT4_FC_REPLAY))
		     && EXT4_MB_GRP_IBITMAP_CORRUPT(grp)) ||
		    IS_ERR(inode_bitmap_bh)) {
			inode_bitmap_bh = NULL;
			goto next_group;
		}

repeat_in_this_group:
		ret2 = find_inode_bit(sb, group, inode_bitmap_bh, &ino);
		if (!ret2)
			goto next_group;

		if (group == 0 && (ino + 1) < EXT4_FIRST_INO(sb)) {
			ext4_error(sb, "reserved inode found cleared - "
				   "inode=%lu", ino + 1);
			ext4_mark_group_bitmap_corrupted(sb, group,
					EXT4_GROUP_INFO_IBITMAP_CORRUPT);
			goto next_group;
		}

		if ((!(sbi->s_mount_state & EXT4_FC_REPLAY)) && !handle) {
			BUG_ON(nblocks <= 0);
			handle = __ext4_journal_start_sb(NULL, dir->i_sb,
				 line_no, handle_type, nblocks, 0,
				 ext4_trans_default_revoke_credits(sb));
			if (IS_ERR(handle)) {
				err = PTR_ERR(handle);
				ext4_std_error(sb, err);
				goto out;
			}
		}
		BUFFER_TRACE(inode_bitmap_bh, "get_write_access");
		err = ext4_journal_get_write_access(handle, sb, inode_bitmap_bh,
						    EXT4_JTR_NONE);
		if (err) {
			ext4_std_error(sb, err);
			goto out;
		}
		ext4_lock_group(sb, group);
		ret2 = ext4_test_and_set_bit(ino, inode_bitmap_bh->b_data);
		if (ret2) {
			/* Someone already took the bit. Repeat the search
			 * with lock held.
			 */
			ret2 = find_inode_bit(sb, group, inode_bitmap_bh, &ino);
			if (ret2) {
				ext4_set_bit(ino, inode_bitmap_bh->b_data);
				ret2 = 0;
			} else {
				ret2 = 1; /* we didn't grab the inode */
			}
		}
		ext4_unlock_group(sb, group);
		ino++;		/* the inode bitmap is zero-based */
		if (!ret2)
			goto got; /* we grabbed the inode! */

		if (ino < EXT4_INODES_PER_GROUP(sb))
			goto repeat_in_this_group;
next_group:
		if (++group == ngroups)
			group = 0;
	}
	err = -ENOSPC;
	goto out;

got:
	BUFFER_TRACE(inode_bitmap_bh, "call ext4_handle_dirty_metadata");
	err = ext4_handle_dirty_metadata(handle, NULL, inode_bitmap_bh);
	if (err) {
		ext4_std_error(sb, err);
		goto out;
	}

	BUFFER_TRACE(group_desc_bh, "get_write_access");
	err = ext4_journal_get_write_access(handle, sb, group_desc_bh,
					    EXT4_JTR_NONE);
	if (err) {
		ext4_std_error(sb, err);
		goto out;
	}

	/* We may have to initialize the block bitmap if it isn't already */
	if (ext4_has_group_desc_csum(sb) &&
	    gdp->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT)) {
		struct buffer_head *block_bitmap_bh;

		block_bitmap_bh = ext4_read_block_bitmap(sb, group);
		if (IS_ERR(block_bitmap_bh)) {
			err = PTR_ERR(block_bitmap_bh);
			goto out;
		}
		BUFFER_TRACE(block_bitmap_bh, "get block bitmap access");
		err = ext4_journal_get_write_access(handle, sb, block_bitmap_bh,
						    EXT4_JTR_NONE);
		if (err) {
			brelse(block_bitmap_bh);
			ext4_std_error(sb, err);
			goto out;
		}

		BUFFER_TRACE(block_bitmap_bh, "dirty block bitmap");
		err = ext4_handle_dirty_metadata(handle, NULL, block_bitmap_bh);

		/* recheck and clear flag under lock if we still need to */
		ext4_lock_group(sb, group);
		if (ext4_has_group_desc_csum(sb) &&
		    (gdp->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT))) {
			gdp->bg_flags &= cpu_to_le16(~EXT4_BG_BLOCK_UNINIT);
			ext4_free_group_clusters_set(sb, gdp,
				ext4_free_clusters_after_init(sb, group, gdp));
			ext4_block_bitmap_csum_set(sb, gdp, block_bitmap_bh);
			ext4_group_desc_csum_set(sb, group, gdp);
		}
		ext4_unlock_group(sb, group);
		brelse(block_bitmap_bh);

		if (err) {
			ext4_std_error(sb, err);
			goto out;
		}
	}

	/* Update the relevant bg descriptor fields */
	if (ext4_has_group_desc_csum(sb)) {
		int free;
		struct ext4_group_info *grp = NULL;

		if (!(sbi->s_mount_state & EXT4_FC_REPLAY)) {
			grp = ext4_get_group_info(sb, group);
			if (!grp) {
				err = -EFSCORRUPTED;
				goto out;
			}
			down_read(&grp->alloc_sem); /*
						     * protect vs itable
						     * lazyinit
						     */
		}
		ext4_lock_group(sb, group); /* while we modify the bg desc */
		free = EXT4_INODES_PER_GROUP(sb) -
			ext4_itable_unused_count(sb, gdp);
		if (gdp->bg_flags & cpu_to_le16(EXT4_BG_INODE_UNINIT)) {
			gdp->bg_flags &= cpu_to_le16(~EXT4_BG_INODE_UNINIT);
			free = 0;
		}
		/*
		 * Check the relative inode number against the last used
		 * relative inode number in this group. if it is greater
		 * we need to update the bg_itable_unused count
		 */
		if (ino > free)
			ext4_itable_unused_set(sb, gdp,
					(EXT4_INODES_PER_GROUP(sb) - ino));
		if (!(sbi->s_mount_state & EXT4_FC_REPLAY))
			up_read(&grp->alloc_sem);
	} else {
		ext4_lock_group(sb, group);
	}

	ext4_free_inodes_set(sb, gdp, ext4_free_inodes_count(sb, gdp) - 1);
	if (S_ISDIR(mode)) {
		ext4_used_dirs_set(sb, gdp, ext4_used_dirs_count(sb, gdp) + 1);
		if (sbi->s_log_groups_per_flex) {
			ext4_group_t f = ext4_flex_group(sbi, group);

			atomic_inc(&sbi_array_rcu_deref(sbi, s_flex_groups,
							f)->used_dirs);
		}
	}
	if (ext4_has_group_desc_csum(sb)) {
		ext4_inode_bitmap_csum_set(sb, gdp, inode_bitmap_bh,
					   EXT4_INODES_PER_GROUP(sb) / 8);
		ext4_group_desc_csum_set(sb, group, gdp);
	}
	ext4_unlock_group(sb, group);

	BUFFER_TRACE(group_desc_bh, "call ext4_handle_dirty_metadata");
	err = ext4_handle_dirty_metadata(handle, NULL, group_desc_bh);
	if (err) {
		ext4_std_error(sb, err);
		goto out;
	}

	percpu_counter_dec(&sbi->s_freeinodes_counter);
	if (S_ISDIR(mode))
		percpu_counter_inc(&sbi->s_dirs_counter);

	if (sbi->s_log_groups_per_flex) {
		flex_group = ext4_flex_group(sbi, group);
		atomic_dec(&sbi_array_rcu_deref(sbi, s_flex_groups,
						flex_group)->free_inodes);
	}

	inode->i_ino = ino + group * EXT4_INODES_PER_GROUP(sb);
	/* This is the optimal IO size (for stat), not the fs block size */
	inode->i_blocks = 0;
	inode->i_mtime = inode->i_atime = inode_set_ctime_current(inode);
	ei->i_crtime = inode->i_mtime;

	memset(ei->i_data, 0, sizeof(ei->i_data));
	ei->i_dir_start_lookup = 0;
	ei->i_disksize = 0;

	/* Don't inherit extent flag from directory, amongst others. */
	ei->i_flags =
		ext4_mask_flags(mode, EXT4_I(dir)->i_flags & EXT4_FL_INHERITED);
	ei->i_flags |= i_flags;
	ei->i_file_acl = 0;
	ei->i_dtime = 0;
	ei->i_block_group = group;
	ei->i_last_alloc_group = ~0;

	ext4_set_inode_flags(inode, true);
	if (IS_DIRSYNC(inode))
		ext4_handle_sync(handle);
	if (insert_inode_locked(inode) < 0) {
		/*
		 * Likely a bitmap corruption causing inode to be allocated
		 * twice.
		 */
		err = -EIO;
		ext4_error(sb, "failed to insert inode %lu: doubly allocated?",
			   inode->i_ino);
		ext4_mark_group_bitmap_corrupted(sb, group,
					EXT4_GROUP_INFO_IBITMAP_CORRUPT);
		goto out;
	}
	inode->i_generation = get_random_u32();

	/* Precompute checksum seed for inode metadata */
	if (ext4_has_metadata_csum(sb)) {
		__u32 csum;
		__le32 inum = cpu_to_le32(inode->i_ino);
		__le32 gen = cpu_to_le32(inode->i_generation);
		csum = ext4_chksum(sbi, sbi->s_csum_seed, (__u8 *)&inum,
				   sizeof(inum));
		ei->i_csum_seed = ext4_chksum(sbi, csum, (__u8 *)&gen,
					      sizeof(gen));
	}

	ext4_clear_state_flags(ei); /* Only relevant on 32-bit archs */
	ext4_set_inode_state(inode, EXT4_STATE_NEW);

	ei->i_extra_isize = sbi->s_want_extra_isize;
	ei->i_inline_off = 0;
	if (ext4_has_feature_inline_data(sb) &&
	    (!(ei->i_flags & EXT4_DAX_FL) || S_ISDIR(mode)))
		ext4_set_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA);
	ret = inode;
	err = dquot_alloc_inode(inode);
	if (err)
		goto fail_drop;

	/*
	 * Since the encryption xattr will always be unique, create it first so
	 * that it's less likely to end up in an external xattr block and
	 * prevent its deduplication.
	 */
	if (encrypt) {
		err = fscrypt_set_context(inode, handle);
		if (err)
			goto fail_free_drop;
	}

	if (!(ei->i_flags & EXT4_EA_INODE_FL)) {
		err = ext4_init_acl(handle, inode, dir);
		if (err)
			goto fail_free_drop;

		err = ext4_init_security(handle, inode, dir, qstr);
		if (err)
			goto fail_free_drop;
	}

	if (ext4_has_feature_extents(sb)) {
		/* set extent flag only for directory, file and normal symlink*/
		if (S_ISDIR(mode) || S_ISREG(mode) || S_ISLNK(mode)) {
			ext4_set_inode_flag(inode, EXT4_INODE_EXTENTS);
			ext4_ext_tree_init(handle, inode);
		}
	}

	if (ext4_handle_valid(handle)) {
		ei->i_sync_tid = handle->h_transaction->t_tid;
		ei->i_datasync_tid = handle->h_transaction->t_tid;
	}

	err = ext4_mark_inode_dirty(handle, inode);
	if (err) {
		ext4_std_error(sb, err);
		goto fail_free_drop;
	}

	ext4_debug("allocating inode %lu\n", inode->i_ino);
	trace_ext4_allocate_inode(inode, dir, mode);
	brelse(inode_bitmap_bh);
	return ret;

fail_free_drop:
	dquot_free_inode(inode);
fail_drop:
	clear_nlink(inode);
	unlock_new_inode(inode);
out:
	dquot_drop(inode);
	inode->i_flags |= S_NOQUOTA;
	iput(inode);
	brelse(inode_bitmap_bh);
	return ERR_PTR(err);
}

int my_ext4_create(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
    handle_t *handle;
    struct inode *inode;
    int err, credits, retries = 0;

    err = dquot_initialize(dir);
    if (err)
        return err;

    credits = (EXT4_DATA_TRANS_BLOCKS(dir->i_sb) +
           EXT4_INDEX_EXTRA_TRANS_BLOCKS + 3);
retry:
    inode = my_ext4_new_inode_start_handle(idmap, dir, mode, &dentry->d_name,
                        0, NULL, EXT4_HT_DIR, credits);
    handle = ext4_journal_current_handle();
    err = PTR_ERR(inode);
    if (!IS_ERR(inode)) {
        inode->i_op = &ext4_file_inode_operations;
        inode->i_fop = &ext4_file_operations;
        ext4_set_aops(inode);
        err = ext4_add_nondir(handle, dentry, &inode);
        if (!err)
            ext4_fc_track_create(handle, dentry);
    }
    if (handle)
        ext4_journal_stop(handle);
    if (!IS_ERR_OR_NULL(inode))
        iput(inode);
    if (err == -ENOSPC && ext4_should_retry_alloc(dir->i_sb, &retries))
        goto retry;
    return err;
}
