#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.fs"
#endif

#include <errno.h>
#include <math.h>
#include <string.h>
#include <sys/vfs.h>

#ifdef HAS_XFS
# include <linux/xfs_fs.h>
#endif

#include <metautils/lib/metautils.h>

#include "./fs.h"

long
get_free_space(const char *path, long chunk_size)
{
	struct statfs sfs;
	long result;
	gdouble free_inodes_d, free_chunks_d, total_chunks_d, chunk_size_d;
	gdouble blocks_max_d, block_size_d, blocks_avail_d;

	if (statfs(path, &sfs) < 0) {
		ERROR("Failed to get fs info on path %s : %s", path, strerror(errno));
		return (-1);
	}

	chunk_size_d = chunk_size;	/*type conversion */
	free_inodes_d = sfs.f_ffree;	/*type conversion */
	blocks_max_d = sfs.f_blocks;	/*type conversion */
	blocks_avail_d = sfs.f_bavail;	/*type conversion */
	block_size_d = sfs.f_bsize;	/*type conversion */

	total_chunks_d = blocks_max_d * block_size_d / chunk_size_d;
	free_chunks_d = blocks_avail_d * block_size_d / chunk_size_d;

	switch (sfs.f_type) {
#ifdef HAS_XFS
	case XFS_SUPER_MAGIC:
#endif
		break;
	default:
		if (free_chunks_d > free_inodes_d)
			free_chunks_d = free_inodes_d;
		break;
	}
	if (free_chunks_d <= 0.0 || total_chunks_d <= 0.0)
		return 0;

	result = floor(100.0 * (free_chunks_d / total_chunks_d));

	DEBUG("STATFS: idle=%ld chunk_size=%f bmax=%f bavail=%f bsize=%f iavail=%f -> free_chunks_d=%f total_chunks_d=%f",
		result, chunk_size_d, blocks_max_d, blocks_avail_d, block_size_d, free_inodes_d, free_chunks_d, total_chunks_d);

	return result;
}

