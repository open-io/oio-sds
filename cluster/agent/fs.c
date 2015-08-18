/*
OpenIO SDS cluster
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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

	if (statfs(path, &sfs) < 0)
		return -1;

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

