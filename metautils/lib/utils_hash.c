/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils"
#endif
#include <errno.h>
#include "metautils.h"

gsize
metautils_hash_content_path(const gchar *src, gsize src_size,
	gchar *dst, gsize dst_size, gsize dst_bitlength)
{
	if (!src || !src_size || !dst || !dst_size || !dst_bitlength) {
		errno = EINVAL;
		return 0;
	}

	/* Hash itself */
	hash_sha256_t h;
	gsize h_len = sizeof(hash_sha256_t);
	GChecksum *checksum  = g_checksum_new (G_CHECKSUM_SHA256);
	g_checksum_update (checksum, (guint8*)src, src_size);
	g_checksum_get_digest (checksum, h, &h_len);
	g_checksum_free (checksum);

	/* Compute the hexadecimal form, with the last byte partially zeroed */
	bzero(dst, dst_size);
	buffer2str(h, h_len, dst, dst_size);
	dst[dst_size-1]='\0';

	dst_bitlength = MIN(dst_bitlength, 8 * sizeof(hash_sha256_t));
	register gsize to_zero = dst_bitlength % 8;
	to_zero = to_zero ? (8 - to_zero) : 0;
	if (to_zero) {
		register gsize result_bytes = dst_bitlength / 8 + (to_zero ? 1 : 0);
		h[result_bytes-1] = (h[result_bytes-1] >> to_zero) << to_zero;
	}

	/* Trim to the latest quartet */
	register gsize result_quartets = (dst_bitlength / 4) + ((dst_bitlength % 4) ? 1 : 0);
	if (dst_size > result_quartets)
		bzero(dst+result_quartets, dst_size-result_quartets);

	return result_quartets;
}

