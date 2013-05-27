/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef LOG_DOMAIN
# define LOG_DOMAIN "metautils"
#endif
#include <string.h>
#include <errno.h>
#include <glib.h>
#include <openssl/sha.h>
#include "./metautils.h"

gsize
metautils_hash_content_path(const gchar *src, gsize src_size,
	gchar *dst, gsize dst_size, gsize dst_bitlength)
{
	register gsize non_zero;
	register gsize to_zero;
	register gsize result_bytes;
	register gsize result_quartets;
	guchar h_result[SHA256_DIGEST_LENGTH];
	SHA256_CTX h_ctx;

	if (!src || !src_size) {
		errno = EINVAL;
		return 0;
	}
	if (!dst || !dst_size || !dst_bitlength) {
		errno = EINVAL;
		return 0;
	}
	if (dst_bitlength > 8 * SHA256_DIGEST_LENGTH)
		dst_bitlength = 8 * SHA256_DIGEST_LENGTH;

	/* Hash itself */
	SHA256_Init(&h_ctx);
	SHA256_Update(&h_ctx, src, src_size);
	SHA256_Final(h_result, &h_ctx);

	/* Compute the hexadecimal form, with the last byte partially zeroed */
	non_zero = dst_bitlength % 8;
	to_zero = non_zero ? (8 - non_zero) : 0;
	result_bytes = dst_bitlength / 8 + (to_zero ? 1 : 0);
	if (to_zero)
		h_result[result_bytes-1] = (h_result[result_bytes-1] >> to_zero) << to_zero;

	bzero(dst, dst_size);
	buffer2str(h_result, sizeof(h_result), dst, dst_size);
	dst[dst_size-1]='\0';

	/* Trim to the latest quartet */
	result_quartets = (dst_bitlength / 4) + ((dst_bitlength % 4) ? 1 : 0);
	if (dst_size > result_quartets)
		bzero(dst+result_quartets, dst_size-result_quartets);

	return result_quartets;
}

