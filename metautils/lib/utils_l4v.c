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
#define LOG_DOMAIN "metautils.l4v"
#endif

#include <string.h>
#include <glib.h>
#include "./metautils.h"

gint
l4v_prepend_size(void *src, gsize srcSize, GError ** error)
{
	if (!src || srcSize < 1) {
		GSETERROR(error, "Invalid parameter");
		return 0;
	}

	if (srcSize < 4) {
		GSETERROR(error, "Buffer to small");
		return 0;
	}

	srcSize -= 4;
	*((guint32*)src) = g_htonl(srcSize);
	return 1;
}


gint
l4v_get_size(void *src, gsize * size, GError ** error)
{
	if (!src || !size || (*size) < 4U) {
		GSETERROR(error, "Invalid parameter (src=%p size=%p/%i)",
				src, size, (size != NULL ? *size : ~0U));
		return 0;
	}

	guint32 s32 = *((guint32*)src);
	s32 = g_ntohl(s32);
	*size = s32;
	return 1;
}


gint
l4v_is_complete(void *src, gsize srcSize, GError ** error)
{
	gsize s;

	if (!src || srcSize < 1) {
		GSETERROR(error, "Invalid parameter");
		return -1;
	}

	if (srcSize < 4) {
		GSETERROR(error, "Buffer too small");
		return 0;
	}

	s = srcSize;

	if (!l4v_get_size(src, &s, error))
		return -1;

	return ((s <= srcSize - 4) ? 1 : 0);
}


gint
l4v_extract(void *src, gsize srcSize, void **dst, gsize * dstSize, GError ** error)
{
	gsize s;

	if (!src || srcSize < 4 || !dst || !dstSize) {
		GSETERROR(error, "Invalid parameter");
		return 0;
	}

	switch (l4v_is_complete(src, srcSize, error)) {
	case 1:
		s = srcSize;
		if (!l4v_get_size(src, &s, error))
			return 0;
		*dst = ((guint8 *) src) + 4;
		*dstSize = s;
		return 1;

	case 0:
		GSETERROR(error, "Buffer uncomplete");
		return 0;

	default:
		/*error message already set */
		return 0;
	}
}


gint
l4v_fill(void *src, gsize srcSize, void *dst, gsize dstSize, GError ** error)
{
	if (!src || srcSize < 1 || !dst || dstSize < 4) {
		GSETERROR(error, "Invalid parameter");
		return 0;
	}

	if (dstSize < srcSize - 4) {
		GSETERROR(error, "Buffer to small");
		return 0;
	}

	if (!l4v_prepend_size(dst, dstSize, error))
		return 0;

	g_memmove(((guint8 *) dst) + 4, src, srcSize);

	return 1;
}


GByteArray *
l4v_read_2to(int fd, gint ms1, gint msAll, GError ** err)
{
	gint rc = 0;
	int nbRecv = 0;
	GByteArray *gba = NULL;
	guint8 recvBuf[2048];
	gsize msgSize = 0;

	/* the size */
	memset(recvBuf, 0x00, sizeof(recvBuf));
	rc = sock_to_read_size(fd, ms1, recvBuf, 4, err);
	if (rc < 4) {
		GSETERROR(err, "Failed to read %d bytes on socket", 4);
		goto errorLabel;
	}

	sock_set_tcpquickack(fd, TRUE);

	msgSize = 4;
	if (!l4v_get_size(recvBuf, &msgSize, err)) {
		GSETERROR(err, "Cannot retrieve the serialized L4V size");
		goto errorLabel;
	}

	gba = g_byte_array_sized_new(MIN(msgSize + 4 + 4, 65536));
	if (!gba) {
		GSETERROR(err, "Cannot create a pre-allocated buffer");
		goto errorLabel;
	}

	if (!g_byte_array_append(gba, recvBuf, 4)) {
		GSETERROR(err, "Memory allocation failure");
		goto errorLabel;
	}

	/* the remaining */
	while (gba->len < msgSize + 4) {
		nbRecv = sock_to_read(fd, msAll, recvBuf, MIN(sizeof(recvBuf), msgSize + 4 - gba->len), err);
		if (nbRecv <= 0) {
			GSETERROR(err, "Read failed after %i bytes", gba->len);
			goto errorLabel;
		}
		else {
			if (!g_byte_array_append(gba, recvBuf, nbRecv)) {
				GSETERROR(err, "Memory allocation failure");
				goto errorLabel;
			}
		}
	}

	return gba;

      errorLabel:

	if (gba)
		g_byte_array_free(gba, TRUE);

	return NULL;
}


GByteArray *
l4v_read(int fd, gint ms, GError ** err)
{
	return l4v_read_2to(fd, ms, ms, err);
}
