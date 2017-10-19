/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#include "metautils.h"

GByteArray *
l4v_read_2to(int fd, gint ms1, gint msAll, GError ** err)
{
	guint8 recvBuf[4096];

	/* the size */
	int rc = sock_to_read_size(fd, ms1, recvBuf, 4, err);
	if (rc < 4) {
		GSETERROR(err, "Failed to read %d bytes on socket", 4);
		return NULL;
	}

	guint32 s32 = *((guint32*)recvBuf);
	gsize msgSize = g_ntohl(s32);

	GByteArray *gba = g_byte_array_sized_new(MIN(msgSize + 4 + 4, 16384));
	gba = g_byte_array_append(gba, recvBuf, 4);

	/* the remaining */
	while (gba->len < msgSize + 4) {
		int nbRecv = sock_to_read(fd, msAll, recvBuf,
				MIN(sizeof(recvBuf), msgSize + 4 - gba->len), err);
		if (nbRecv <= 0) {
			GSETERROR(err, "Read failed after %i bytes", gba->len);
			g_byte_array_free(gba, TRUE);
			return NULL;
		} else {
			g_byte_array_append(gba, recvBuf, nbRecv);
		}
	}

	return gba;
}
