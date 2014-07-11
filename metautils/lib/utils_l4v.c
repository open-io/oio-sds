#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metautils.l4v"
#endif

#include "metautils.h"


gboolean
l4v_extract(void *s, gsize ssize, void **d, gsize *dsize)
{
	if (!s || ssize < 4)
		return 0;

	register gsize s4 = l4v_get_size(s);

	if (s4 > ssize - 4)
		return 0;

	*d = ((guint8 *) s) + 4;
	*dsize = s4;
	return 1;
}


gint
l4v_fill(void *src, gsize srcSize, void *dst, gsize dstSize, GError ** error)
{
	if (NULL == src || srcSize < 1 || NULL == dst || dstSize < 4) {
		GSETERROR(error, "Invalid parameter");
		return 0;
	}

	if (dstSize < srcSize - 4) {
		GSETERROR(error, "Buffer to small");
		return 0;
	}

	l4v_prepend_size(dst, dstSize);
	g_memmove(((guint8 *) dst) + 4, src, srcSize);
	return 1;
}


GByteArray *
l4v_read_2to(int fd, gint ms1, gint msAll, GError ** err)
{
	gint rc = 0;
	int nbRecv = 0;
	GByteArray *gba = NULL;
	guint8 recvBuf[4096];
	gsize msgSize = 0;

	/* the size */
	rc = sock_to_read_size(fd, ms1, recvBuf, 4, err);
	if (rc < 4) {
		GSETERROR(err, "Failed to read %d bytes on socket", 4);
		return NULL;
	}

	msgSize = l4v_get_size(recvBuf);
	gba = g_byte_array_sized_new(MIN(msgSize + 4 + 4, 16384));

	if (NULL == gba) {
		GSETERROR(err, "Cannot create a pre-allocated buffer");
		return NULL;
	}

	gba = g_byte_array_append(gba, recvBuf, 4);

	/* the remaining */
	while (gba->len < msgSize + 4) {
		nbRecv = sock_to_read(fd, msAll, recvBuf,
				MIN(sizeof(recvBuf), msgSize + 4 - gba->len), err);
		if (nbRecv <= 0) {
			GSETERROR(err, "Read failed after %i bytes", gba->len);
			g_byte_array_free(gba, TRUE);
			return NULL;
		}
		else {
			if (!g_byte_array_append(gba, recvBuf, nbRecv)) {
				GSETERROR(err, "Memory allocation failure");
				g_byte_array_free(gba, TRUE);
				return NULL;
			}
		}
	}

	return gba;
}


GByteArray *
l4v_read(int fd, gint ms, GError ** err)
{
	return l4v_read_2to(fd, ms, ms, err);
}

