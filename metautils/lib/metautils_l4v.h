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

#ifndef OIO_SDS__metautils__lib__metautils_l4v_h
# define OIO_SDS__metautils__lib__metautils_l4v_h 1

#include <glib/gtypes.h>

/**
 * Copy src to dst+4 and prepend dstsize in dst.
 *
 * In theory, src and dst could even overlap.
 *
 * @param src the source buffer
 * @param srcSize the size of the source buffer
 * @param dst the destination buffer
 * @param dstsize the size of the destination buffer.
 * @param error an error structure set in case of error
 *
 * @return 1 in case of success, 0 in case of error (err is set)
 */
gint l4v_fill(void *src, gsize srcSize, void *dst, gsize dstsize, GError ** error);

/**
 * Reads a whole L4V enclosed buffer from the file descriptor fd.
 *
 * @param fd an opened an connected file descriptor.
 * @param ms the maximal time in milliseconds spent in network latencies
 * @param err an error structure set in case of error
 *
 * @return the data read under the form of a GLib byte Array
 */
GByteArray *l4v_read(int fd, gint ms, GError ** err);

/**
 * Reads a whole L4V enclosed buffer from the file descriptor fd.
 *
 * @param fd an opened an connected file descriptor.
 * @param ms1 the maximal time spent to wait the header of the data
 *        (the size on 4 bytes)
 * @param msAll the maximal time spent to wait the body of the data
 * @param err an error structure set in case of error
 *
 * @return the data read under the form of a GLib byte Array
 */
GByteArray *l4v_read_2to(int fd, gint ms1, gint msAll, GError ** err);

static inline gsize
l4v_get_size(const guint8 *src)
{
	register guint32 s32 = *((guint32*)src);
	s32 = g_ntohl(s32);
	return s32;
}

static inline void
l4v_prepend_size(void *src, register gsize srcSize)
{
	srcSize -= 4;
	*((guint32*)src) = g_htonl(srcSize);
}

#endif /*OIO_SDS__metautils__lib__metautils_l4v_h*/
