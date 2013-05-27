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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <metautils.h>
#include "./round_buffer.h"

#if 0
# define SLAB_SIZE (1<<19)
# define BUFLEN ((1<<22)+SLAB_SIZE)
#else
# define BUFLEN 8744243
#endif


struct {
	unsigned char original [BUFLEN];
	unsigned char copy [BUFLEN];
} buffers;

static void
randomize (void)
{
	register int s, i;
	memset(&buffers, 0x00, sizeof(buffers));
	for (i=0, s=0; s<BUFLEN ;)
		s += snprintf((char*)buffers.original+s, BUFLEN-s, "%i_", i++);
}

static ssize_t fill_chunk (round_buffer_t *src, ssize_t offset, ssize_t nb)
{
	ssize_t r=0, r_max=0, r_local=0;
	while ( r_local<nb && offset<BUFLEN ) {
		r_max = BUFLEN - offset;
		if (r_max > nb-r_local)
			r_max = nb-r_local;
		r = rb_input_from( src, (char*)buffers.copy+offset+r_local, r_max);
		if (r<0)
			return -1;
		if (r==0) {
			g_print("%"G_GSSIZE_FORMAT" bytes have been read (total %"G_GSSIZE_FORMAT")\n",
				r_local, offset+r_local);
			return r_local;
		}
		g_print("%"G_GSIZE_FORMAT" bytes read, now %"G_GSIZE_FORMAT" (total %"G_GSIZE_FORMAT")\n",
			r, r + r_local, offset+r_local+r);
		r_local += r;
	}

	g_print("%"G_GSIZE_FORMAT" bytes have been read (total %"G_GSIZE_FORMAT")\n",
		r_local, offset+r_local);
	return r_local;
}

int main (int argc, char ** args)
{
	size_t sizeFeed = 0;
	ssize_t feed_from_buffer (void *uData, char *b, size_t s)
	{
		size_t max, nb;
		(void)uData;
		if (sizeFeed>=BUFLEN) return 0;
		max = BUFLEN - sizeFeed;
		nb = MIN(s,max);
		memcpy (b, buffers.original+sizeFeed, nb);
		sizeFeed += nb;
		return nb;
	}
	(void)argc;
	(void)args;

	round_buffer_t *rb = NULL;
	if (log4c_init()) {
		fprintf(stderr,"cannot init log4c\r\n");
		abort();
	}

	/*simulate chunks read*/
	size_t content_offset=0, chunk_size = 512002;

	randomize();
	rb = rb_create_with_callback (chunk_size, feed_from_buffer, NULL);
	rb_set_mark( rb);

	while ( content_offset<BUFLEN ) {
		ssize_t r;

		g_printerr("reading a new chunk\n");

		/*read one chunk*/
		r = fill_chunk( rb, content_offset, chunk_size);
		rb_dump( rb);

		assert(r>=0);
		if (r==0) {
			g_printerr("fin prematuree\n");
			break;
		}

		/*check what have been read*/
		if (0 != memcmp( buffers.original+content_offset, buffers.copy+content_offset, r)) {
			g_printerr("copied chunk differ from original\n");
			abort();
		} else {
			g_printerr("original and copied chunks are equal\n");
		}

		/*prepare for next chunk*/
		g_printerr("%"G_GSIZE_FORMAT" bytes read from chunk, now %"G_GSIZE_FORMAT"\n", r, r+content_offset);
		rb_set_mark( rb);
		rb_dump( rb);
		content_offset += r;
	}

	if (0 == memcmp(buffers.original, buffers.copy, BUFLEN)) {
		fprintf(stdout,"copied buffers are equal\r\n");
	} else {
		fputs ("copied buffers differ\r\n", stdout);
		abort();
	}
	rb_destroy( rb);

	return 0;
}

