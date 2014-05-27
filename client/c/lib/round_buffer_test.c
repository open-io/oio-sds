#include "./gs_internals.h"

#define BUFFER_MAXLEN 8744243


struct {
	unsigned char original [BUFFER_MAXLEN];
	unsigned char copy [BUFFER_MAXLEN];
} buffers;

static void
randomize (void)
{
	register int s, i;
	memset(&buffers, 0x00, sizeof(buffers));
	for (i=0, s=0; s<BUFFER_MAXLEN ;)
		s += snprintf((char*)buffers.original+s, BUFFER_MAXLEN-s, "%i_", i++);
}

static ssize_t fill_chunk (round_buffer_t *src, ssize_t offset, ssize_t nb)
{
	ssize_t r=0, r_max=0, r_local=0;
	while ( r_local<nb && offset<BUFFER_MAXLEN ) {
		r_max = BUFFER_MAXLEN - offset;
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
		if (sizeFeed>=BUFFER_MAXLEN) return 0;
		max = BUFFER_MAXLEN - sizeFeed;
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

	while ( content_offset<BUFFER_MAXLEN ) {
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

	if (0 == memcmp(buffers.original, buffers.copy, BUFFER_MAXLEN)) {
		fprintf(stdout,"copied buffers are equal\r\n");
	} else {
		fputs ("copied buffers differ\r\n", stdout);
		abort();
	}
	rb_destroy( rb);

	return 0;
}

