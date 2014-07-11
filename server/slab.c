#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.utils.slab"
#endif

#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "slab.h"
#include "internals.h"

static inline const gchar *
data_slab_type2str(struct data_slab_s *ds)
{
	if (!ds)
		return "!!!";

	switch (ds->type) {
		case STYPE_BUFFER:
			return "BUFFER";
		case STYPE_BUFFER_STATIC:
			return "BUFFER_STATIC";
		case STYPE_FILE:
			return "FILE";
		case STYPE_PATH:
			return "PATH";
		case STYPE_EOF:
			return "EOF";
	}

	return "???";
}

gsize
data_slab_size(struct data_slab_s *ds)
{
	if (!ds)
		return 0;

	switch (ds->type) {
		case STYPE_BUFFER:
		case STYPE_BUFFER_STATIC:
			if (!ds->data.buffer.buff || !ds->data.buffer.alloc)
				return 0;
			if (ds->data.buffer.start >= ds->data.buffer.end)
				return 0;
			return (ds->data.buffer.end - ds->data.buffer.start);
		case STYPE_FILE:
			return ds->data.file.end - ds->data.file.start;
		case STYPE_PATH:
			if (ds->data.path.fd < 0)
				return 0;
			return ds->data.path.end - ds->data.path.start;
		case STYPE_EOF:
			return 0;
	}

	g_assert_not_reached();
	return 0;
}

gboolean
data_slab_has_data(struct data_slab_s *ds)
{
	switch (ds->type) {
		case STYPE_BUFFER:
		case STYPE_BUFFER_STATIC:
			return ds->data.buffer.buff != NULL
				&& (ds->data.buffer.start < ds->data.buffer.end);
		case STYPE_FILE:
			return ds->data.file.start < ds->data.file.end;
		case STYPE_PATH:
			if (ds->data.path.fd < 0)
				return TRUE;
			return ds->data.path.start < ds->data.path.end;
		case STYPE_EOF:
			return FALSE;
	}
	g_assert_not_reached();
	return FALSE;
}

void
data_slab_free(struct data_slab_s *ds)
{
	switch (ds->type) {
		case STYPE_BUFFER:
			if (ds->data.buffer.buff) {
				g_free(ds->data.buffer.buff);
				ds->data.buffer.buff = NULL;
				ds->data.buffer.start = ds->data.buffer.end = 0;
			}
			break;
		case STYPE_BUFFER_STATIC:
			break;
		case STYPE_FILE:
			if (ds->data.file.fd >= 0)
				metautils_pclose(&(ds->data.file.fd));
			break;
		case STYPE_PATH:
			if (ds->data.path.path) {
				if (ds->data.path.flags & FLAG_UNLINK)
					unlink(ds->data.path.path);
				g_free(ds->data.path.path);
			}
			if (ds->data.path.fd >= 0)
				metautils_pclose(&(ds->data.path.fd));
			break;
		case STYPE_EOF:
			break;
	}
	ds->next = NULL;
	g_free(ds);
}

void
data_slab_sequence_clean_data(struct data_slab_sequence_s *dss)
{
	register struct data_slab_s *ds;

	while (NULL != (ds = dss->first)) {
		dss->first = ds->next;
		data_slab_free(ds);
	}

	dss->first = dss->last = NULL;
}

gboolean
data_slab_sequence_ready_for_data(struct data_slab_sequence_s *dss)
{
	if (!dss)
		return FALSE;

	if (dss->first && dss->first->type == STYPE_EOF) {
		data_slab_sequence_clean_data(dss);
		return FALSE;
	}

	return TRUE;
}

gboolean
data_slab_sequence_has_data(struct data_slab_sequence_s *dss)
{
	register struct data_slab_s *ds;

	while (NULL != (ds = dss->first)) {

		if (data_slab_has_data(ds))
			return TRUE;

		dss->first = ds->next;
		if (!dss->first)
			dss->last = NULL;
		data_slab_free(ds);
	}

	return FALSE;
}

gboolean
data_slab_send(struct data_slab_s *ds, int fd)
{
	off_t remaining;
	ssize_t w;

	switch (ds->type) {
		case STYPE_BUFFER:
		case STYPE_BUFFER_STATIC:
			errno = 0;
			w = write(fd,
					ds->data.buffer.buff + ds->data.buffer.start,
					ds->data.buffer.end - ds->data.buffer.start);
			if (w < 0)
				return FALSE;
			ds->data.buffer.start += (guint) w;
			return TRUE;

		case STYPE_FILE:
			remaining = ds->data.file.end - ds->data.file.start;
			w = sendfile(fd, ds->data.file.fd, &(ds->data.file.start), remaining);
			if (w < 0)
				return FALSE;
			return TRUE;

		case STYPE_PATH:

			/* lazy file opening */
			if (ds->data.path.fd < 0) {
				ds->data.path.fd = open(ds->data.path.path, O_RDONLY);
				if (0 > ds->data.path.fd)
					return FALSE;
				if (!(ds->data.path.flags & FLAG_OFFSET))
					ds->data.path.start = 0;
				if (!(ds->data.path.flags & FLAG_END)) {
					struct stat64 s;
					if (0 > fstat64(ds->data.path.fd, &s))
						return FALSE;
					ds->data.path.end = s.st_size;
				}
			}
			
			/* send a chunk now */
			remaining = ds->data.path.end - ds->data.path.start;
			w = sendfile(fd, ds->data.path.fd, &(ds->data.path.start), remaining);
			if (w < 0)
				return FALSE;
			return TRUE;

		case STYPE_EOF:
			shutdown(fd, SHUT_RDWR);
			return TRUE;
	}

	return TRUE;
}

gboolean
data_slab_consume(struct data_slab_s *ds, guint8 **p_data, gsize *p_size)
{
	gsize max, remaining;

	if (!ds || !p_data || !p_size || !data_slab_has_data(ds))
		return FALSE;

	max = *p_size;
	*p_size = 0;

	switch (ds->type) {
		case STYPE_BUFFER:
		case STYPE_BUFFER_STATIC:

			EXTRA_ASSERT(ds->data.buffer.start <= ds->data.buffer.alloc);
			EXTRA_ASSERT(ds->data.buffer.start <= ds->data.buffer.end);
			EXTRA_ASSERT(ds->data.buffer.end <= ds->data.buffer.alloc);

			remaining = ds->data.buffer.end  - ds->data.buffer.start;
			if (remaining < max)
				max = remaining;
			*p_data = ds->data.buffer.buff + ds->data.buffer.start;
			*p_size = max;
			ds->data.buffer.start += max;

			EXTRA_ASSERT(ds->data.buffer.start <= ds->data.buffer.alloc);
			EXTRA_ASSERT(ds->data.buffer.start <= ds->data.buffer.end);
			EXTRA_ASSERT(ds->data.buffer.end <= ds->data.buffer.alloc);

			return TRUE;
		case STYPE_FILE:
		case STYPE_PATH:
			g_error("DESIGN ERROR : cannot consume data from a file slab");
			return FALSE;
		case STYPE_EOF:
			return FALSE;
	}

	g_assert_not_reached();
	return FALSE;
}

gboolean
data_slab_sequence_send(struct data_slab_sequence_s *dss, int fd)
{
	if (!dss->first) {
		g_assert_not_reached();
		return TRUE;
	}

	return data_slab_send(dss->first, fd);
}

void
data_slab_sequence_append(struct data_slab_sequence_s *dss,
		struct data_slab_s *ds)
{
	if (!dss->first || !dss->last) {
		EXTRA_ASSERT(dss->last == NULL && dss->first == NULL);
		dss->last = (dss->first = ds);
	}
	else {
		dss->last->next = ds;
		dss->last = ds;
	}
	ds->next = NULL;
}

struct data_slab_s*
data_slab_sequence_shift(struct data_slab_sequence_s *dss)
{
	struct data_slab_s *ds;

	if (!(ds = dss->first)) {
		dss->last = NULL;
		return NULL;
	}

	if (!(dss->first = ds->next))
		dss->last = NULL;

	ds->next = NULL;
	return ds;
}

void
data_slab_sequence_unshift(struct data_slab_sequence_s *dss,
		struct data_slab_s *ds)
{
	if (!data_slab_has_data(ds))
		data_slab_free(ds);
	else {
		if (!dss->first) {
			dss->first = dss->last = ds;
			ds->next = NULL;
		}
		else {
			ds->next = dss->first;
			dss->first = ds;
		}
	}
}

void
data_slab_trace(const gchar *tag, struct data_slab_s *ds)
{
	if (!GRID_TRACE_ENABLED())
		return;

	(void) tag;
	GString *gstr = g_string_sized_new(256);
	switch (ds->type) {
		case STYPE_BUFFER:
		case STYPE_BUFFER_STATIC:
			g_string_append_printf(gstr, "| buffer=%p alloc=%u start=%u end=%u size(%"G_GSIZE_FORMAT")",
				ds->data.buffer.buff,
				ds->data.buffer.alloc,
				ds->data.buffer.start,
				ds->data.buffer.end,
				data_slab_size(ds));
			break;
		case STYPE_FILE:
			g_string_append_printf(gstr, "| fd=%d start=%"G_GSIZE_FORMAT" end=%"G_GSIZE_FORMAT"",
				ds->data.file.fd,
				ds->data.file.start,
				ds->data.file.end);
		case STYPE_PATH:
			g_string_append_printf(gstr, "| fd=%d start=%"G_GSIZE_FORMAT" end=%"G_GSIZE_FORMAT" path=%s",
				ds->data.path.fd,
				ds->data.path.start,
				ds->data.path.end,
				ds->data.path.path);
		case STYPE_EOF:
			break;
	}

	GRID_TRACE("%s %p type=%s%s", tag, ds, data_slab_type2str(ds), gstr->str);
	g_string_free(gstr, TRUE);
}

void
data_slab_sequence_trace(struct data_slab_sequence_s *dss)
{
	struct data_slab_s *s;

	if (!GRID_TRACE_ENABLED())
		return;

	GRID_TRACE(" DSS %p -> %p", dss->first, dss->last);
	for (s = dss->first; s ;) {
		data_slab_trace("SLAB", s);
		if (s == dss->last)
			break;
		s = s->next;
	}
}

gsize
data_slab_sequence_size(struct data_slab_sequence_s *dss)
{
	gsize total = 0;
	struct data_slab_s *s;

	for (s = dss->first; s ;) {
		total += data_slab_size(s);
		if (s == dss->last)
			break;
		s = s->next;
	}

	return total;
}

//------------------------------------------------------------------------------

struct data_slab_s *
data_slab_make_empty(gsize alloc)
{
	struct data_slab_s ds;
	ds.type = STYPE_BUFFER;
	ds.data.buffer.buff = g_malloc(alloc);
	ds.data.buffer.start = 0;
	ds.data.buffer.end = 0;
	ds.data.buffer.alloc = alloc;
	ds.next = NULL;
	return g_memdup(&ds, sizeof(ds));
}

struct data_slab_s *
data_slab_make_eof(void)
{
	struct data_slab_s ds;
	ds.type = STYPE_EOF;
	ds.next = NULL;
	return g_memdup(&ds, sizeof(ds));
}

struct data_slab_s *
data_slab_make_file(int fd, off_t start, off_t end)
{
	struct data_slab_s ds;
	ds.type = STYPE_FILE;
	ds.data.file.start = start;
	ds.data.file.end = end;
	ds.data.file.fd = fd;
	ds.next = NULL;
	return g_memdup(&ds, sizeof(ds));
}

struct data_slab_s *
data_slab_make_path2(const gchar *path, off_t start, off_t end)
{
	struct data_slab_s ds;
	ds.type = STYPE_PATH;
	ds.data.path.path = g_strdup(path);
	ds.data.path.start = start;
	ds.data.path.end = end;
	ds.data.path.fd = -1;
	ds.data.path.flags = FLAG_OFFSET|FLAG_END;
	ds.next = NULL;
	return g_memdup(&ds, sizeof(ds));
}

struct data_slab_s *
data_slab_make_path(const gchar *path, gboolean must_unlink)
{
	struct data_slab_s ds;
	ds.type = STYPE_PATH;
	ds.data.path.path = g_strdup(path);
	ds.data.path.start = 0;
	ds.data.path.end = 0;
	ds.data.path.fd = -1;
	ds.data.path.flags = must_unlink ? FLAG_UNLINK : 0;
	ds.next = NULL;
	return g_memdup(&ds, sizeof(ds));
}

struct data_slab_s *
data_slab_make_tempfile(const gchar *path)
{
	return data_slab_make_path(path, TRUE);
}

struct data_slab_s *
data_slab_make_buffer2(guint8 *buff, gboolean tobefreed, gsize start,
		gsize end, gsize alloc)
{
	struct data_slab_s ds;
	ds.type = tobefreed ? STYPE_BUFFER : STYPE_BUFFER_STATIC;
	ds.data.buffer.start = start;
	ds.data.buffer.end = end;
	ds.data.buffer.alloc = alloc;
	ds.data.buffer.buff = buff;
	ds.next = NULL;
	return g_memdup(&ds, sizeof(ds));
}

