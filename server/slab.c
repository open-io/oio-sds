/*
OpenIO SDS server
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

#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#include "slab.h"
#include "internals.h"

gsize
data_slab_size(struct data_slab_s *ds)
{
	switch (ds->type) {
		case STYPE_BUFFER:
		case STYPE_BUFFER_STATIC:
			if (!ds->data.buffer.buff || !ds->data.buffer.alloc)
				return 0;
			if (ds->data.buffer.start >= ds->data.buffer.end)
				return 0;
			return (ds->data.buffer.end - ds->data.buffer.start);
		case STYPE_GBYTES:
			return g_bytes_get_size (ds->data.gbytes);
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
		case STYPE_GBYTES:
			return 0 < g_bytes_get_size (ds->data.gbytes);
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
			ds->data.buffer.buff = NULL;
			ds->data.buffer.start = ds->data.buffer.end = 0;
			break;
		case STYPE_GBYTES:
			g_bytes_unref (ds->data.gbytes);
			break;
		case STYPE_EOF:
			break;
	}
	ds->next = NULL;
	SLICE_FREE (struct data_slab_s, ds);
}

void
data_slab_sequence_clean_data(struct data_slab_sequence_s *dss)
{
	for (struct data_slab_s *ds; NULL != (ds = dss->first); ) {
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
	ssize_t w;

	switch (ds->type) {
		case STYPE_BUFFER:
		case STYPE_BUFFER_STATIC:
			/* send */
			errno = 0;
			w = write(fd,
					ds->data.buffer.buff + ds->data.buffer.start,
					ds->data.buffer.end - ds->data.buffer.start);
			if (w < 0)
				return FALSE;
			/* consume */
			ds->data.buffer.start += (guint) w;
			return TRUE;

		case STYPE_GBYTES:
			do {
				gsize l = 0;
				gconstpointer b = g_bytes_get_data (ds->data.gbytes, &l);
				/* send */
				errno = 0;
				w = write(fd, b, l);
				if (w < 0)
					return FALSE;
				/* consume */
				GBytes *old = ds->data.gbytes;
				ds->data.gbytes = g_bytes_new_from_bytes (old, w, l-w);
				g_bytes_unref (old);
				return TRUE;
			} while (0);
			return TRUE;

		case STYPE_EOF:
			shutdown(fd, SHUT_RDWR);
			return TRUE;
	}

	g_assert_not_reached ();
	return FALSE;
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

		case STYPE_GBYTES:
		case STYPE_EOF:
			/* consuming from such sources is not managed yet, neither by the
			   server that never fills them nor the be clients that do not
			   manage them. */
			g_assert_not_reached ();
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

//------------------------------------------------------------------------------

static struct data_slab_s * _slab (void) { return SLICE_NEW0(struct data_slab_s); }

struct data_slab_s *
data_slab_make_empty(gsize alloc)
{
	struct data_slab_s *ds = _slab();
	ds->type = STYPE_BUFFER;
	ds->data.buffer.buff = g_malloc(alloc);
	ds->data.buffer.start = 0;
	ds->data.buffer.end = 0;
	ds->data.buffer.alloc = alloc;
	ds->next = NULL;
	return ds;
}

struct data_slab_s *
data_slab_make_eof(void)
{
	struct data_slab_s *ds = _slab();
	ds->type = STYPE_EOF;
	ds->next = NULL;
	return ds;
}

struct data_slab_s *
data_slab_make_buffer2(guint8 *buff, gboolean tobefreed, gsize start,
		gsize end, gsize alloc)
{
	struct data_slab_s *ds = _slab();
	ds->type = tobefreed ? STYPE_BUFFER : STYPE_BUFFER_STATIC;
	ds->data.buffer.start = start;
	ds->data.buffer.end = end;
	ds->data.buffer.alloc = alloc;
	ds->data.buffer.buff = buff;
	ds->next = NULL;
	return ds;
}

struct data_slab_s *
data_slab_make_gbytes(GBytes *gb)
{
	struct data_slab_s *ds = _slab();
	ds->type = STYPE_GBYTES;
	ds->data.gbytes = gb;
	ds->next = NULL;
	return ds;
}

