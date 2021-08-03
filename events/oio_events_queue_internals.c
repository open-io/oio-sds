/*
OpenIO SDS event queue
Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021 OVH SAS

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

#include <glib.h>

#include "oio_events_queue.h"
#include "oio_events_queue_internals.h"

void
oio_events_queue_send_buffered(struct oio_events_queue_s *self,
		struct oio_events_queue_buffer_s *buffer, guint max)
{
	guint sent = 0;
	gboolean __send(gpointer key, gpointer msg, gpointer u UNUSED) {
		g_free(key);
		oio_events_queue__send(self, (gchar*)msg);
		sent++;
		return TRUE;
	}

	const gint64 start = oio_ext_monotonic_time();
	oio_events_queue_buffer_maybe_flush(buffer, __send, NULL, max);
	const gint64 duration = oio_ext_monotonic_time() - start;
	if (duration > G_TIME_SPAN_SECOND) {
		GRID_WARN("Pushing %u buffered events to the send queue took %.3fs",
				sent, duration / (gdouble)G_TIME_SPAN_SECOND);
	}
	EXTRA_ASSERT(sent <= max);
}

void
oio_events_queue_flush_key(struct oio_events_queue_s *self,
		struct oio_events_queue_buffer_s *buffer, gchar *key)
{
	gboolean __send(gpointer key_, gpointer msg, gpointer u UNUSED) {
		g_free(key_);
		oio_events_queue__send(self, (gchar*)msg);
		return TRUE;
	}

	oio_events_queue_buffer_flush_key(buffer, __send, NULL, key);
}
