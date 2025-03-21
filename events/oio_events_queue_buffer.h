/*
OpenIO SDS event queue
Copyright (C) 2016-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2025 OVH SAS

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

#ifndef OIO_SDS__sqlx__oio_events_queue_buffer_h
# define OIO_SDS__sqlx__oio_events_queue_buffer_h 1

#include <glib.h>
#include <metautils/lib/metautils.h>

struct oio_events_queue_buffer_s
{
	struct lru_tree_s *msg_by_key;
	GMutex msg_by_key_lock;
	gint64 delay;
};

void oio_events_queue_buffer_init(struct oio_events_queue_buffer_s *buf);
void oio_events_queue_buffer_clean(struct oio_events_queue_buffer_s *buf);
void oio_events_queue_buffer_set_delay(struct oio_events_queue_buffer_s *buf,
		gint64 new_delay);
void oio_events_queue_buffer_put(struct oio_events_queue_buffer_s *buf,
		gchar *tag, gchar *data);

/** Flush the buffered event keyed with `key`, if any, no matter the
 * configured delay. Does nothing if there is no event.
 * `key` will be freed. */
void oio_events_queue_buffer_flush_key(struct oio_events_queue_buffer_s *buf,
		GHRFunc send, gpointer user_data, gchar *key);

/** Flush at most `max` events older than the configured delay. Each flushed
 *  event is passed to `send` then removed from the buffer. `send` is
 *  responsible for cleaning the event, and should not block. */
void oio_events_queue_buffer_maybe_flush(struct oio_events_queue_buffer_s *buf,
		GHRFunc send, gpointer user_data, guint max);

gboolean oio_events_queue_buffer_is_empty(struct oio_events_queue_buffer_s *buf);

#endif
