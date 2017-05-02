/*
OpenIO SDS event queue
Copyright (C) 2016 OpenIO, original work as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

void oio_events_queue_buffer_init(struct oio_events_queue_buffer_s *buf,
		gint64 delay);
void oio_events_queue_buffer_clean(struct oio_events_queue_buffer_s *buf);
void oio_events_queue_buffer_set_delay(struct oio_events_queue_buffer_s *buf,
		gint64 new_delay);
void oio_events_queue_buffer_put(struct oio_events_queue_buffer_s *buf,
		gchar *key, gchar *msg);

/** Flush at most `max` events older than the configured delay. Each flushed
 *  event is passed to `send` then removed from the buffer. `send` is
 *  responsible for cleaning the event, and should not block. */
void oio_events_queue_buffer_maybe_flush(struct oio_events_queue_buffer_s *buf,
		GHRFunc send, gpointer user_data, guint max);

#endif
