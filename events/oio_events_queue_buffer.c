/*
OpenIO SDS event queue
Copyright (C) 2016 OpenIO, original work as part of OpenIO SDS

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

#include <core/oio_core.h>
#include "oio_events_queue_buffer.h"


void
oio_events_queue_buffer_init(struct oio_events_queue_buffer_s *buf,
		gint64 delay)
{
	g_mutex_init(&(buf->msg_by_key_lock));
	buf->msg_by_key = lru_tree_create((GCompareFunc)g_strcmp0, g_free, g_free,
			LTO_NOATIME|LTO_NOUTIME);
	buf->delay = delay;
}

void
oio_events_queue_buffer_clean(struct oio_events_queue_buffer_s *buf)
{
	lru_tree_destroy(buf->msg_by_key);
	g_mutex_clear(&(buf->msg_by_key_lock));
}

void
oio_events_queue_buffer_set_delay(struct oio_events_queue_buffer_s *buf,
		gint64 new_delay)
{
	buf->delay = new_delay;
}

void
oio_events_queue_buffer_maybe_flush(struct oio_events_queue_buffer_s *buf,
		GHRFunc send, gpointer user_data, guint max)
{
	gint64 now = oio_ext_monotonic_time();
	g_mutex_lock(&(buf->msg_by_key_lock));
	lru_tree_foreach_older_steal(buf->msg_by_key, send, user_data,
			now - buf->delay, max);
	g_mutex_unlock(&(buf->msg_by_key_lock));
}

void oio_events_queue_buffer_put(struct oio_events_queue_buffer_s *buf,
		gchar *key, gchar *msg)
{
	g_mutex_lock(&(buf->msg_by_key_lock));
	lru_tree_insert(buf->msg_by_key, key, msg);
	g_mutex_unlock(&(buf->msg_by_key_lock));
}
