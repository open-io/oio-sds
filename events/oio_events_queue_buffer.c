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

#include <core/oio_core.h>
#include "oio_events_queue_buffer.h"

static GHashTable *
oio_events_queue_buffer_renew(struct oio_events_queue_buffer_s *buf)
{
	g_mutex_lock(&(buf->msg_by_key_lock));
	GHashTable *old = buf->msg_by_key;
	buf->msg_by_key = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, g_free);
	buf->last_renew = oio_ext_monotonic_time();
	g_mutex_unlock(&(buf->msg_by_key_lock));
	return old;
}

void
oio_events_queue_buffer_init(struct oio_events_queue_buffer_s *buf,
		gint64 delay)
{
	g_mutex_init(&(buf->msg_by_key_lock));
	buf->delay = delay;
	oio_events_queue_buffer_renew(buf);
}

void
oio_events_queue_buffer_clean(struct oio_events_queue_buffer_s *buf)
{
	g_hash_table_unref(buf->msg_by_key);
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
		GHRFunc send, gpointer user_data)
{
	if (oio_ext_monotonic_time() > buf->last_renew + buf->delay) {
		GHashTable *old = oio_events_queue_buffer_renew(buf);
		g_hash_table_foreach_steal(old, send, user_data);
		g_hash_table_unref(old);
	}
}

void oio_events_queue_buffer_put(struct oio_events_queue_buffer_s *buf,
		gchar *key, gchar *msg)
{
	g_mutex_lock(&(buf->msg_by_key_lock));
	g_hash_table_insert(buf->msg_by_key, key, msg);
	g_mutex_unlock(&(buf->msg_by_key_lock));
}
