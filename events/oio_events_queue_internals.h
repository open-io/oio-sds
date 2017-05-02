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
#ifndef OIO_SDS__sqlx__oio_events_queue_internals_h
# define OIO_SDS__sqlx__oio_events_queue_internals_h 1

#include <core/internals.h>

#include "oio_events_queue_buffer.h"

struct oio_events_queue_s;

struct oio_events_queue_vtable_s
{
	void (*destroy) (struct oio_events_queue_s *self);
	void (*send) (struct oio_events_queue_s *self, gchar *msg);
	void (*send_overwritable)(struct oio_events_queue_s *self,
			gchar *key, gchar *msg);
	gboolean (*is_stalled) (struct oio_events_queue_s *self);
	void (*set_max_pending) (struct oio_events_queue_s *self, guint v);
	void (*set_buffering) (struct oio_events_queue_s *self, gint64 v);
	GError * (*run) (struct oio_events_queue_s *self, gboolean (*) (gboolean));
};

struct oio_events_queue_abstract_s
{
	struct oio_events_queue_vtable_s *vtable;
};

void oio_events_queue_send_buffered(struct oio_events_queue_s *self,
		struct oio_events_queue_buffer_s *buffer, guint max);

#endif /*OIO_SDS__sqlx__oio_events_queue_internals_h*/
