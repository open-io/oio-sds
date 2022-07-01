/*
OpenIO SDS event queue
Copyright (C) 2016-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2022 OVH SAS

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
	guint64 (*get_total_sent_events) (struct oio_events_queue_s *self);
	guint64 (*get_total_send_time) (struct oio_events_queue_s *self);
	gint64 (*get_health) (struct oio_events_queue_s *self);
	void (*set_buffering) (struct oio_events_queue_s *self, gint64 v);
	GError * (*start) (struct oio_events_queue_s *self);
	void (*flush_overwritable)(struct oio_events_queue_s *self,
			gchar *key);
};

struct oio_events_queue_abstract_s
{
	struct oio_events_queue_vtable_s *vtable;
};

/** Flush any overwritable event keyed with `key`,
 * disregarding the buffer delay. */
void oio_events_queue_flush_key(struct oio_events_queue_s *self,
		struct oio_events_queue_buffer_s *buffer, gchar *key);

void oio_events_queue_send_buffered(struct oio_events_queue_s *self,
		struct oio_events_queue_buffer_s *buffer, guint max);

#endif /*OIO_SDS__sqlx__oio_events_queue_internals_h*/
