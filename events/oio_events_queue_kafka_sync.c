/*
OpenIO SDS event queue
Copyright (C) 2024 OVH SAS

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
#include <unistd.h>

#include <librdkafka/rdkafka.h>

#include <core/oio_core.h>
#include <events/events_variables.h>

#include "kafka.h"
#include "oio_events_queue.h"
#include "oio_events_queue_internals.h"
#include "oio_events_queue_kafka_sync.h"
#include "oio_events_queue_buffer.h"

static void _q_destroy (struct oio_events_queue_s *self);
static gboolean _q_send (struct oio_events_queue_s *self, gchar *msg);
static gint64 _q_get_health(struct oio_events_queue_s *self);
static GError * _q_start (struct oio_events_queue_s *self);
static guint64 _q_get_total_send_time(struct oio_events_queue_s *self);
static guint64 _q_get_total_sent_events(struct oio_events_queue_s *self);

static struct oio_events_queue_vtable_s vtable_KAFKA =
{
	.destroy = _q_destroy,
	.send = _q_send,
	// Notice that send_time corresponds only to the sending of the message.
	.get_total_send_time = _q_get_total_send_time,
	.get_total_sent_events = _q_get_total_sent_events,
	.get_health = _q_get_health,
	.start = _q_start,
};


GError *
oio_events_queue_factory__create_kafka_sync(
		const char *endpoint, const char *topic,
		struct oio_events_queue_s **out)
{
	EXTRA_ASSERT(endpoint != NULL);
	EXTRA_ASSERT(out != NULL);
	EXTRA_ASSERT(topic != NULL);
	*out = NULL;

	struct _queue_with_endpoint_s *self = g_malloc0(sizeof(*self));
	self->vtable = &vtable_KAFKA;
	self->endpoint = g_strdup(endpoint);
	self->queue_name = g_strdup(topic);
	self->healthy = FALSE;
	self->kafka = NULL;

	self->event_send_count = grid_single_rrd_create(
			oio_ext_monotonic_seconds(), OIO_EVENTS_STATS_HISTORY_SECONDS);
	self->event_send_time = grid_single_rrd_create(
			oio_ext_monotonic_seconds(), OIO_EVENTS_STATS_HISTORY_SECONDS);

	*out = (struct oio_events_queue_s*) self;

	return NULL;
}

// --------------------------------------------------------

void
_q_destroy(struct oio_events_queue_s *self)
{
	if (!self) return;

	struct _queue_with_endpoint_s *q = (struct _queue_with_endpoint_s*) self;

	q->healthy = FALSE;

	kafka_destroy(q->kafka);
	oio_str_clean(&q->endpoint);
	oio_str_clean(&q->username);
	oio_str_clean(&q->password);
	oio_str_clean(&q->queue_name);
	grid_single_rrd_destroy(q->event_send_count);
	grid_single_rrd_destroy(q->event_send_time);
	q->event_send_count = NULL;
	q->event_send_time = NULL;
	q->vtable = NULL;
	g_free(q);
}


gboolean
_q_send(struct oio_events_queue_s *self, gchar *msg)
{
	struct _queue_with_endpoint_s *q = (struct _queue_with_endpoint_s*) self;
	const size_t msglen = strlen(msg);
	gint64 start = oio_ext_monotonic_time();
	GError *err = kafka_publish_message(q->kafka, msg, msglen, q->queue_name, TRUE);
	gint64 end = oio_ext_monotonic_time();
	time_t end_seconds = end / G_TIME_SPAN_SECOND;

	/* count the operation whether it's a success or a failure */
	grid_single_rrd_add(q->event_send_count, end_seconds, 1);
	grid_single_rrd_add(q->event_send_time, end_seconds, end - start);

	g_free(msg);

	if (err) {
		GRID_ERROR("%s", err->message);
		return FALSE;
	}
	return TRUE;
}

gint64
_q_get_health(struct oio_events_queue_s *self)
{
	struct _queue_with_endpoint_s *q = (struct _queue_with_endpoint_s*) self;
	EXTRA_ASSERT(q != NULL && q->vtable != NULL);

	if (!q->healthy) {
		/* Queue is explicitly unhealthy */
		return SCORE_DOWN;
	}
	/* No buffer for this queue, if it is not down, it is up. */
	return SCORE_MAX;
}

guint64
_q_get_total_send_time(struct oio_events_queue_s *self)
{
	struct _queue_with_endpoint_s *q = (struct _queue_with_endpoint_s*) self;
	EXTRA_ASSERT(q != NULL && q->vtable != NULL);
	gint64 now = oio_ext_monotonic_seconds();
	return grid_single_rrd_get(q->event_send_time, now);
}

guint64
_q_get_total_sent_events(struct oio_events_queue_s *self)
{
	struct _queue_with_endpoint_s *q = (struct _queue_with_endpoint_s*) self;
	EXTRA_ASSERT(q != NULL && q->vtable != NULL);
	gint64 now = oio_ext_monotonic_seconds();
	return grid_single_rrd_get(q->event_send_count, now);
}

static GError *
_q_start (struct oio_events_queue_s *self)
{
	struct _queue_with_endpoint_s *q = (struct _queue_with_endpoint_s*) self;
	g_assert_nonnull(q);
	g_assert(q->vtable == &vtable_KAFKA);

	q->healthy = TRUE;

	GError *err = kafka_create(q->endpoint, q->queue_name, &q->kafka, TRUE);

	if (err){
		GRID_ERROR("Error while creating sync queue");
		return err;
	}

	return err;
}
