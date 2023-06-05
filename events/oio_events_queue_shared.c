/*
OpenIO SDS event queue
Copyright (C) 2022-2023 OVH SAS

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
#include <math.h>

#include <events/events_variables.h>

#include "oio_events_queue.h"
#include "oio_events_queue_internals.h"
#include "oio_events_queue_shared.h"


// Internally used functions and structs, shared by several implementations

_queue_BEANSTALKD_intercept_running_f intercept_running = NULL;

void
_event_dropped(const char *msg, const size_t msglen)
{
	GRID_NOTICE("Dropped %d bytes event: %.*s",
			(int)msglen, (int)MIN(msglen,2048), msg);
}

void
_q_destroy(struct oio_events_queue_s *self)
{
	if (!self) return;

	struct _queue_with_endpoint_s *q = (struct _queue_with_endpoint_s*) self;

	q->running = FALSE;
	q->healthy = FALSE;

	if (q->worker) {
		g_thread_join(q->worker);
		q->worker = NULL;
	}

	g_async_queue_unref(q->queue);
	oio_str_clean(&q->endpoint);
	oio_str_clean(&q->username);
	oio_str_clean(&q->password);
	oio_str_clean(&q->queue_name);
	oio_str_clean(&q->routing_key);
	oio_str_clean(&q->exchange_name);
	oio_str_clean(&q->exchange_type);
	g_strfreev(q->extra_args);
	oio_events_queue_buffer_clean(&(q->buffer));
	grid_single_rrd_destroy(q->event_send_count);
	grid_single_rrd_destroy(q->event_send_time);
	q->event_send_count = NULL;
	q->event_send_time = NULL;
	q->vtable = NULL;
	g_free(q);
}

/**
 * Drain the queue of pending events.
 * In addition, print a warning that some events have been lost.
 */
void
_q_flush_pending(struct _queue_with_endpoint_s *q)
{
	guint count = 0;
	while (0 < g_async_queue_length(q->queue)) {
		gchar *msg = g_async_queue_try_pop(q->queue);
		if (msg) {
			_event_dropped(msg, strlen(msg));
			oio_str_clean(&msg);
			++ count;
		}
	}
	if (count > 0)
		GRID_WARN("%u events lost", count);
}

gboolean
_q_is_empty(struct _queue_with_endpoint_s *q)
{
	return oio_events_queue_buffer_is_empty(&q->buffer)
		&& 0 >= g_async_queue_length(q->queue);
}

gboolean
_q_is_running(struct _queue_with_endpoint_s *q)
{
#ifdef HAVE_EXTRA_DEBUG
	if (intercept_running != NULL) {
		return (*intercept_running)(q);
	}
#endif
	return q->running;
}

gboolean
_q_is_stalled(struct oio_events_queue_s *self)
{
	struct _queue_with_endpoint_s *q = (struct _queue_with_endpoint_s*) self;
	EXTRA_ASSERT (q != NULL && q->vtable != NULL);
	const int l = g_async_queue_length(q->queue);
	if (l <= 0) {
		return FALSE;
	}
	return ((guint)l) >= oio_events_common_max_pending;
}

void
_q_send(struct oio_events_queue_s *self, gchar *msg)
{
	struct _queue_with_endpoint_s *q = (struct _queue_with_endpoint_s*) self;
	g_async_queue_push(q->queue, msg);
}

void
_q_send_overwritable(struct oio_events_queue_s *self, gchar *key, gchar *msg)
{
	struct _queue_with_endpoint_s *q = (struct _queue_with_endpoint_s*) self;
	oio_events_queue_buffer_put(&(q->buffer), key, msg);
}

void
_q_set_buffering(struct oio_events_queue_s *self, gint64 v)
{
	struct _queue_with_endpoint_s *q = (struct _queue_with_endpoint_s *)self;
	if (q->buffer.delay != v) {
		GRID_INFO("events buffering delay set to %"G_GINT64_FORMAT"s",
				v / G_TIME_SPAN_SECOND);
		oio_events_queue_buffer_set_delay(&(q->buffer), v);
	}
}

void
_q_flush_buffered(struct _queue_with_endpoint_s *q, gboolean total)
{
	const gint avail =
		oio_events_common_max_pending - g_async_queue_length(q->queue);
	if (avail < (gint) oio_events_common_max_pending / 100) {
		GRID_WARN("Pending events queue is reaching maximum: %d/%d",
				g_async_queue_length(q->queue),
				oio_events_common_max_pending);
	}

	/* This is not an else clause, we want to send the buffered events
	 * (even if we do it slowly). */
	const guint half = MAX(1U, (guint)avail / 2);
	oio_events_queue_send_buffered(
			(struct oio_events_queue_s*)q, &(q->buffer),
			total ? G_MAXUINT : half);
}

void
_q_flush_overwritable(struct oio_events_queue_s *self, gchar *key)
{
	struct _queue_with_endpoint_s *q = (struct _queue_with_endpoint_s*) self;
	oio_events_queue_flush_key((struct oio_events_queue_s*)q, &(q->buffer), key);
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

guint64
_q_get_avg_send_rate(struct oio_events_queue_s *self, gint64 duration)
{
	struct _queue_with_endpoint_s *q = (struct _queue_with_endpoint_s*) self;
	EXTRA_ASSERT(q != NULL && q->vtable != NULL);
	EXTRA_ASSERT(duration > 0);
	time_t period = MIN(duration, OIO_EVENTS_STATS_HISTORY_SECONDS);
	gint64 now = oio_ext_monotonic_seconds();
	guint64 count = grid_single_rrd_get_delta(q->event_send_count, now, period);
	return count / period;
}

guint64
_q_get_avg_send_time(struct oio_events_queue_s *self, gint64 duration)
{
	struct _queue_with_endpoint_s *q = (struct _queue_with_endpoint_s*) self;
	EXTRA_ASSERT(q != NULL && q->vtable != NULL);
	time_t period = MIN(duration, OIO_EVENTS_STATS_HISTORY_SECONDS);
	gint64 now = oio_ext_monotonic_seconds();
	guint64 tot_time = grid_single_rrd_get_delta(q->event_send_time, now, period);
	guint64 count = grid_single_rrd_get_delta(q->event_send_count, now, period);
	guint64 avg_send_time = tot_time / MAX(count, 1);
	return avg_send_time;
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
	double max_score = ((double)SCORE_MAX);
	return (gint64) (max_score / (1.0 + log(1.0 + q->pending_events * 0.1)));
}
