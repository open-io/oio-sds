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

#ifndef OIO_SDS__sqlx__oio_events_queue_shared_h
# define OIO_SDS__sqlx__oio_events_queue_shared_h 1

#include <glib.h>

#include <core/internals.h>


// Internally used functions and structures, shared by several implementations

#define EXPO_BACKOFF(DELAY,TRY,MAX_TRIES) \
	g_usleep((1 << MIN(TRY, MAX_TRIES)) * DELAY); \
	TRY++

/* Holds data necessary to connect to an external queue service
 * with a TCP endpoint (Beanstalkd, RabbitMQ, etc.). */
struct _queue_with_endpoint_s
{
	struct oio_events_queue_vtable_s *vtable;
	GAsyncQueue *queue;
	GThread *worker;

	gchar *endpoint;
	gchar *username;
	gchar *password;
	gchar *queue_name;  // only for RabbitMQ
	gchar *tube;  // tube for Beanstalkd, routing key for RabbitMQ
	gchar *exchange_name;  // only for RabbitMQ
	gchar *exchange_type;  // only for RabbitMQ
	gchar **extra_args;  // only for RabbitMQ
	gint64 pending_events;

	volatile gboolean running;  // used to control the infinite loop
	volatile gboolean healthy;  // used to know if a queue is explicitly unhealthy

	struct oio_events_queue_buffer_s buffer;
	struct grid_single_rrd_s *event_send_count;
	struct grid_single_rrd_s *event_send_time;
};

#ifdef HAVE_EXTRA_DEBUG
/* Used by tests to intercept the result of the parsing of beanstalkd
 * replies */
typedef void (*_queue_BEANSTALKD_intercept_error_f) (GError *err);
#endif

/* Used by tests to intercept the checks for completion */
typedef gboolean (*_queue_BEANSTALKD_intercept_running_f) (
		struct _queue_with_endpoint_s *q);

extern _queue_BEANSTALKD_intercept_running_f intercept_running;

void _event_dropped(const char *msg, const size_t msglen);
void _q_destroy (struct oio_events_queue_s *self);
void _q_flush_buffered(struct _queue_with_endpoint_s *q, gboolean total);
void _q_flush_overwritable(struct oio_events_queue_s *self, gchar *key);
void _q_flush_pending(struct _queue_with_endpoint_s *q);
/** Get the average send rate over the specified duration. */
guint64 _q_get_avg_send_rate(struct oio_events_queue_s *self, gint64 duration);
/** Get the average send time over the specified duration. */
guint64 _q_get_avg_send_time(struct oio_events_queue_s *self, gint64 duration);
/** Get a health metric for the events queue, from 0 (bad) to 100 (good). */
gint64 _q_get_health(struct oio_events_queue_s *self);
guint64 _q_get_total_send_time(struct oio_events_queue_s *self);
guint64 _q_get_total_sent_events(struct oio_events_queue_s *self);
gboolean _q_is_empty(struct _queue_with_endpoint_s *q);
gboolean _q_is_running(struct _queue_with_endpoint_s *q);
/** Does the queue reached the maximum pending events? */
gboolean _q_is_stalled(struct oio_events_queue_s *self);
void _q_send(struct oio_events_queue_s *self, gchar *msg);
void _q_send_overwritable(struct oio_events_queue_s *self, gchar *key,
		gchar *msg);
void _q_set_buffering(struct oio_events_queue_s *self, gint64 v);

#endif /*OIO_SDS__sqlx__oio_events_queue_shared_h*/
