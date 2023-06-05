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

// These are the new header names, for RabbitMQ>=0.12.0
// #include <rabbitmq-c/amqp.h>
// #include <rabbitmq-c/tcp_socket.h>
#include <amqp.h>

#include <core/oio_core.h>
#include <events/events_variables.h>

#include "rabbitmq.h"
#include "oio_events_queue.h"
#include "oio_events_queue_internals.h"
#include "oio_events_queue_rabbitmq.h"
#include "oio_events_queue_buffer.h"
#include "oio_events_queue_shared.h"

static GError * _q_start (struct oio_events_queue_s *self);

static struct oio_events_queue_vtable_s vtable_RABBITMQ =
{
	.destroy = _q_destroy,
	.send = _q_send,
	.send_overwritable = _q_send_overwritable,
	.is_stalled = _q_is_stalled,
	.get_total_send_time = _q_get_total_send_time,
	.get_total_sent_events = _q_get_total_sent_events,
	.get_health = _q_get_health,
	.set_buffering = _q_set_buffering,
	.start = _q_start,
	.flush_overwritable = _q_flush_overwritable,
};

#ifdef HAVE_EXTRA_DEBUG
static _queue_BEANSTALKD_intercept_error_f intercept_errors = NULL;
#endif

GError *
oio_events_queue_factory__create_rabbitmq(
		const char *endpoint, const char *routing_key,
		struct oio_events_queue_s **out)
{
	EXTRA_ASSERT(endpoint != NULL);
	EXTRA_ASSERT(routing_key != NULL);
	EXTRA_ASSERT(out != NULL);
	*out = NULL;

	GError *err = NULL;
	const char *username = NULL;
	const char *password = NULL;
	const char *real_endpoint = NULL;

	// Look for a user name (and password) in the endpoint
	gchar **creds_endpoint_toks = g_strsplit(endpoint, "@", 2);
	if (g_strv_length(creds_endpoint_toks) > 1) {
		username = creds_endpoint_toks[0];
		real_endpoint = creds_endpoint_toks[1];

		char *sep = strchr(creds_endpoint_toks[0], ':');
		if (sep != NULL) {
			password = sep + 1;
			*sep = '\0';
		}
		// Else no password, will use the default one.
	} else {
		real_endpoint = endpoint;
	}

	/* XXX: here we used to call metautils_url_valid_for_connect()
	 * on the provided endpoint, but this function did not support
	 * DNS names, and thus was failing when the endpoint was not
	 * an IP address. */

	struct _queue_with_endpoint_s *self = g_malloc0(sizeof(*self));
	self->vtable = &vtable_RABBITMQ;
	self->queue = g_async_queue_new();
	self->endpoint = g_strdup(real_endpoint);
	self->username = g_strdup(username);  // NULL-safe
	self->password = g_strdup(password);  // NULL-safe
	self->queue_name = g_strdup(oio_events_amqp_queue_name);
	self->routing_key = g_strdup(routing_key);
	self->exchange_name = g_strdup(oio_events_amqp_exchange_name);
	self->exchange_type = g_strdup(oio_events_amqp_exchange_type);
	self->extra_args = NULL;
	// self->pending_events = 0;  // Already 0
	self->running = FALSE;
	self->healthy = FALSE;

	oio_events_queue_buffer_init(&(self->buffer));
	self->event_send_count = grid_single_rrd_create(
			oio_ext_monotonic_seconds(), OIO_EVENTS_STATS_HISTORY_SECONDS);
	self->event_send_time = grid_single_rrd_create(
			oio_ext_monotonic_seconds(), OIO_EVENTS_STATS_HISTORY_SECONDS);

	*out = (struct oio_events_queue_s*) self;

	g_strfreev(creds_endpoint_toks);
	return err;
}

// --------------------------------------------------------

struct _running_ctx_s {
	gint64 last_flush;
	gint64 last_check;
	gint64 now;
	guint attempts_connect;
	guint attempts_check;
	guint attempts_put;
	struct rabbitmq_s *rabbitmq;
};

static gboolean
_q_declare_exchange_and_queue(struct _queue_with_endpoint_s *q,
		struct _running_ctx_s *ctx)
{
	GError *err = rabbitmq_declare_exchange(
			ctx->rabbitmq,
			q->exchange_type,
			FALSE,  // not passive, really declare it
			TRUE,   // durable
			FALSE   // do not auto-delete
	);
#ifdef HAVE_EXTRA_DEBUG
	if (intercept_errors)
		(*intercept_errors) (err);
#endif
	if (err) {
		GRID_WARN("Failed to declare RabbitMQ exchange %s: %s",
				q->exchange_name, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	/* Declare a queue with the configured name. */
	err = rabbitmq_declare_queue(
			ctx->rabbitmq,
			q->queue_name,
			FALSE,  // not passive, really declare it
			TRUE,   // durable
			FALSE,  // not exclusive
			FALSE   // do not auto-delete
	);
#ifdef HAVE_EXTRA_DEBUG
	if (intercept_errors)
		(*intercept_errors) (err);
#endif
	if (err) {
		GRID_WARN("Failed to declare RabbitMQ queue %s: %s",
				q->queue_name, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	/* Then bind it to the configured exchange with a routing key */
	err = rabbitmq_bind_queue(ctx->rabbitmq, q->queue_name,
			oio_events_amqp_bind_routing_key);
#ifdef HAVE_EXTRA_DEBUG
	if (intercept_errors)
		(*intercept_errors) (err);
#endif
	if (err) {
		GRID_WARN("Failed to bind RabbitMQ queue %s with routing key %s: %s",
				q->queue_name, oio_events_amqp_bind_routing_key, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	return TRUE;
}

static gboolean
_q_reconnect(struct _queue_with_endpoint_s *q UNUSED, struct _running_ctx_s *ctx)
{
	EXTRA_ASSERT(ctx->rabbitmq != NULL);

	if (ctx->rabbitmq && ctx->rabbitmq->conn) {
		return TRUE;
	}

	GError *err = rabbitmq_connect(ctx->rabbitmq);
#ifdef HAVE_EXTRA_DEBUG
	if (intercept_errors)
		(*intercept_errors) (err);
#endif
	if (err) {
		GRID_WARN("Failed to (re)connect: %s", err->message);
		g_clear_error(&err);
		ctx->attempts_connect += 1;
		return FALSE;
	} else {
		if (ctx->attempts_connect > 0) {
			/* After a reconnection, try to redeclare exchange and queue
			 * If it works, that's good, we will be able to send events again.
			 * If it fails, maybe they already exist, that's not a big deal.
			 */
			_q_declare_exchange_and_queue(q, ctx);
			ctx->attempts_connect = 0;
		}
		return TRUE;
	}
}

// TODO(FVE): factorize the following functions
// They have been copied from oio_events_queue_beanstalkd.c
// and just slightly modified.

/**
 * Poll the next message and manage it.
 * Returns TRUE if the loop might continue or FALSE it the loop should
 * pause a bit.
 */
static gboolean
_q_manage_message(struct _queue_with_endpoint_s *q, struct _running_ctx_s *ctx)
{
	EXTRA_ASSERT(ctx->rabbitmq != NULL && ctx->rabbitmq->conn != NULL);

	gboolean rc = TRUE;
	gchar* msg = g_async_queue_timeout_pop(q->queue, 200 * G_TIME_SPAN_MILLISECOND);
	if (!msg) goto exit;
	if (!*msg) goto exit;

	/* forward the event as a RabbitMQ message */
	const size_t msglen = strlen(msg);
	gint64 start = oio_ext_monotonic_time();
	GError *err = rabbitmq_send_msg(ctx->rabbitmq, msg, msglen, q->routing_key);
	gint64 end = oio_ext_monotonic_time();
	time_t end_seconds = end / G_TIME_SPAN_SECOND;
	/* count the operation whether it's a success or a failure */
	grid_single_rrd_add(q->event_send_count, end_seconds, 1);
	grid_single_rrd_add(q->event_send_time, end_seconds, end - start);
#ifdef HAVE_EXTRA_DEBUG
	if (intercept_errors)
		(*intercept_errors) (err);
#endif
	if (!err) {
		ctx->attempts_put = 0;
	} else {
		if (CODE_IS_RETRY(err->code) || CODE_IS_NETWORK_ERROR(err->code)) {
			GRID_NOTICE("RabbitMQ recoverable error with [%s]: (%d) %s",
					q->endpoint, err->code, err->message);
			g_async_queue_push_front(q->queue, msg);
			msg = NULL;
			ctx->attempts_put += 1;
			rc = FALSE;
		} else {
			GRID_WARN("RabbitMQ unrecoverable error with [%s]: (%d) %s",
					q->endpoint, err->code, err->message);
			_event_dropped(msg, msglen);
			ctx->attempts_put = 0;
		}
		g_clear_error(&err);
	}

exit:
	oio_str_clean(&msg);
	return rc;
}

/**
 * Do a pseudo-periodic check of the backend.
 * A STAT command is sent when a delay (since the last command) is reached.
 */
static gboolean
_q_maybe_check(struct _queue_with_endpoint_s *q, struct _running_ctx_s *ctx)
{
	EXTRA_ASSERT(ctx->rabbitmq != NULL && ctx->rabbitmq->conn != NULL);

	if (oio_events_beanstalkd_check_period <= 0 ||
			ctx->last_check >= OLDEST(ctx->now, oio_events_beanstalkd_check_period))
		return TRUE;

	struct rabbitmq_queue_stats_s stats;
	GError *err = rabbitmq_get_stats(ctx->rabbitmq, q->queue_name, &stats);
#ifdef HAVE_EXTRA_DEBUG
	if (intercept_errors)
		(*intercept_errors) (err);
#endif
	if (err)
		goto exit;

	q->pending_events = stats.message_count;

	const gint64 max_jobs = oio_events_beanstalkd_check_level_deny;
	if (max_jobs > 0 && q->pending_events > max_jobs) {
		err = BUSY("FULL (current=%" G_GINT64_FORMAT
				" > limit=%" G_GINT64_FORMAT ")",
				q->pending_events, max_jobs);
		goto exit;
	}

	const gint64 alert = oio_events_beanstalkd_check_level_alert;
	if (alert > 0 && q->pending_events > alert) {
		GRID_WARN("RabbitMQ load alert (current=%" G_GINT64_FORMAT
				" > limit=%" G_GINT64_FORMAT ", queue=%s)",
				q->pending_events, alert, q->queue_name);
	}

exit:
	if (err) {
		GRID_WARN("RabbitMQ error with [%s]: (%d) %s",
				q->endpoint, err->code, err->message);
		g_clear_error(&err);

		ctx->attempts_check += 1;
		q->healthy = FALSE;
		// maybe the rabbit is down, force reconnection next time
		amqp_destroy_connection(ctx->rabbitmq->conn);
		ctx->rabbitmq->conn = NULL;

		return FALSE;
	} else {
		ctx->last_check = ctx->now;
		if (ctx->attempts_check > 0) {
			// queue is working again!
			ctx->attempts_check = 0;
			q->healthy = TRUE;
		}
		return TRUE;
	}
}

static GError *
_q_run(struct _queue_with_endpoint_s *q)
{
	GError *err = NULL;
	struct _running_ctx_s ctx = {0};
	err = rabbitmq_create(
			q->endpoint, q->exchange_name, q->username, q->password,
			(const gchar **)q->extra_args, &(ctx.rabbitmq));
	if (err)
		return err;

	/* Try to declare the RabbitMQ exchange. It is not that bad if we can't,
	 * we will just buffer events until someone else declares it. */
	_q_declare_exchange_and_queue(q, &ctx);

	/* Loop until the (asked) end or until there is no event */
	while (_q_is_running(q)) {
		ctx.now = oio_ext_monotonic_time();

		/* Maybe do a periodic flush of buffered/delayed events. */
		if (ctx.now - ctx.last_flush > q->buffer.delay / 10) {
			ctx.last_flush = ctx.now;
			_q_flush_buffered(q, FALSE);
		}

		if (!_q_reconnect(q, &ctx)) {
			EXPO_BACKOFF(100 * G_TIME_SPAN_MILLISECOND, ctx.attempts_connect, 5);
			continue;
		}

		if (!_q_maybe_check(q, &ctx)) {
			EXPO_BACKOFF(100 * G_TIME_SPAN_MILLISECOND, ctx.attempts_check, 5);
			continue;
		}

		if (!_q_manage_message(q, &ctx)) {
			EXPO_BACKOFF(100 * G_TIME_SPAN_MILLISECOND, ctx.attempts_put, 5);
		}
	}

	/* Exit phase */
	const gint64 deadline_exit = oio_ext_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
	while (!_q_is_empty(q)) {
		ctx.now = oio_ext_monotonic_time();
		GRID_WARN("exiting...");

		/* The exit phase doesn't last forever */
		if (ctx.now > deadline_exit)
			break;

		_q_flush_buffered(q, TRUE);

		if (!_q_reconnect(q, &ctx)) {
			g_usleep(100 * G_TIME_SPAN_MILLISECOND);
			continue;
		}

		if (!_q_manage_message(q, &ctx)) {
			g_usleep(100 * G_TIME_SPAN_MILLISECOND);
		}
	}

	_q_flush_pending(q);

	/* close the socket to the RabbitMQ broker */
	rabbitmq_destroy(ctx.rabbitmq);

	return NULL;
}

static gpointer
_q_worker(gpointer p)
{
	metautils_ignore_signals();
	GError *err = _q_run((struct _queue_with_endpoint_s*)p);
	if (err) {
		GRID_WARN("Events queue run error: (%d) %s", err->code, err->message);
		g_clear_error(&err);
	}
	return p;
}

static GError *
_q_start (struct oio_events_queue_s *self)
{
	struct _queue_with_endpoint_s *q = (struct _queue_with_endpoint_s*) self;
	g_assert_nonnull(q);
	g_assert(q->vtable == &vtable_RABBITMQ);
	g_assert_null(q->worker);

	GError *err = NULL;

	q->running = TRUE;
	q->healthy = TRUE;
	q->worker = g_thread_try_new("event|rabbitmq", _q_worker, q, &err);
	if (!q->worker) {
		GRID_WARN("%s worker startup error: (%d) %s", __FUNCTION__,
				err ? err->code : 0, err ? err->message : "");
	}
	return err;
}
