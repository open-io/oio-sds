/*
OpenIO SDS event queue
Copyright (C) 2016-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2023 OVH SAS

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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <glib.h>

#include <core/oio_core.h>
#include <events/events_variables.h>

#include "beanstalkd.h"
#include "oio_events_queue.h"
#include "oio_events_queue_internals.h"
#include "oio_events_queue_beanstalkd.h"
#include "oio_events_queue_buffer.h"
#include "oio_events_queue_shared.h"


static GError * _q_start (struct oio_events_queue_s *self);

static struct oio_events_queue_vtable_s vtable_BEANSTALKD =
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

/* -------------------------------------------------------------------------- */

GError *
oio_events_queue_factory__create_beanstalkd (
		const char *endpoint, const char *tube,
		struct oio_events_queue_s **out)
{
	EXTRA_ASSERT(endpoint != NULL);
	EXTRA_ASSERT(tube != NULL);
	EXTRA_ASSERT(out != NULL);
	*out = NULL;

	if (!metautils_url_valid_for_connect (endpoint))
		return BADREQ("Invalid beanstalkd endpoint [%s]", endpoint);

	struct _queue_with_endpoint_s *self = g_malloc0 (sizeof(*self));
	self->vtable = &vtable_BEANSTALKD;
	self->queue = g_async_queue_new ();
	self->queue_name = g_strdup(tube);
	self->endpoint = g_strdup (endpoint);
	self->running = FALSE;
	self->healthy = FALSE;

	oio_events_queue_buffer_init(&(self->buffer));
	self->event_send_count = grid_single_rrd_create(
			oio_ext_monotonic_seconds(), OIO_EVENTS_STATS_HISTORY_SECONDS);
	self->event_send_time = grid_single_rrd_create(
			oio_ext_monotonic_seconds(), OIO_EVENTS_STATS_HISTORY_SECONDS);

	*out = (struct oio_events_queue_s*) self;
	return NULL;
}


struct _running_ctx_s {
	gint64 last_flush;
	gint64 last_check;
	gint64 now;
	guint attempts_connect;
	guint attempts_check;
	guint attempts_put;
	struct beanstalkd_s *beanstalkd;
};

static gboolean
_q_reconnect(struct _queue_with_endpoint_s *q UNUSED, struct _running_ctx_s *ctx)
{
	EXTRA_ASSERT(ctx->beanstalkd != NULL);

	if (ctx->beanstalkd->fd >= 0)
		return TRUE;

	GError *err = beanstalkd_reconnect(ctx->beanstalkd);
#ifdef HAVE_EXTRA_DEBUG
	if (intercept_errors)
		(*intercept_errors) (err);
#endif
	if (err) {
		g_clear_error(&err);
		ctx->attempts_connect += 1;
		return FALSE;
	} else {
		ctx->attempts_connect = 0;
		return TRUE;
	}
}


/**
 * Poll the next message and manage it.
 * Returns TRUE if the loop might continue or FALSE it the loop should
 * pause a bit.
 */
static gboolean
_q_manage_message(struct _queue_with_endpoint_s *q, struct _running_ctx_s *ctx)
{
	EXTRA_ASSERT(ctx->beanstalkd != NULL && ctx->beanstalkd->fd >= 0);

	gboolean rc = TRUE;
	gchar* msg = g_async_queue_timeout_pop (q->queue, 200 * G_TIME_SPAN_MILLISECOND);
	if (!msg) goto exit;
	if (!*msg) goto exit;

	/* forward the event as a beanstalkd job */
	const size_t msglen = strlen(msg);
	gint64 start = oio_ext_monotonic_time();
	GError *err = beanstalkd_put_job(ctx->beanstalkd, msg, msglen);
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
			GRID_NOTICE("Beanstalkd recoverable error with [%s]: (%d) %s",
					q->endpoint, err->code, err->message);
			g_async_queue_push_front(q->queue, msg);
			msg = NULL;
			ctx->attempts_put += 1;
			rc = FALSE;
		} else {
			GRID_WARN("Beanstalkd unrecoverable error with [%s]: (%d) %s",
					q->endpoint, err->code, err->message);
			_event_dropped(msg, msglen);
			ctx->attempts_put = 0;
		}
		g_clear_error (&err);
	}

exit:
	oio_str_clean (&msg);
	return rc;
}

/**
 * Do a pseudo-periodic check of the backend.
 * A STAT command is sent when a delay (since the last command) is reached.
 */
static gboolean
_q_maybe_check(struct _queue_with_endpoint_s *q, struct _running_ctx_s *ctx)
{
	EXTRA_ASSERT(ctx->beanstalkd != NULL && ctx->beanstalkd->fd >= 0);

	if (oio_events_beanstalkd_check_period <= 0 ||
			ctx->last_check >= OLDEST(ctx->now, oio_events_beanstalkd_check_period))
		return TRUE;

	gchar **lines = NULL;
	GError *err = beanstalkd_get_stats(ctx->beanstalkd, &lines);
#ifdef HAVE_EXTRA_DEBUG
	if (intercept_errors)
		(*intercept_errors) (err);
#endif
	if (err)
		goto exit;

	gint64 total = 0;
	if (lines) {
		for (gchar **pline = lines; *pline ;++pline) {
			gchar *line = *pline;
			gint64 count = 0;
			if (!g_str_has_prefix(line, "current-jobs-"))
				continue;
			if (!(line = strchr(line, ':')))
				continue;
			if (!oio_str_is_number(g_strchug(line+1), &count))
				continue;
			total += count;
		}
		g_strfreev(lines);
	}

	q->pending_events = total;

	const gint64 max_jobs = oio_events_beanstalkd_check_level_deny;
	if (max_jobs > 0 && total > max_jobs) {
		err = BUSY("FULL (current=%" G_GINT64_FORMAT
				" > limit=%" G_GINT64_FORMAT ")", total, max_jobs);
		goto exit;
	}

	const gint64 alert = oio_events_beanstalkd_check_level_alert;
	if (alert > 0 && total > alert) {
		GRID_WARN("Beanstalkd load alert (current=%" G_GINT64_FORMAT
				" > limit=%" G_GINT64_FORMAT ")", total, alert);
	}

exit:
	if (err) {
		GRID_WARN("Beanstalkd error with [%s]: (%d) %s",
				q->endpoint, err->code, err->message);
		g_clear_error(&err);
		ctx->attempts_check += 1;
		return FALSE;
	} else {
		ctx->last_check = ctx->now;
		ctx->attempts_check = 0;
		return TRUE;
	}
}

static GError *
_q_run (struct _queue_with_endpoint_s *q)
{
	struct _running_ctx_s ctx = {0};
	beanstalkd_create(q->endpoint, q->queue_name, &(ctx.beanstalkd));

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

	/* close the socket to the beanstalkd */
	beanstalkd_destroy(ctx.beanstalkd);

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
	g_assert(q->vtable == &vtable_BEANSTALKD);
	g_assert_null(q->worker);

	GError *err = NULL;

	q->running = TRUE;
	q->healthy = TRUE;
	q->worker = g_thread_try_new("event|beanstalk", _q_worker, q, &err);
	if (!q->worker) {
		GRID_WARN("%s worker startup error: (%d) %s", __FUNCTION__,
				err ? err->code : 0, err ? err->message : "");
	}
	return err;
}

