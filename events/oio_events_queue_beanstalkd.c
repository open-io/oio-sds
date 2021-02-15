/*
OpenIO SDS event queue
Copyright (C) 2016-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021 OVH SAS

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
#include <math.h>

#include <core/oio_core.h>
#include <events/events_variables.h>

#include "beanstalkd.h"
#include "oio_events_queue.h"
#include "oio_events_queue_internals.h"
#include "oio_events_queue_beanstalkd.h"
#include "oio_events_queue_buffer.h"

#define EXPO_BACKOFF(DELAY,TRY,MAX_TRIES) \
	g_usleep((1 << MIN(TRY, MAX_TRIES)) * DELAY); \
	TRY++

static void _q_destroy (struct oio_events_queue_s *self);
static void _q_send (struct oio_events_queue_s *self, gchar *msg);
static void _q_send_overwritable(struct oio_events_queue_s *self, gchar *key, gchar *msg);
static gboolean _q_is_stalled (struct oio_events_queue_s *self);
static gint64 _q_get_health(struct oio_events_queue_s *self);
static void _q_set_buffering (struct oio_events_queue_s *self, gint64 v);
static GError * _q_start (struct oio_events_queue_s *self);

static struct oio_events_queue_vtable_s vtable_BEANSTALKD =
{
	.destroy = _q_destroy,
	.send = _q_send,
	.send_overwritable = _q_send_overwritable,
	.is_stalled = _q_is_stalled,
	.get_health = _q_get_health,
	.set_buffering = _q_set_buffering,
	.start = _q_start
};

struct _queue_BEANSTALKD_s
{
	struct oio_events_queue_vtable_s *vtable;
	GAsyncQueue *queue;
	GThread *worker;

	gchar *endpoint;
	gchar *tube;
	gint64 pending_events;

	volatile gboolean running;

	struct oio_events_queue_buffer_s buffer;
};

#ifdef HAVE_EXTRA_DEBUG
/* Used by tests to intercept the result of the parsing of beanstalkd
 * replies */
typedef void (*_queue_BEANSTALKD_intercept_error_f) (GError *err);

/* Used by tests to intercept the checks for completion */
typedef gboolean (*_queue_BEANSTALKD_intercept_running_f) (
		struct _queue_BEANSTALKD_s *q);

static _queue_BEANSTALKD_intercept_error_f intercept_errors = NULL;

static _queue_BEANSTALKD_intercept_running_f intercept_running = NULL;
#endif

/* -------------------------------------------------------------------------- */

static gboolean
_q_is_empty(struct _queue_BEANSTALKD_s *q)
{
	return oio_events_queue_buffer_is_empty(&q->buffer)
		&& 0 >= g_async_queue_length(q->queue);
}

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

	struct _queue_BEANSTALKD_s *self = g_malloc0 (sizeof(*self));
	self->vtable = &vtable_BEANSTALKD;
	self->queue = g_async_queue_new ();
	self->tube = g_strdup(tube);
	self->endpoint = g_strdup (endpoint);
	self->running = FALSE;

	oio_events_queue_buffer_init(&(self->buffer));

	*out = (struct oio_events_queue_s*) self;
	return NULL;
}

static void
_q_set_buffering(struct oio_events_queue_s *self, gint64 v)
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s *)self;
	if (q->buffer.delay != v) {
		GRID_INFO("events buffering delay set to %"G_GINT64_FORMAT"s",
				v / G_TIME_SPAN_SECOND);
		oio_events_queue_buffer_set_delay(&(q->buffer), v);
	}
}

static void
_flush_buffered(struct _queue_BEANSTALKD_s *q, gboolean total)
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

static gboolean
_is_running(struct _queue_BEANSTALKD_s *q)
{
#ifdef HAVE_EXTRA_DEBUG
	if (NULL != intercept_running) {
		return (*intercept_running)(q);
	}
#endif
	return q->running;
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
_q_reconnect(struct _queue_BEANSTALKD_s *q UNUSED, struct _running_ctx_s *ctx)
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

static void
_event_dropped(const char *msg, const size_t msglen)
{
	GRID_NOTICE("Dropped %d bytes event: %.*s",
			(int)msglen, (int)MIN(msglen,2048), msg);
}

/**
 * Poll the next messge and manage it.
 * Returns TRUE if the loop might continue or FALSE it the loop should
 * pause a bit.
 */
static gboolean
_q_manage_message(struct _queue_BEANSTALKD_s *q, struct _running_ctx_s *ctx)
{
	EXTRA_ASSERT(ctx->beanstalkd != NULL && ctx->beanstalkd->fd >= 0);

	gboolean rc = TRUE;
	gchar* msg = g_async_queue_timeout_pop (q->queue, 200 * G_TIME_SPAN_MILLISECOND);
	if (!msg) goto exit;
	if (!*msg) goto exit;

	/* forward the event as a beanstalkd job */
	const size_t msglen = strlen(msg);
	GError *err = beanstalkd_put_job(ctx->beanstalkd, msg, msglen);
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
 * Drain the queue of pending events.
 * In addition, print a warning that some events have been lost.
 */
static void
_q_flush_pending(struct _queue_BEANSTALKD_s *q)
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

/**
 * Do a pseudo-periodic check of the backend.
 * A STAT command is sent when a delay (since the last command) is reached.
 */
static gboolean
_q_maybe_check(struct _queue_BEANSTALKD_s *q, struct _running_ctx_s *ctx)
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
_q_run (struct _queue_BEANSTALKD_s *q)
{
	struct _running_ctx_s ctx = {0};
	beanstalkd_factory(q->endpoint, q->tube, &(ctx.beanstalkd));

	/* Loop until the (asked) end or until there is no event */
	while (_is_running(q)) {
		ctx.now = oio_ext_monotonic_time();

		/* Maybe do a periodic flush of buffered/delayed events. */
		if (ctx.now - ctx.last_flush > q->buffer.delay / 10) {
			ctx.last_flush = ctx.now;
			_flush_buffered(q, FALSE);
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

		_flush_buffered(q, TRUE);

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
	GError *err = _q_run((struct _queue_BEANSTALKD_s*)p);
	if (err) {
		GRID_WARN("Events queue run error: (%d) %s", err->code, err->message);
		g_clear_error(&err);
	}
	return p;
}

static GError *
_q_start (struct oio_events_queue_s *self)
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s*) self;
	g_assert_nonnull(q);
	g_assert(q->vtable == &vtable_BEANSTALKD);
	g_assert_null(q->worker);

	GError *err = NULL;

	q->running = TRUE;
	q->worker = g_thread_try_new("event|beanstalk", _q_worker, q, &err);
	if (!q->worker) {
		GRID_WARN("%s worker startup error: (%d) %s", __FUNCTION__,
				err ? err->code : 0, err ? err->message : "");
	}
	return err;
}

static void
_q_destroy (struct oio_events_queue_s *self)
{
	if (!self) return;

	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s*) self;
	g_assert(q->vtable == &vtable_BEANSTALKD);

	q->running = FALSE;

	if (q->worker) {
		g_thread_join(q->worker);
		q->worker = NULL;
	}

	g_async_queue_unref (q->queue);
	oio_str_clean (&q->endpoint);
	oio_str_clean (&q->tube);
	oio_events_queue_buffer_clean(&(q->buffer));

	q->vtable = NULL;
	g_free (q);
}

static void
_q_send (struct oio_events_queue_s *self, gchar *msg)
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s*) self;
	EXTRA_ASSERT (q != NULL && q->vtable == &vtable_BEANSTALKD);
	g_async_queue_push (q->queue, msg);
}

static void
_q_send_overwritable(struct oio_events_queue_s *self, gchar *key, gchar *msg)
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s*) self;
	oio_events_queue_buffer_put(&(q->buffer), key, msg);
}

static gboolean
_q_is_stalled (struct oio_events_queue_s *self)
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s*) self;
	EXTRA_ASSERT (q != NULL && q->vtable == &vtable_BEANSTALKD);
	const int l = g_async_queue_length (q->queue);
	if (l <= 0)
		return FALSE;
	return ((guint)l) >= oio_events_common_max_pending;
}

static gint64
_q_get_health(struct oio_events_queue_s *self)
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s*) self;
	EXTRA_ASSERT(q != NULL && q->vtable == &vtable_BEANSTALKD);

	gint64 res = (gint64) (100.0 / (1.0 + log(1.0 + q->pending_events * 0.1)));
	return MIN(SCORE_MAX, res);
}

