/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqliterepo_variables.h>
#include <sqliterepo/sqliterepo_remote_variables.h>

#include "gridd_client_pool.h"

#define MAX_ROUND 32

struct gridd_client_pool_s
{
	struct gridd_client_pool_vtable_s *vtable;
	struct event_client_s **active_clients;
	GAsyncQueue *pending_clients;

	gint64 last_timeout_check;

	int fdmon;
	/* notifications */
	int efd; /*!< event file descriptor */

	guint active_clients_size;
	guint active_clients_max;
	guint active_count;

	/* if set to any non-zero value, new requests are not started */
	int closed;
};

static void _destroy (struct gridd_client_pool_s *p);

static void _defer (struct gridd_client_pool_s *p, struct event_client_s *ev);

static GError* _round (struct gridd_client_pool_s *p, time_t sec);

static void _reconfigure (struct gridd_client_pool_s *p);

static struct gridd_client_pool_vtable_s VTABLE =
{
	_destroy,
	_defer,
	_round,
	_reconfigure
};

struct gridd_client_pool_s *
gridd_client_pool_create(void)
{
	int fdmon, efd;
	struct gridd_client_pool_s *pool;

	if ((efd = eventfd(0, EFD_NONBLOCK)) < 0) {
		GRID_WARN("eventfd() error: (%d) %s", errno, strerror(errno));
		metautils_pclose(&efd);
		return NULL;
	}

	if ((fdmon = epoll_create(64)) < 0) {
		GRID_WARN("epoll_create error: (%d) %s", errno, strerror(errno));
		metautils_pclose(&efd);
		return NULL;
	}

	const guint maxfd = metautils_syscall_count_maxfd();

	pool = g_malloc0(sizeof(*pool));
	pool->pending_clients = g_async_queue_new();

	pool->fdmon = fdmon;
	pool->active_clients_size = maxfd;
	pool->active_clients_max = maxfd;
	pool->active_clients = g_malloc0(pool->active_clients_size
			* sizeof(struct event_client_s*));

	pool->efd = efd;
	efd = -1;

	/* then monitors at least the notifications pipe's output */
	struct epoll_event ev = {0};
	ev.events = EPOLLIN;
	ev.data.fd = pool->efd;
	if (epoll_ctl(pool->fdmon, EPOLL_CTL_ADD, pool->efd, &ev) < 0) {
		GRID_ERROR("epoll error: (%d) %s", errno, strerror(errno));
		gridd_client_pool_destroy(pool);
		return NULL;
	}

	pool->vtable = &VTABLE;

	_reconfigure(pool);
	return pool;
}

/* ------------------------------------------------------------------------- */

static void
eventfd_consume(int fd)
{
	guint64 event_count = 0u;
	int rc = metautils_syscall_read(fd, &event_count, 8);
	if (rc < 0 && errno != EAGAIN) {  // EAGAIN -> counter is 0
		GRID_WARN("Failed to read deferred requests counter: (%d) %s",
				errno, strerror(errno));
	} else if (event_count > 100u) {
		GRID_NOTICE("Possible election storm, %"G_GUINT64_FORMAT
				" new deferred requests to execute", event_count);
	} else if (GRID_DEBUG_ENABLED()) {
		GRID_DEBUG("%"G_GUINT64_FORMAT" new deferred requests to execute",
				event_count);
	}
}

static int
event_client_monitor(struct gridd_client_pool_s *pool, struct event_client_s *mc)
{
	int fd, rc, interest;
	struct epoll_event ev = {0};

	EXTRA_ASSERT(pool != NULL);
	EXTRA_ASSERT(mc != NULL);
	EXTRA_ASSERT(mc->client != NULL);

	interest = gridd_client_interest(mc->client);
	if (interest & CLIENT_RD)
		ev.events |= EPOLLIN;
	if (interest & CLIENT_WR)
		ev.events |= EPOLLOUT;
	EXTRA_ASSERT(ev.events != 0);
	ev.events |= (EPOLLHUP|EPOLLERR|EPOLLONESHOT);

	ev.data.fd = fd = gridd_client_fd(mc->client);
	EXTRA_ASSERT(fd >= 0);

	rc = epoll_ctl(pool->fdmon, EPOLL_CTL_ADD, fd, &ev);
	if (rc < 0) {
		pool->active_clients[fd] = NULL;
		GRID_WARN("MONITOR error: (%d) %s", errno, strerror(errno));
		return 0;
	}

	pool->active_count ++;
	pool->active_clients[fd] = mc;
	return 1;
}

void
event_client_free(struct event_client_s *ec)
{
	if (!ec)
		return;
	if (ec->on_end)
		ec->on_end(ec);
	if (ec->client)
		gridd_client_free(ec->client);
	g_free (ec);
}

static void
_destroy(struct gridd_client_pool_s *pool)
{
	if (!pool)
		return;
	EXTRA_ASSERT(pool->vtable == &VTABLE);

	pool->closed = ~0;

	if (pool->efd >= 0)
		metautils_pclose(&(pool->efd));
	if (pool->fdmon >= 0)
		metautils_pclose(&(pool->fdmon));

	if (pool->pending_clients) {
		struct event_client_s *ec;
		while (NULL != (ec = g_async_queue_try_pop(pool->pending_clients)))
			event_client_free(ec);
		g_async_queue_unref(pool->pending_clients);
		pool->pending_clients = NULL;
	}

	if (pool->active_clients) {
		for (guint i=0; i<pool->active_clients_size ;i++) {
			struct event_client_s *ec = pool->active_clients[i];
			pool->active_clients[i] = NULL;
			if (ec)
				event_client_free(ec);
		}
		g_free(pool->active_clients);
		pool->active_clients = NULL;
	}

	g_free(pool);
}

static void
_pool_unmonitor(struct gridd_client_pool_s *pool, int fd)
{
	if (pool->fdmon >= 0)
		(void) epoll_ctl(pool->fdmon, EPOLL_CTL_DEL, fd, NULL);
	EXTRA_ASSERT(pool->active_count > 0);
	-- pool->active_count;
	pool->active_clients[fd] = NULL;
}

static void
_manage_timeouts(struct gridd_client_pool_s *pool)
{
	if (pool->active_count <= 0)
		return;

	gint64 now = oio_ext_monotonic_time ();
	if (now - pool->last_timeout_check < oio_sqlx_timeout_check_period)
		return;
	pool->last_timeout_check = now;

	for (guint i=0; i<pool->active_clients_size ;i++) {
		struct event_client_s *ec;
		if (!(ec = pool->active_clients[i]))
			continue;

		EXTRA_ASSERT(ec->client != NULL);
		EXTRA_ASSERT((int)i == gridd_client_fd(ec->client));

		if (gridd_client_expire (ec->client, now)) {
			GRID_INFO("EXPIRED Client fd=%d [%s]", i, gridd_client_url(ec->client));
			_pool_unmonitor(pool, i);
			event_client_free(ec);
		}
	}

	gint64 elapsed = oio_ext_monotonic_time () - now;
	if (elapsed > oio_sqlx_timeout_check_max) {
		GRID_WARN("Client pool timeout check took %"G_GINT64_FORMAT" ms",
				elapsed / G_TIME_SPAN_MILLISECOND);
	} else {
		GRID_DEBUG("Client pool timeout check took %"G_GINT64_FORMAT" ms",
				elapsed / G_TIME_SPAN_MILLISECOND);
	}
}

static void
_manage_requests(struct gridd_client_pool_s *pool)
{
	struct event_client_s *ec = NULL;
	guint count_dropped = 0;

	EXTRA_ASSERT(pool != NULL);

	gint64 start = oio_ext_monotonic_time();
	while (pool->active_count < pool->active_clients_max) {
		ec = g_async_queue_try_pop(pool->pending_clients);
		if (NULL == ec)
			break;
		EXTRA_ASSERT(ec->client != NULL);

#ifdef HAVE_ENBUG
		if (oio_sqlx_request_failure_threshold >= oio_ext_rand_int_range(1,100))
			ec->deadline_start = 0;
#endif
		if (start > ec->deadline_start) {
			count_dropped ++;
			gridd_client_fail(ec->client,
					NEWERROR(CODE_AVOIDED, "Queued for too long"));
			event_client_free(ec);
			continue;
		}

		if (!gridd_client_start(ec->client)) {
			GError *err = gridd_client_error(ec->client);
			if (NULL != err) {
				GRID_WARN("STARTUP Client fd=%d [%s]: (%d) %s",
						gridd_client_fd(ec->client), gridd_client_url(ec->client),
						err->code, err->message);
				g_clear_error(&err);
			} else {
				GRID_WARN("STARTUP Client fd=%d [%s]: already started",
						gridd_client_fd(ec->client), gridd_client_url(ec->client));
				EXTRA_ASSERT(err != NULL);
			}
			event_client_free(ec);
		} else if (!event_client_monitor(pool, ec)) {
			event_client_free(ec);
		}
	}

	if (count_dropped > 0)
		GRID_WARN("%u syncing RPC dropped (queued for too long)", count_dropped);

	gint64 elapsed = oio_ext_monotonic_time() - start;
	if (elapsed > 5 * G_TIME_SPAN_SECOND) {
		GRID_INFO("Client pool request management took %"G_GINT64_FORMAT"s, "
				"this is a bit too much",
				elapsed / G_TIME_SPAN_SECOND);
		gint qlen = g_async_queue_length(pool->pending_clients);
		if (qlen > (gint)pool->active_clients_max)
			GRID_WARN("Client pool still has %d pending requests, "
					"are we under an election storm?", qlen);
	}
}

static void
_manage_one_event(struct gridd_client_pool_s *pool, int fd, int evt)
{
	struct event_client_s *ec = pool->active_clients[fd];

	_pool_unmonitor(pool, fd);

	EXTRA_ASSERT(ec != NULL);
	EXTRA_ASSERT(ec->client != NULL);
	EXTRA_ASSERT(fd == gridd_client_fd(ec->client));

	if ((evt & EPOLLERR) || (evt & EPOLLHUP)) {
		GRID_DEBUG("%s CLIENT [%s] fd=%d cnx error", __FUNCTION__,
				gridd_client_url(ec->client), gridd_client_fd(ec->client));
		event_client_free(ec);
	}
	else {
		/* TODO check here how long it took with that election */
		gridd_client_react(ec->client);

		if (gridd_client_finished(ec->client))
			event_client_free(ec);
		else if (!event_client_monitor(pool, ec))
			event_client_free(ec);
	}
}

static void
_manage_all_events(struct gridd_client_pool_s *pool,
		struct epoll_event *ev, int maxevt)
{
	for (int i = 0; i < maxevt; ++i) {
		if (ev[i].data.fd == pool->efd)
			eventfd_consume(pool->efd);
		else
			_manage_one_event(pool, ev[i].data.fd, ev[i].events);
	}
}

static void
_reconfigure(struct gridd_client_pool_s *pool)
{
	EXTRA_ASSERT(pool != NULL);
	EXTRA_ASSERT(pool->vtable == &VTABLE);
	if (sqliterepo_fd_max_active <= 0) {
		pool->active_clients_max = pool->active_clients_size;
	} else {
		pool->active_clients_max =
			CLAMP(sqliterepo_fd_max_active, 1, pool->active_clients_size);
	}
}

static GError *
_round(struct gridd_client_pool_s *pool, time_t sec)
{
	EXTRA_ASSERT(pool != NULL);
	EXTRA_ASSERT(pool->vtable == &VTABLE);
	EXTRA_ASSERT(pool->fdmon >= 0);
	g_assert(sqliterepo_fd_max_active > 0);

	struct epoll_event ev[MAX_ROUND];
	int rc = epoll_wait(pool->fdmon, ev, MAX_ROUND, sec * 1000L);

	if (rc < 0 && errno != EINTR)
		return NEWERROR(errno, "epoll_wait error: %s", strerror(errno));

	if (rc > 0)
		_manage_all_events(pool, ev, rc);
	_manage_timeouts(pool);
	_manage_requests(pool);
	return NULL;
}

static void
_defer(struct gridd_client_pool_s *pool, struct event_client_s *ev)
{
	EXTRA_ASSERT(pool != NULL);
	EXTRA_ASSERT(pool->vtable == &VTABLE);
	EXTRA_ASSERT(ev != NULL);
	EXTRA_ASSERT(pool->pending_clients != NULL);
	EXTRA_ASSERT(pool->efd >= 0);

	if (pool->closed) {
		GRID_INFO("Request dropped");
		event_client_free(ev);
	} else {
		gint64 now = oio_ext_monotonic_time();
		ev->deadline_start = now + 4 * G_TIME_SPAN_SECOND;
		/* eventfd requires 8-byte integer */
		guint64 c = 1u;
		g_async_queue_push(pool->pending_clients, ev);
		int rc = metautils_syscall_write(pool->efd, &c, 8);
		if (unlikely(rc < 0)) {
			GRID_WARN("Failed to signal new deferred requests: (%d) %s",
					errno, strerror(errno));
		}
	}
}

