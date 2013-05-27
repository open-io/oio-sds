/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.sqlx.clients"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/resource.h>

#include <glib.h>

#include "../metautils/lib/metatypes.h"
#include "../metautils/lib/metautils.h"
#include "../metautils/lib/metacomm.h"

#include "./internals.h"
#include "./gridd_client.h"
#include "./client_pool.h"

#define MAX_ROUND 32

static GQuark gquark_log = 0;

static int event_client_monitor(struct client_pool_s *pool, int first,
		struct event_client_s *mc);

static void
fd_consume_input(int fd)
{
	guint8 data[2048];
	SQLX_ASSERT(fd > 0);
	while (0 <= read(fd, data, sizeof(data))) {}
}

static void
client_pool_trace(const gchar *event, struct client_pool_s *pool)
{
	GRID_TRACE("POOL [%d/%d fd=%d] (%s)", pool->active_count,
			pool->active_max, pool->fdmon, event);
}

static int
event_client_monitor(struct client_pool_s *pool, int first,
		struct event_client_s *mc)
{
	int fd, rc, interest;
	struct epoll_event ev;

	SQLX_ASSERT(pool != NULL);
	SQLX_ASSERT(mc != NULL);
	SQLX_ASSERT(mc->client != NULL);

	ev.data.ptr = NULL;
	ev.events = 0;
	interest = gridd_client_interest(mc->client);

	if (interest & CLIENT_RD)
		ev.events |= EPOLLIN;
	if (interest & CLIENT_WR)
		ev.events |= EPOLLOUT;
	
	SQLX_ASSERT(ev.events != 0);
	ev.events |= (EPOLLHUP|EPOLLERR|EPOLLONESHOT);

	ev.data.fd = fd = gridd_client_fd(mc->client);
	SQLX_ASSERT(fd >= 0);

	rc = epoll_ctl(pool->fdmon, first?EPOLL_CTL_ADD:EPOLL_CTL_MOD, fd, &ev);
	GRID_TRACE("MONITOR fd=%d rc=%d", fd, rc);

	if (rc < 0) {
		pool->active_clients[fd] = NULL;
		GRID_WARN("MONITOR error: (%d) %s", errno, strerror(errno));
		return 0;
	}
	else {
		pool->active_count ++;
		pool->active_clients[fd] = mc;
		client_pool_trace("NEW CLIENT", pool);
		return 1;
	}
}

static void
event_client_free(struct event_client_s *ec)
{
	/*GRID_TRACE2("%s(%p)", __FUNCTION__, ec);*/

	if (!ec)
		return;

	if (ec->on_end)
		ec->on_end(ec);

	if (ec->client)
		gridd_client_free(ec->client);

	memset(ec, 0, sizeof(*ec));
	g_free(ec);
}

static void
_client_queue_empty(GQueue **q)
{
	if (!q || !*q)
		return;

	struct event_client_s *ec;
	while (NULL != (ec = g_queue_pop_head(*q)))
		event_client_free(ec);

	g_queue_free(*q);
	*q = NULL;
	q = NULL;
}

void
client_pool_destroy(struct client_pool_s *pool)
{
	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	if (!pool)
		return;

	pool->closed = ~0;

	if (pool->fd_in >= 0)
		close(pool->fd_in);
	if (pool->fd_out >= 0)
		close(pool->fd_out);
	if (pool->fdmon >= 0)
		close(pool->fdmon);

	if (pool->notifications)
		_client_queue_empty(&(pool->notifications));

	if (pool->pending_clients)
		_client_queue_empty(&(pool->pending_clients));

	if (pool->active_clients) {
		for (guint i=0; i<pool->active_clients_size ;i++) {
			struct event_client_s *ec = pool->active_clients[i];
			if (ec)
				event_client_free(ec);
			pool->active_clients[i] = NULL;
		}
		g_free(pool->active_clients);
	}

	if (pool->lock) {
		g_mutex_lock(pool->lock);
		g_mutex_unlock(pool->lock);
		g_mutex_free(pool->lock);
	}

	memset(pool, 0, sizeof(*pool));
	pool->fdmon = -1;
	pool->fd_in = -1;
	pool->fd_out = -1;

	g_free(pool);
}

struct client_pool_s *
client_pool_create(guint max)
{
	int fdmon, fd[2];
	struct client_pool_s *pool;

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	if (0 != pipe(fd)) {
		GRID_WARN("pipe() error: (%d) %s", errno, strerror(errno));
		close(fd[0]);
		close(fd[1]);
		return NULL;
	}

	if (0 > (fdmon = epoll_create(64))) {
		GRID_WARN("epoll_create error: (%d) %s", errno, strerror(errno));
		close(fd[0]);
		close(fd[1]);
		return NULL;
	}

	struct rlimit limit;
	memset(&limit, 0, sizeof(limit));
	if (0 != getrlimit(RLIMIT_NOFILE, &limit))
		limit.rlim_cur = limit.rlim_max = 32768;

	pool = g_malloc0(sizeof(*pool));
	pool->lock = g_mutex_new();
	pool->pending_clients = g_queue_new();
	pool->notifications = g_queue_new();

	pool->fdmon = fdmon;
	pool->active_max = max>1?max:1;
	pool->active_clients_size = MAX(pool->active_max,limit.rlim_cur);
	pool->active_clients = g_malloc0(pool->active_clients_size
			* sizeof(struct event_client_s*));

	pool->fd_in = fd[0];
	fd[0] = -1;
	shutdown(pool->fd_in, SHUT_WR);
	sock_set_non_blocking(pool->fd_in, TRUE);

	pool->fd_out = fd[1];
	fd[1] = -1;
	shutdown(pool->fd_out, SHUT_RD);
	sock_set_non_blocking(pool->fd_out, TRUE);

	/* then monitors at least the notifications pipe's output */
	struct epoll_event ev;
	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = pool->fd_in;
	if (0 > epoll_ctl(pool->fdmon, EPOLL_CTL_ADD, pool->fd_in, &ev)) {
		GRID_ERROR("epoll error: (%d) %s", errno, strerror(errno));
		client_pool_destroy(pool);
		return NULL;
	}

	return pool;
}

static void
client_pool_manage_timeouts(struct client_pool_s *pool)
{
	/*GRID_TRACE2("%s(%p)", __FUNCTION__, pool);*/
	SQLX_ASSERT(pool != NULL);

	for (guint i=0; i<pool->active_clients_size ;i++) {
		struct event_client_s *ec;

		if (!(ec = pool->active_clients[i]))
			continue;
		SQLX_ASSERT(ec->client != NULL);

		if (gridd_client_finished(ec->client)) {
			GRID_TRACE2("Client fd=%d [%s] finished", i, gridd_client_url(ec->client));
			pool->active_count --;
			pool->active_clients[i] = NULL;
			event_client_free(ec);
		}
		else {
			GTimeVal now;
			g_get_current_time(&now);
			if (gridd_client_expired(ec->client, &now)) {
				GRID_DEBUG("Client fd=%d [%s] expired", i, gridd_client_url(ec->client));
				pool->active_count --;
				pool->active_clients[i] = NULL;
				event_client_free(ec);
			}
		}
	}
}

static void
client_pool_manage_requests(struct client_pool_s *pool)
{
	guint count = 0, remaining;
	struct event_client_s *ec;

	/*GRID_TRACE2("%s(%p)", __FUNCTION__, pool);*/
	SQLX_ASSERT(pool != NULL);

	while (pool->active_count < pool->active_max &&
			NULL != (ec = g_queue_pop_head(pool->pending_clients)))
	{
		SQLX_ASSERT(ec->client != NULL);

		if (!gridd_client_start(ec->client))
			event_client_free(ec);
		else if (!event_client_monitor(pool, 1, ec))
			event_client_free(ec);
		else
			count ++;
	}

	remaining = g_queue_get_length(pool->pending_clients);

	if (count > 0 || remaining > 0) {
		gchar str[256];
		g_snprintf(str, sizeof(str), "NEW (%u/%u)", count, remaining);
		client_pool_trace(str, pool);
	}
}

static void
client_pool_manage_error(struct client_pool_s *pool, int fd)
{
	struct event_client_s *ec;

	/*GRID_TRACE2("%s(%p,%d)", __FUNCTION__, pool, fd);*/
	SQLX_ASSERT(pool != NULL);
	SQLX_ASSERT(fd >= 0);

	ec = pool->active_clients[fd];
	pool->active_clients[fd] = NULL;
	SQLX_ASSERT(ec != NULL);
	SQLX_ASSERT(ec->client != NULL);

	SQLX_ASSERT(pool->active_count > 0);
	pool->active_count --;

	GRID_DEBUG("%s CLIENT [%s] fd=%d cnx error", __FUNCTION__,
			gridd_client_url(ec->client), gridd_client_fd(ec->client));

	gridd_client_cnx_error(ec->client);
	event_client_free(ec);
}

static void
client_pool_manage_event(struct client_pool_s *pool, int fd)
{
	struct event_client_s *ec;

	/*GRID_TRACE2("%s(%p,%d)", __FUNCTION__, pool, fd);*/
	SQLX_ASSERT(pool != NULL);
	SQLX_ASSERT(fd >= 0);

	ec = pool->active_clients[fd];
	pool->active_clients[fd] = NULL;
	SQLX_ASSERT(ec != NULL);
	SQLX_ASSERT(ec->client != NULL);

	SQLX_ASSERT(pool->active_count > 0);
	pool->active_count --;

	GRID_TRACE2("%s CLIENT [%s] fd=%d event", __FUNCTION__,
			gridd_client_url(ec->client),
			gridd_client_fd(ec->client));

	gridd_client_step(ec->client);

	if (!gridd_client_finished(ec->client)) {
		GRID_TRACE2("%s CLIENT not done", __FUNCTION__);
		if (!event_client_monitor(pool, 0, ec))
			event_client_free(ec);
	}
	else {
		GRID_TRACE2("%s CLIENT done", __FUNCTION__);
		event_client_free(ec);
	}
}

static void
client_pool_manage_notifications(struct client_pool_s *pool)
{
	struct event_client_s *ev;
	GQueue *q;

	/*GRID_TRACE2("%s(%p)", __FUNCTION__, pool);*/
	SQLX_ASSERT(pool != NULL);

	g_mutex_lock(pool->lock);
	fd_consume_input(pool->fd_in);
	q = pool->notifications;
	pool->notifications = g_queue_new();
	g_mutex_unlock(pool->lock);

	while (NULL != (ev = g_queue_pop_head(q)))
		g_queue_push_tail(pool->pending_clients, ev);

	g_queue_free(q);
}

GError *
client_pool_round(struct client_pool_s *pool, time_t sec)
{
	int i, rc;
	struct epoll_event ev[MAX_ROUND];

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	/*GRID_TRACE2("%s(%p,%lu)", __FUNCTION__, pool, sec);*/
	SQLX_ASSERT(pool != NULL);
	SQLX_ASSERT(pool->fdmon >= 0);

	rc = epoll_wait(pool->fdmon, ev, MAX_ROUND, sec * 1000L);

	if (rc < 0 && errno != EINTR)
		return g_error_new(gquark_log, errno,
				"epoll_wait error: %s", strerror(errno));

	client_pool_manage_notifications(pool);

	if (rc > 0) {
		/*GRID_TRACE2("%s %d events", __FUNCTION__, rc);*/
		for (i=0; i<rc ;i++) {
			if (ev[i].data.fd != pool->fd_in) {
				if (ev[i].events & EPOLLERR || ev[i].events & EPOLLHUP)
					client_pool_manage_error(pool, ev[i].data.fd);
				else
					client_pool_manage_event(pool, ev[i].data.fd);
			}
		}
		client_pool_trace("EVENTS MANAGED", pool);
	}

	client_pool_manage_timeouts(pool);
	client_pool_manage_requests(pool);
	/*GRID_TRACE2("%s exiting!", __FUNCTION__);*/
	return NULL;
}

void
client_pool_defer(struct client_pool_s *pool, struct event_client_s *ev)
{
	guint8 c = 0;

	/*GRID_TRACE2("%s(%p,%p)", __FUNCTION__, pool, ev);*/
	SQLX_ASSERT(pool != NULL);
	SQLX_ASSERT(ev != NULL);
	SQLX_ASSERT(pool->lock != NULL);
	SQLX_ASSERT(pool->notifications != NULL);
	SQLX_ASSERT(pool->fd_out >= 0);

	if (!pool->closed) {
		g_mutex_lock(pool->lock);
		g_queue_push_tail(pool->notifications, ev);
		g_mutex_unlock(pool->lock);
		(void) write(pool->fd_out, &c, 1);
	}
	else {
		GRID_DEBUG("Request dropped");
		event_client_free(ev);
	}
}

guint
client_pool_get_max(struct client_pool_s *pool)
{
	if (!pool)
		return 0;
	return pool->active_max + 1 /* 1 for epoll */;
}

void
client_pool_set_max(struct client_pool_s *pool, guint max)
{
	g_assert(pool != NULL);
	g_assert(max > 1);
	pool->active_max = max - 1; /* 1 for epoll */
}
