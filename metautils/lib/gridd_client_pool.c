#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "sqliterepo"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/resource.h>

#include "metautils.h"
#include "metautils_syscall.h"
#include "gridd_client.h"
#include "gridd_client_pool.h"

#define MAX_ROUND 32

struct gridd_client_pool_s
{
	struct gridd_client_pool_vtable_s *vtable;
	struct event_client_s **active_clients;
	GAsyncQueue *pending_clients;

	time_t last_timeout_check;

	int fdmon;
	/* notifications */
	int fd_in; /*!< consumes the notifications here */
	int fd_out; /*!< send anything to notify */

	int active_clients_size;
	int active_max;
	int active_count;

	/* if set to any non-zero value, new requests are not started */
	int closed;
};

static void _destroy (struct gridd_client_pool_s *p);

static guint _get_max (struct gridd_client_pool_s *pool);

static void _set_max (struct gridd_client_pool_s *pool, guint max);

static void _defer (struct gridd_client_pool_s *p, struct event_client_s *ev);

static GError* _round (struct gridd_client_pool_s *p, time_t sec);

static struct gridd_client_pool_vtable_s VTABLE =
{
	_destroy,
	_get_max,
	_set_max,
	_defer,
	_round
};

struct gridd_client_pool_s *
gridd_client_pool_create(void)
{
	int fdmon, fd[2];
	struct gridd_client_pool_s *pool;

	if (0 != pipe(fd)) {
		GRID_WARN("pipe() error: (%d) %s", errno, strerror(errno));
		metautils_pclose(&(fd[0]));
		metautils_pclose(&(fd[1]));
		return NULL;
	}

	if (0 > (fdmon = epoll_create(64))) {
		GRID_WARN("epoll_create error: (%d) %s", errno, strerror(errno));
		metautils_pclose(&(fd[0]));
		metautils_pclose(&(fd[1]));
		return NULL;
	}

	// TODO FIXME factorize this in metautils
	struct rlimit limit;
	memset(&limit, 0, sizeof(limit));
	if (0 != getrlimit(RLIMIT_NOFILE, &limit))
		limit.rlim_cur = limit.rlim_max = 32768;

	pool = g_malloc0(sizeof(*pool));
	pool->pending_clients = g_async_queue_new();

	pool->fdmon = fdmon;
	pool->active_max = limit.rlim_cur;
	pool->active_clients_size = limit.rlim_cur;
	pool->active_clients = g_malloc0(pool->active_clients_size
			* sizeof(struct event_client_s*));

	pool->fd_in = fd[0];
	fd[0] = -1;
	metautils_syscall_shutdown(pool->fd_in, SHUT_WR);
	sock_set_non_blocking(pool->fd_in, TRUE);

	pool->fd_out = fd[1];
	fd[1] = -1;
	metautils_syscall_shutdown(pool->fd_out, SHUT_RD);
	sock_set_non_blocking(pool->fd_out, TRUE);

	/* then monitors at least the notifications pipe's output */
	struct epoll_event ev;
	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = pool->fd_in;
	if (0 > epoll_ctl(pool->fdmon, EPOLL_CTL_ADD, pool->fd_in, &ev)) {
		GRID_ERROR("epoll error: (%d) %s", errno, strerror(errno));
		gridd_client_pool_destroy(pool);
		return NULL;
	}

	pool->vtable = &VTABLE;
	return pool;
}

/* ------------------------------------------------------------------------- */

static void
fd_consume_input(int fd)
{
	guint8 data[256];
	(void) metautils_syscall_read(fd, data, sizeof(data));
}

static int
event_client_monitor(struct gridd_client_pool_s *pool, struct event_client_s *mc)
{
	int fd, rc, interest;
	struct epoll_event ev;

	EXTRA_ASSERT(pool != NULL);
	EXTRA_ASSERT(mc != NULL);
	EXTRA_ASSERT(mc->client != NULL);

	memset(&ev, 0, sizeof(ev));

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

static void
event_client_free(struct event_client_s *ec)
{
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
_destroy(struct gridd_client_pool_s *pool)
{
	if (!pool)
		return;
	EXTRA_ASSERT(pool->vtable == &VTABLE);

	pool->closed = ~0;

	if (pool->fd_in >= 0)
		metautils_pclose(&(pool->fd_in));
	if (pool->fd_out >= 0)
		metautils_pclose(&(pool->fd_out));
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
		for (int i=0; i<pool->active_clients_size ;i++) {
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
	GTimeVal now;
	struct event_client_s *ec;

	if (pool->active_count <= 0)
		return;

	g_get_current_time(&now);
	if (pool->last_timeout_check == now.tv_sec)
		return;

	for (int i=0; i<pool->active_clients_size ;i++) {

		if (!(ec = pool->active_clients[i]))
			continue;

		EXTRA_ASSERT(ec->client != NULL);
		EXTRA_ASSERT(i == gridd_client_fd(ec->client));

		if (gridd_client_expired(ec->client, &now)) {
			GRID_INFO("EXPIRED Client fd=%d [%s]", i, gridd_client_url(ec->client));
			_pool_unmonitor(pool, i);
			event_client_free(ec);
		}
	}
}

static void
_manage_requests(struct gridd_client_pool_s *pool)
{
	struct event_client_s *ec;

	EXTRA_ASSERT(pool != NULL);

	while (pool->active_count < pool->active_max) {
		ec = g_async_queue_try_pop(pool->pending_clients);
		if (NULL == ec)
			return;
		EXTRA_ASSERT(ec->client != NULL);

		if (!gridd_client_start(ec->client)) {
			GError *err = gridd_client_error(ec->client);
			if (NULL != err) {
				GRID_WARN("STARTUP Client fd=%d [%s] : (%d) %s",
						gridd_client_fd(ec->client), gridd_client_url(ec->client),
						err->code, err->message);
				g_clear_error(&err);
			}
			else {
				GRID_WARN("STARTUP Client fd=%d [%s] : already started",
						gridd_client_fd(ec->client), gridd_client_url(ec->client));
				g_assert(err != NULL);
			}
			event_client_free(ec);
		}
		else if (!event_client_monitor(pool, ec))
			event_client_free(ec);
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
	for (int i=0; i < maxevt ;++i) {
		if (ev[i].data.fd == pool->fd_in)
			fd_consume_input(pool->fd_in);
		else
			_manage_one_event(pool, ev[i].data.fd, ev[i].events);
	}
}

static GError *
_round(struct gridd_client_pool_s *pool, time_t sec)
{
	EXTRA_ASSERT(pool != NULL);
	EXTRA_ASSERT(pool->vtable == &VTABLE);
	EXTRA_ASSERT(pool->fdmon >= 0);

	struct epoll_event ev[MAX_ROUND];
	memset(ev, 0, sizeof(ev));
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
	EXTRA_ASSERT(pool->fd_out >= 0);

	if (pool->closed) {
		GRID_INFO("Request dropped");
		event_client_free(ev);
	}
	else {
		guint8 c = 0;
		g_async_queue_push(pool->pending_clients, ev);
		(void) metautils_syscall_write(pool->fd_out, &c, 1);
	}
}

/* Bias introduced : 1 for epoll, 2 for the pipe */

static guint
_get_max(struct gridd_client_pool_s *pool)
{
	EXTRA_ASSERT(pool != NULL);
	EXTRA_ASSERT(pool->vtable == &VTABLE);
	return pool->active_max + 3;
}

static void
_set_max(struct gridd_client_pool_s *pool, guint max)
{
	EXTRA_ASSERT(pool != NULL);
	EXTRA_ASSERT(pool->vtable == &VTABLE);
	g_assert(max > 3);
	pool->active_max = max - 3;
}

