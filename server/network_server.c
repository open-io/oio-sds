/*
OpenIO SDS server
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/common_variables.h>
#include <server/server_variables.h>

#include "internals.h"

GQuark gq_count_all = 0;
GQuark gq_time_all = 0;
GQuark gq_count_unexpected = 0;
GQuark gq_time_unexpected = 0;
GQuark gq_count_overloaded = 0;
GQuark gq_time_overloaded = 0;

static gboolean _endpoint_is_UNIX (struct endpoint_s *u);
static gboolean _endpoint_is_INET6 (struct endpoint_s *u);
static gboolean _endpoint_is_INET4 (struct endpoint_s *u);
static gboolean _endpoint_is_INET (struct endpoint_s *u);

static GError * _endpoint_open (struct endpoint_s *u, gboolean udp_allowed);
static void _endpoint_close (struct endpoint_s *u);

static struct network_client_s* _endpoint_accept_one(
		struct network_server_s *srv, const struct endpoint_s *e);

static void _client_clean(struct network_server_s *srv,
		struct network_client_s *client);

static void _client_manage_event(struct network_client_s *client, int events);

static gboolean _client_has_pending_output(struct network_client_s *client);

static gboolean _client_ready_for_output(struct network_client_s *client);

static void _client_remove_from_monitored(struct network_server_s *srv,
		struct network_client_s *clt);

static void _client_add_to_monitored(struct network_server_s *srv,
		struct network_client_s *clt);

static void _cb_tcp_worker(struct network_client_s *clt,
		struct network_server_s *srv);

static void _cb_stats(struct server_stat_msg_s *msg,
		struct network_server_s *srv);

static void _manage_udp_task(struct network_client_s *clt,
		struct network_server_s *srv);

static void
_client_sock_name(int fd, gchar *dst, gsize dst_size)
{
	struct sockaddr_storage ss;
	socklen_t ss_len;

	ss_len = sizeof(ss);
	if (0 == getsockname(fd, (struct sockaddr*)&ss, &ss_len))
		grid_sockaddr_to_string((struct sockaddr*)&ss, dst, dst_size);
}

static gboolean
_client_has_pending_output(struct network_client_s *client)
{
	return data_slab_sequence_has_data(&(client->output));
}

static gboolean
_client_send_pending_output(struct network_client_s *client)
{
	return data_slab_sequence_send(&(client->output), client->fd);
}

static int
_cnx_notify_accept(struct network_server_s *srv)
{
	int inxs = EXCESS_NONE;
	g_mutex_lock(&srv->lock_threads);
	++ srv->cnx_accept;
	++ srv->cnx_clients;
	if (srv->cnx_clients > srv->cnx_max)
		inxs = EXCESS_HARD;
	g_mutex_unlock(&srv->lock_threads);
	return inxs;
}

static void
_cnx_notify_close(struct network_server_s *srv)
{
	g_mutex_lock(&srv->lock_threads);
	EXTRA_ASSERT(srv->cnx_clients > 0);
	-- srv->cnx_clients;
	++ srv->cnx_close;
	g_mutex_unlock(&srv->lock_threads);
}

static void __attribute__ ((constructor))
_constructor (void)
{
	gq_count_overloaded = g_quark_from_static_string (OIO_STAT_PREFIX_REQ ".OVERLOADED");
	gq_time_overloaded = g_quark_from_static_string (OIO_STAT_PREFIX_TIME ".OVERLOADED");

	gq_count_unexpected = g_quark_from_static_string (OIO_STAT_PREFIX_REQ ".UNEXPECTED");
	gq_time_unexpected = g_quark_from_static_string (OIO_STAT_PREFIX_TIME ".UNEXPECTED");
	gq_count_all = g_quark_from_static_string (OIO_STAT_PREFIX_REQ);
	gq_time_all = g_quark_from_static_string (OIO_STAT_PREFIX_TIME);
}

static gint
_server_stat_cmp (const struct server_stat_s *st0,
		const struct server_stat_s *st1)
{
	return CMP(st0->which,st1->which);
}

static guint64 *
_stat_locate (struct network_server_s *srv, GQuark which)
{
	struct server_stat_s key = {.which=which, .value=0};
	struct server_stat_s *p = (struct server_stat_s*) bsearch (&key,
			srv->stats->data, srv->stats->len, sizeof(key),
			(GCompareFunc)_server_stat_cmp);
	g_assert (p == NULL || p->which == which);
	return p ? &(p->value) : NULL;
}

/* Public API --------------------------------------------------------------- */

void
network_server_stat_push2 (struct network_server_s *srv, gboolean increment,
		GQuark k1, guint64 v1, GQuark k2, guint64 v2)
{
	network_server_stat_push4 (srv, increment, k1, v1, k2, v2, 0, 0, 0, 0);
}

void
network_server_stat_push4 (struct network_server_s *srv, gboolean increment,
		GQuark k1, guint64 v1, GQuark k2, guint64 v2,
		GQuark k3, guint64 v3, GQuark k4, guint64 v4)
{
	EXTRA_ASSERT (srv != NULL);
	struct server_stat_msg_s *m = SLICE_NEW0 (struct server_stat_msg_s);
	m->which[0] = k1, m->which[1] = k2, m->which[2] = k3, m->which[3] = k4;
	m->value[0] = v1, m->value[1] = v2, m->value[2] = v3, m->value[3] = v4;
	m->increment = BOOL(increment);
	g_thread_pool_push (srv->pool_stats, m, NULL);
}

GArray*
network_server_stat_getall (struct network_server_s *srv)
{
	EXTRA_ASSERT (srv != NULL);
	GArray *out = g_array_new (FALSE, TRUE, sizeof(struct server_stat_s));
	g_mutex_lock (&srv->lock_stats);
	g_array_append_vals (out, srv->stats->data, srv->stats->len);
	g_mutex_unlock (&srv->lock_stats);
	return out;
}

void
network_server_reconfigure(struct network_server_s *srv)
{
	if (!srv)
		return;

	/* Reconfigure the server */
	guint emax = server_fd_max_passive;
	if (!emax) {
		emax = metautils_syscall_count_maxfd();
		if (emax <= 10) {
			GRID_WARN("Not enough max file descriptors (%u)", srv->cnx_max);
			emax = 0;
		} else {
			emax -= 10;
		}
	}
	if (emax > 0)
		srv->cnx_max = emax;

	/* Reconfigure the thread pools */
	g_thread_pool_set_max_unused_threads(server_threadpool_max_unused);
	g_thread_pool_set_max_idle_time(
			server_threadpool_max_idle / G_TIME_SPAN_MILLISECOND);

	gint _map(const guint i) {
		return (i<=0 || i>G_MAXINT) ? -1 : (gint)i;
	}

	g_thread_pool_set_max_threads(
			srv->pool_stats, _map(server_threadpool_max_stat), NULL);

	g_thread_pool_set_max_threads(
			srv->pool_tcp, _map(server_threadpool_max_tcp), NULL);

	g_thread_pool_set_max_threads(
			srv->pool_udp, _map(server_threadpool_max_udp), NULL);
}

struct network_server_s *
network_server_init(void)
{
	int efd;
	if ((efd = eventfd(0, EFD_NONBLOCK)) < 0) {
		GRID_ERROR("eventfd creation failure: (%d) %s",
				errno, strerror(errno));
		return NULL;
	}

	struct network_server_s *result = g_malloc0(sizeof(struct network_server_s));
	result->flag_continue = ~0;
	result->cnx_max = metautils_syscall_count_maxfd();
	g_mutex_init(&result->lock_stats);
	result->stats = g_array_new (FALSE, TRUE, sizeof(struct server_stat_s));
	result->queue_monitor = g_async_queue_new();
	result->endpointv = g_malloc0(sizeof(struct endpoint_s*));
	g_mutex_init(&result->lock_threads);
	result->eventfd = efd;
	result->epollfd = epoll_create(1024);
	result->gq_gauge_threads =      g_quark_from_static_string ("gauge thread.active");
	result->gq_gauge_cnx_current =  g_quark_from_static_string ("gauge cnx.client");
	result->gq_counter_cnx_accept = g_quark_from_static_string ("counter cnx.accept");
	result->gq_counter_cnx_close =  g_quark_from_static_string ("counter cnx.close");

	/* no limit at the creation ... */
	result->pool_stats = g_thread_pool_new(
			(GFunc)_cb_stats, result, 0, FALSE, NULL);
	result->pool_tcp = g_thread_pool_new(
			(GFunc)_cb_tcp_worker, result, 0, FALSE, NULL);
	result->pool_udp = g_thread_pool_new(
			(GFunc)_manage_udp_task, result, 0, FALSE, NULL);

	/* ... and then supersedes the limits now */
	network_server_reconfigure(result);

	GRID_DEBUG("SERVER ready with epollfd[%d] eventfd[%d]",
			result->epollfd, result->eventfd);

	return result;
}

void
network_server_allow_udp(struct network_server_s *srv)
{
	g_assert(srv != NULL);

	for (struct endpoint_s **pe = srv->endpointv; srv->endpointv && *pe; ++pe) {
		GRID_ERROR("BUG: Can't call %s when servers are already open",
				__FUNCTION__);
		g_assert((*pe)->fd < 0);
	}
	srv->udp_allowed = TRUE;
}

static void
_stop_pools (struct network_server_s *srv)
{
	g_thread_pool_stop_unused_threads ();

	if (srv->pool_udp) {
		g_thread_pool_free (srv->pool_udp, FALSE, TRUE);
		srv->pool_udp = NULL;
	}
	if (srv->pool_stats) {
		g_thread_pool_free (srv->pool_stats, FALSE, TRUE);
		srv->pool_stats = NULL;
	}
	if (srv->pool_tcp) {
		g_thread_pool_free (srv->pool_tcp, FALSE, TRUE);
		srv->pool_tcp = NULL;
	}
}

void
network_server_clean(struct network_server_s *srv)
{
	if (!srv)
		return;

	_stop_pools (srv);
	if (srv->thread_tcp != NULL)
		g_error("Event thread not joined: %s", "tcp");
	if (srv->thread_udp != NULL)
		g_error("Event thread not joined: %s", "udp");

	g_mutex_clear(&srv->lock_stats);
	g_mutex_clear(&srv->lock_threads);

	network_server_close_servers(srv);

	if (srv->endpointv) {
		for (struct endpoint_s **u=srv->endpointv; *u ;u++)
			g_free(*u);
		g_free(srv->endpointv);
	}

	if (srv->stats)
		g_array_free (srv->stats, TRUE);

	metautils_pclose(&(srv->eventfd));

	if (srv->queue_monitor) {
		g_async_queue_unref(srv->queue_monitor);
		srv->queue_monitor = NULL;
	}

	g_free(srv);
}

static void
_srv_append_endpoint (struct network_server_s *srv, struct endpoint_s *e)
{
	const gsize len = g_strv_length((gchar**) srv->endpointv);
	srv->endpointv = g_realloc(srv->endpointv, sizeof(void*) * (len+2));
	srv->endpointv[len] = e;
	srv->endpointv[len+1] = NULL;
}

static void
_srv_bind_host(struct network_server_s *srv, const gchar *url, gpointer u,
		network_transport_factory factory, guint32 flags)
{
	EXTRA_ASSERT(srv != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(factory != NULL);

	const gsize len = strlen(url);
	struct endpoint_s *e = g_malloc0(sizeof(*e) + 1 + len);
	e->magic = MAGIC_ENDPOINT;
	e->fd = -1;
	e->fd_udp = -1;
	e->flags = flags;
	e->factory_udata = u;
	e->factory_hook = factory;
	memcpy(e->url, url, len);

	if (*url == '/') {
		GRID_DEBUG("URL configured : LOCAL endpoint=%s", e->url);
	} else {
		gchar *port;
		if (NULL != (port = strrchr(e->url, ':'))) {
			*port = '\0';
			++ port;
			e->port_cfg = atoi(port);
		}
		GRID_DEBUG("URL configured : INET port=%d endpoint=%s", e->port_cfg, e->url);
	}

	_srv_append_endpoint (srv, e);
}

void
network_server_bind_host(struct network_server_s *srv, const gchar *url, gpointer u,
		network_transport_factory factory)
{
	_srv_bind_host(srv, url, u, factory, 0);
}

void
network_server_bind_host_lowlatency(struct network_server_s *srv,
		const gchar *url, gpointer u, network_transport_factory factory)
{
	_srv_bind_host(srv, url, u, factory, NETSERVER_LATENCY);
}

gchar**
network_server_endpoints (struct network_server_s *srv)
{
	g_assert_nonnull(srv);
	GPtrArray *tmp = g_ptr_array_new();
	for (struct endpoint_s **pe = srv->endpointv; srv->endpointv && *pe; ++pe) {
		if ((*pe)->fd < 0)
			continue;
		g_ptr_array_add(tmp,
				g_strdup_printf("%s:%d", (*pe)->url, (*pe)->port_real));
	}
	g_ptr_array_add (tmp, NULL);
	return (gchar**) g_ptr_array_free(tmp, FALSE);
}

void
network_server_close_servers(struct network_server_s *srv)
{
	EXTRA_ASSERT(srv != NULL);
	for (struct endpoint_s **pu=srv->endpointv; *pu ;pu++)
		_endpoint_close (*pu);
}

GError *
network_server_open_servers(struct network_server_s *srv)
{
	g_assert(srv != NULL);

	for (struct endpoint_s **u = srv->endpointv; srv->endpointv && *u; u++) {
		GError *err;
		if (NULL != (err = _endpoint_open(*u, srv->udp_allowed))) {
			g_prefix_error(&err, "url open error : ");
			network_server_close_servers(srv);
			return err;
		}
	}

	for (struct endpoint_s **u = srv->endpointv; srv->endpointv && *u; u++) {
		GRID_DEBUG("fd=%d port=%d endpoint=%s ready", (*u)->fd,
				(*u)->port_real, (*u)->url);
	}

	return NULL;
}

static void
_drain_eventfd(int fd)
{
	guint64 event_count = 0u;
	int rc = metautils_syscall_read(fd, &event_count, 8);
	if (rc < 0 && errno != EAGAIN) {  // EAGAIN -> counter is 0
		GRID_WARN("Failed to reset event counter: (%d) %s",
				errno, strerror(errno));
	} else if (event_count > 100u) {
		GRID_INFO("Burst of %"G_GUINT64_FORMAT" events", event_count);
	}
}

static const char *
epoll2str(int how)
{
	switch (how) {
		case EPOLL_CTL_ADD:
			return "ADD";
		case EPOLL_CTL_DEL:
			return "DEL";
		case EPOLL_CTL_MOD:
			return "MOD";
		default:
			return "???";
	}
}

static void
ARM_WAKER(struct network_server_s *srv, int how)
{
	struct epoll_event ev;
	ev.data.ptr = &(srv->eventfd);
	ev.events = EPOLLIN|EPOLLET|EPOLLONESHOT;

	if (0 == epoll_ctl(srv->epollfd, how, srv->eventfd, &ev))
		return;
	GRID_DEBUG("WUP epoll_ctl(%d,%d,%s) = (%d) %s", srv->epollfd,
			srv->eventfd, epoll2str(how), errno, strerror(errno));
}

static void
ARM_CLIENT(struct network_server_s *srv, struct network_client_s *clt, int how)
{
	struct epoll_event ev;
	ev.data.ptr = clt;
	ev.events = EPOLLIN|EPOLLET|EPOLLONESHOT;
	if (clt->events & CLT_WRITE)
		ev.events |= EPOLLOUT;

	if (0 == epoll_ctl(srv->epollfd, how, clt->fd, &ev)) {
		if (how != EPOLL_CTL_DEL)
			_client_add_to_monitored(srv, clt);
		return;
	}

	GRID_WARN("CLT epoll_ctl(%d,%d,%s) = (%d) %s", srv->epollfd,
			clt->fd, epoll2str(how), errno, strerror(errno));
	_client_clean(srv, clt);
}

static void
ARM_ENDPOINT(struct network_server_s *srv, struct endpoint_s *e, int how)
{
	struct epoll_event ev;
	ev.events = EPOLLIN|EPOLLET|EPOLLONESHOT;
	ev.data.ptr = e;
	if (0 == epoll_ctl(srv->epollfd, how, e->fd, &ev))
		return;
	GRID_DEBUG("SRV epoll_ctl(%d,%d,%s) = (%d) %s", srv->epollfd,
			e->fd, epoll2str(how), errno, strerror(errno));
}

static void
_manage_client_event(struct network_server_s *srv,
		struct network_client_s *clt, register int ev0)
{
	_client_remove_from_monitored(srv, clt);

	if (!srv->flag_continue)
		clt->transport.waiting_for_close = TRUE;

	ev0 = MACRO_COND(ev0 & EPOLLIN, CLT_READ, 0)
		| MACRO_COND(ev0 & EPOLLOUT, CLT_WRITE, 0)
		| MACRO_COND(ev0 & (EPOLLERR|EPOLLHUP|EPOLLRDHUP), CLT_ERROR, 0);
	clt->events = MACRO_COND(!ev0, CLT_ERROR, ev0);

	if (ev0 & EPOLLIN)
		clt->time.evt_in = oio_ext_monotonic_time();

	if (clt->events & CLT_ERROR)
		ARM_CLIENT(srv, clt, EPOLL_CTL_DEL);
	g_thread_pool_push(srv->pool_tcp, clt, NULL);
}

static void
_manage_endpoint_event (struct network_server_s *srv, struct endpoint_s *e)
{
	for (guint i=0; i<server_accept_batch_size ;++i) {
		struct network_client_s *clt = _endpoint_accept_one(srv, e);
		if (!clt) break;
		if (clt->current_error)
			_client_clean(srv, clt);
		else {
			ARM_CLIENT(srv, clt, EPOLL_CTL_ADD);
		}
	}
	ARM_ENDPOINT(srv, e, EPOLL_CTL_MOD);
}

static void
_manage_events(struct network_server_s *srv)
{
	int erc;
	struct epoll_event *pev, allev[server_event_batch_size];

	erc = epoll_wait(srv->epollfd, allev, server_event_batch_size, 500);
	if (erc > 0) {
		while (erc-- > 0) {
			pev = allev+erc;
			if (pev->data.ptr == &(srv->eventfd))
				continue;
			if (MAGIC_ENDPOINT == *((unsigned int*)(pev->data.ptr)))
				_manage_endpoint_event (srv, pev->data.ptr);
			else
				_manage_client_event(srv, pev->data.ptr, pev->events);
		}
	}

	_drain_eventfd(srv->eventfd);
	ARM_WAKER(srv, EPOLL_CTL_MOD);
	struct network_client_s *clt;
	while (NULL != (clt = g_async_queue_try_pop(srv->queue_monitor))) {
		EXTRA_ASSERT(clt->events != 0 && !(clt->events & CLT_ERROR));
		ARM_CLIENT(srv, clt, EPOLL_CTL_MOD);
	}
}

static void
_server_shutdown_inactive_connections(struct network_server_s *srv)
{
	guint count = 0;
	gint64 now = oio_ext_monotonic_time ();
	const gint64 ti = now - server_cnx_ttl_idle;
	const gint64 tc = now - server_cnx_ttl_never;
	const gint64 tp = now - server_cnx_ttl_persist;

	struct network_client_s *clt, *n;
	for (clt=srv->first ; clt ; clt=n) {
		n = clt->next;
		EXTRA_ASSERT(clt->fd >= 0);
		if (clt->time.evt_in) {
			if (clt->time.evt_in < ti) {
				GRID_DEBUG("cnx %d closed: %s", clt->fd, "idle for too long");
				_manage_client_event(srv, clt, 0);
				++ count;
			} else if (clt->time.cnx < tp) {
				GRID_DEBUG("cnx %d closed: %s", clt->fd, "open since too long");
				_manage_client_event(srv, clt, 0);
				++ count;
			}
		} else if (clt->time.cnx < tc) { /* never input */
			GRID_DEBUG("cnx %d closed: %s", clt->fd, "inactive since too long");
			_manage_client_event(srv, clt, 0);
			++ count;
		}
	}

	if (count) GRID_INFO ("%u cnx closed (idle or inactive)", count);
}

static gpointer
_thread_cb_events(gpointer d)
{
	metautils_ignore_signals();

	struct network_server_s *srv = d;
	for (gint64 next = 0; srv->flag_continue ;) {
		_manage_events(srv);
		gint64 now = oio_ext_monotonic_time ();
		if (now > next) {
			_server_shutdown_inactive_connections(srv);
			next = now + 30 * G_TIME_SPAN_SECOND;
		}
	}

	/* the server connections are being closed in the main thread that
	 * received the exit signal. They will be removed automatically from
	 * the epoll pool.*/

	GRID_DEBUG("Server %p waiting for its connections", srv);
	server_cnx_ttl_never = 5 * G_TIME_SPAN_SECOND;
	server_cnx_ttl_persist = 5 * G_TIME_SPAN_SECOND;
	server_cnx_ttl_idle = 1 * G_TIME_SPAN_SECOND;

	for (gint64 next = 0; 0 < srv->cnx_clients ;) {
		_manage_events(srv);
		gint64 now = oio_ext_monotonic_time ();
		if (now > next) {
			_server_shutdown_inactive_connections(srv);
			next = now + 1 * G_TIME_SPAN_SECOND;
		}
	}

	return d;
}

static gsize
_endpoint_count_all (struct endpoint_s **pu)
{
	gsize count = 0;
	for (; *pu ;++pu) { count ++; }
	return count;
}

static gsize
_endpoint_count_udp (struct endpoint_s **pu)
{
	gsize count = 0;
	for (; *pu ;++pu) { if ((*pu)->fd_udp > 0) { count ++; } }
	return count;
}

static void
_endpoint_monitor_udp (struct endpoint_s **pu, struct pollfd *pfd)
{
	for (gint i=0; pu[i] ;++i) {
		pfd[i].fd = pu[i]->fd_udp;
		pfd[i].events = pu[i]->fd_udp > 0 ? POLLIN : 0;
		pfd[i].revents = 0;
	}
}

static void
_manage_udp_task(struct network_client_s *clt, struct network_server_s *srv)
{
	EXTRA_ASSERT(clt != NULL);
	EXTRA_ASSERT(clt->server == srv);

	if (!srv->flag_continue) {
		GRID_TRACE("PING %s -> %s discarded (server stopping)",
				clt->peer_name, clt->local_name);
	} else {

		const gint64 now = oio_ext_monotonic_time();

		/* OIO_SERVER_UDP_QUEUE_MAXAGE is arbitrary but it avoids managing
		 * pings that have probably been retried by the emitter. */
		if (now - clt->time.evt_in > server_udp_queue_ttl) {
			GRID_DEBUG("PING %s -> %s queued for too long",
					clt->peer_name, clt->local_name);
		} else {
			int rc = clt->transport.notify_input(clt);
			if (rc != RC_PROCESSED) {
				GRID_DEBUG("PING %s -> %s processing error",
						clt->peer_name, clt->local_name);
			}
		}
	}
	_client_clean(srv, clt);
}

static void
_manage_udp_event(struct network_server_s *srv, struct endpoint_s *e,
		struct pollfd *pfd)
{
	/* destined for little notifications, there is currently no clue ping
	 * are bigger than few 100's of bytes. 1k is enough. */
	guint8 buf[1024];

	/* consume several messages, but not indefinitely to avoid starvations
	 * with other ping sockets */
	for (gint i=0; i<8 ;++i) {
		struct sockaddr_storage ss;
		socklen_t ss_len = sizeof(ss);
		ssize_t r = recvfrom(pfd->fd, buf, sizeof(buf), 0,
				(struct sockaddr*)&ss, &ss_len);
		if (r <= 0)
			break;

		/* fake a client, the transport needs it */
		struct network_client_s *clt = SLICE_NEW0(struct network_client_s);
		clt->server = srv;
		clt->fd = -1;
		clt->events = CLT_READ;
		clt->time.cnx = oio_ext_monotonic_time ();
		clt->time.evt_in = clt->time.cnx;
		grid_sockaddr_to_string((struct sockaddr*)&ss,
				clt->peer_name, sizeof(clt->peer_name));
		g_snprintf(clt->local_name, sizeof(clt->local_name), "%s:%d",
				e->url, e->port_real);

		if (e->factory_hook)
			e->factory_hook(e->factory_udata, clt);

		/* Insert a slab in the input queue */
		data_slab_sequence_append(&clt->input,
				data_slab_make_buffer(g_memdup(buf, r), r));

		/* notify the transport layer, and manage this in another thread */
		EXTRA_ASSERT(NULL != clt->transport.notify_input);

		/* `server_udp_queue_maxlen` is arbitrary, but it is only used to
		 * avoid a memory leak */
		const guint unprocessed = g_thread_pool_unprocessed(srv->pool_udp);
		if (unprocessed > server_udp_queue_maxlen) {
			GRID_DEBUG("UDP dropped %s -> %s", clt->peer_name, clt->local_name);
		} else {
			GError *err = NULL;
			if (!g_thread_pool_push(srv->pool_udp, clt, &err)) {
				GRID_WARN("UDP discarded %s -> %s: (%d) %s",
						clt->peer_name, clt->local_name,
						err->code, err->message);
				g_clear_error(&err);
				_client_clean(srv, clt);
			}
		}
	}
}

static gpointer
_thread_cb_ping(gpointer d)
{
	metautils_ignore_signals();

	struct network_server_s *srv = d;

	/* no server open, no need to continue */
	if (_endpoint_count_udp(srv->endpointv) <= 0)
		return d;

	const gsize count_structs = _endpoint_count_all(srv->endpointv);
	struct pollfd pfd[count_structs];
	_endpoint_monitor_udp(srv->endpointv, pfd);

	while (srv->flag_continue) {
		int rc = metautils_syscall_poll(pfd, count_structs, 1000);
		if (rc < 0) {
			GRID_WARN("PING poll error (%d) %s", errno, strerror(errno));
		} else if (rc > 0) {
			for (guint i=0; i<count_structs ;++i) {
				if (pfd[i].revents & POLLIN)
					_manage_udp_event(srv, srv->endpointv[i], pfd+i);
				pfd[i].revents = 0;
			}
		}
	}

	return d;
}

GError *
network_server_run(struct network_server_s *srv, void (*on_reload)(void))
{
	struct endpoint_s **pu, *u;
	GError *err = NULL;

	/* Sanity checks */
	EXTRA_ASSERT(srv != NULL);
	for (pu=srv->endpointv; (u = *pu) ;pu++) {
		if (u->fd < 0) {
			_stop_pools (srv);
			return NEWERROR(EINVAL,
					"DESIGN ERROR : some servers are not open");
		}
	}
	if (!srv->flag_continue) {
		_stop_pools (srv);
		return NULL;
	}

	for (pu=srv->endpointv; srv->flag_continue && (u = *pu) ;pu++)
		ARM_ENDPOINT(srv, u, EPOLL_CTL_ADD);
	ARM_WAKER(srv, EPOLL_CTL_ADD);

	if (srv->udp_allowed)
		srv->thread_udp = g_thread_new("udp", _thread_cb_ping, srv);
	srv->thread_tcp = g_thread_new("tcp", _thread_cb_events, srv);

	while (srv->flag_continue) {
		g_usleep(1 * G_TIME_SPAN_SECOND);
		network_server_stat_push4 (srv, FALSE,
				srv->gq_gauge_threads, (guint64) g_thread_pool_get_num_threads(srv->pool_tcp),
				srv->gq_gauge_cnx_current, srv->cnx_clients,
				srv->gq_counter_cnx_accept, srv->cnx_accept,
				srv->gq_counter_cnx_close, srv->cnx_close);
		if (main_signal_SIGHUP) {
			main_signal_SIGHUP = FALSE;
			if (on_reload)
				(*on_reload)();
		}
	}

	network_server_close_servers(srv);
	GRID_DEBUG("Server %p waiting for its threads", srv);

	/* wait for the event threads */
	if (srv->thread_tcp) {
		g_thread_join(srv->thread_tcp);
		srv->thread_tcp = NULL;
	}
	if (srv->thread_udp) {
		g_thread_join(srv->thread_udp);
		srv->thread_udp = NULL;
	}

	/* XXX(jfs): seems legit but requires exit critical path to be reviewed.
	_stop_pools (srv); */
	ARM_WAKER(srv, EPOLL_CTL_DEL);

	GRID_DEBUG("Server %p exiting its main loop", srv);
	return err;
}

void
network_server_stop(struct network_server_s *srv)
{
	if (!srv)
		return;
	srv->flag_continue = FALSE;
}

/* Endpoint features ------------------------------------------------------- */

static gboolean _endpoint_is_UNIX (struct endpoint_s *u)
{ return u->url[0] == '/'; }

static gboolean _endpoint_is_INET6 (struct endpoint_s *u)
{ return u->url[0] == '['; }

static gboolean _endpoint_is_INET4 (struct endpoint_s *u)
{ return !_endpoint_is_UNIX(u) && !_endpoint_is_INET6(u); }

static gboolean _endpoint_is_INET (struct endpoint_s *u)
{ return !_endpoint_is_UNIX(u); }

static void
_endpoint_close (struct endpoint_s *u)
{
	if (!u) return;
	if (u->fd >= 0) {
		if (_endpoint_is_UNIX (u))
			(void) unlink (u->url);
		metautils_pclose(&(u->fd));
	}
	if (u->fd_udp >= 0)
		metautils_pclose(&(u->fd_udp));
	u->port_real = 0;
}

static GError *
_endpoint_open(struct endpoint_s *u, gboolean udp_allowed)
{
	EXTRA_ASSERT(u != NULL);

	struct sockaddr_storage ss = {0};
	socklen_t ss_len;

	/* patch some socket preferences that make sense only for INET sockets */
	if (_endpoint_is_UNIX(u)) {
		u->port_real = 0;
		u->port_cfg = 0;
		u->flags &= ~(NETSERVER_THROUGHPUT|NETSERVER_LATENCY);
	}

	/* Get a socket of the right type */
	if (_endpoint_is_UNIX(u))
		u->fd = socket_nonblock(AF_UNIX, SOCK_STREAM, 0);
	else {
		if (_endpoint_is_INET6(u)) {
			u->fd = socket_nonblock(AF_INET6, SOCK_STREAM, 0);
			if (udp_allowed)
				u->fd_udp = socket_nonblock(AF_INET6, SOCK_DGRAM, 0);
		} else {
			u->fd = socket_nonblock(AF_INET, SOCK_STREAM, 0);
			if (udp_allowed)
				u->fd_udp = socket_nonblock(AF_INET, SOCK_DGRAM, 0);
		}
		if (udp_allowed && u->fd_udp < 0)
			return NEWERROR(errno, "socket(udp) = '%s'", strerror(errno));
	}
	if (u->fd < 0)
		return NEWERROR(errno, "socket(tcp) = '%s'", strerror(errno));

	if (_endpoint_is_INET(u)) {
		sock_set_reuseaddr (u->fd, TRUE);
		if (u->fd_udp >= 0)
			sock_set_reuseaddr (u->fd_udp, TRUE);
	}

	/* Bind the socket the right way according to its type */
	if (_endpoint_is_UNIX(u)) {
		struct sockaddr_un *sun = (struct sockaddr_un*) &ss;
		ss_len = sizeof(*sun);
		sun->sun_family = AF_UNIX;
		g_strlcpy(sun->sun_path, u->url, sizeof(sun->sun_path));
	} else if (_endpoint_is_INET6(u)) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6*) &ss;
		ss_len = sizeof(*s6);
		s6->sin6_family = AF_INET6;
		s6->sin6_port = htons(u->port_cfg);
		inet_pton(AF_INET6, u->url, &(s6->sin6_addr));
	} else {
		struct sockaddr_in *s4 = (struct sockaddr_in*) &ss;
		ss_len = sizeof(*s4);
		s4->sin_family = AF_INET;
		s4->sin_port = htons(u->port_cfg);
		inet_pton(AF_INET, u->url, &(s4->sin_addr));
	}

	if (0 > bind(u->fd, (struct sockaddr*)&ss, ss_len)) {
		int errsave = errno;
		u->port_real = 0;
		if (_endpoint_is_UNIX(u))
			metautils_pclose (&u->fd);
		return NEWERROR(errsave, "bind(tcp,%s) = '%s'", u->url, strerror(errsave));
	}
	if (u->fd_udp >= 0 && 0 > bind(u->fd_udp, (struct sockaddr*)&ss, ss_len)) {
		int errsave = errno;
		return NEWERROR(errsave, "bind(udp,%s) = '%s'", u->url, strerror(errsave));
	}

	if (_endpoint_is_INET(u)) {
		/* for INET sockets, get the port really used */
		memset(&ss, 0, sizeof(ss));
		ss_len = sizeof(ss);
		getsockname(u->fd, (struct sockaddr*)&ss, &ss_len);
		if (_endpoint_is_INET4(u))
			u->port_real = ntohs(((struct sockaddr_in*)&ss)->sin_port);
		else
			u->port_real = ntohs(((struct sockaddr_in6*)&ss)->sin6_port);

		/* and benefit from the TCP_FASTOPEN support */
		sock_set_fastopen(u->fd);
	}

	if (0 > listen(u->fd, 32768))
		return NEWERROR(errno, "listen() = '%s'", strerror(errno));

	return NULL;
}

static struct network_client_s *
_endpoint_accept_one(struct network_server_s *srv, const struct endpoint_s *e)
{
	int fd;
	struct sockaddr_storage ss;
	socklen_t ss_len;

retry:
	memset(&ss, 0, sizeof(ss));
	ss_len = sizeof(ss);
	fd = accept_nonblock(e->fd, (struct sockaddr*)&ss, &ss_len);

	if (0 > fd) {
		if (errno == EINTR)
			goto retry;
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			GRID_WARN("fd=%d ACCEPT error (%d %s)", e->fd, errno, strerror(errno));
		return NULL;
	}

	switch (e->flags) {
		case NETSERVER_THROUGHPUT:
			sock_set_cork(fd, TRUE);
			break;
		case NETSERVER_LATENCY:
			sock_set_client_default(fd);
			break;
		default:
			break;
	}

	struct network_client_s *clt = SLICE_NEW0(struct network_client_s);
	if (NULL == clt) {
		metautils_pclose(&fd);
		_cnx_notify_close(srv);
		return NULL;
	}

	switch (_cnx_notify_accept(srv)) {
		case EXCESS_NONE:
			break;
		case EXCESS_HARD:
			SLICE_FREE(struct network_client_s, clt);
			metautils_pclose(&fd);
			_cnx_notify_close(srv);
			GRID_WARN("Too many inbound connections! (max=%u)",
					srv->cnx_max);
			return NULL;
	}

	clt->server = srv;
	clt->fd = fd;
	grid_sockaddr_to_string((struct sockaddr*)&ss,
			clt->peer_name, sizeof(clt->peer_name));
	_client_sock_name(fd, clt->local_name, sizeof(clt->local_name));
	clt->time.cnx = oio_ext_monotonic_time ();
	clt->events = CLT_READ;

	clt->input.first = clt->input.last = NULL;
	clt->output.first = clt->output.last = NULL;

	if (e->factory_hook)
		e->factory_hook(e->factory_udata, clt);
	return clt;
}

/* Server features ---------------------------------------------------------- */

static void
_cb_stats(struct server_stat_msg_s *msg, struct network_server_s *srv)
{
	void _manage_at(const int n) {
		const guint64 value = msg->value[n];
		const GQuark which = msg->which[n];
		if (!which)
			return;
		guint64 *p = _stat_locate (srv, which);
		if (p)
			*p = (msg->increment ? *p : 0) + value;
		else {
			/* The set of stats should be stable, and populated once at the
			 * process startup. So that inserting then sorting for each stat
			 * added shouldn't have a big impact during the server's lifetime */
			struct server_stat_s st = {.value=value, .which=which};
			g_array_append_vals (srv->stats, &st, 1);
			g_array_sort (srv->stats, (GCompareFunc)_server_stat_cmp);
		}
	}
	g_mutex_lock (&srv->lock_stats);
	for (int i=0; i<4 ;++i) _manage_at (i);
	g_mutex_unlock (&srv->lock_stats);
	SLICE_FREE(struct server_stat_msg_s, msg);
}

static void
_cb_tcp_worker(struct network_client_s *clt, struct network_server_s *srv)
{
	EXTRA_ASSERT(clt != NULL);
	EXTRA_ASSERT(clt->server == srv);

	if ((clt->events & CLT_ERROR) || !clt->events) {
		_client_clean(srv, clt);
		return;
	}

	/* The event stayed *really* long in the queue of the thread pool.
	 * Let's close the connection, and let the client retry it's request. */
	if (clt->events & CLT_READ) {
		const gint64 now = oio_ext_monotonic_time();
		if (clt->time.evt_in < OLDEST(now, server_queue_max_delay)) {
			GRID_INFO("STARVING fd %d peer %s delay %"G_GINT64_FORMAT"ms",
					clt->fd, clt->peer_name,
					(now - clt->time.evt_in) / G_TIME_SPAN_MILLISECOND);
			_client_clean(srv, clt);
			return;
		}
		if (clt->time.evt_in < OLDEST(now, server_queue_warn_delay)) {
			GRID_INFO("CLOGGED fd %d peer %s delay %"G_GINT64_FORMAT"ms",
					clt->fd, clt->peer_name,
					(now - clt->time.evt_in) / G_TIME_SPAN_MILLISECOND);
		}
	}

	_client_manage_event(clt, clt->events);

	/* re Monitor the socket */
	if (_client_ready_for_output(clt) && _client_has_pending_output(clt))
		clt->events |= CLT_WRITE;
	if (!(clt->flags & (NETCLIENT_IN_CLOSED|NETCLIENT_IN_PAUSED)))
		clt->events |= CLT_READ;

	if (!clt->events || (clt->events & CLT_ERROR)) {
		_client_clean(srv, clt);
	}
	else {
		g_async_queue_push(srv->queue_monitor, clt);
		guint64 evt_count = 1u;
		ssize_t w = write(srv->eventfd, &evt_count, 8);
		if (w != 8) {
			GRID_WARN("event thread notification failed: (%d) %s",
					errno, strerror(errno));
		}
	}
}

/* Client functions --------------------------------------------------------- */

static void
_client_remove_from_monitored(struct network_server_s *srv,
		struct network_client_s *clt)
{
	EXTRA_ASSERT(clt->server == srv);

	if (srv->first == clt) {
		EXTRA_ASSERT(clt->prev == NULL);
		if (NULL != (srv->first = clt->next))
			srv->first->prev = NULL;
	}
	else {
		EXTRA_ASSERT(clt->prev != NULL);
		if (NULL != (clt->prev->next = clt->next))
			clt->next->prev = clt->prev;
	}

	clt->next = clt->prev = NULL;
}

static void
_client_add_to_monitored(struct network_server_s *srv,
		struct network_client_s *clt)
{
	EXTRA_ASSERT(clt->server == srv);
	EXTRA_ASSERT(clt->prev == NULL);
	EXTRA_ASSERT(clt->next == NULL);
	EXTRA_ASSERT(clt->fd >= 0);

	if (NULL != (clt->next = srv->first))
		clt->next->prev = clt;
	srv->first = clt;
}

static gboolean
_client_ready_for_output(struct network_client_s *clt)
{
	if (!clt || clt->fd < 0)
		return FALSE;

	if (clt->flags & NETCLIENT_OUT_CLOSED)
		return FALSE;

	if (!data_slab_sequence_ready_for_data(&(clt->output))) {
		clt->flags |= NETCLIENT_OUT_CLOSED;
		return FALSE;
	}

	return TRUE;
}

static void
_client_clean(struct network_server_s *srv, struct network_client_s *clt)
{
	/* Notifies the upper layer the client is being exiting. */
	if (clt->transport.notify_error)
		clt->transport.notify_error(clt);

	EXTRA_ASSERT(clt->prev == NULL);
	EXTRA_ASSERT(clt->next == NULL);

	if (clt->fd >= 0) {
		metautils_pclose(&(clt->fd));
		_cnx_notify_close(srv);
	}

	clt->flags = clt->events = 0;
	memset(&(clt->time), 0, sizeof(clt->time));

	data_slab_sequence_clean_data(&(clt->input));
	data_slab_sequence_clean_data(&(clt->output));
	clt->input.first = clt->input.last = NULL;
	clt->output.first = clt->output.last = NULL;

	/* clean the transport, if any */
	struct network_transport_s *t = &(clt->transport);
	if (t->client_context && t->clean_context)
		t->clean_context(t->client_context);
	memset(t, 0x00, sizeof(*t));

	if (clt->current_error)
		g_clear_error(&(clt->current_error));

	SLICE_FREE(struct network_client_s, clt);
}

static int
_ds_feed(int fd, struct data_slab_s *ds)
{
	while (ds->data.buffer.end < ds->data.buffer.alloc) {
		ssize_t r = read(fd, ds->data.buffer.buff + ds->data.buffer.end,
				ds->data.buffer.alloc - ds->data.buffer.end);
		if (r < 0)
			return MACRO_COND((errno==EAGAIN || errno==EWOULDBLOCK), RC_NOTREADY, RC_ERROR);
		if (r == 0)
			return RC_NODATA;
		ds->data.buffer.end += r;
	}

	return RC_PROCESSED;
}

#define SLAB_STARTSIZE   1024
#define SLAB_MAXSIZE    16384
#define ROUND_MAXSIZE  524288

static int
_client_manage_input(struct network_client_s *client)
{
	guint total, size;

	int _notify(void) {
		if (!data_slab_sequence_has_data(&(client->input))) {
			/* drain the data */
			data_slab_sequence_clean_data(&(client->input));
			return RC_PROCESSED;
		}
		return client->transport.notify_input(client);
	}

	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->fd >= 0);
	EXTRA_ASSERT(client->transport.notify_input != NULL);

	for (size=SLAB_STARTSIZE, total=0; total < ROUND_MAXSIZE ;) {

		int rc;
		struct data_slab_s *in = data_slab_make_empty(size);

		switch (rc = _ds_feed(client->fd, in)) {
			case RC_ERROR:
				data_slab_free(in);
				return RC_ERROR;
			case RC_NODATA: /* no more data to expect */
			case RC_NOTREADY:
				if (!in->data.buffer.end)
					data_slab_free(in);
				else {
					data_slab_sequence_append(&(client->input), in);
					total += in->data.buffer.end;
				}
				in = NULL;
				if (RC_NODATA == _notify())
					rc = RC_NODATA;
				return rc;
			case RC_PROCESSED:
				if (!in->data.buffer.end)
					data_slab_free(in);
				else {
					data_slab_sequence_append(&(client->input), in);
					total += in->data.buffer.end;
				}
				size = SLAB_MAXSIZE;
				in = NULL;
				break;
			default:
				g_assert_not_reached();
		}
	}

	return _notify();
}

static int
_client_manage_output(struct network_client_s *client)
{
	int rc;
	if (client->flags & NETCLIENT_OUT_CLOSED) {
		data_slab_sequence_clean_data(&(client->output));
		return RC_NODATA;
	}
	rc = RC_NODATA;
	while (_client_has_pending_output(client)) {
		if (!_client_send_pending_output(client)) {
			if (errno != EAGAIN)
				return RC_ERROR;
			return RC_NOTREADY;
		}
		rc = RC_PROCESSED;
	}
	return rc;
}

static void
_client_manage_event(struct network_client_s *clt, int events)
{
	int rcI, rcO;

	clt->events = 0;
	rcO = _client_has_pending_output(clt);
	rcI = events & CLT_READ ;

	do {
		/* Try to send some data if any */
		if (rcO) {
			switch (_client_manage_output(clt)) {
				case RC_ERROR:
					clt->events |= CLT_ERROR;
					rcO = 0;
					break;
				case RC_NODATA:
				case RC_NOTREADY:
					rcO = 0;
					break;
				case RC_PROCESSED:
					rcO = 1;
					break;
			}
		}

		/* Try to read some data if any available */
		if (rcI) {
			switch (_client_manage_input(clt)) {
				case RC_ERROR:
					clt->events |= CLT_ERROR;
					rcI = 0;
					break;
				case RC_NODATA:
					clt->flags |= NETCLIENT_IN_CLOSED;
					// FALLTHROUGH
				case RC_NOTREADY:
					/* no need to loop again */
					rcI = 0;
					break;
				case RC_PROCESSED:
					rcI = 1;
					break;
			}
		}
	} while (rcI || rcO);

	clt->events |= (events & CLT_ERROR); /* set CLT_ERROR if it was already present */
}

int
network_client_send_slab(struct network_client_s *client, struct data_slab_s *ds)
{
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(ds != NULL);

	client->time.evt_out = oio_ext_monotonic_time ();

	if (!_client_ready_for_output(client)) {
		const int type = ds->type;
		GRID_TRACE("fd=%d/%s discarding data, output closed",
				client->fd, client->peer_name);
		data_slab_free(ds);
		return MACRO_COND(type == STYPE_EOF, 0, -1);
	}

	/* Try to send the slab now, if allowed */
	if (!_client_has_pending_output(client)) {
		if (!data_slab_send(ds, client->fd)) {
			if (errno != EAGAIN) {
				data_slab_free(ds);
				return -1;
			}
		}
	}

	/* manage what remains */
	if (!data_slab_has_data(ds))
		data_slab_free(ds);
	else
		data_slab_sequence_append(&(client->output), ds);
	return 0;
}

void
network_client_close_output(struct network_client_s *clt, int now)
{
	EXTRA_ASSERT(clt != NULL);

	if (clt->fd < 0)
		return;

	if (!(clt->flags & NETCLIENT_OUT_CLOSED)) {
		GRID_DEBUG("fd=%d Closing output", clt->fd);
		if (!now) {
			if (!(clt->flags & NETCLIENT_OUT_CLOSE_PENDING)) {
				network_client_send_slab(clt, data_slab_make_eof());
				clt->flags |= NETCLIENT_OUT_CLOSE_PENDING;
			}
		}
		else {
			clt->flags |= NETCLIENT_OUT_CLOSED;
			data_slab_sequence_clean_data(&(clt->output));
		}
	}
}

void
network_client_allow_input(struct network_client_s *clt, gboolean v)
{
	EXTRA_ASSERT(clt != NULL);

	if (!clt || clt->fd < 0)
		return;

	if (!v) {
		if (!(clt->flags & NETCLIENT_IN_CLOSED))
			clt->flags |= NETCLIENT_IN_PAUSED;
	}
	else {
		EXTRA_ASSERT(!(clt->flags & NETCLIENT_IN_CLOSED));
		clt->flags &= ~NETCLIENT_IN_PAUSED;
	}
}

int
network_server_first_udp (struct network_server_s *srv)
{
	if (!srv || !srv->udp_allowed || !srv->endpointv)
		return -1;
	for (struct endpoint_s **pe=srv->endpointv; *pe ;++pe) {
		if ((*pe)->fd_udp >= 0)
			return (*pe)->fd_udp;
	}
	return -1;
}
