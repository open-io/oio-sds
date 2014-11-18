#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.utils.server"
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <metautils/lib/metautils.h>

#include "internals.h"
#include "stats_holder.h"
#include "network_server.h"
#include "resolv.h"
#include "slab.h"

enum {
	NETSERVER_THROUGHPUT = 0x0001,
	NETSERVER_LATENCY    = 0x0002,
};

#define MAGIC_ENDPOINT 0xFFFFFFFF

struct endpoint_s
{
	unsigned int magic;
	int fd;
	int port_real;
	int port_cfg;
	guint32 flags;
	gpointer factory_udata;
	network_transport_factory factory_hook;
	gchar url[1];
};

struct network_server_s
{
	struct endpoint_s **endpointv;

	struct network_client_s *first;

	GThread *thread_events;

	GAsyncQueue *queue_events; /* from the events_thread to the workers */
	GAsyncQueue *queue_monitor; /* from the workers to the events_thread */
	GThread *thread_first_worker;

	struct grid_stats_holder_s *stats;

	GMutex *lock_threads;

	guint64 counter_created;
	guint64 counter_destroyed;
	guint64 counter_hitmax;
	guint64 active_in;
	guint64 active_out;

	guint workers_total;
	guint workers_active;
	guint workers_hit_max;

	struct grid_single_rrd_s *workers_active_1; /* at least 30 slots, 1/sec */
	struct grid_single_rrd_s *workers_active_60; /* at least 60 slots, 1/min */

	guint workers_minimum;
	guint workers_minimum_spare;
	guint workers_maximum;

	guint64 cnx_accept;
	guint64 cnx_close;
	guint cnx_max_sys;
	guint cnx_max;
	guint cnx_clients;
	guint cnx_backlog;

	time_t workers_max_idle_delay;

	/* when waiting for a clean axit ... */
	time_t atexit_max_open_never_input; /*< max connection time
										  for connection without any input.*/
	time_t atexit_max_idle; /*< max idle time since last input */
	time_t atexit_max_open_persist; /*< max connection time for persistant
									  connections*/

	struct timespec now;

	int wakeup[2];
	int epollfd;
	gboolean flag_continue : 1;

};

enum
{
	NETCLIENT_IN_CLOSED         = 0x0001,
	NETCLIENT_OUT_CLOSED        = 0x0002,
	NETCLIENT_OUT_CLOSE_PENDING = 0x0004,
	NETCLIENT_IN_PAUSED         = 0x0008,
};

static gboolean _endpoint_bind(struct endpoint_s *u, int port);

static GError * _endpoint_open(struct endpoint_s *u);

static struct network_client_s* _endpoint_manage_event(
		struct network_server_s *srv, struct endpoint_s *e);

static void _server_start_one_worker(struct network_server_s *srv,
		gboolean counters_changed);

static void _server_update_main_stats(struct network_server_s *srv);

static gpointer _thread_cb_worker(gpointer td);

static void _client_clean(struct network_server_s *srv,
		struct network_client_s *client);

static void _client_manage_event(struct network_client_s *client, int events);

static gboolean _client_has_pending_output(struct network_client_s *client);

static gboolean _client_ready_for_output(struct network_client_s *client);

static void _client_remove_from_monitored(struct network_server_s *srv,
		struct network_client_s *clt);

static void _client_add_to_monitored(struct network_server_s *srv,
		struct network_client_s *clt);

static void _thread_start(struct network_server_s *srv);
static void _thread_stop(struct network_server_s *srv);
static void _thread_become_active(struct network_server_s *srv);
static void _thread_become_inactive(struct network_server_s *srv);
static gboolean _thread_can_die(struct network_server_s *srv);

static guint _start_necessary_threads(struct network_server_s *srv);

/* Returns the number of processors, at the runtime */
static guint _server_count_procs(void);

/* Returns the number of max file descriptors for this process */
static guint _server_get_maxfd(void);

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

static gboolean
_cnx_notify_accept(struct network_server_s *srv)
{
	gboolean inxs;
	g_mutex_lock(srv->lock_threads);
	++ srv->cnx_accept;
	++ srv->cnx_clients;
	inxs = 1 + srv->workers_active > srv->workers_maximum + srv->cnx_backlog ;
	g_mutex_unlock(srv->lock_threads);
	return inxs;
}

static void
_cnx_notify_close(struct network_server_s *srv)
{
	g_mutex_lock(srv->lock_threads);
	EXTRA_ASSERT(srv->cnx_clients > 0);
	-- srv->cnx_clients;
	++ srv->cnx_close;
	g_mutex_unlock(srv->lock_threads);
}

/* Public API --------------------------------------------------------------- */


struct network_server_s *
network_server_init(void)
{
	int wakeup[2];
	guint count, maxfd;
	struct network_server_s *result;

	wakeup[0] = wakeup[1] = -1;
	if (0 > pipe(wakeup)) {
		GRID_ERROR("PIPE creation failure : (%d) %s", errno, strerror(errno));
		return NULL;
	}
	shutdown(wakeup[0], SHUT_WR);
	shutdown(wakeup[1], SHUT_RD);
	fcntl(wakeup[0], F_SETFL, O_NONBLOCK|fcntl(wakeup[0], F_GETFL));

	count = _server_count_procs();
	maxfd = _server_get_maxfd();

	result = g_malloc0(sizeof(struct network_server_s));
	result->flag_continue = ~0;
	result->stats = grid_stats_holder_init();

	clock_gettime(CLOCK_MONOTONIC_COARSE, &result->now);

	result->queue_events = g_async_queue_new();
	result->queue_monitor = g_async_queue_new();

	result->endpointv = g_malloc0(sizeof(struct endpoint_s*));
	result->lock_threads = g_mutex_new();
	result->workers_max_idle_delay = SERVER_DEFAULT_MAX_IDLEDELAY;
	result->workers_minimum = count;
	result->workers_minimum_spare = count;
	result->workers_maximum = SERVER_DEFAULT_MAX_WORKERS;
	result->cnx_max_sys = maxfd;
	result->cnx_max = (result->cnx_max_sys * 99) / 100;
	result->cnx_backlog = 50;
	result->wakeup[0] = wakeup[0];
	result->wakeup[1] = wakeup[1];
	result->epollfd = epoll_create(4096);

	// XXX JFS : #slots as a power of 2 ... for efficient modulos
	result->workers_active_1 = grid_single_rrd_create(result->now.tv_sec, 32);
	result->workers_active_60 = grid_single_rrd_create(result->now.tv_sec/60, 64);

	result->atexit_max_open_never_input = 3;
	result->atexit_max_idle = 2;
	result->atexit_max_open_persist = 10;

	GRID_INFO("SERVER ready with epollfd[%d] pipe[%d,%d]",
			result->epollfd, result->wakeup[0], result->wakeup[1]);

	return result;
}

void
network_server_clean(struct network_server_s *srv)
{
	if (!srv)
		return;

	if (srv->thread_events != NULL) {
		GRID_WARN("EventThread not joined!");
		g_error("EventThread not joined!");
	}
	if (srv->thread_first_worker) {
		GRID_WARN("FirstThread not joined!");
		g_error("FirstThread not joined!");
	}

	if (srv->lock_threads)
		g_mutex_free(srv->lock_threads);

	network_server_close_servers(srv);

	if (srv->endpointv) {
		struct endpoint_s **u;
		for (u=srv->endpointv; *u ;u++)
			g_free(*u);
		g_free(srv->endpointv);
	}

	if (srv->stats) {
		grid_stats_holder_clean(srv->stats);
	}

	metautils_pclose(&(srv->wakeup[0]));
	metautils_pclose(&(srv->wakeup[1]));

	if (srv->queue_monitor) {
		g_async_queue_unref(srv->queue_monitor);
		srv->queue_monitor = NULL;
	}

	if (srv->queue_events) {
		g_async_queue_unref(srv->queue_events);
		srv->queue_events = NULL;
	}

	if (srv->workers_active_1) {
		grid_single_rrd_destroy(srv->workers_active_1);
		srv->workers_active_1 = NULL;
	}
	if (srv->workers_active_60) {
		grid_single_rrd_destroy(srv->workers_active_60);
		srv->workers_active_60 = NULL;
	}

	g_free(srv);
}

static void
_bind_host(struct network_server_s *srv, const gchar *url, gpointer u,
		network_transport_factory factory, guint32 flags)
{
	gchar *port;
	struct endpoint_s *e;
	gsize len;

	EXTRA_ASSERT(srv != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(factory != NULL);

	/* endpoint creation */
	len = strlen(url);
	e = g_malloc0(sizeof(*e) + 1 + len);
	e->magic = MAGIC_ENDPOINT;
	e->fd = -1;
	e->flags = flags;
	e->factory_udata = u;
	e->factory_hook = factory;
	memcpy(e->url, url, len);

	if (NULL != (port = strrchr(e->url, ':'))) {
		*port = '\0';
		++ port;
		e->port_cfg = atoi(port);
	}

	GRID_DEBUG("URL configured : fd=%d port=%d endpoint=%s",
			e->fd, e->port_cfg, e->url);

	/* append the endpoint to the array in the server */
	len = g_strv_length((gchar**) srv->endpointv);
	srv->endpointv = g_realloc(srv->endpointv, sizeof(struct endpoint_s*) * (len+2));
	srv->endpointv[len] = e;
	srv->endpointv[len+1] = NULL;
}

void
network_server_bind_host(struct network_server_s *srv, const gchar *url, gpointer u,
		network_transport_factory factory)
{
	_bind_host(srv, url, u, factory, 0);
}

void
network_server_bind_host_lowlatency(struct network_server_s *srv,
		const gchar *url, gpointer u, network_transport_factory factory)
{
	_bind_host(srv, url, u, factory, NETSERVER_LATENCY);
}

void
network_server_bind_host_throughput(struct network_server_s *srv, const gchar *url, gpointer u,
		network_transport_factory factory)
{
	_bind_host(srv, url, u, factory, NETSERVER_THROUGHPUT);
}

void
network_server_close_servers(struct network_server_s *srv)
{
	struct endpoint_s **pu, *u;

	EXTRA_ASSERT(srv != NULL);
	for (pu=srv->endpointv; pu && (u = *pu) ;pu++) {
		if (u->fd >= 0)
			metautils_pclose(&(u->fd));
		u->port_real = 0;
	}
}

GError *
network_server_open_servers(struct network_server_s *srv)
{
	struct endpoint_s **u;

	EXTRA_ASSERT(srv != NULL);

	for (u=srv->endpointv; u && *u ;u++) {
		GError *err;
		if (NULL != (err = _endpoint_open(*u))) {
			g_prefix_error(&err, "url open error : ");
			network_server_close_servers(srv);
			return err;
		}
	}

	for (u=srv->endpointv; u && *u ;u++) {
		GRID_DEBUG("fd=%d port=%d endpoint=%s ready", (*u)->fd,
				(*u)->port_real, (*u)->url);
	}

	return NULL;
}

static void
_drain(int fd)
{
	char buff[2048];
	while (0 < read(fd, buff, sizeof(buff))) {}
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
	ev.data.ptr = srv->wakeup;
	ev.events = EPOLLIN|EPOLLET|EPOLLONESHOT;

	if (0 == epoll_ctl(srv->epollfd, how, srv->wakeup[0], &ev))
		return;
	GRID_DEBUG("WUP epoll_ctl(%d,%d,%s) = (%d) %s", srv->epollfd,
			srv->wakeup[0], epoll2str(how), errno, strerror(errno));
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

#define MAXEV 64

static void
_manage_client_event(struct network_server_s *srv,
		struct network_client_s *clt, register int ev0,
		struct timespec *now)
{
	_client_remove_from_monitored(srv, clt);

	if (!srv->flag_continue)
		clt->transport.waiting_for_close = TRUE;

	ev0 = MACRO_COND(ev0 & EPOLLIN, CLT_READ, 0)
		| MACRO_COND(ev0 & EPOLLOUT, CLT_WRITE, 0)
		| MACRO_COND(ev0 & (EPOLLERR|EPOLLHUP|EPOLLRDHUP), CLT_ERROR, 0);
	clt->events = MACRO_COND(!ev0, CLT_ERROR, ev0);

	if (ev0 & EPOLLIN)
		memcpy(&clt->time.evt_in, now, sizeof(struct timespec));

	if (clt->events & CLT_ERROR)
		ARM_CLIENT(srv, clt, EPOLL_CTL_DEL);
	g_async_queue_push(srv->queue_events, clt);
}

static void
_manage_events(struct network_server_s *srv)
{
	struct network_client_s *clt;
	struct epoll_event allev[MAXEV], *pev;
	struct timespec now;
	int rc, erc;

	(void) rc;
	erc = epoll_wait(srv->epollfd, allev, MAXEV, 500);
	if (erc > 0) {
		network_server_now(&now);
		while (erc-- > 0) {
			pev = allev+erc;

			if (pev->data.ptr == srv->wakeup)
				continue;
			if (MAGIC_ENDPOINT == *((unsigned int*)(pev->data.ptr))) {
				struct endpoint_s *e = pev->data.ptr;
				while (NULL != (clt = _endpoint_manage_event(srv, e))) {
					if (clt->current_error) {
						_client_clean(srv, clt);
					} else {
						ARM_CLIENT(srv, clt, EPOLL_CTL_ADD);
					}
				}
				ARM_ENDPOINT(srv, e, EPOLL_CTL_MOD);
			}
			else {
				_manage_client_event(srv, pev->data.ptr, pev->events, &now);
			}
		}
	}

	_drain(srv->wakeup[0]);
	ARM_WAKER(srv, EPOLL_CTL_MOD);
	while (NULL != (clt = g_async_queue_try_pop(srv->queue_monitor))) {
		EXTRA_ASSERT(clt->events != 0 && !(clt->events & CLT_ERROR));
		ARM_CLIENT(srv, clt, EPOLL_CTL_MOD);
	}
}

static void
_server_shutdown_inactive_connections(struct network_server_s *srv)
{
	struct network_client_s *clt, *n;

	time_t now = network_server_bogonow(srv);
	time_t ti = now - srv->atexit_max_idle;
	time_t tc = now - srv->atexit_max_open_never_input;
	time_t tp = now - srv->atexit_max_open_persist;

	for (clt=srv->first ; clt ; clt=n) {
		n = clt->next;
		EXTRA_ASSERT(clt->fd >= 0);
		if (clt->time.evt_in.tv_sec) {
			if (clt->time.evt_in.tv_sec < ti || clt->time.cnx < tp) {
				_manage_client_event(srv, clt, 0, NULL);
			}
		}
		else if (clt->time.cnx < tc) { /* never input */
			_manage_client_event(srv, clt, 0, NULL);
		}
	}
}

static gpointer
_thread_cb_events(gpointer d)
{
	struct network_server_s *srv = d;
	time_t now, last;

	metautils_ignore_signals();
	GRID_INFO("EVENTS thread starting pfd=%d", srv->epollfd);

	now = last = network_server_bogonow(srv);

	while (srv->flag_continue) {
		_manage_events(srv);
		now = network_server_bogonow(srv);
		if (now > last + 30 || now < last) {
			_server_shutdown_inactive_connections(srv);
			last = now;
		}
	}

	/* XXX the server connections are being closed in the main thread that
	 * received the exit signal. They will be removed automatically from
	 * the epoll pool.*/

	while (0 < srv->cnx_clients) {
		_manage_events(srv);
		_server_shutdown_inactive_connections(srv);
	}

	return d;
}

GError *
network_server_run(struct network_server_s *srv)
{
	struct endpoint_s **pu, *u;
	time_t now, last_update;
	GError *err = NULL;

	/* Sanity checks */
	EXTRA_ASSERT(srv != NULL);
	for (pu=srv->endpointv; (u = *pu) ;pu++) {
		if (u->fd < 0)
			return NEWERROR(EINVAL,
					"DESIGN ERROR : some servers are not open");
	}
	if (!srv->flag_continue)
		return NULL;

	for (pu=srv->endpointv; srv->flag_continue && (u = *pu) ;pu++)
		ARM_ENDPOINT(srv, u, EPOLL_CTL_ADD);
	ARM_WAKER(srv, EPOLL_CTL_ADD);

	_server_start_one_worker(srv, FALSE);
	srv->thread_events = g_thread_create(_thread_cb_events, srv, TRUE, NULL);

	clock_gettime(CLOCK_MONOTONIC_COARSE, &srv->now);
	last_update = network_server_bogonow(srv);
	while (srv->flag_continue) {
		now = network_server_bogonow(srv);
		if (last_update < now) {
			_server_update_main_stats(srv);
			last_update = now;
		}
		usleep(_start_necessary_threads(srv) ? 50000 : 500000);
		clock_gettime(CLOCK_MONOTONIC_COARSE, &srv->now);
	}

	network_server_close_servers(srv);

	/* Wait for all the workers */
	while (srv->workers_total) {
		GRID_DEBUG("Waiting for %u workers to die", srv->workers_total);
		usleep(200000);
		clock_gettime(CLOCK_MONOTONIC_COARSE, &srv->now);
	}
	srv->thread_first_worker = NULL;

	/* wait for the first event thread */
	if (srv->thread_events) {
		g_thread_join(srv->thread_events);
		srv->thread_events = NULL;
	}

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

struct grid_stats_holder_s *
network_server_get_stats(struct network_server_s *srv)
{
	EXTRA_ASSERT(srv != NULL);
	return srv->stats;
}

gint
network_server_pending_events(struct network_server_s *srv)
{
	if (NULL == srv || NULL == srv->queue_events)
		return G_MAXINT;
	return g_async_queue_length(srv->queue_events);
}

gdouble
network_server_reqidle(struct network_server_s *srv)
{
	gint pending = network_server_pending_events(srv);
	if (pending == G_MAXINT)
		return 0.0;
	if (pending < 1)
		pending = 1;
	gdouble d = pending;
	return 100.0 / d;
}

time_t
network_server_bogonow(const struct network_server_s *srv)
{
	return srv->now.tv_sec;
}

void
network_server_now(struct timespec *ts)
{
	clock_gettime(CLOCK_MONOTONIC, ts);
}


/* Endpoint features ------------------------------------------------------- */

static gboolean
_endpoint_bind(struct endpoint_s *u, int port)
{
	struct sockaddr_in ss;
	socklen_t ss_len;

	EXTRA_ASSERT(port >= 0 && port < 65536);

	memset(&ss, 0, sizeof(ss));
	ss_len = sizeof(ss);
	ss.sin_family = AF_INET;
	ss.sin_port = htons(port);
	inet_pton(AF_INET, u->url, &(ss.sin_addr));

	sock_set_reuseaddr(u->fd, TRUE);

	if (0 > bind(u->fd, (struct sockaddr*)&ss, ss_len)) {
		u->port_real = 0;
		return FALSE;
	}

	fcntl(u->fd, F_SETFL, (fcntl(u->fd, F_GETFL)|O_NONBLOCK));

	memset(&ss, 0, sizeof(ss));
	ss_len = sizeof(ss);
	getsockname(u->fd, (struct sockaddr*)&ss, &ss_len);

	u->port_real = ntohs(ss.sin_port);
	return TRUE;
}

static GError *
_endpoint_open(struct endpoint_s *u)
{
	EXTRA_ASSERT(u != NULL);

	u->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (u->fd < 0)
		return NEWERROR(errno, "socket() = '%s'", strerror(errno));

	sock_set_reuseaddr(u->fd, TRUE);
	sock_set_non_blocking(u->fd, TRUE);

	/* Bind the socket on our URL */
	if (!_endpoint_bind(u, u->port_cfg))
		return NEWERROR(errno, "bind() = '%s'", strerror(errno));

	/* make the socket listen to incoming connections */
	if (0 > listen(u->fd, 32768))
		return NEWERROR(errno, "listen() = '%s'", strerror(errno));

	return NULL;
}

static struct network_client_s *
_endpoint_manage_event(struct network_server_s *srv, struct endpoint_s *e)
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
			sock_set_linger_default(fd);
			sock_set_nodelay(fd, TRUE);
			sock_set_tcpquickack(fd, TRUE);
			break;
		default:
			break;
	}

	struct network_client_s *clt = g_malloc0(sizeof(*clt));
	if (NULL == clt) {
		metautils_pclose(&fd);
		_cnx_notify_close(srv);
		return NULL;
	}

	if (_cnx_notify_accept(srv))
		clt->current_error = NEWERROR(CODE_UNAVAILABLE, "Server overloaded.");

	clt->main_stats = srv->stats;
	clt->server = srv;
	clt->fd = fd;
	grid_sockaddr_to_string((struct sockaddr*)&ss,
			clt->peer_name, sizeof(clt->peer_name));
	_client_sock_name(fd, clt->local_name, sizeof(clt->local_name));
	clt->time.cnx = network_server_bogonow(srv);
	clt->events = CLT_READ;

	clt->input.first = clt->input.last = NULL;
	clt->output.first = clt->output.last = NULL;

	if (e->factory_hook)
		e->factory_hook(e->factory_udata, clt);
	return clt;
}

/* Server features ---------------------------------------------------------- */

static void
_server_start_one_worker(struct network_server_s *srv, gboolean counters_changed)
{
	if (!srv->flag_continue)
		return;

	if (!counters_changed)
		_thread_start(srv);

	GThread *th = g_thread_create(_thread_cb_worker, srv, TRUE, NULL);

	if (!th) {
		_thread_stop(srv);
		g_message("Thread creation failure : worker");
	}
}

static void
_server_update_main_stats(struct network_server_s *srv)
{
	guint64 max_sec[30], max_min[60];
	time_t now = network_server_bogonow(srv);

	g_mutex_lock(srv->lock_threads);
	grid_single_rrd_get_allmax(srv->workers_active_1, now, 30, max_sec);
	grid_single_rrd_get_allmax(srv->workers_active_60, now/60, 60, max_min);
	g_mutex_unlock(srv->lock_threads);

	grid_stats_holder_set(srv->stats,
			"server.thread.gauge.min", guint_to_guint64(srv->workers_minimum),
			"server.thread.gauge.max", guint_to_guint64(srv->workers_maximum),
			"server.thread.gauge.total", guint_to_guint64(srv->workers_total),
			"server.thread.gauge.active", guint_to_guint64(srv->workers_active),
			"server.cnx.gauge.client", guint_to_guint64(srv->cnx_clients),
			"server.cnx.gauge.max", guint_to_guint64(srv->cnx_max),
			"server.cnx.gauge.max_sys", guint_to_guint64(srv->cnx_max_sys),

			"server.thread.counter.created", srv->counter_created,
			"server.thread.counter.destroyed", srv->counter_destroyed,
			"server.thread.counter.hit_max", srv->counter_hitmax,
			"server.thread.counter.active_in", srv->active_in,
			"server.thread.counter.active_out", srv->active_out,
			"server.cnx.counter.accept", srv->cnx_accept,
			"server.cnx.counter.close", srv->cnx_close,

			"server.thread.max.1", max_sec[1], // 0 is probably uncomplete
			"server.thread.max.5", max_sec[4],
			"server.thread.max.15", max_sec[14],
			"server.thread.max.30", max_sec[29],
			"server.thread.max.60", max_min[1], // idem
			"server.thread.max.300", max_min[4],
			"server.thread.max.900", max_min[14],
			"server.thread.max.3600", max_min[59],
			NULL);
}

void
network_server_set_maxcnx(struct network_server_s *srv, guint max)
{
	EXTRA_ASSERT(srv != NULL);

	guint emax = CLAMP(max, 2, srv->cnx_max_sys);

	if (emax != max)
		GRID_WARN("MAXCNX [%u] clamped to [%u]", max, emax);

	if (srv->cnx_max != emax) {
		GRID_INFO("MAXCNX [%u] changed to [%u]", srv->cnx_max, emax);
		srv->cnx_max = emax;
	}
}

void
network_server_set_cnx_backlog(struct network_server_s *srv, guint cnx_bl)
{
	EXTRA_ASSERT(srv != NULL);

	guint max_bl = MAX(srv->cnx_max - srv->workers_maximum, 0);
	guint bl = MIN(cnx_bl, max_bl);

	if (bl != cnx_bl)
		GRID_WARN("CNX BACKLOG clamped to [%u]", bl);

	if (bl != srv->cnx_backlog) {
		GRID_INFO("CNX BACKLOG changed to [%u]", bl);
		srv->cnx_backlog = bl;
	}
}

static gboolean
_thread_maybe_become_first(struct network_server_s *srv)
{
	gboolean is_first = FALSE;

	if (!srv->thread_first_worker) {
		g_mutex_lock(srv->lock_threads);
		if (!srv->thread_first_worker) {
			srv->thread_first_worker = g_thread_self();
			is_first = TRUE;
		}
		g_mutex_unlock(srv->lock_threads);
	}

	return is_first;
}

static struct network_client_s *
get_next_client(struct network_server_s *srv)
{
	GTimeVal when;
	g_get_current_time(&when);
	g_time_val_add(&when, 1000000L);
	return g_async_queue_timed_pop(srv->queue_events, &when);
}

static void
_work_on_client(struct network_server_s *srv, struct network_client_s *clt)
{
	if ((clt->events & CLT_ERROR) || !clt->events) {
		_client_clean(srv, clt);
		return;
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
		write(srv->wakeup[1], "", 1);
	}
}

static gpointer
_thread_cb_worker(gpointer td)
{
	struct grid_stats_holder_s *local_stats = NULL;
	time_t last_update, last_not_idle;
	struct network_server_s *srv = td;

	metautils_ignore_signals();
	_thread_maybe_become_first(srv);
	last_update = last_not_idle = network_server_bogonow(srv);
	local_stats = grid_stats_holder_init();
	GRID_DEBUG("Thread starting for srv %p", srv);

	while (srv->flag_continue || srv->cnx_clients > 0) {
		struct network_client_s *clt = get_next_client(srv);
		if (!clt) {
			gboolean expired = network_server_bogonow(srv) >
				(last_not_idle + srv->workers_max_idle_delay);
			if (expired && _thread_can_die(srv)) {
				GRID_DEBUG("Thread idle for too long, exiting!");
				goto label_exit;
			}
		}
		else { /* something happened */
			EXTRA_ASSERT(clt->server == srv);

			_thread_become_active(srv);
			last_not_idle = network_server_bogonow(srv);
			clt->local_stats = local_stats;
			_work_on_client(srv, clt);
			_thread_become_inactive(srv);
		}

		/* periodically merge the local stats in the main stats */
		if (last_update < network_server_bogonow(srv)) {
			grid_stats_holder_increment_merge(srv->stats, local_stats);
			grid_stats_holder_zero(local_stats);
			last_update = network_server_bogonow(srv);
		}
	}

	/* thread exiting due to a server stop */
	GRID_DEBUG("Thread exiting for srv %p", srv);
	_thread_stop(srv);

label_exit:
	if (local_stats) {
		grid_stats_holder_increment_merge(srv->stats, local_stats);
		grid_stats_holder_clean(local_stats);
	}
	return td;
}

static guint
_server_count_procs(void)
{
	FILE *in;
	gchar line[512];
	guint count = 0;

	in = fopen("/proc/cpuinfo", "r");
	if (in) {
		memset(line, 0, sizeof(line));
		while (fgets(line, sizeof(line), in)) {
			if (g_str_has_prefix(line, "processor"))
				count ++;
		}
		fclose(in);
	}

	return MACRO_COND(count < 2, 1, count);
}

static guint
_server_get_maxfd(void)
{
	struct rlimit limit;

	if (0 != getrlimit(RLIMIT_NOFILE, &limit)) {
		GRID_WARN("getrlimit() error : (%d) %s", errno, strerror(errno));
		return 512;
	}
	else {
		guint u = limit.rlim_cur;
		return u;
	}
}

/* Thread counters handling ------------------------------------------------- */

static void
_thread_start(struct network_server_s *srv)
{
	g_mutex_lock(srv->lock_threads);
	srv->workers_total ++;
	srv->counter_created ++;
	g_mutex_unlock(srv->lock_threads);
}

static void
_thread_stop(struct network_server_s *srv)
{
	g_mutex_lock(srv->lock_threads);
	srv->workers_total --;
	srv->counter_destroyed ++;
	g_mutex_unlock(srv->lock_threads);
}

static gboolean
_thread_too_few(struct network_server_s *srv, guint total)
{
	return total < srv->workers_minimum
		|| ((total - srv->workers_active) < srv->workers_minimum_spare);
}

static void
_thread_become_active(struct network_server_s *srv)
{
	time_t now = network_server_bogonow(srv);

	g_mutex_lock(srv->lock_threads);

	++ srv->workers_active;
	++ srv->active_in;

	grid_single_rrd_set_default(srv->workers_active_1,
			srv->workers_active);
	grid_single_rrd_set_default(srv->workers_active_60,
			srv->workers_active);

	grid_single_rrd_pushifmax(srv->workers_active_1, now,
			srv->workers_active);
	grid_single_rrd_pushifmax(srv->workers_active_60, now/60,
			srv->workers_active);

	if (_thread_too_few(srv, srv->workers_total)) {
		srv->workers_hit_max ++;
		srv->counter_hitmax ++;
	}
	g_mutex_unlock(srv->lock_threads);
}

static void
_thread_become_inactive(struct network_server_s *srv)
{
	time_t now = network_server_bogonow(srv);

	g_mutex_lock(srv->lock_threads);

	-- srv->workers_active;
	++ srv->active_out;

	grid_single_rrd_set_default(srv->workers_active_1,
			srv->workers_active);
	grid_single_rrd_set_default(srv->workers_active_60,
			srv->workers_active);

	grid_single_rrd_pushifmax(srv->workers_active_1, now,
			srv->workers_active);
	grid_single_rrd_pushifmax(srv->workers_active_60, now / 60,
			srv->workers_active);

	if (_thread_too_few(srv, srv->workers_total)) {
		srv->workers_hit_max ++;
		srv->counter_hitmax ++;
	}
	g_mutex_unlock(srv->lock_threads);
}

static gboolean
_thread_can_die(struct network_server_s *srv)
{
	gboolean rc = FALSE;

	if (srv->thread_first_worker == g_thread_self())
		return FALSE;

	g_mutex_lock(srv->lock_threads);
	if (_thread_too_few(srv, srv->workers_total-1)) {
		srv->counter_hitmax ++;
		srv->workers_hit_max ++;
	}
	else if (!srv->workers_hit_max) {
		srv->workers_total --;
		srv->counter_destroyed ++;
		rc = TRUE;
	}
	g_mutex_unlock(srv->lock_threads);

	return rc;
}

static gboolean
_thread_must_start(struct network_server_s *srv)
{
	gboolean rc = FALSE;

	g_mutex_lock(srv->lock_threads);
	if (srv->workers_total < srv->workers_maximum) {
		if (srv->workers_hit_max || _thread_too_few(srv, srv->workers_total)) {
			srv->workers_total ++;
			srv->counter_created ++;
			rc = TRUE;
		}
	}
	srv->workers_hit_max = 0;
	g_mutex_unlock(srv->lock_threads);

	return rc;
}

static gboolean
_thread_can_start(struct network_server_s *srv)
{
	gboolean rc = FALSE;

	g_mutex_lock(srv->lock_threads);
	if (srv->flag_continue && srv->workers_total < srv->workers_maximum) {
		srv->workers_total ++;
		srv->counter_created ++;
		rc = TRUE;
	}
	g_mutex_unlock(srv->lock_threads);

	return rc;
}

static guint
_start_necessary_threads(struct network_server_s *srv)
{
	guint count = 0;
	gint length;

	if (!srv->flag_continue)
		return 0;

	for (; _thread_must_start(srv) ;count++)
		_server_start_one_worker(srv, TRUE);

	while (srv->flag_continue) {
		length = g_async_queue_length(srv->queue_events);
		if (length < 0)
			break;
		if (((guint)length) < srv->workers_total)
			break;
		if (!_thread_can_start(srv))
			break;
		_server_start_one_worker(srv, TRUE);
		count ++;
	}

	return count;
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
	(void) srv;

	/* Notifies the upper layer the client is being exiting. */
	if (clt->transport.notify_error)
		clt->transport.notify_error(clt);

	EXTRA_ASSERT(clt->prev == NULL);
	EXTRA_ASSERT(clt->next == NULL);
	EXTRA_ASSERT(clt->fd >= 0);

	metautils_pclose(&(clt->fd));
	_cnx_notify_close(srv);

	clt->local_stats = NULL;
	clt->main_stats = NULL;
	clt->flags = clt->events = 0;
	bzero(&(clt->time), sizeof(clt->time));

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

	g_free(clt);
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
		if (!client->transport.notify_input)
			return RC_PROCESSED;
		if (!data_slab_sequence_has_data(&(client->input))) {
			/* drain the data */
			data_slab_sequence_clean_data(&(client->input));
			return RC_PROCESSED;
		}
		GRID_TRACE2("fd=%d passing %u/%"G_GSIZE_FORMAT" to transport %p",
				client->fd, total,
				data_slab_sequence_size(&(client->input)),
				client->transport.notify_input);
		return client->transport.notify_input(client);
	}

	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->fd >= 0);

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

	client->time.evt_out = network_server_bogonow(client->server);

	if (!_client_ready_for_output(client)) {
		register int type = ds->type;
		GRID_DEBUG("fd=%d Discarding data, output closed", client->fd);
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
	EXTRA_ASSERT(clt->fd >= 0);

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

