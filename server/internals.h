/*
OpenIO SDS server
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__server__internals_h
# define OIO_SDS__server__internals_h 1

#include <metautils/lib/metautils.h>
#include <server/network_server.h>

# ifndef  OIO_STAT_PREFIX_REQ
#  define OIO_STAT_PREFIX_REQ "counter req.hits"
# endif

# ifndef  OIO_STAT_PREFIX_TIME
#  define OIO_STAT_PREFIX_TIME "counter req.time"
# endif

/* How long (in microseconds) a connection might stay idle between two
 * requests */
#ifndef  SERVER_DEFAULT_CNX_IDLE
# define SERVER_DEFAULT_CNX_IDLE  (5 * G_TIME_SPAN_MINUTE)
#endif

/* How long (in microseconds) a connection might exist since its creation
 * (whatever it is active or not) */
#ifndef  SERVER_DEFAULT_CNX_LIFETIME
# define SERVER_DEFAULT_CNX_LIFETIME  (2 * G_TIME_SPAN_HOUR)
#endif

/* How long (in microseconds) a connection might exist since its creation
 * when it received no request at all */
#ifndef  SERVER_DEFAULT_CNX_INACTIVE
# define SERVER_DEFAULT_CNX_INACTIVE  (30 * G_TIME_SPAN_SECOND)
#endif

enum {
	NETSERVER_THROUGHPUT = 0x0001,
	NETSERVER_LATENCY    = 0x0002,
};

enum {
	EXCESS_NONE = 0,
	EXCESS_HARD
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
	GThreadPool *pool_stats;
	GThreadPool *pool_workers;

	GAsyncQueue *queue_monitor; /* from the workers to the events_thread */

	GMutex lock_stats;
	GArray *stats; /* <struct server_stat_s> */

	GMutex lock_threads;

	guint64 active_in;
	guint64 active_out;

	guint64 cnx_accept;
	guint64 cnx_close;
	guint cnx_max_sys;
	guint cnx_max;
	volatile guint cnx_clients;
	guint cnx_backlog;

	gint64 atexit_max_open_never_input; /*< max delay for cnx without any input.*/
	gint64 atexit_max_idle; /*< max idle time since last input */
	gint64 atexit_max_open_persist; /*< max total time for persistant cnx*/

	GQuark gq_gauge_threads;
	GQuark gq_gauge_cnx_current;
	GQuark gq_gauge_cnx_max;
	GQuark gq_gauge_cnx_maxsys;
	GQuark gq_counter_cnx_accept;
	GQuark gq_counter_cnx_close;

	int wakeup[2];
	int epollfd;
	volatile gboolean flag_continue;
	gboolean abort_allowed;
};

enum
{
	NETCLIENT_IN_CLOSED         = 0x0001,
	NETCLIENT_OUT_CLOSED        = 0x0002,
	NETCLIENT_OUT_CLOSE_PENDING = 0x0004,
	NETCLIENT_IN_PAUSED         = 0x0008,
};

#endif /*OIO_SDS__server__internals_h*/
