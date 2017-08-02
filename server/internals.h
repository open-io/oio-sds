/*
OpenIO SDS server
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

#ifndef OIO_SDS__server__internals_h
# define OIO_SDS__server__internals_h 1

#include <metautils/lib/metautils.h>
#include <server/network_server.h>

#ifndef OIO_SERVER_UDP_QUEUE_MAXLEN
#define OIO_SERVER_UDP_QUEUE_MAXLEN 8192
#endif

#ifndef OIO_SERVER_UDP_QUEUE_MAXAGE
#define OIO_SERVER_UDP_QUEUE_MAXAGE (2 * G_TIME_SPAN_SECOND)
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
	int fd_udp;
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

	GThread *thread_udp;
	GThread *thread_tcp;
	GThreadPool *pool_stats;
	GThreadPool *pool_tcp;
	GThreadPool *pool_udp;

	GAsyncQueue *queue_monitor; /* from the workers to the events_thread */

	GMutex lock_stats;
	GArray *stats; /* <struct server_stat_s> */

	GMutex lock_threads;

	guint64 cnx_accept;
	guint64 cnx_close;
	volatile guint cnx_max;
	volatile guint cnx_clients;

	GQuark gq_gauge_threads;
	GQuark gq_gauge_cnx_current;
	GQuark gq_counter_cnx_accept;
	GQuark gq_counter_cnx_close;

	int eventfd;
	int epollfd;
	volatile gboolean flag_continue;
	gboolean abort_allowed;
	gboolean udp_allowed;
};

enum
{
	NETCLIENT_IN_CLOSED         = 0x0001,
	NETCLIENT_OUT_CLOSED        = 0x0002,
	NETCLIENT_OUT_CLOSE_PENDING = 0x0004,
	NETCLIENT_IN_PAUSED         = 0x0008,
};

#endif /*OIO_SDS__server__internals_h*/
