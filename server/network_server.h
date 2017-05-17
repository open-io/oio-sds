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

#ifndef OIO_SDS__server__network_server_h
# define OIO_SDS__server__network_server_h 1

# include <server/slab.h>

struct network_server_s;
struct grid_stats_holder_s;
struct network_client_s;
struct network_transport_s;
struct gba_view_s;

/* To be defined by the application instatiating the transport */
struct transport_client_context_s;

enum {
	RC_ERROR,
	RC_NODATA,
	RC_NOTREADY,
	RC_PROCESSED,
};

struct server_stat_s /* stored in the server */
{
	guint64 value;
	GQuark  which;
};

struct server_stat_msg_s /* sent by the workers */
{
	guint64  value[4];
	GQuark   which[4];
	gboolean increment : 1; /* FALSE -> reset */
};

typedef void (*network_transport_cleaner_f) (
			struct transport_client_context_s*);

struct network_transport_s
{
	/* Associate private data to the  */
	struct transport_client_context_s *client_context;

	network_transport_cleaner_f clean_context;

	/* Be notified that a piece of data is ready */
	int (*notify_input)  (struct network_client_s *);
	void (*notify_error)  (struct network_client_s *);
	gboolean waiting_for_close;
};

enum network_client_event_e {
	CLT_READ=0X01,
	CLT_WRITE=0X02,
	CLT_ERROR=0X04
};

struct network_client_s
{
	int fd;
	enum network_client_event_e events;
	struct network_server_s *server;

	int flags;
	struct { /* monotonic timers */
		gint64 cnx;
		gint64 evt_out;
		gint64 evt_in;
	} time;

	/* Pending input */
	struct data_slab_sequence_s input;
	/* Pending output */
	struct data_slab_sequence_s output;
	/* What to do with pending data */
	struct network_transport_s transport;
	GError *current_error;

	struct network_client_s *prev; /*!< DO NOT USE */
	struct network_client_s *next; /*!< DO NOT USE */

	gchar local_name[128];
	gchar peer_name[128];
};

extern GQuark gq_count_all;
extern GQuark gq_time_all;
extern GQuark gq_count_unexpected;
extern GQuark gq_time_unexpected;
extern GQuark gq_count_overloaded;
extern GQuark gq_time_overloaded;

struct network_server_s * network_server_init(void);

/* Re-set the limits of the server with the values stored in the central
 * configuration facility */
void network_server_reconfigure(struct network_server_s *srv);

/* must be called PRIOR to network_server_open_servers */
void network_server_allow_udp(struct network_server_s *srv);

typedef void (*network_transport_factory) (gpointer u,
		struct network_client_s *clt);

void network_server_bind_host(struct network_server_s *srv,
		const gchar *url, gpointer factory_udata,
		network_transport_factory factory);

void network_server_bind_host_throughput(struct network_server_s *srv,
		const gchar *url, gpointer factory_udata,
		network_transport_factory factory);

/* returns a NULL-terminated array of strings, containing the actual IP:PORT
 * the server has been bond to, in the order they have been declared.
 * @param srv MUST be a valid server
 * @return a valid (but maybe empty) array of string, NULL terminated. Free it
 *         with g_strfreev() */
gchar** network_server_endpoints (struct network_server_s *srv);

int network_server_first_udp (struct network_server_s *srv);

void network_server_bind_host_lowlatency(struct network_server_s *srv,
		const gchar *url, gpointer factory_udata,
		network_transport_factory factory);

void network_server_close_servers(struct network_server_s *srv);

GError * network_server_open_servers(struct network_server_s *srv);

GError * network_server_run(struct network_server_s *srv,
		void (*on_reload)(void));

void network_server_stop(struct network_server_s *srv);

void network_server_clean(struct network_server_s *srv);

void network_server_stat_push2 (struct network_server_s *srv, gboolean inc,
		GQuark k1, guint64 v1, GQuark k2, guint64 v2);

void network_server_stat_push4 (struct network_server_s *srv, gboolean inc,
		GQuark k1, guint64 v1, GQuark k2, guint64 v2,
		GQuark k3, guint64 v3, GQuark k4, guint64 v4);

/* Synchronosly get the current value of the stat named <which> */
guint64 network_server_stat_getone (struct network_server_s *srv, GQuark which);

GArray* network_server_stat_getall (struct network_server_s *srv);

/* -------------------------------------------------------------------------- */

void network_client_allow_input(struct network_client_s *clt, gboolean v);

void network_client_close_output(struct network_client_s *clt, int now);

int network_client_send_slab(struct network_client_s *client,
		struct data_slab_s *slab);

#endif /*OIO_SDS__server__network_server_h*/
