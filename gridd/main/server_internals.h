/*
OpenIO SDS gridd
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__gridd__main__server_internals_h
# define OIO_SDS__gridd__main__server_internals_h 1

#include <glib.h>
#include <gridd/main/message_handler.h>
#include <gridd/main/sock.h>

#define NAME_GENERAL "General"
#define NAME_SERVICE "Service"
#define NAME_SERVICETAGS "ServiceTags"
#define NAME_SRV_TYPE "type"
#define NAME_NAMESPACE "namespace"
#define NAME_REGISTER "register"
#define NAME_LOAD_NS_INFO "load_ns_info"
#define NAME_PIDFILE "pidfile"
#define NAME_DAEMON "daemon"
#define NAME_PATH "path"
#define NAME_PARAM "param"
#define NAME_PLUGINS "plugins"
#define NAME_SERVERS "servers"
#define NAME_LISTEN "listen"
#define NAME_TIMEOUT_CNX "to_cnx"
#define NAME_TIMEOUT_OP "to_op"
#define NAME_WORKERS "workers"
#define NAME_MIN_WORKERS "min_workers"
#define NAME_MIN_SPARE_WORKERS "min_spare_workers"
#define NAME_MAX_SPARE_WORKERS "max_spare_workers"
#define NAME_MAX_WORKERS "max_workers"
#define NAME_ALERT_PERIOD "alert_period"

#define SIZE_SRVNAME 64
#define SIZE_PLUGINNAME 64
#define SIZE_MSGHANDLERNAME 64

#define GET_NS_INFO_RETRY_DELAY 10

#ifndef DAEMON_DEFAULT_TIMEOUT_ACCEPT
#define DAEMON_DEFAULT_TIMEOUT_ACCEPT 1000
#endif

#ifndef DAEMON_DEFAULT_TIMEOUT_READ
#define DAEMON_DEFAULT_TIMEOUT_READ 1000
#endif

struct buffer_s {
	guint8 *buf;
	gsize size;
	gsize offset;
};

/*message handlers, loaded from plugins*/
struct message_handler_s {
	gchar                     name[SIZE_MSGHANDLERNAME];
	message_matcher_f         matcher;
	message_handler_f         handler;
	gpointer                  udata;
	struct message_handler_s *next;
	message_handler_v2_f	  handler_v2;
};

#define CHECK_WORKER_COUNTERS(Min,Max,MinSpare,MaxSpare) do {\
	if (Min < 1) Min = 1;\
	if (Max < 1) Max = 1;\
	if (MinSpare <= 0) MinSpare = 0;\
	if (MaxSpare < 1) MaxSpare = 1;\
	if (MaxSpare < MinSpare) MaxSpare = MinSpare;\
	if (Max < Min) Max = Min;\
} while (0)

struct thread_monitoring_s {
	gint nb_workers;        /* gauge */
	gint used_workers;      /* gauge */
	gint max_workers;       /* gauge */
	gint max_spare_workers; /* gauge */
	gint min_spare_workers; /* gauge */
	gint min_workers;       /* gauge */

	/* for stats purposes */
	guint64 max_reached;       /* counter */
	guint64 wake;              /* counter */
	guint64 creation;          /* counter */
	guint64 destruction;       /* counter */
};

struct alert_cfg_s {
	time_t last_sent;
	time_t frequency;
};

/*servers and the message handlers used by them*/
typedef struct server_s {
	/*used to chain the servers*/
	struct server_s *next;
	/**/
	GRecMutex recMutex;
	struct thread_monitoring_s mon;
	struct thread_monitoring_s mon0;
	/**/
	gchar name[SIZE_SRVNAME];
	ACCEPT_POOL ap;
	gint to_connection;
	gint to_operation;
	struct message_handler_s **handlers;
	gint nbHandlers;
	/**/
	struct alert_cfg_s alert_cfg;
} *SERVER;

struct server_stats_s {
	guint64 total;
	guint64 created;
	guint64 stopped;
};

volatile gboolean may_continue;

extern char *config_file;

extern gsize default_to_operation;
extern gsize default_to_connection;
extern gsize default_max_workers;
extern gsize default_max_spare_workers;
extern gsize default_min_spare_workers;
extern gsize default_min_workers;
extern struct message_handler_s BEACON_MSGHANDLER;
extern struct server_s BEACON_SRV;

/* NEW WAY INFORMATION */
extern gboolean old_style;

#endif /*OIO_SDS__gridd__main__server_internals_h*/
