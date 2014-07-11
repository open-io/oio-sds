#ifndef __SERVER_INTERNALS_H__
# define __SERVER_INTERNALS_H__

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

#define NAME_FATAL "fatal"
#define NAME_ERROR "error"
#define NAME_CRITICAL "critical"
#define NAME_WARNING "warning"
#define NAME_MESSAGE "message"
#define NAME_INFO "info"
#define NAME_DEBUG "debug"

#define SIZE_SRVNAME 64
#define SIZE_PLUGINNAME 64
#define SIZE_MSGHANDLERNAME 64

#define GET_NS_INFO_RETRY_DELAY 10

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
	GStaticRecMutex recMutex;
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


extern char *config_file;
extern char *log4c_file;
extern char *pid_file;

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
extern gchar* service_type;
extern gboolean rec_service;
extern gboolean load_ns_info;
extern namespace_info_t *ns_info;
extern addr_info_t *serv_addr;
extern GPtrArray *serv_tags;

#endif /*__SERVER_INTERNALS_H__*/
