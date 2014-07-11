#ifndef _GRIDAGENT_H
#define _GRIDAGENT_H

#include <metautils/lib/metatypes.h>

#define AGENT_DEFAULT_EVENT_XATTR "user.grid.agent.incoming-time"

#define AGENT_SOCK_PATH "/GRID/common/run/gridagent.sock"

#define MSG_SRVTYPE_LST "SRVTYPELST"
#define MSG_SRV_GET1 "SRVGET1"
#define MSG_SRV_LST "SRVLST"
#define MSG_SRV_PSH "SRVPSH"
#define MSG_SRV_CLR "SRVCLR"
#define MSG_SRV_CNT "SRVCNT"
#define MSG_EVT_PUSH "EVTPSH"
#define MSG_GETNS   "GETNS"
#define MSG_LSTSVC  "LSTSVC"
#define MSG_LSTTASK "LSTTASK"
#define MSG_ERRCID_STORE "ERRCID_STORE"
#define MSG_ERRCID_FETCH "ERRCID_FETCH"
#define MSG_ERRCID_FLUSH "ERRCID_FLUSH"
#define MSG_ERRCID_FIXED "ERRCID_FIXED"
#define MSG_ERRM2_UNREF "ERRM2_UNREF"

#define MSG_EVENTS_CONFIGURATION "EVT_CONFIG"
#define MSG_EVENTS_PATTERNS "EVT_PATTERNS"
#define MSG_SRVTYPE_CONFIG "SRVTYPE_CONFIG"

#define LIMIT_MAX_ERRCID 20000
#define MAX_TASKID_LENGTH 128

#define STATUS_OK 200
#define STATUS_ERROR 500

#define RAWX_INFO_URL "/info"
#define RAWX_STAT_URL "/stat"

#define SPOOL_DIRNAME_LENGTH 512
#define SUFFIX_SPOOL_INCOMING "incoming"
#define SUFFIX_SPOOL_TRASH    "trash"
#define SUFFIX_SPOOL_PENDING  "pending"

#ifndef  GRIDCONF_LOCAL_BASEDIR_DEFAULT
# define GRIDCONF_LOCAL_BASEDIR_DEFAULT "/"
#endif

#ifndef  GRIDCONF_DISTANT_BASEDIR_DEFAULT
# define GRIDCONF_DISTANT_BASEDIR_DEFAULT "/"
#endif

#ifndef  GRIDCONF_DISTANT_LISTSRV_DEFAULT
# define GRIDCONF_DISTANT_LISTSRV_DEFAULT "services.list"
#endif

#ifndef  GRIDCONF_DISTANT_LISTFILES_DEFAULT
# define GRIDCONF_DISTANT_LISTFILES_DEFAULT "files.list"
#endif

typedef struct message_s {
        guint32 length;
        void *data;
} message_t;

typedef struct request_s {
	char *cmd;
	char *arg;
	guint32 arg_size;
} request_t;

typedef struct response_s {
        guint32 status;
        guint32 data_size;
        void *data;
} response_t;

#define NAMESPACES_TASK_WORKER(TaskId,NSWorkerCreator,Name) static int Name ( gpointer udata, GError **error) {\
	gpointer ns_k, ns_v;\
	GHashTableIter ns_iterator;\
	TRACE_POSITION();\
	(void)udata;\
	/*Run all the namespaces currenly known*/\
	g_hash_table_iter_init(&ns_iterator, namespaces);\
	while (g_hash_table_iter_next(&ns_iterator,&ns_k,&ns_v)) {\
		namespace_data_t *ns_data = ns_v;\
		if (!namespace_is_available(ns_data))\
			INFO("[task_id=%s] Namespace '%s' is not (yet) available", TaskId, (gchar*)ns_k);\
		else if (!NSWorkerCreator(ns_data,error)) {\
			GSETERROR(error,"[task_id=%s] Failed to start a sub worker for namespace '%s'", TaskId, (gchar*)ns_k);\
			task_done(TaskId);\
			return 0;\
		}\
		else DEBUG("[task_id=%s] task started for Namespace '%s'", TaskId, (gchar*)ns_k);\
	}\
	task_done(TaskId);\
	return 1;\
}

#define NAMESPACE_TASK_CREATOR(Name,TaskId,NSWorkerCreator,Period) \
static int \
Name ( gpointer udata, GError **error) {\
	gpointer ns_k, ns_v;\
	GHashTableIter ns_iterator;\
	TRACE_POSITION();\
	(void)udata;\
	g_hash_table_iter_init(&ns_iterator, namespaces);\
	while (g_hash_table_iter_next(&ns_iterator,&ns_k,&ns_v)) {\
		gchar ns_id[128+LIMIT_LENGTH_NSNAME+1];\
		namespace_data_t *ns_data = ns_v;\
		g_snprintf(ns_id,sizeof(ns_id),"%s.%s",TaskId,ns_data->name);\
		if (!namespace_is_available(ns_data)) {\
			if (is_task_scheduled(ns_id)) {\
				remove_task(ns_id); \
				DEBUG("[task_id=%s] task running for an unavailable namespace", ns_id);\
			} else DEBUG("[task_id=%s] Namespace '%s' is not (yet) available", ns_id, (gchar*)ns_k);\
		}\
		else {\
			if (!is_task_scheduled(ns_id)) {\
				task_t *task = set_task_callbacks(create_task(Period,ns_id),NSWorkerCreator,g_free,g_strdup(ns_data->name));\
					if (!add_task_to_schedule(task, error)) {\
				GSETERROR(error,"[task_id=%s] Failed to start a sub worker for namespace '%s'", TaskId, (gchar*)ns_k);\
					task_done(TaskId);\
					return 0;\
				} else DEBUG("[task_id=%s] subtask started ", ns_id);\
			}\
		}\
	}\
	task_done(TaskId);\
	return 1;\
}

#endif	/* _GRIDAGENT_H */
