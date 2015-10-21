/*
OpenIO SDS cluster
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

#ifndef OIO_SDS__cluster__agent__gridagent_h
# define OIO_SDS__cluster__agent__gridagent_h 1

#include <metautils/lib/metatypes.h>

#define AGENT_DEFAULT_EVENT_XATTR "user.grid.agent.incoming-time"

#define MSG_SRVTYPE_LST "SRVTYPELST"
#define MSG_SRV_LST "SRVLST"
#define MSG_SRV_PSH "SRVPSH"
#define MSG_SRV_CLR "SRVCLR"
#define MSG_GETNS   "GETNS"
#define MSG_LSTSVC  "LSTSVC"
#define MSG_LSTTASK "LSTTASK"
#define MSG_ERRCID_STORE "ERRCID_STORE"
#define MSG_ERRCID_FETCH "ERRCID_FETCH"
#define MSG_ERRCID_FLUSH "ERRCID_FLUSH"
#define MSG_ERRCID_FIXED "ERRCID_FIXED"
#define MSG_ERRM2_UNREF "ERRM2_UNREF"

#define MSG_EVENTS_CONFIGURATION "EVT_CONFIG"
#define MSG_SRVTYPE_CONFIG "SRVTYPE_CONFIG"

#define LIMIT_MAX_ERRCID 20000
#define MAX_TASKID_LENGTH 64

#define STATUS_OK CODE_FINAL_OK
#define STATUS_ERROR CODE_INTERNAL_ERROR

#define SPOOL_DIRNAME_LENGTH 512
#define SUFFIX_SPOOL_INCOMING "incoming"
#define SUFFIX_SPOOL_TRASH    "trash"
#define SUFFIX_SPOOL_PENDING  "pending"

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
	(void)udata;\
	/*Run all the namespaces currently known*/\
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
	(void)udata;\
	g_hash_table_iter_init(&ns_iterator, namespaces);\
	while (g_hash_table_iter_next(&ns_iterator,&ns_k,&ns_v)) {\
		gchar ns_id[MAX_TASKID_LENGTH+LIMIT_LENGTH_NSNAME];\
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

#endif /*OIO_SDS__cluster__agent__gridagent_h*/
