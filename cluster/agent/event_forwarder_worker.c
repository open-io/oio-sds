#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.event.forward"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <attr/xattr.h>

#include <metautils/lib/metautils.h>

#include <cluster/lib/gridcluster.h>
#include <cluster/events/gridcluster_events.h>
#include <cluster/events/gridcluster_eventsremote.h>
#include <cluster/events/gridcluster_eventhandler.h>
#include <cluster/conscience/conscience.h>


#include "./agent.h"
#include "./asn1_request_worker.h"
#include "./event_workers.h"
#include "./io_scheduler.h"
#include "./message.h"
#include "./namespace_get_task_worker.h"
#include "./services_workers.h"
#include "./task.h"
#include "./task_scheduler.h"

#define TASK_ID "event_forward_task"

#ifdef HAVE_EXTRA_DEBUG
# define XDEBUG(FMT,...) DEBUG(FMT,##__VA_ARGS__)
#else
# define XDEBUG(...) 
#endif

struct event_handle_s {
	namespace_data_t *ns_data;
	gint ref_count;

	container_id_t cid;
	gchar str_cid[STRLEN_CONTAINERID];

	time_t xattr_time;
	gint64 xattr_seq;
	gchar ueid[256];
	gchar type[256];
	gridcluster_event_t *event;
	gchar *path;
};

enum action_status_e {
	ES_NONE,
	ES_PUSH_PENDING,
	ES_PUSHED,
	ES_STATUS_PENDING
};

struct event_action_s {
	gchar id[512];
	gchar path[1024];

	struct event_handle_s *handle;

	gchar srvtype[LIMIT_LENGTH_SRVTYPE];
	gchar str_target[STRLEN_ADDRINFO];
	addr_info_t target;
	enum action_status_e action_status;
	int event_status;
	time_t last_request;
	struct {
		guint push;
		guint status;
	} attempts;
	guint workers;
};

static GHashTable *ht_event_by_ueid = NULL;

static GHashTable *ht_idle_actions = NULL;
static GHashTable *ht_pending_actions = NULL;

/**
 * The type of the parameter associated to the task in the main scheduler
 */
struct event_task_data_s {
	gchar ns_name[LIMIT_LENGTH_NSNAME];
	gchar task_id[sizeof(TASK_ID) + 1 + LIMIT_LENGTH_NSNAME];
};

/* ------------------------------------------------------------------------- */

static const gchar*
event_status_to_string(int status)
{
	switch (status) {
		case CODE_EVT_ERROR_DEF:
			return "ERROR_DEF";
		case CODE_EVT_ERROR_TMP:
			return "ERROR_TMP";
		case CODE_EVT_NOTFOUND:
			return "NOTFOUND";
		case CODE_EVT_WORKINPROGRESS:
			return "WORKINPROGRESS";
		case CODE_EVT_WORKDONE:
			return "WORKDONE";
		default:
			return "INVALID";
	}
}

static const gchar*
action_status_to_string(enum action_status_e status)
{
	switch (status) {
		case ES_NONE:
			return "NONE";
		case ES_PUSH_PENDING:
			return "PUSH_PENDING";
		case ES_PUSHED:
			return "PUSHED";
		case ES_STATUS_PENDING:
			return "STATUS_PENDING";
		default:
			return "INVALID";
	}
}

static void
_static_init(void)
{
	if (!ht_event_by_ueid)
		ht_event_by_ueid = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
	
	if (!ht_idle_actions)
		ht_idle_actions = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
	if (!ht_pending_actions)
		ht_pending_actions = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
}

static GHashTable*
__extract_cid_ht(void)
{
	GHashTable *ht_result;
	GHashTableIter iter;
	gpointer k, v, new_key;

	ht_result = g_hash_table_new_full(container_id_hash, container_id_equal, NULL, g_free);
	g_hash_table_iter_init(&iter, ht_event_by_ueid);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		struct event_handle_s *h;
		if (NULL != (h = v)) {
			new_key = g_memdup(h->cid, sizeof(container_id_t));
			g_hash_table_insert(ht_result, new_key, new_key);
		}
	}

	return ht_result;
}

static guint
agent_count_pending_actions(void)
{
	return g_hash_table_size(ht_pending_actions);
}

static guint
agent_count_pending_events(void)
{
	return g_hash_table_size(ht_event_by_ueid);
}

/* ------------------------------------------------------------------------- */

struct service_pool_s {
	time_t last_update;
	GArray *pool;
};

static GHashTable *local_services = NULL;

static void
_free_array(gpointer p)
{
	struct service_pool_s *spool = p;
	if (p)
		return;
	if (spool->pool) {
		g_array_set_size(spool->pool, 0);
		g_array_free(spool->pool, TRUE);
	}
	bzero(spool, sizeof(*spool));
	g_free(spool);
}

static void
__zero_service(namespace_data_t *ns_data, const gchar *type_name, addr_info_t *ai)
{
	guint i;
	addr_info_t *addr;
	struct service_pool_s *spool;
	gchar key[LIMIT_LENGTH_NSNAME+1+LIMIT_LENGTH_SRVTYPE+1];

	bzero(key, sizeof(key));
	g_snprintf(key, sizeof(key), "%s:%s", ns_data->name, type_name);

	if (!(IS_FORKED_AGENT))
		abort();
	if (!local_services)
		return;
	if (!(spool = g_hash_table_lookup(local_services, key)))
		return;
	if (!spool->pool || !spool->pool->len)
		return;

	for (i=spool->pool->len; i>0 ;i--) {
		addr = & g_array_index(spool->pool, addr_info_t, i-1);
		if (addr_info_equal(addr, ai)) {
			g_array_remove_index_fast(spool->pool, i-1);
			return;
		}
	}
}

static gboolean
__choose_service(namespace_data_t *ns_data, const gchar *type_name, struct service_info_s *si, GError **err)
{
	struct service_pool_s *spool;
	time_t now;
	gchar key[LIMIT_LENGTH_NSNAME+1+LIMIT_LENGTH_SRVTYPE+1];

	if (!(IS_FORKED_AGENT)) {
		GSETERROR(err, "Invalid state : illegal call in a non-forked agent");
		return FALSE;
	}

	if (!local_services) {
		local_services = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, _free_array);
		if (!local_services) {
			GSETCODE(err, EINVAL, "Failed to init the local service table");
			return FALSE;
		}
	}

	bzero(key, sizeof(key));
	g_snprintf(key, sizeof(key), "%s:%s", ns_data->name, type_name);

	spool = g_hash_table_lookup(local_services, key);
	if (!spool) {
		spool = g_malloc0(sizeof(struct service_pool_s));
		spool->pool = g_array_sized_new(TRUE, TRUE, sizeof(addr_info_t), 16);
		g_hash_table_insert(local_services, g_strdup(key), spool);
	}

	now = time(0);
	if (now < spool->last_update ||
			(now > (spool->last_update+(spool->pool->len ? 10 : 1)))) {

		GError *local_error = NULL;

		/* Fill it with up services */
		GSList *ns_services = list_namespace_services(ns_data->name, type_name, &local_error);
		if (!ns_services) {
			if (local_error)
				WARN("Error when getting fresh services for [%s] : %s",
						key, gerror_get_message(local_error));
			else {
				if (now > spool->last_update + 20) {
					g_array_set_size(spool->pool, 0);
					spool->last_update = now;
				}
				else {
					DEBUG("No service available for [%s], we keep the old services", key);
				}
			}
		}
		else {
			GSList *l;

			g_array_set_size(spool->pool, 0);
			for (l=ns_services; l ;l=l->next) {
				if (NULL != l->data)
					g_array_append_vals(spool->pool, &(((struct service_info_s*)(l->data))->addr), 1);
			}
			spool->last_update = time(0);

			g_slist_foreach(ns_services, service_info_gclean, NULL);
			g_slist_free(ns_services);
		}

		if (local_error)
			g_clear_error(&local_error);
	}

	if (!spool->pool->len) {
		GSETERROR(err, "No service of type [%s] in ns [%s]", type_name, ns_data->name);
		return FALSE;
	}

	guint i;
	addr_info_t *addr;

	i = rand();
	i = i % spool->pool->len;
	addr = & g_array_index(spool->pool, addr_info_t, i);

	bzero(si, sizeof(service_info_t));
	g_strlcpy(si->type, type_name, sizeof(si->type)-1);
	g_strlcpy(si->ns_name, ns_data->name, sizeof(si->ns_name)-1);
	g_memmove(&(si->addr), addr, sizeof(addr_info_t));

	return TRUE;
}

static gboolean
check_spool_dirs(namespace_data_t *ns_data, GError **error)
{
	gboolean check_directory(const gchar *path) {
		if (g_file_test(path, G_FILE_TEST_IS_DIR|G_FILE_TEST_IS_EXECUTABLE))
			return TRUE;
		if (!g_mkdir_with_parents(path, event_directory_mode))
			return TRUE;
		GSETERROR(error, "Failed to create a directory with path [%s] : %s",
				path, strerror(errno));
		return FALSE;
	}

	return	check_directory(ns_data->queues.dir_trash)
		&& check_directory(ns_data->queues.dir_incoming)
		&& check_directory(ns_data->queues.dir_pending);
}

/* ------------------------------------------------------------------------- */

static void
event_handle_destroy(struct event_handle_s *handle)
{
	XDEBUG("UEID[%s] CID[%s] ref_count=%d being destroyed",
			handle->ueid, handle->str_cid,
			handle->ref_count);

	if (handle->event)
		g_hash_table_destroy(handle->event);
	if (handle->path)
		g_free(handle->path);

	bzero(handle, sizeof(*handle));
	g_free(handle);
}

static void
event_handle_unref(struct event_handle_s *handle)
{
	XDEBUG("UEID[%s] CID[%s] ref_count= %d -> %d",
			handle->ueid, handle->str_cid,
			handle->ref_count, handle->ref_count - 1);

	handle->ref_count = handle->ref_count - 1;
	g_assert(handle->ref_count >= 0);

	if (!handle->ref_count) {
		g_hash_table_remove(ht_event_by_ueid, handle->ueid);
		event_handle_destroy(handle);
	}
}

static void
event_handle_ref(struct event_handle_s *handle)
{
	XDEBUG("UEID[%s] CID[%s] ref_count= %d -> %d ",
			handle->ueid, handle->str_cid,
			handle->ref_count, handle->ref_count + 1);

	handle->ref_count = handle->ref_count + 1;
}

static struct event_handle_s*
event_handle_load(namespace_data_t *ns_data, const gchar *basedir,
		const struct path_data_s *pd, GError **error)
{
	struct event_handle_s *handle;

	handle = g_try_malloc0(sizeof(struct event_handle_s));
	if (!handle) {
		GSETCODE(error, ENOMEM, "malloc error");
		return NULL;
	}

	handle->ns_data = ns_data;
	handle->ref_count = 0;

	g_memmove(handle->cid, pd->id, sizeof(container_id_t));
	g_strlcpy(handle->str_cid, pd->str_cid, sizeof(handle->str_cid)-1);

	handle->xattr_time = pd->xattr_time;
	handle->xattr_seq = pd->xattr_seq;
	handle->path = g_strconcat(basedir, G_DIR_SEPARATOR_S, pd->relpath, NULL);

	/* Load the event from the disk */
	do {
		gchar *encoded = NULL;
		gsize encoded_size = 0;
		if (!g_file_get_contents(handle->path, &encoded, &encoded_size, error)) {
			GSETERROR(error, "read error");
			g_free(handle);
			return NULL;
		}
		handle->event = gridcluster_decode_event2((guint8*)encoded, encoded_size, error);
		g_free(encoded);
	} while (0);
	if (!handle->event) {
		GSETERROR(error, "deserialization error");
		g_free(handle);
		return NULL;
	}

	/* get its UEID */
	do {
		GByteArray *gba;
		gba = g_hash_table_lookup(handle->event, "UEID");
		if (!gba) {
			GSETERROR(error, "missing UEID");
			g_hash_table_destroy(handle->event);
			g_free(handle);
			return NULL;
		}
		g_memmove(handle->ueid, gba->data, MIN(gba->len, sizeof(handle->ueid)-1));
	} while (0);

	/* get its type */
	do {
		GByteArray *gba;
		gba = g_hash_table_lookup(handle->event, "TYPE");
		if (!gba) {
			GSETERROR(error, "missing TYPE");
			g_hash_table_destroy(handle->event);
			g_free(handle);
			return NULL;
		}
		g_memmove(handle->type, gba->data, MIN(gba->len, sizeof(handle->type)-1));
	} while (0);

	g_hash_table_insert(ht_event_by_ueid, handle->ueid, handle);
	return handle;
}

static struct event_handle_s*
event_handle_load_from_path(namespace_data_t *ns_data, const gchar *path, GError **error)
{
	struct event_handle_s *handle;
	gchar *dirname, *bn;
	struct path_data_s pd;

	bn = g_path_get_basename(path);
	dirname = g_path_get_dirname(path);

	bzero(&pd, sizeof(pd));
	gridcluster_eventxattr_get_seq(path, &(pd.xattr_seq));
	gridcluster_eventxattr_get_incoming_time(path, &(pd.xattr_time));
	gridcluster_eventxattr_get_container_id(path, &(pd.id), pd.str_cid, sizeof(pd.str_cid));
	stat(path, &(pd.stat));
	g_strlcpy(pd.relpath, bn, sizeof(pd.relpath) - 1);
	pd.relpath_size = strlen(pd.relpath);

	handle = event_handle_load(ns_data, dirname, &pd, error);

	g_free(dirname);
	g_free(bn);
	return handle;
}

/* ------------------------------------------------------------------------- */

static gchar *
action_compute_path(struct event_action_s *action)
{
	return g_strconcat(action->handle->ns_data->queues.dir_pending,
			G_DIR_SEPARATOR_S, action->handle->ueid,
			",", action->srvtype, ",", action->str_target, NULL);
}

static void
action_compute_id(struct event_action_s *action)
{
	if (action->srvtype[0])
		g_snprintf(action->id, sizeof(action->id), "%s,%s,", action->handle->ueid, action->srvtype);
	else
		g_snprintf(action->id, sizeof(action->id), "%s,,%s", action->handle->ueid, action->str_target);

	XDEBUG("ACTION[%s] ID known srv=%s addr=%s", action->id, action->srvtype, action->str_target);
}

static void
action_destroy(struct event_action_s *action)
{
	XDEBUG("ACTION[%s] workers=%u being destroyed", action->id, action->workers);
	
	if (-1 == unlink(action->path))
		WARN("ACTION[%s] unlink failed (%s) for path=%s", action->id,
				strerror(errno), action->path);
	else
		DEBUG("ACTION[%s] unlinked path=%s", action->id, action->path);

	if (action->handle) {
		event_handle_unref(action->handle);
		action->handle = NULL;
	}		

	g_hash_table_remove(ht_pending_actions, action->id);
	g_hash_table_remove(ht_idle_actions, action->id);

	bzero(action, sizeof(*action));
	g_free(action);
}

static void
action_trash(struct event_action_s *action)
{
	gchar *trash_path = NULL;

	XDEBUG("ACTION[%s] workers=%u being trashed", action->id, action->workers);

	trash_path = g_strconcat(action->handle->ns_data->queues.dir_trash,
			G_DIR_SEPARATOR_S, action->handle->ueid, NULL);

	if (-1 == g_rename(action->path, trash_path))
		WARN("ACTION[%s] trash failed (%s) for path=%s", action->id,
				strerror(errno), action->path);
	else
		DEBUG("ACTION[%s] trashed path=%s", action->id, action->path);

	if (action->handle) {
		event_handle_unref(action->handle);
		action->handle = NULL;
	}

	g_hash_table_remove(ht_pending_actions, action->id);
	g_hash_table_remove(ht_idle_actions, action->id);

	bzero(action, sizeof(*action));
	g_free(action);
	g_free(trash_path);
}

static gboolean
action_save(struct event_action_s *action, GError **error)
{
	gchar *new_path;
	
	new_path = action_compute_path(action);
	if (-1 == rename(action->path, new_path)) {
		GSETERROR(error, "rename error (%s) %s -> %s", strerror(errno),
				action->path, new_path);
		g_free(new_path);
		return FALSE;
	}

	bzero(action->path, sizeof(action->path));
	g_strlcpy(action->path, new_path, sizeof(action->path)-1);
	g_free(new_path);

	DEBUG("ACTION[%s] saved path=%s", action->id, action->path);
	return TRUE;
}

static void
action_make_idle(struct event_action_s *action)
{
	g_hash_table_remove(ht_pending_actions, action->id);
	g_hash_table_insert(ht_idle_actions, action->id, action);
	DEBUG("ACTION[%s] is now idle", action->id);
}

static void
action_make_pending(struct event_action_s *action)
{
	g_hash_table_remove(ht_idle_actions, action->id);
	g_hash_table_insert(ht_pending_actions, action->id, action);
	DEBUG("ACTION[%s] is now pending", action->id);
}

static void
action_restart_push_or_destroy(struct event_action_s *action)
{
	GError *err;
	action->action_status = ES_NONE;

	if ('\0' != action->srvtype[0]) {
		/* reset the target address */
		if (action->target.port != 0) {
			bzero(action->str_target, sizeof(action->str_target));
			bzero(&(action->target), sizeof(action->target));
			err = NULL;
			if (!action_save(action, &err)) {
				ERROR("ACTION[%s] save error : %s", action->id, gerror_get_message(err));
				g_clear_error(&err);
				action_destroy(action);
				return;
			}
		}
	}

	action_make_idle(action);
	XDEBUG("ACTION[%s] scheduled for a PUSH", action->id);
}

static void
action_restart_status(struct event_action_s *action)
{
	XDEBUG("ACTION[%s] scheduled for a STATUS", action->id);
	action->action_status = ES_PUSHED;
	action_make_idle(action);
}

static gboolean
action_register(struct event_action_s *action, GError **error)
{
	XDEBUG("ACTION[%s] being registered", action->id);

	if (g_hash_table_lookup(ht_idle_actions, action->id)) {
		GSETERROR(error, "already an idle action with ID=%s", action->id);
		return FALSE;
	}
	if (g_hash_table_lookup(ht_pending_actions, action->id)) {
		GSETERROR(error, "already a pending action with ID=%s", action->id);
		return FALSE;
	}

	action_make_idle(action);
	return TRUE;
}

static gboolean
action_link_to_event(struct event_action_s *action, GError **error)
{
	gboolean rc = FALSE;
	gchar *new_path;

	new_path = action_compute_path(action);

	if (-1 == link(action->handle->path, new_path))
		GSETERROR(error, "link error (%s) %s -> %s", strerror(errno),
			action->handle->path, new_path);
	else {
		bzero(action->path, sizeof(action->path));
		g_strlcpy(action->path, new_path, sizeof(action->path)-1);
		rc = TRUE;
	}

	g_free(new_path);
	return rc;
}

static gboolean
action_unpack_path(struct event_action_s *action, const gchar *path,
		gchar *ueid, gsize ueid_size, GError **error)
{
	gchar *bn, **tokens;

	g_strlcpy(action->path, path, sizeof(action->path)-1);

	if (!(bn = g_path_get_basename(path))) {
		GSETERROR(error, "no basename in path");
		return FALSE;
	}
	bzero(action->id, sizeof(action->id));
	g_strlcpy(action->id, bn, sizeof(action->id)-1);
	g_free(bn);

	tokens = g_strsplit(action->id, ",", 3);
	if (!tokens) {
		GSETERROR(error, "split error");
		return FALSE;
	}

	if (g_strv_length(tokens) != 3) {
		g_strfreev(tokens);
		GSETERROR(error, "invalid basename");
		return FALSE;
	}

	g_strlcpy(ueid, tokens[0], ueid_size-1);
	g_strlcpy(action->srvtype, tokens[1], sizeof(action->srvtype)-1);

	if (*(tokens[2])) {
		if (!l4_address_init_with_url(&(action->target), tokens[2], error)) {
			g_strfreev(tokens);
			GSETERROR(error, "invalid event action address");
			return FALSE;
		}
	}

	XDEBUG("ACTION[%s] unpacked srv=%s addr=%s", action->id, action->srvtype, action->str_target);

	g_strfreev(tokens);
	return TRUE;
}

static struct event_action_s*
action_load(namespace_data_t *ns_data, const gchar *path, GError **error)
{
	struct event_action_s *action;
	gchar ueid[256];

	XDEBUG("ACTION[-] loading from path=%s", path);
	bzero(ueid, sizeof(ueid));
	action = g_malloc0(sizeof(*action));
	action->action_status = ES_NONE;
	action->event_status = ~0;

	/* the path contains the UEID that is the key to the event */
	if (!action_unpack_path(action, path, ueid, sizeof(ueid), error)) {
		g_free(action);
		GSETERROR(error, "invalid basename");
		return NULL;
	}

	action->action_status = (action->target.port == 0) ? ES_NONE : ES_PUSHED;

	/* Try to reuse an event handle, or load one new by default */
	action->handle = g_hash_table_lookup(ht_event_by_ueid, ueid);
	if (action->handle)
		DEBUG("ACTION[%s] event already loaded UEID[%s]", action->id, ueid);
	else {
		action->handle = event_handle_load_from_path(ns_data, path, error);
		if (!action->handle) {
			GSETERROR(error, "event cannot be loaded for ACTION[%s]", action->id);
			g_free(action);
			return NULL;
		}

		DEBUG("ACTION[%s] event first loaded UEID[%s]", action->id, ueid);
	}
	event_handle_ref(action->handle);

	if (action_register(action, error)) {
		XDEBUG("ACTION[%s] reloaded!", action->id);
		return action;
	}

	event_handle_unref(action->handle);
	g_free(action);
	return NULL;
}

static struct event_action_s*
action_create_targeted(struct event_handle_s *handle,
		const gchar *s, const addr_info_t *ai, GError **error)
{
	struct event_action_s *action;

	if (!s && !ai) {
		GSETERROR(error, "NULL targets");
		return NULL;
	}

	action = g_malloc0(sizeof(*action));
	action->handle = handle;
	action->action_status = ES_NONE;
	action->event_status = ~0;

	if (s)
		g_strlcpy(action->srvtype, s, sizeof(action->srvtype)-1);
	else if (ai) {
		g_memmove(&(action->target), ai, sizeof(addr_info_t));
		addr_info_to_string(&(action->target), action->str_target, sizeof(action->str_target));
	}

	action_compute_id(action);

	/* Link the event to the new target */
	if (!action_link_to_event(action, error)) {
		GSETERROR(error, "persistency error");
		g_free(action);
		return NULL;
	}

	TRACE("ACTION[%s] created from scratch", action->id);

	if (action_register(action, error)) {
		event_handle_ref(action->handle);
		return action;
	}

	g_free(action);
	return NULL;
}

/* ------------------------------------------------------------------------- */

static void
asn1_action_cleaner(gpointer p)
{
	struct event_action_s *action;
	
	action = p;

	action->last_request = time(0);
	-- action->workers ;

	XDEBUG("ACTION[%s] workers=%u action=%s event=%s cleaning worker",
			action->id, action->workers,
			action_status_to_string(action->action_status),
			event_status_to_string(action->event_status));

#ifdef HAVE_EXTRA_DEBUG
	if (action->workers > 0) {
		FATAL("ACTION[%s] abnormal condition, action done but %u workers still up",
			action->id, action->workers);
		g_error("ACTION[%s] abnormal condition, action done but %u workers still up",
			action->id, action->workers);
	}
#endif

	switch (action->action_status) {

		case ES_NONE: /* PUSH failed */
			action_restart_push_or_destroy(action);
			return;

		case ES_PUSHED: /* STATUS failed or PUSH succeeded */
			switch (action->event_status) {
				case CODE_EVT_ERROR_DEF:
					INFO("ACTION[%s] ERROR addr=%s", action->id, action->str_target);
					action_trash(action);
					return;
				case CODE_EVT_ERROR_TMP:
					action_restart_push_or_destroy(action);
					return;
				case CODE_EVT_NOTFOUND:
					action_restart_push_or_destroy(action);
					return;
				case CODE_EVT_WORKINPROGRESS:
					action_restart_status(action);
					return;
				case CODE_EVT_WORKDONE:
					INFO("ACTION[%s] DONE addr=%s", action->id, action->str_target);
					action_destroy(action);
					return;
				default:
#ifdef HAVE_EXTRA_DEBUG
					g_error("ACTION[%s] unexpected status (%x) from addr=%s ",
							action->id, action->event_status, action->str_target);
#endif
					action_destroy(action);
					return;
			}

		case ES_PUSH_PENDING:
			DEBUG("ACTION[%s] PUSH timeout", action->id);

			if (action->srvtype[0]) {
				/* reset the chosen address and ensure following actions
				 * won't target the same service */
				__zero_service(action->handle->ns_data, action->srvtype, &(action->target));
				bzero(&(action->target), sizeof(addr_info_t));
				bzero(&(action->str_target), sizeof(action->str_target));
			}

			action->action_status = ES_NONE;
			action_make_idle(action);
			return;
		case ES_STATUS_PENDING: /* Timeout */
			DEBUG("ACTION[%s] STATUS timeout", action->id);
			action->action_status = ES_PUSHED;
			action_make_idle(action);
			return;
		default:
			/* abnormal, pending status should have been
			 * changed in a final handler */
			FATAL("ACTION[%s] abnormal pending status : action=%x/%s event=%x/%s",
				action->id,
				action->action_status, action_status_to_string(action->action_status),
				action->event_status, event_status_to_string(action->event_status));
#ifdef HAVE_EXTRA_DEBUG
			g_error("ACTION[%s] abnormal action's status, check the logs", action->id);
#endif
			action_destroy(action);
			return;
	}
}

static int
asn1_response_handler(worker_t *worker, GError **error)
{
	GByteArray *gba_code;
	struct asn1_session_s *asn1_session;
	struct event_action_s *action;
	
	asn1_session = asn1_worker_get_session(worker);
	action = asn1_worker_get_session_data(worker);
	gba_code = g_hash_table_lookup(asn1_session->resp_headers,"EVENT_STATUS");
	if (!gba_code) {
		GSETERROR(error,"Distant service reply a message without EVENT_STATUS");
		return 0;
	}

	g_byte_array_append(gba_code, (guint8*)"", 1);
	g_byte_array_set_size(gba_code, gba_code->len - 1);
	action->event_status = g_ascii_strtoll((gchar*)gba_code->data, NULL, 10);

	DEBUG("ACTION[%s] status received %s", action->id,
			action_status_to_string(action->action_status));
	return 1;
}

static gint
asn1_push_error_handler(worker_t *worker, GError **error)
{
	struct event_action_s *action;
	(void) error;
	action = asn1_worker_get_session_data(worker);
	action->action_status = ES_NONE;
	DEBUG("ACTION[%s] PUSH error", action->id);
	return 1;
}

static gint
asn1_push_final_handler(worker_t *worker, GError **error)
{
	struct event_action_s *action;
	(void) error;
	action = asn1_worker_get_session_data(worker);
	action->action_status = ES_PUSHED;
	DEBUG("ACTION[%s] PUSH done", action->id);
	return 1;
}

static gint
asn1_status_error_handler(worker_t *worker, GError **error)
{
	struct event_action_s *action;
	(void) error;
	action = asn1_worker_get_session_data(worker);
	action->action_status = ES_PUSHED;
	DEBUG("ACTION[%s] STATUS error", action->id);
	return 1;
}

static gint
asn1_status_final_handler(worker_t *worker, GError **error)
{
	struct event_action_s *action;
	(void) error;
	action = asn1_worker_get_session_data(worker);
	action->action_status = ES_PUSHED;
	DEBUG("ACTION[%s] STATUS done", action->id);
	return 1;
}

/* ------------------------------------------------------------------------- */

static gboolean
action_start_worker_push(struct event_action_s *action, GError **error)
{
	const gchar *ueid;
	worker_t *asn1_worker;
	GByteArray *encoded;

	ueid = action->handle->ueid;

	/* check the action has at least a service or an address */
	if (!action->target.port) {
		struct service_info_s si;

		if (!action->srvtype) {
			FATAL("ACTION[%s] has no target", action->id);
#ifdef HAVE_EXTRA_DEBUG
			g_error("ACTION[%s] has no target", action->id);
#endif
			GSETERROR(error, "No service type specified");
			return FALSE;
		}

		bzero(&si, sizeof(struct service_info_s));
		if (!__choose_service(action->handle->ns_data, action->srvtype, &si, error)) {
			GSETERROR(error, "No service available TYPE[%s]", action->srvtype);
			return FALSE;
		}

		g_memmove(&(action->target), &(si.addr), sizeof(addr_info_t));
		bzero(action->str_target, sizeof(action->str_target));
		addr_info_to_string(&(action->target), action->str_target, sizeof(action->str_target));

		if (!action_save(action, error)) {
			GSETERROR(error, "persistency error");
			return FALSE;
		}
	}

	encoded = gridcluster_encode_event(action->handle->event, error);
	if (!encoded) {
		GSETERROR(error, "event encoding error");
		return FALSE;
	}

	asn1_worker = create_asn1_worker(&(action->target), REQ_EVT_PUSH);
	asn1_worker_set_handlers(asn1_worker, asn1_response_handler,
			asn1_push_error_handler, asn1_push_final_handler);
	asn1_worker_set_request_body(asn1_worker, encoded);
	g_hash_table_insert(asn1_worker_get_session(asn1_worker)->req_headers, g_strdup(MSG_HEADER_UEID),
			g_byte_array_append(g_byte_array_new(), (guint8*)ueid, strlen(ueid)));

	g_byte_array_free(encoded, FALSE);

	if (asn1_request_worker(asn1_worker, error)) {
		++ action->workers;
		asn1_worker_set_session_data(asn1_worker, action, asn1_action_cleaner);
		return TRUE;
	}

	GSETERROR(error, "ASN.1 worker startup error");
	free_asn1_worker(asn1_worker, TRUE);
	return FALSE;
}

static gboolean
action_start_worker_status(struct event_action_s *action, GError **error)
{
	const gchar *ueid;
	worker_t *asn1_worker;

	ueid = action->handle->ueid;

	asn1_worker = create_asn1_worker(&(action->target), REQ_EVT_STATUS);
	asn1_worker_set_handlers(asn1_worker, asn1_response_handler,
			asn1_status_error_handler, asn1_status_final_handler);
	g_hash_table_insert(asn1_worker_get_session(asn1_worker)->req_headers, g_strdup(MSG_HEADER_UEID),
			g_byte_array_append(g_byte_array_new(), (guint8*)ueid, strlen(ueid)));

	if (asn1_request_worker(asn1_worker, error)) {
		++ action->workers;
		asn1_worker_set_session_data(asn1_worker, action, asn1_action_cleaner);
		return TRUE;
	}

	GSETERROR(error, "ASN.1 worker startup error");
	free_asn1_worker(asn1_worker,TRUE);
	return FALSE;
}

/* ------------------------------------------------------------------------- */

static gboolean
push_event_final_calback(gridcluster_event_t *e, gpointer udata, gpointer edata, GError **err)
{
	(void) e;
	(void) edata;
	(void) udata;
	(void) err;
	return TRUE;
}

static gboolean
push_event_address_forwarder(gridcluster_event_t *e, gpointer udata, gpointer edata, GError **err, const addr_info_t *a)
{
	(void) e;
	(void) udata;
	return NULL != action_create_targeted((struct event_handle_s*)edata, NULL, a, err);
}

static gboolean
push_event_service_forwarder (gridcluster_event_t *e, gpointer udata, gpointer edata, GError **err, const gchar *s)
{
	(void) e;
	(void) udata;
	return NULL != action_create_targeted((struct event_handle_s*)edata, s, NULL, err);
}

static gboolean
process_event(namespace_data_t *ns_data, struct event_handle_s *handle, GError **error)
{
	static struct gridcluster_event_hooks_s hooks = {
		push_event_address_forwarder,
		push_event_service_forwarder,
		push_event_final_calback,
		push_event_final_calback,
	};
	gint rc;

	rc = gridcluster_manage_event_no_defaults(ns_data->conscience->event_handler,
			handle->event, handle, error, &hooks);
	if (rc)
		return TRUE;
	GSETERROR(error,"Failed to manage the event");
	return FALSE;
}

static guint
agent_run_incoming_events(namespace_data_t *ns_data, guint max)
{
	GSList *earliest = NULL, *l;
	guint counter_ok, counter_error;
	time_t delay;
	const gchar *dirname;
	GHashTable *ht_cid;

	gboolean filter_event_not_yet_managed(path_data_t *pd) {
		return NULL == g_hash_table_lookup(ht_cid, pd->id);
	}

	if (max <= 0) {
		TRACE("[NS=%s] too many events already managed", ns_data->name);
		return 0;
	}
	if (!ns_data || !ns_data->conscience->event_handler) {
		DEBUG("[NS=%s] Namespace events not yet ready", ns_data->name);
		return 0;
	}

	dirname = ns_data->queues.dir_incoming;
	delay = get_event_delay(ns_data);

	counter_ok = counter_error = 0;
	ht_cid = __extract_cid_ht();
	earliest = agent_list_earliest_events(dirname, max, delay, filter_event_not_yet_managed);
	g_hash_table_destroy(ht_cid);

#ifdef HAVE_EXTRA_DEBUG
	if (earliest && TRACE_ENABLED()) {
		TRACE("[NS=%s] incoming elements from [%s], delayed events for [%ld] seconds :",
			ns_data->name, dirname, delay);
		for (l=earliest; l ;l=l->next) {
			struct path_data_s *pd = l->data;
			TRACE(" XATTR[%ld:%"G_GINT64_FORMAT"] CID[%s] PATH[%s]",
					pd->xattr_time, pd->xattr_seq,
					pd->str_cid, pd->relpath);
		}
	}
#endif

	for (l=earliest; l ;l=l->next) {
		path_data_t *pd;
		struct event_handle_s *handle;
		GError *err;
		gboolean rc;

		pd = (path_data_t*)l->data;

		err = NULL;
		handle = event_handle_load(ns_data, dirname, pd, &err);
		if (!handle) {
			counter_error ++;
			ERROR("[NS=%s] Event error CID[%s] time[%ld] seq[%"G_GINT64_FORMAT"] at [%s] : %s",
				ns_data->name,
				pd->str_cid, pd->xattr_time, pd->xattr_seq,
				pd->relpath, gerror_get_message(err));
			g_clear_error(&err);
			continue;
		}
		if (err)
			g_clear_error(&err);

		event_handle_ref(handle);
		rc = process_event(ns_data, handle, &err);
		unlink(handle->path);
		event_handle_unref(handle);

		if (!rc) {
			counter_error ++;
			ERROR("[NS=%s] Process error CID[%s] time[%ld] seq[%"G_GINT64_FORMAT"] at [%s] : %s",
				ns_data->name,
				pd->str_cid, pd->xattr_time, pd->xattr_seq,
				pd->relpath, gerror_get_message(err));
		}
		else {
			counter_ok++;
			INFO("[NS=%s] Managed CID[%s] time[%ld] seq[%"G_GINT64_FORMAT"] at [%s]",
				ns_data->name,
				pd->str_cid, pd->xattr_time, pd->xattr_seq,
				pd->relpath);

		}

		if (err)
			g_clear_error(&err);
	}

	g_slist_foreach(earliest, g_free1, NULL);
	g_slist_free(earliest);

	return counter_ok;
}

static gboolean
action_push_is_delayed(struct event_action_s *action, time_t now)
{
	if (action->last_request == 0)
		return FALSE;
	switch (action->attempts.push) {
		case 0:
			return action->last_request >= now - 1;
		default:
			return action->last_request >= now - 2;
	}
}

static gboolean
action_status_is_delayed(struct event_action_s *action, time_t now)
{
	if (action->last_request == 0)
		return FALSE;
	switch (action->attempts.status) {
		case 0:
			return action->last_request >= now - 1;
		case 1:
			return action->last_request >= now - 2;
		default:
			return action->last_request >= now - 2;
	}
}

static guint
agent_start_idle_actions(namespace_data_t *ns_data, guint max)
{
	time_t now;
	guint counter_ok, counter_err;
	GList *list_of_values, *l;

	(void) max;
	(void) ns_data;

	counter_ok = counter_err = 0;
	list_of_values = g_hash_table_get_values(ht_idle_actions);
	now = time(0);
	for (l=list_of_values; l ;l=l->next) {
		GError *err;
		struct event_action_s *action;

		err = NULL;
		action = l->data;

		if (counter_ok > max)
			break;
		
		switch (action->action_status) {
		case ES_NONE:
			if (action_push_is_delayed(action, now) ) {
				TRACE("ACTION[%s] PUSH delayed", action->id);
			}
			else if (!action_start_worker_push(action, &err)) {
				WARN("ACTION[%s] PUSH request startup failed : %s",
						action->id, gerror_get_message(err));
				++ counter_err;
			}
			else {
				++ action->attempts.push;
				action->last_request = time(0);
				action->action_status = ES_PUSH_PENDING;
				action_make_pending(action);
				INFO("ACTION[%s] PUSH request started", action->id);
				++ counter_ok;
			}
			break;
		case ES_PUSHED:
			if (action_status_is_delayed(action, now)) {
				TRACE("ACTION[%s] STATUS delayed", action->id);
			}
			else if (!action_start_worker_status(action, &err)) {
				WARN("ACTION[%s] STATUS request startup failed : %s",
						action->id, gerror_get_message(err));
				++ counter_err;
			}
			else {
				++ action->attempts.status;
				action->last_request = time(0);
				action->action_status = ES_STATUS_PENDING;
				action_make_pending(action);
				INFO("ACTION[%s] STATUS request started", action->id);
				++ counter_ok;
			}
			break;
		default:
			FATAL("ACTION[%s] is pending but in idle set", action->id);
#ifdef HAVE_EXTRA_DEBUG
			g_error("ACTION[%s] is pending but in idle set", action->id);
#endif
			action->action_status = ES_PUSHED;
			action_make_idle(action);
			break;
		}

		if (err)
			g_clear_error(&err);
	}
	g_list_free(list_of_values);

	return counter_ok;
}

/* ------------------------------------------------------------------------- */

static inline void
build_taskid(gchar *dst, gsize dst_size, const gchar *ns_name)
{
	g_snprintf(dst, dst_size, TASK_ID".%s", ns_name);
}

/* Define the per-namespace subtask action */
static int
task_action_events(gpointer task_param, GError **error)
{
	guint current;
	gchar *ns_name;
	struct namespace_data_s *ns_data;
	struct event_task_data_s task_data;

	bzero(&task_data, sizeof(task_data));

	ns_name = task_param;
	if (!ns_name) {
		GSETERROR(error,"Misconfigured gridagent task (no session data)");
		return 0;
	}

	g_strlcpy(task_data.ns_name, ns_name, sizeof(task_data.ns_name)-1);
	build_taskid(task_data.task_id, sizeof(task_data.task_id), ns_name);

	if (!event_enable_manage) {
		task_done(task_data.task_id);
		DEBUG("[task_id=%s] events disabled on this host", task_data.task_id);
		return 1;
	}

	ns_data = g_hash_table_lookup(namespaces, ns_name);
	if (!ns_data || !ns_data->conscience) {
		GSETERROR(error,"Namespace misconfigured");
		goto error_label;
	}
	if (!check_spool_dirs(ns_data, error)) {
		GSETERROR(error,"Spool directory state failure");
		goto error_label;
	}

	/* Start some actions */
	current = agent_count_pending_actions();
	DEBUG("[task_id=%s] ACTIONS this turn : max=%u current=%u",
			task_data.task_id, max_events_actions_pending, current);
	if (max_events_actions_pending > current) {
		guint managed = agent_start_idle_actions(ns_data,
				max_events_actions_pending - current);
		if (managed)
			DEBUG("[task_id=%s] %u idle tasks started (total %u)",
				task_data.task_id, managed, agent_count_pending_actions());
	}

	current = agent_count_pending_events();
	DEBUG("[task_id=%s] EVENTS this turn : max=%u current=%u",
			task_data.task_id, max_events_pending, current);
	if (max_events_pending > current) {
		guint managed = agent_run_incoming_events(ns_data, max_events_pending - current + 10);
		if (managed)
			INFO("[task_id=%s] %u new events managed (total %u)", task_data.task_id,
					managed, agent_count_pending_events());
	}

	task_done(task_data.task_id);
	return 1;
error_label:
	task_done(task_data.task_id);
	return 0;
}

static void
_recover_actions(namespace_data_t *ns_data)
{
	const gchar *bn;
	const gchar *dirname;
	guint count;
	GError *err;
	GDir *gdir;

	count = 0;
	err = NULL;
	dirname = ns_data->queues.dir_pending;
	gdir = g_dir_open(dirname, 0, &err);
	if (!gdir) {
		ERROR("[NS=%s] Failed to recover previous actions : %s",
				ns_data->name, gerror_get_message(err));
		g_clear_error(&err);
		return;
	}

	while (NULL != (bn = g_dir_read_name(gdir))) {
		gchar *fullpath;

		fullpath = g_strconcat(dirname, G_DIR_SEPARATOR_S, bn, NULL);
		if (NULL == action_load(ns_data, fullpath, &err))
			ERROR("[NS=%s] Failed to recover ACTION[%s] : %s",
					ns_data->name, bn, gerror_get_message(err));
		else
			++ count;
		if (err)
			g_clear_error(&err);
		g_free(fullpath);
	}

	g_dir_close(gdir);

	if (count)
		INFO("[NS=%s] recovered %u actions", ns_data->name, count);
}

int
agent_start_event_all_tasks(const gchar *ns_name, GError **error)
{
	namespace_data_t *ns_data;
	gchar task_id[sizeof(TASK_ID)+LIMIT_LENGTH_NSNAME+1];
	task_t *task;

	build_taskid(task_id, sizeof(task_id), ns_name);

	ns_data = g_hash_table_lookup(namespaces, ns_name);
	if (!ns_data) {
		GSETERROR(error, "[task_id=%s] Namespace not found", task_id);
		return 0;
	}
	if (!check_spool_dirs(ns_data, error)) {
		GSETERROR(error, "[task_id=%s] event directories problems", task_id);
		return 0;
	}
	_static_init();

	task = create_task(1L, task_id);
	set_task_callbacks(task, task_action_events, g_free, g_strdup(ns_name));

	if (!add_task_to_schedule(task, error)) {
		GSETERROR(error,"[task_id=%s] Failed to start a sub worker", task_id);
		return 0;
	}
	DEBUG("[task_id=%s] subtask started ", task_id);

	_recover_actions(ns_data);

	return 1;
}

