#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "atos.grid."MODULE_NAME".plugin"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>

#include <gridd/main/plugin.h>
#include <gridd/main/message_handler.h>
#include <gridd/main/srvstats.h>
#include <gridd/main/srvtimer.h>
#include <gridd/main/srvalert.h>
#include <cluster/lib/gridcluster.h>
#include <metautils/lib/metautils.h>
#include <cluster/events/gridcluster_eventsremote.h>

#include "module.h"
#include "event_storage.h"
#include "event_manager.h"
#include "gridd_module.h"



#define POLIX_ERRCODE_CONFIG     510 //wrong configuration string
#define POLIX_ERRCODE_OTHER      512 //could not connect to the DB

#define LOCK_STATS()   g_static_rec_mutex_lock(&stat_mutex)
#define UNLOCK_STATS() g_static_rec_mutex_unlock(&stat_mutex)


typedef gint(*_cmd_handler_f) (struct request_context_s *, GError **);

struct cmd_s
{
	char *c;
	_cmd_handler_f h;
	gint64 *pStat;
	gint64 *pTimeStat;
};


struct module_stats_s {
	struct {
		guint64 total;
		guint64 push;
		guint64 status;
	} counters;
	struct {
		guint64 total;
		guint64 push;
		guint64 status;
	} times;
};




static GStaticRecMutex       stat_mutex;
static struct module_stats_s module_stats;
static gchar                 source_namespace[LIMIT_LENGTH_NSNAME+1];
static grid_polix_t          *polix;
static GThreadPool           *workers_pool = NULL;
static GHashTable            *ht_type_counters = NULL;




static GPtrArray* _prepare_tags(void)
{
	TRACE("Preparing required service tags");
	GPtrArray* result = NULL;

	result = g_ptr_array_new();
	/*add useful and statistics tags */
	service_tag_set_value_macro(service_info_ensure_tag(result, NAME_MACRO_CPU_NAME), NAME_MACRO_CPU_TYPE, NULL);
	TRACE("Service tags ready");
	return result;
}

/***********************************************/




static void
init_reply_ctx_with_request(struct request_context_s *req, struct reply_context_s *rep)
{
	if (rep) {
		memset(rep, 0x00, sizeof(struct reply_context_s));
		rep->req_ctx = req;
	}
}


static char*
config_load_ns(GHashTable *params, const gchar *key )
{
	gchar* ns = NULL;

	ns = g_hash_table_lookup(params, key);

	if (ns)
		GRID_INFO("param[%s=%s] configured", key, ns);
	return ns;											
}

static guint
config_get_max_workers(GHashTable *params, const gchar *key, guint def)
{
	gchar *str;
	gint64 i64;
	guint u;

	str = g_hash_table_lookup(params, key);
	if (!str)
		return def;

	i64 = g_ascii_strtoll(str, NULL, 10);
	if (i64 <= 0 || i64 > 1000)
		return def;

	u = i64;
	return u;
}



static GHashTable*
stats_copy_counters(GHashTable *src)
{
	GHashTable *result;
	GHashTableIter iter;
	gpointer k, v;

	result = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	g_hash_table_iter_init(&iter, src);
	while (g_hash_table_iter_next(&iter, &k, &v))
		g_hash_table_insert(result, g_strdup((gchar*)k), g_memdup(v, sizeof(guint64)));

	return result;
}


static void
stats_count_event(const gchar *type)
{
	guint64 *counter, u64;

	if (!type)
		return;

	LOCK_STATS(); /* XXX Start of critical section */

	counter = g_hash_table_lookup(ht_type_counters, type);
	if (counter)
		*counter = *counter + 1LLU;
	else {
		u64 = 1LLU;
		g_hash_table_insert(ht_type_counters, g_strdup(type), g_memdup(&u64, sizeof(u64)));
	}

	UNLOCK_STATS(); /* XXX End of criticial section */
}



static void
__srvstat_set_const_u64(const gchar *name, guint64 u64)
{
	gdouble d;

	d = u64;
	srvstat_set(name, d);
}


static void
stats_update(gpointer d)
{
	struct module_stats_s local_stats;
	GHashTableIter iter;
	GHashTable *ht_copy;
	gpointer k, v;
	gchar name[256];
	gdouble dval;

	(void) d;

	LOCK_STATS();
	memcpy(&local_stats, &module_stats, sizeof(struct module_stats_s));
	ht_copy = stats_copy_counters(ht_type_counters);
	UNLOCK_STATS();

	/* Request type counters */
	__srvstat_set_const_u64(MODULE_NAME".counter.request.total",   local_stats.counters.total);
	__srvstat_set_const_u64(MODULE_NAME".counter.request.push",    local_stats.counters.push);
	__srvstat_set_const_u64(MODULE_NAME".counter.request.status",  local_stats.counters.status);
	__srvstat_set_const_u64(MODULE_NAME".counter.times.total",     local_stats.times.total);
	__srvstat_set_const_u64(MODULE_NAME".counter.times.push",      local_stats.times.push);
	__srvstat_set_const_u64(MODULE_NAME".counter.times.status",    local_stats.times.status);

	/* Event types counters */
	g_hash_table_iter_init(&iter, ht_copy);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		g_snprintf(name, sizeof(name), MODULE_NAME".counter.type:%s", (gchar*)k);
		__srvstat_set_const_u64(name, *((guint64*)v));
	}
	g_hash_table_destroy(ht_copy);

	/* Workers counters */
	dval = g_thread_pool_get_max_threads(workers_pool);
	srvstat_set(MODULE_NAME".gauge.workers.max", dval);

	dval = g_thread_pool_get_num_threads(workers_pool);
	srvstat_set(MODULE_NAME".gauge.workers.current", dval);

	dval = g_thread_pool_get_num_unused_threads();
	srvstat_set(MODULE_NAME".gauge.workers.idle", dval);

	dval = g_thread_pool_unprocessed(workers_pool);
	srvstat_set(MODULE_NAME".gauge.workers.queue", dval);
}




static gsize
extract_ueid_from_headers(MESSAGE request, GError **error, gchar *dst, gsize dst_size)
{
	void *data = NULL;
	gsize data_size = 0;

	if (0 >= message_get_field(request,MSG_HEADER_UEID,sizeof(MSG_HEADER_UEID)-1, &data, &data_size, NULL)) {
		GSETCODE(error,400,"Header '"MSG_HEADER_UEID"' extraction failure");
		return 0;
	}

	bzero(dst, dst_size);
	memcpy(dst, data, MIN(dst_size,data_size));
	dst[dst_size-1] = '\0';
	return strlen(dst);
}


static gridcluster_event_t*
extract_event_from_body(MESSAGE request, GError **error)
{
	void *data;
	gsize data_size;
	gridcluster_event_t *event;

	if (0 >= message_get_BODY(request, &data, &data_size, error)) {
		GSETCODE(error, 400, "Bad request: no body");
		return NULL;
	}
	if (!(event = gridcluster_decode_event2(data, data_size, error))) {
		GSETCODE(error, 400, "Bad requets: invalid body");
		return NULL;
	}

	return event;
}




	static void
delete_ueid(const gchar* ueid)
{
	if (pes_delete(ueid, TRUE))
		INFO("Deleted UEID=[%s]", ueid);
	else
		WARN("Delete failed UEID[%s] : %s", ueid, strerror(errno));

}



//----------------------------------------------------------------------------
	static void
thread_func_event_manager(gpointer p, gpointer user_data)
{
	polix_event_t* pe = NULL;
	event_status_et status = ES_ERROR_TMP;
	GError *err = NULL;
	gboolean allow_retry = TRUE;

	pe = p;
	(void) user_data;

	GRID_DEBUG("WORKING ON UEID[%s]", pe->ueid);

	if (!pe || !pe->event)
		GRID_ERROR("Event loading error UEID[%s] : %s", pe->ueid, gerror_get_message(err));
	else {
		if (err)
			g_clear_error(&err);

		if (polix_event_manager(polix, pe->ueid, pe->event, &allow_retry, FALSE/*dryrun*/, &err)) 
			status = ES_DONE;
		else if (err)
			GRID_ERROR("Failed to manage event UEID[%s: %s", pe->ueid, gerror_get_message(err));	
		//g_hash_table_destroy(event);   
	}

	if (err)
		g_clear_error(&err);

	if (status != ES_DONE) /* Manage recoverable errors */
		status = allow_retry ? ES_ERROR_TMP : ES_ERROR_DEF;

	// save status
	if (!pes_set_status(pe, status)) {
		GRID_ERROR("Event set status failed UEID[%s]", pe->ueid/*, gerror_get_message(err)*/);
		delete_ueid(pe->ueid);
	}

	if (err)
		g_clear_error(&err);

}



	static void
repctx_add_string_header(struct reply_context_s *ctx, const gchar *name, const gchar *value)
{
	GByteArray *gba_str;

	gba_str = g_byte_array_new();
	g_byte_array_append(gba_str, (const guint8*)value, strlen(value)+1);
	g_byte_array_set_size(gba_str, gba_str->len-1);

	reply_context_add_header_in_reply(ctx, name, gba_str);
	g_byte_array_free(gba_str, TRUE);
}

static void
repctx_add_int_header(struct reply_context_s *ctx, const gchar *name, gint value)
{
	GByteArray *gba_code;
	gchar wrk_buf[32];

	g_snprintf(wrk_buf,sizeof(wrk_buf),"%d", value);

	gba_code = g_byte_array_new();
	g_byte_array_append(gba_code, (const guint8*)wrk_buf, strlen(wrk_buf)+1);
	g_byte_array_set_size(gba_code, gba_code->len-1);

	reply_context_add_header_in_reply(ctx, name, gba_code);
	g_byte_array_free(gba_code,TRUE);
}


static gboolean
reply_set_status_code(struct reply_context_s *ctx, const gchar *str_ueid,
		event_status_et *status, GError **error)
{
	*status = ES_NOTFOUND;

	if (!pes_get_status(str_ueid, status)) {
		GSETCODE(error, 500, "No status available for [%s]", str_ueid);
		return FALSE;
	}

	reply_context_clear(ctx, FALSE);

	switch (*status) {
		case ES_ERROR_DEF:
			repctx_add_int_header(ctx, MSG_HEADER_EVENT_STATUS, CODE_EVT_ERROR_DEF);
			repctx_add_string_header(ctx, MSG_HEADER_EVENT_MESSAGE, "management failed");
			reply_context_set_message(ctx,200,"event cannot be managed definitely");
			return TRUE;
		case ES_ERROR_TMP:
			repctx_add_int_header(ctx, MSG_HEADER_EVENT_STATUS, CODE_EVT_ERROR_TMP);
			repctx_add_string_header(ctx, MSG_HEADER_EVENT_MESSAGE, "management failed");
			reply_context_set_message(ctx,200,"event cannot be managed temporarily");
			return TRUE;
		case ES_NOTFOUND:
			repctx_add_int_header(ctx, MSG_HEADER_EVENT_STATUS, CODE_EVT_NOTFOUND);
			reply_context_set_message(ctx,200,"Event not found");
			return TRUE;
		case ES_WORKING:
			repctx_add_int_header(ctx, MSG_HEADER_EVENT_STATUS, CODE_EVT_WORKINPROGRESS);
			reply_context_set_message(ctx,200,"work in progress");
			return TRUE;
		case ES_DONE:
			repctx_add_int_header(ctx, MSG_HEADER_EVENT_STATUS, CODE_EVT_WORKDONE);
			reply_context_set_message(ctx,200,"work done");
			return TRUE;
		default:
			GSETCODE(error, 500, "event status error STATUS[%d] UEID[%s]",
					*status, str_ueid);
			return FALSE;
	}
}



static gint
handler_push_event(struct request_context_s *req_ctx, GError ** err)
{
	polix_event_t* pe = NULL;
	event_status_et status;
	struct reply_context_s ctx;
	gchar str_ueid[2048], str_type[256];
	gsize str_ueid_size;

	(void) err;

	init_reply_ctx_with_request(req_ctx, &ctx);
	memset(str_ueid, 0x00, sizeof(str_ueid));

	// init polix_event
	if (!(pe = pe_create())) {
		GSETERROR(&(ctx.warning), "Invalid allocation memory");
		goto error_label;
	}

	// extract data from request
	str_ueid_size = extract_ueid_from_headers(req_ctx->request, &(ctx.warning), str_ueid, sizeof(str_ueid));
	if (!str_ueid_size) {
		GSETERROR(&(ctx.warning), "Invalid request header");
		goto error_label;
	}
	pe->ueid = g_strdup(str_ueid);

	if (!(pe->event=extract_event_from_body(req_ctx->request, &(ctx.warning)))) {
		GSETERROR(&(ctx.warning), "Invalid request body");
		goto error_label;
	}

	gridcluster_event_get_type(pe->event, str_type, sizeof(str_type));
	//g_hash_table_destroy(event);
	//event = NULL;

	gboolean g_to_launnch = FALSE;
	if (!pes_IsExist(pe->ueid)) {
		pes_set_status(pe, ES_WORKING);
		g_to_launnch = TRUE;
	 }

	if (g_to_launnch)
		stats_count_event(str_type);

	if (!reply_set_status_code(&ctx, str_ueid, &status, &(ctx.warning))) {
		GSETERROR(&(ctx.warning), "Could not fetch the status of UEID=[%s]", str_ueid);
		//eventservice_decache_event(str_ueid);
		goto error_label;
	}
	if (!reply_context_reply(&ctx, &(ctx.warning))) {
		GSETERROR(&(ctx.warning),"Request successful but reply failure!");
		//eventservice_decache_event(str_ueid);
		goto reply_error_label;
	}

	if (g_to_launnch) {
		/* the reply has been received by the peer, we can really start to
		 * manage this event */
		g_thread_pool_push(workers_pool, pe/* g_strdup(str_ueid)*/, NULL);
		pe = NULL;
	}
	reply_context_log_access(&ctx, "NS=%s|UEID=%s", source_namespace, str_ueid);
	reply_context_clear(&ctx, TRUE);


	/* no need to decache the event, we know it has not been processed yet */
	TRACE("SUCCESS");
	return TRUE;

error_label:
	TRACE("FAILURE");
	reply_context_clear(&ctx, FALSE);
	reply_context_set_message(&ctx, gerror_get_code(ctx.warning), gerror_get_message(ctx.warning));
	reply_context_reply(&ctx, NULL);
reply_error_label:
	reply_context_log_access(&ctx, "NS=%s|UEID=%s", source_namespace, str_ueid);
	reply_context_clear(&ctx, TRUE);
	if (pe) 
		pes_delete(pe->ueid, TRUE);
	return FALSE;
}



static gint
handler_status_event(struct request_context_s *req_ctx, GError ** err)
{
	struct reply_context_s ctx;
	event_status_et status = ES_NOTFOUND;
	gchar str_ueid[2048];
	gsize str_ueid_size;

	(void) err;

	init_reply_ctx_with_request(req_ctx, &ctx);
	bzero(str_ueid, sizeof(str_ueid));

	str_ueid_size = extract_ueid_from_headers(req_ctx->request, &(ctx.warning), str_ueid, sizeof(str_ueid));
	if (!str_ueid_size) {
		GSETERROR(&(ctx.warning),"Invalid request");
		goto error_label;
	}

	if (!reply_set_status_code(&ctx, str_ueid, &status, &(ctx.warning))) {
		GSETERROR(&(ctx.warning),"Status not found");
		goto error_label;
	}

	if (!reply_context_reply(&ctx, &(ctx.warning))) {
		GSETERROR(&(ctx.warning),"Request successful but reply failure!");
		goto reply_error_label;
	}

	reply_context_log_access(&ctx, "NS=%s|UEID=%s", source_namespace, str_ueid);

	switch (status) {
		case ES_DONE:
		case ES_ERROR_TMP:
		case ES_ERROR_DEF:
			GRID_DEBUG("Event no pending, decaching it UEID=[%s]", str_ueid);
			//eventservice_decache_event(str_ueid);
			delete_ueid(str_ueid);
			break;
		default:
			GRID_DEBUG("Event still pending so not destroyed UEID=[%s]", str_ueid);
			break;
	}

	reply_context_clear(&ctx, TRUE);
	return TRUE;

error_label:
	reply_context_set_message(&ctx, gerror_get_code(ctx.warning), gerror_get_message(ctx.warning));
	reply_context_reply(&ctx, NULL);
reply_error_label:
	reply_context_log_access(&ctx, "NS=%s|UEID=%s", source_namespace, str_ueid);
	reply_context_clear(&ctx, TRUE);
	return FALSE;
}


/*************************************************/

static inline struct cmd_s *module_find_handler(gchar * n, gsize l)
{
	static struct cmd_s CMD[] = {
		{REQ_EVT_PUSH,   handler_push_event,   &(module_stats.counters.push),   &(module_stats.times.push)},
		{REQ_EVT_STATUS, handler_status_event, &(module_stats.counters.status), &(module_stats.times.status)},
		{NULL, NULL, NULL, NULL}
	};

	(void) l;
	struct cmd_s *c;

	for (c = CMD; c && c->c && c->h; c++) {
		if (0 == g_ascii_strcasecmp(c->c, n))
			return c;
	}

	return NULL;
}

static gint
plugin_matcher(MESSAGE m, void *param, GError ** err)
{
	void *name = NULL;
	gsize nameLen = 0;

	(void) param;
	if (!m) {
		GSETERROR(err, "Invalid parameter");
		return -1;
	}

	if (!message_has_NAME(m, err))
		return 0;

	message_get_NAME(m, &name, &nameLen, err);
	if (!name || nameLen <= 0) {
		INFO("The message contains an invalid NAME parameter");
		return 0;
	}

	return (module_find_handler((gchar *) name, nameLen) != NULL ? 1 : 0);
}

static gint
plugin_handler(struct request_context_s *ctx, GError ** err)
{
	GRID_DEBUG("MESSAGE HANDLE BY %s plugin", MODULE_NAME);

	void *name;
	gsize nameLen;
	struct cmd_s *cmd = NULL;
	gint rc;
	GTimer *timer;

	if (!ctx->request) {
		GSETERROR(err, "Invalid parameter");
		return 0;
	}

	message_get_NAME(ctx->request, &name, &nameLen, err);
	if (!name || nameLen <= 6) {
		GSETERROR(err, "The message contains an invalid NAME parameter");
		return 0;
	}

	cmd = module_find_handler((gchar *) name, nameLen);
	if (!cmd) {
		GSETERROR(err, "This message does not concern this plugin.");
		return 0;
	}

	timer = g_timer_new();
	rc = cmd->h(ctx, err);
	g_timer_stop(timer);

	LOCK_STATS();
	module_stats.counters.total ++;
	*(cmd->pStat) = *(cmd->pStat) + 1;
	*(cmd->pTimeStat) += floor(g_timer_elapsed(timer, NULL) * 1000.0);
	UNLOCK_STATS();

	g_timer_destroy(timer);

	GRID_DEBUG("%s return code = %d", MODULE_NAME, rc);

	return (rc);
}


static gboolean plugin_configure(GHashTable *params, GError **error)
{
	guint max_workers;
	gchar* ns = NULL;

    workers_pool = NULL;
    bzero(source_namespace, sizeof(source_namespace));
    memset(&module_stats, 0x00, sizeof(struct module_stats_s));

	pes_init();

	g_static_rec_mutex_init(&stat_mutex);

	ht_type_counters = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	/* extract param */
	if (!(ns = config_load_ns(params, KEY_NAMESPACE))) {
		GSETERROR(error, "no [%s] key in the config", KEY_NAMESPACE);
		return FALSE;
	}
	g_strlcpy(source_namespace, ns, sizeof(source_namespace)-1);

	/* create handle for action services */
	polix = polix_event_create();
	if (!polix) {
		GSETERROR(error, "Polix creation failure");
		return FALSE;
	}

	/* init workers thread pool */
	max_workers = config_get_max_workers(params, "max_workers", 20);
	workers_pool = g_thread_pool_new(thread_func_event_manager, NULL,
			max_workers, TRUE, error);
	if (!workers_pool) {
		GSETERROR(error, "Workers thread pool creation failed");
		return FALSE;
	}
	NOTICE("Threadpool started with [%u] workers", max_workers);

	GRID_DEBUG("Plugin configured");
	return TRUE;
}



static gint
plugin_init(GHashTable * params, GError ** err)
{
	g_setenv("GS_DEBUG_ENABLE", "0", TRUE);

	if (!params) {
		GSETCODE(err, POLIX_ERRCODE_CONFIG, "Invalid parameter");
		return 0;
	}

	/* configure*/
	if (!plugin_configure(params, err))
		return 0;

	/* configure gridd / conscience */
	GPtrArray* service_tags = NULL;
	service_tags = _prepare_tags();
	if (!message_handler_add_v2(MODULE_NAME, plugin_matcher, plugin_handler, service_tags, err)) {
		GSETCODE(err, POLIX_ERRCODE_OTHER, "Module init error");
		return 0;
	}

    srvtimer_register_regular(MODULE_NAME " stats", stats_update, NULL, NULL, 1LLU);

	return 1;
}


static gint
plugin_close(GError ** err)
{
	(void) err;


	//eventservice_close();
	if (workers_pool) {
		g_thread_pool_free(workers_pool, FALSE, FALSE);
		workers_pool = NULL;
	}
	pes_close();
	polix_event_free(polix);


	GRID_DEBUG("Plugin closed");
	return 1;
}

struct exported_api_s exported_symbol = {
	MODULE_NAME,
	plugin_init,
	plugin_close,
	NULL,
	NULL
};

