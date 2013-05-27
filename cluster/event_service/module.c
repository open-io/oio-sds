/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define MODULE_NAME "event_service"
#ifndef LOG_DOMAIN
# define LOG_DOMAIN MODULE_NAME".plugin"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <arpa/inet.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <metautils.h>
#include <metacomm.h>
#include <gridcluster.h>
#include <plugin.h>
#include <message_handler.h>
#include <srvalert.h>
#include <srvtimer.h>
#include <srvstats.h>

#define LOCK_STATS()   g_static_rec_mutex_lock(&stat_mutex)
#define UNLOCK_STATS() g_static_rec_mutex_unlock(&stat_mutex)

#include "./event_service_internals.h"
#include "../events/gridcluster_events.h"
#include "../events/gridcluster_eventsremote.h"
#include "../events/gridcluster_eventhandler.h"
#include "../conscience/conscience.h"

/* ------------------------------------------------------------------------- */

typedef gboolean (*_cmd_handler_f) (struct request_context_s *);

static gint plugin_handler(MESSAGE m, gint cnx, void *param, GError ** err);

struct cmd_s
{
	char *c;
	_cmd_handler_f h;
	guint32 *req_counter;
	guint32 *req_time;
};

struct module_stats_s {
	struct {
		struct {
			guint32 total;
			guint32 push;
			guint32 status;
		} request;
	} counters;
	struct {
		guint32 total;
		guint32 push;
		guint32 status;
	} times;
	GTimer *timer;
};

/* ------------------------------------------------------------------------- */

static gchar type_name[LIMIT_LENGTH_SRVTYPE+1];

static gchar namespace_name[LIMIT_LENGTH_NSNAME+1];

static GStaticMutex counters_mutex;

static GStaticRecMutex stat_mutex;
static gsize stat_index = 0;
static gsize stat_count = 0;
static struct module_stats_s *stats_memory = NULL;
static struct module_stats_s stats_current;

/* ------------------------------------------------------------------------- */

static inline struct module_stats_s *
_get_stats(gsize i)
{
	return stats_memory + (i % stat_count);
}

static void
register_in_cluster(gint64 req_idle)
{
	struct service_info_s *si;
	GError *error;
	char *addr;
	int port;

	si = NULL;
	addr = NULL;
	error = NULL;

	if (!get_network_socket(plugin_handler, &addr, &port, &error)) {
		ERROR("Failed to get the socket used by gridd : %s", gerror_get_message(error));
		if (error)
			g_error_free(error);
		if (addr)
			g_free(addr);
		return;
	}

	si = g_malloc0(sizeof(struct service_info_s));
	g_assert(si != NULL);

	/*set the header */
	service_info_set_address(si, addr, port, &error);
	g_free(addr);
	g_strlcpy(si->ns_name, namespace_name, sizeof(si->ns_name));
	g_strlcpy(si->type, type_name, sizeof(si->type));

	/*add useful and statistics tags */
	si->tags = g_ptr_array_new();
	service_tag_set_value_macro(service_info_ensure_tag(si->tags, NAME_MACRO_CPU_NAME), NAME_MACRO_CPU_TYPE, NULL);
	service_tag_set_value_i64(service_info_ensure_tag(si->tags, NAME_TAGNAME_REQIDLE), req_idle);

	if (!register_namespace_service(si, &error)) {
		ERROR("Failed to register the service : %s", gerror_get_message(error));
		g_clear_error(&error);
	}
	else {
		gchar str_addr[STRLEN_ADDRINFO+1];
		addr_info_to_string(&(si->addr), str_addr, sizeof(str_addr));
		DEBUG("Registered %s=[%s:%d] in NS=[%s] req_idle=%"G_GINT64_FORMAT, si->type,
				str_addr, port, si->ns_name, req_idle);
	}

	service_info_clean(si);
}

#define SAVESTAT(Field) do {\
        gdouble val, t, diff;\
        val=working_stats.Field;\
        diff = (working_stats.Field - oldest_stats.Field);\
	t = (working_stats.Field - oldest_stats.Field);\
        srvstat_set(MODULE_NAME".nb."#Field, val);\
        srvstat_set(MODULE_NAME".rate."#Field, diff / elapsed);\
        srvstat_set(MODULE_NAME".t."#Field, (t>0.0)&&(diff>0.0)? (t/diff) : 0.0);\
} while (0)

static void
stats_update(gpointer d)
{
	gint64 req_idle;
	struct module_stats_s working_stats, oldest_stats, *p_stats;
	gdouble elapsed;

	(void) d;

	LOCK_STATS();
	memcpy(&working_stats, &stats_current, sizeof(struct module_stats_s));
	/*get the oldest state */
	p_stats = _get_stats(stat_index);
	elapsed = g_timer_elapsed(p_stats->timer, NULL);
	memcpy(&oldest_stats, p_stats, sizeof(struct module_stats_s));
	/*replace the oldest state with the current, and skip to next oldest */
	memcpy(&(p_stats->counters), &(stats_current.counters), sizeof(stats_current.counters));
	memcpy(&(p_stats->times),    &(stats_current.times),    sizeof(stats_current.times));
	g_timer_reset(p_stats->timer);
	stat_index++;
	UNLOCK_STATS();

	/*Now we can register the stats in the gridd repository*/
	SAVESTAT(counters.request.total);
	SAVESTAT(counters.request.push);
	SAVESTAT(counters.request.status);

	/*And finally, we compute the request-idle and send the META2 stats*/
	do {
		gdouble req_rate, req_time, counter_diff_d, time_used_d;
		gdouble effective_time_used_d;

		counter_diff_d =
			(working_stats.counters.request.push   - oldest_stats.counters.request.push  ) +
			(working_stats.counters.request.status - oldest_stats.counters.request.status);
		time_used_d =
			(working_stats.times.push   - oldest_stats.times.push  ) +
			(working_stats.times.status - oldest_stats.times.status);

		time_used_d /= 1000.0;
		req_rate = counter_diff_d / elapsed;
		req_time = counter_diff_d <= 0.0 ? 0.0 : (time_used_d / counter_diff_d);
		effective_time_used_d = req_time * req_rate;

		req_idle = (effective_time_used_d >= elapsed) ? 0.0
		    : floor(100.0 * (elapsed - effective_time_used_d) / elapsed);
		/*	
		DEBUG("req_idle=%lld elapsed=%.3f time_used_d=%.3f counter_diff_d=%lld effective_time_used_d=%.3f",
		    req_idle, elapsed, time_used_d, counter_diff_d, effective_time_used_d);
		*/
	} while (0);

	register_in_cluster(req_idle > 0 ? req_idle : 1.0);
}

/* ------------------------------------------------------------------------- */

static inline void
init_reply_ctx_with_request(struct request_context_s *req, struct reply_context_s *rep)
{
	if (rep) {
		memset(rep, 0x00, sizeof(struct reply_context_s));
		rep->req_ctx = req;
	}
}

static inline gsize
extract_ueid_from_headers(MESSAGE request, GError **error, gchar *dst, gsize dst_size)
{
	void *data;
	gsize data_size;

	if (0 >= message_get_field(request,MSG_HEADER_UEID,sizeof(MSG_HEADER_UEID)-1, &data, &data_size, NULL)) {
		GSETCODE(error,400,"Header '"MSG_HEADER_UEID"' extraction failure");
		return 0;
	}

	return g_strlcpy(dst, data, MIN(dst_size,data_size+1));
}

static inline gridcluster_event_t*
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

static inline void
repctx_add_string_header(struct reply_context_s *ctx, const gchar *name, const gchar *value)
{
	GByteArray *gba_str;
	gba_str = g_byte_array_new();
	g_byte_array_append(gba_str, (const guint8*)value, strlen(value));
	g_byte_array_append(gba_str, (const guint8*)"", 1);
	reply_context_add_header_in_reply(ctx, name, gba_str);
	g_byte_array_free(gba_str, TRUE);
}

static inline void
repctx_add_int_header(struct reply_context_s *ctx, const gchar *name, gint value)
{
	GByteArray *gba_code;
	gchar wrk_buf[32];
	gba_code = g_byte_array_append(g_byte_array_new(), (const guint8*)wrk_buf, g_snprintf(wrk_buf,sizeof(wrk_buf),"%d", value));
	reply_context_add_header_in_reply(ctx, name, gba_code);
	g_byte_array_free(gba_code,TRUE);
}

static inline gboolean
reply_set_status_code(struct reply_context_s *ctx, const gchar *str_ueid, GError **error)
{
	enum event_status_e status;
	GError *error_local = NULL;

	status = eventservice_stat_event(str_ueid, &error_local);

	switch (status) {
	case ES_ERROR_DEF:
		repctx_add_int_header(ctx, MSG_HEADER_EVENT_STATUS, CODE_EVT_ERROR_DEF);
		repctx_add_string_header(ctx, MSG_HEADER_EVENT_MESSAGE, gerror_get_message(error_local));
		reply_context_set_message(ctx,200,"event cannot be managed");
		return TRUE;
	case ES_ERROR_TMP:
		repctx_add_int_header(ctx, MSG_HEADER_EVENT_STATUS, CODE_EVT_ERROR_TMP);
		repctx_add_string_header(ctx, MSG_HEADER_EVENT_MESSAGE, gerror_get_message(error_local));
		reply_context_set_message(ctx,200,"event cannot be managed");
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
		GSETERROR(&error_local, "event ERROR [%s]", str_ueid);
		if (error)
			*error = error_local;
		return FALSE;
	}

	return TRUE;
}

/* ------------------------------------------------------------------------- */

static gboolean
handler_push_event(struct request_context_s *req_ctx)
{
	GError *error_local;
	struct reply_context_s ctx;
	gridcluster_event_t *event;
	gchar str_ueid[2048];
	gsize str_ueid_size;

	init_reply_ctx_with_request(req_ctx, &ctx);
	error_local = NULL;
	memset(str_ueid, 0x00, sizeof(str_ueid));

	str_ueid_size = extract_ueid_from_headers(req_ctx->request, &error_local, str_ueid, sizeof(str_ueid));
	if (!str_ueid_size)
		goto error_label;
	if (!(event=extract_event_from_body(req_ctx->request, &error_local)))
		goto error_label;
	if (!eventservice_manage_event(str_ueid, event, &error_local)) {
		GSETERROR(&error_local,"Internal error, event management failed");
		goto error_label;
	}
	if (!reply_set_status_code(&ctx, str_ueid, &error_local))
		goto error_label;
	if (!reply_context_reply(&ctx, &error_local)) {
		GSETERROR(&error_local,"Request successful but reply failure!");
		goto reply_error_label;
	}
	
	reply_context_log_access(&ctx, "NS=%s|UEID=%s", namespace_name, str_ueid);
	ctx.warning = error_local;
	reply_context_clear(&ctx, TRUE);
	return TRUE;

error_label:
	reply_context_clear(&ctx, TRUE);
	reply_context_set_message(&ctx, gerror_get_code(error_local), gerror_get_message(error_local));
	reply_context_reply(&ctx, NULL);
reply_error_label:
	ctx.warning = error_local;
	reply_context_log_access(&ctx, "NS=%s", namespace_name);
	reply_context_clear(&ctx, TRUE);
	return FALSE;
}

static gboolean
handler_status_event(struct request_context_s *req_ctx)
{
	GError *error_local;
	struct reply_context_s ctx;
	gchar str_ueid[2048];
	gsize str_ueid_size;

	init_reply_ctx_with_request(req_ctx, &ctx);
	error_local = NULL;
	memset(str_ueid, 0x00, sizeof(str_ueid));

	str_ueid_size = extract_ueid_from_headers(req_ctx->request, &error_local, str_ueid, sizeof(str_ueid));
	if (!str_ueid_size)
		goto error_label;
	if (!reply_set_status_code(&ctx, str_ueid, &error_local))
		goto error_label;
	if (!reply_context_reply(&ctx, &error_local)) {
		GSETERROR(&error_local,"Request successful but reply failure!");
		goto reply_error_label;
	}

	reply_context_log_access(&ctx, "NS=%s|UEID=%s", namespace_name, str_ueid);
	ctx.warning = error_local;
	reply_context_clear(&ctx, TRUE);
	return TRUE;

error_label:
	reply_context_clear(&ctx, TRUE);
	reply_context_set_message(&ctx, gerror_get_code(error_local), gerror_get_message(error_local));
	reply_context_reply(&ctx, NULL);
reply_error_label:
	ctx.warning = error_local;
	reply_context_log_access(&ctx, "NS=%s", namespace_name);
	reply_context_clear(&ctx, TRUE);
	return FALSE;
}

static inline struct cmd_s *
module_find_handler(gchar * n, gsize l)
{
	struct cmd_s *c;
	static struct cmd_s CMD[] = {
		{REQ_EVT_PUSH,   handler_push_event,   &(stats_current.counters.request.push),   &(stats_current.times.push)},
		{REQ_EVT_STATUS, handler_status_event, &(stats_current.counters.request.status), &(stats_current.times.status)},
		{NULL, NULL, NULL, NULL}
	};
	for (c = CMD; c && c->c; c++) {
		if (0 == g_ascii_strncasecmp(c->c, n, l))
			return c;
	}
	return NULL;
}

static gint
plugin_matcher(MESSAGE m, void *param, GError ** err)
{
	struct cmd_s *c;
	gchar *name;
	gsize nameLen;

	(void)param;
	if (!m) {
		GSETERROR(err, "Invalid parameter");
		return -1;
	}

	if (!message_has_NAME(m, err))
		return 0;

	message_get_NAME(m, (void *) &name, &nameLen, err);
	if (!name || nameLen <= 0) {
		INFO("The message contains an invalid NAME parameter");
		return 0;
	}

	c = module_find_handler(name, nameLen);
	return (c ? 1 : 0);
}

static gint
plugin_handler(MESSAGE m, gint cnx, void *param, GError ** err)
{
	gdouble elapsed;
	gchar *name;
	gsize nameLen;
	struct cmd_s *c;
	struct request_context_s ctx;
	GTimer *req_timer;
	gint rc;

	(void)param;
	c = NULL;
	rc = -1;
	req_timer = g_timer_new();

	if (!m) {
		GSETERROR(err, "Invalid parameter");
		goto exit_label;
	}

	message_get_NAME(m, (void *) &name, &nameLen, err);
	if (!name || nameLen <= 6) {
		GSETERROR(err, "The message contains an invalid NAME parameter");
		goto exit_label;
	}

	c = module_find_handler(name, nameLen);
	if (!c) {
		GSETERROR(err, "This message does not concern this plugin.");
		goto exit_label;
	}

	ctx.request = m;
	ctx.fd = cnx;

	rc = c->h(&ctx);
	
exit_label:
	elapsed = g_timer_elapsed(req_timer, NULL);

	g_static_mutex_lock(&counters_mutex);
	if (c) {
		*(c->req_counter) = *(c->req_counter) + 1;
		*(c->req_time) += elapsed;
	}
	stats_current.counters.request.total ++;
	g_static_mutex_unlock(&counters_mutex);

	g_timer_destroy(req_timer);
	return rc;
}

static void
_init_static_data(void)
{
	gsize i;

	memset(namespace_name, 0x00, sizeof(namespace_name));

	g_static_rec_mutex_init(&stat_mutex);
	memset(&stats_current, 0x00, sizeof(struct module_stats_s));
	stat_count = 5;
	stat_index = 0;
	stats_memory = g_try_malloc0(sizeof(struct module_stats_s) * stat_count);
	for (i = 0; i < stat_count; i++)
		(stats_memory + i)->timer = g_timer_new();
}

static gboolean
_load_namespace_name(GHashTable *params, GError **err)
{
	gchar *str;

	str = g_hash_table_lookup(params,"type");
	if (!str) {
		GSETERROR(err,"No 'type' key found in the configuration");
		return FALSE;
	}
	g_strlcpy(type_name, str, sizeof(type_name));

	str = g_hash_table_lookup(params,"namespace");
	if (!str) {
		GSETERROR(err,"No 'namespace' key found in the configuration");
		return FALSE;
	}
	g_strlcpy(namespace_name, str, sizeof(namespace_name));

	NOTICE("Namespace configured to '%s'", namespace_name);
	return TRUE;
}

static gint
plugin_init(GHashTable * params, GError ** err)
{
	(void)params;
	_init_static_data();
	g_static_mutex_init(&counters_mutex);

	if (!_load_namespace_name(params,err)) {
		GSETERROR(err,"Namespace initiation failure");
		goto error_label;
	}

	if (!message_handler_add(MODULE_NAME, plugin_matcher, plugin_handler, err)) {
		GSETERROR(err, "Failed to add a new server message handler");
		goto error_label;
	}

	/* Register this met&2 in gridcluster */
	srvtimer_register_regular(MODULE_NAME " stats", stats_update, NULL, NULL, 1LLU);

	return 1;
error_label:
	return 0;
}

static gint
plugin_close(GError ** err)
{
	DEBUG("Plugin closed");
	(void)err;
	return 1;
}

struct exported_api_s exported_symbol = {
	MODULE_NAME,
	plugin_init,
	plugin_close,
	NULL,
	NULL
};
