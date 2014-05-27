#define MODULE_NAME "vns_agent"

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid."MODULE_NAME".plugin"
#endif

#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <gridd/main/plugin.h>
#include <gridd/main/message_handler.h>
#include <gridd/main/srvstats.h>
#include <gridd/main/srvtimer.h>
#include <gridd/main/srvalert.h>

#include "lib/vns_agent.h"
#include "remote/vns_agent_remote.h"

#define VNS_AGENT_ERRID_CONFIG "vns_agent.config"
#define VNS_AGENT_ERRID_DB     "vns_agent.db"
#define VNS_AGENT_ERRID_OTHER  "vns_agent.other"

#ifndef CFGKEY_ALERT_LIMIT
# define CFGKEY_ALERT_LIMIT "alert_frequency_limit"
#endif

#define JUMPERR(CTX,C,M) \
do {\
	reply_context_clear((CTX), FALSE);\
	reply_context_set_message ((CTX),\
		((CTX)->warning && (CTX)->warning->code ? (CTX)->warning->code : (C)),\
		((CTX)->warning && (CTX)->warning->message ? (CTX)->warning->message : (M)));\
	goto errorLabel;\
} while (0)

#define MSG_BAD_REQUEST "Bad request"
#define MSG_INTERNAL_ERROR "Internal error"
#define MSG_REQUEST_FORBIDEN "Request forbiden"

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

struct vns_agent_stats_s
{
	gint64 total;
	gint64 info;
};

static struct vns_agent_stats_s vnsastats;
static struct vns_agent_stats_s vnsatimes;

static GStaticRecMutex stat_mutex;

static GPtrArray*
_prepare_tags(void)
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

static gint
handler_info(struct request_context_s *req_ctx, GError ** err)
{
        struct reply_context_s ctx;
        char ns_name[LIMIT_LENGTH_NSNAME];

        memset(ns_name, '\0', sizeof(ns_name));
        memset(&ctx, 0x00, sizeof(struct reply_context_s));
        ctx.req_ctx = req_ctx;

        if (!vns_agent_info(ns_name, &(ctx.warning))) {
                GSETERROR(&(ctx.warning), "Failed to get meta1 info");
                JUMPERR(&ctx, 500, MSG_INTERNAL_ERROR);
        }

        reply_context_set_body(&ctx, ns_name, strlen(ns_name), REPLYCTX_COPY | REPLYCTX_DESTROY_ON_CLEAN);
        reply_context_set_message(&ctx, 200, "OK");

        if (!reply_context_reply(&ctx, &(ctx.warning))) {
                GSETERROR(&(ctx.warning), "Failed to send response");
                JUMPERR(&ctx, 500, MSG_INTERNAL_ERROR);
        }

        /* Log access */
        reply_context_log_access(&ctx, "");

        /*clean the working structures */
        reply_context_clear(&ctx, TRUE);
        return (1);

      errorLabel:
        if (ctx.warning && ctx.warning->message)
                WARN("Failed to gather info about this VNS_AGENT. cause:\n\t%s", ctx.warning->message);
        if (!reply_context_reply(&ctx, err))
                GSETERROR(err, "Failed to send response");

        /* Log access */
        reply_context_log_access(&ctx, "");

        /*clean the working structures */
        reply_context_clear(&ctx, TRUE);
        return (0);
}


/*************************************************/

static struct cmd_s CMD[] =
{
	{NAME_MSGNAME_VNSA_INFO, handler_info, &(vnsastats.info), &(vnsatimes.info)},
	{NULL, NULL, NULL, NULL}
};

static inline struct cmd_s *
__find_handler(gchar * n, gsize l)
{
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

	return (__find_handler((gchar *) name, nameLen) != NULL ? 1 : 0);
}

static gint
plugin_handler(struct request_context_s *ctx, GError ** err)
{
	DEBUG("MESSAGE HANDLE BY VNS AGENT plugin");
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

	cmd = __find_handler((gchar *) name, nameLen);
	if (!cmd) {
		GSETERROR(err, "This message does not concern this plugin.");
		return 0;
	}

	timer = g_timer_new();
	rc = cmd->h(ctx, err);
	g_timer_stop(timer);

	LOCK_STATS();
	vnsastats.total++;
	*(cmd->pStat) = *(cmd->pStat) + 1;
	*(cmd->pTimeStat) += floor(g_timer_elapsed(timer, NULL) * 1000.0);
	UNLOCK_STATS();

	g_timer_destroy(timer);

	DEBUG("vns_agent_handler return code = %d", rc);

	return (rc);
}

static void
_init_static_data(void)
{
	g_static_rec_mutex_init(&stat_mutex);
	memset(&vnsastats, 0x00, sizeof(struct vns_agent_stats_s));
	memset(&vnsatimes, 0x00, sizeof(struct vns_agent_stats_s));
}

static gint
plugin_init(GHashTable * params, GError ** err)
{
	if (!params) {
		GSETCODE(err, VNS_AGENT_ERRCODE_CONFIG, "Invalid parameter");
		return 0;
	}

	_init_static_data();

	get_namespace_info_f get_ns_info = NULL;
	get_ns_info = g_hash_table_lookup(params, KEY_NS_INFO_FUNC);
	if (!get_ns_info) {
		GSETCODE(err, VNS_AGENT_ERRCODE_CONFIG, "no [%s] key in the config", KEY_NS_INFO_FUNC);
		return 0;
	}

	if (!vns_agent_init(params, err)) {
		GSETERROR(err, "Back-End init error");
		return 0;
	}

	GPtrArray* service_tags = NULL;
	service_tags = _prepare_tags();

	if (!message_handler_add_v2("vns_agent", plugin_matcher, plugin_handler, service_tags, err)) {
		GSETCODE(err, VNS_AGENT_ERRCODE_OTHER, "Module init error");
		return 0;
	}

	guint64 vns_agent_space_used_refresh_rate;
	gint64 i64;
	gchar * tmp_str = NULL;
	tmp_str = g_hash_table_lookup(params, KEY_SPACE_USED_REFRESH_RATE);
	if (!tmp_str)
		vns_agent_space_used_refresh_rate = DEFAULT_SPACE_USED_REFRESH_RATE;
	else {
		i64 = g_ascii_strtoll(tmp_str, NULL, 10);
		vns_agent_space_used_refresh_rate = i64;
		if (vns_agent_space_used_refresh_rate < LIMIT_MIN_SPACE_USED_REFRESH_RATE || 
				vns_agent_space_used_refresh_rate > LIMIT_MAX_SPACE_USED_REFRESH_RATE) {
			WARN("[space_used_refresh_rate] parameter out of range [%u,%u]",
					LIMIT_MIN_SPACE_USED_REFRESH_RATE, LIMIT_MAX_SPACE_USED_REFRESH_RATE);
			vns_agent_space_used_refresh_rate =
				CLAMP(vns_agent_space_used_refresh_rate, LIMIT_MIN_SPACE_USED_REFRESH_RATE, LIMIT_MAX_SPACE_USED_REFRESH_RATE);
		}
	}

	NOTICE("space_used refresh rate set to [%lu] s", vns_agent_space_used_refresh_rate);

	/* register callback to periodicly refresh vns space_used and send it to the conscience */
	srvtimer_register_regular(MODULE_NAME " virtual ns space_used refresh",
			vns_agent_space_used_refresh, NULL, NULL,
			vns_agent_space_used_refresh_rate);

	return 1;
}

static gint
plugin_configure(GHashTable *params, GError **err)
{
	(void) params;
	(void) err;
	INFO("Reloading plugin configure");
	return 1;
}

static gint
plugin_close(GError ** err)
{
	(void) err;

	DEBUG("about to close the VNS AGENT plugin");
	vns_agent_close();

	return 1;
}
struct exported_api_s exported_symbol = {
	MODULE_NAME,
	plugin_init,
	plugin_close,
	NULL,
	NULL
};

struct exported_api_s exported_symbol_v2 = {
	MODULE_NAME,
	plugin_init,
	plugin_close,
	NULL,
	plugin_configure
};
