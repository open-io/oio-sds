#define MODULE_NAME "acl"

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN MODULE_NAME".plugin"
#endif

#include <string.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#include <gridd/main/plugin.h>
#include <gridd/main/srvtimer.h>
#include <gridd/main/message_handler.h>

#define MODULE_NAME "acl"
#define ACL_REFRESH_CONF_OPTION "acl_refresh_rate"

#define LIMIT_MIN_REFRESH_RATE 1
#define LIMIT_MAX_REFRESH_RATE 30
#define DEFAULT_ACL_REFRESH_RATE 10

static GSList* acl = NULL;
static get_namespace_info_f get_ns_info = NULL;

static void
plugin_reply_error(struct request_context_s *req_ctx, int code, gchar *msg)
{
        struct reply_context_s ctx;
        bzero(&ctx, sizeof(ctx));
        ctx.req_ctx = req_ctx;

        /* Reply now! */
        reply_context_set_body(&ctx, NULL, 0, 0);

	DEBUG("return code  = %d", code);
        reply_context_set_message(&ctx, code, msg);

        reply_context_reply(&ctx, NULL);

        reply_context_clear(&ctx, TRUE);
}


static gint
plugin_matcher (MESSAGE m, void *params, GError **err)
{
	(void) m;
	(void) params;
	(void) err;
	/* trap all requests */
	return 1;
}

static gint
plugin_handler (struct request_context_s* ctx, GError **err)
{
	/* Just check if the remote_addr allow to talk with us
	   & update acl if too old */
	if (!ctx || !ctx->remote_addr) {
		GSETERROR(err, "Invalid parameters : %p | %p", ctx, ctx->remote_addr);
		return 0;
	}
	gchar dst[128];
	gsize dstSize = sizeof(dst);
	guint16 port = 0;

	addr_info_get_addr(ctx->remote_addr, dst, dstSize, &port);

	/* TODO do something with ip v6 addr format */

	if(!authorized_personal_only(dst, acl)) {
		WARN("Remote addr [%s] not allowed to work with this server", dst);
		plugin_reply_error(ctx, 403 , "Permission denied");
		return 1;
	}
	
	DEBUG("client [%s] allowed", dst);
	return 2;
}

static void
acl_display(gpointer data, gpointer udata)
{
	(void) udata;
	DEBUG("rule: [%s]", access_rule_to_string((addr_rule_t*) data));
}

static void
_addr_rule_g_clean(gpointer data, gpointer udata)
{
	(void) udata;
	addr_rule_g_free(data);
}

static void
acl_refresh_conf(gpointer data)
{
	(void) data;
	namespace_info_t* ns_info = NULL;
	GError *error = NULL;
	ns_info = get_ns_info(&error);
	if(!ns_info) {
		ERROR("Failed to load namespace info in acl plugin");
		return;
	}

	GByteArray* acl_allow = NULL;
	GByteArray* acl_deny = NULL;

	acl_allow = g_hash_table_lookup(ns_info->options, NS_ACL_ALLOW_OPTION);
	acl_deny = g_hash_table_lookup(ns_info->options, NS_ACL_DENY_OPTION);
	if (acl_allow && acl_allow->data) {
		TRACE("acl_allow = [%s]", ((gchar*)acl_allow->data));
	}
	if (acl_deny && acl_deny->data) {
		TRACE("acl_deny = [%s]", ((gchar*)acl_deny->data));
	}
		
	g_slist_foreach(acl, _addr_rule_g_clean, NULL);
	g_slist_free(acl);
		
	acl = parse_acl(acl_allow, TRUE);
	g_slist_foreach(acl, acl_display, NULL);
	acl = g_slist_concat(acl, parse_acl(acl_deny, FALSE));

	namespace_info_free(ns_info);
}

static gint
plugin_init (GHashTable* params, GError **error)
{
	DEBUG("Init acl plugin");
	get_ns_info = g_hash_table_lookup(params, NS_INFO_FUNC);
	
	if(!get_ns_info) {
		ERROR("No ns_info_func passed in acl plugin");
		return 0;
	}
	namespace_info_t* ns_info = NULL;
	ns_info = get_ns_info(error);
	if(!ns_info) {
		ERROR("Failed to laod namespace info in acl plugin");
		return 0;
	}

	DEBUG("namespace name = [%s]", ns_info->name);

	GByteArray* acl_allow = NULL;
	GByteArray* acl_deny = NULL;

	acl_allow = g_hash_table_lookup(ns_info->options, NS_ACL_ALLOW_OPTION);
	acl_deny = g_hash_table_lookup(ns_info->options, NS_ACL_DENY_OPTION);
	if (acl_allow && acl_allow->data) {
		TRACE("acl_allow = [%s]", ((gchar*)acl_allow->data));
	}
	else {
		TRACE("No access allow in acl configuration");
	}

	if(acl_deny && acl_deny->data) {
		TRACE("acl_deny = [%s]", ((gchar*)acl_deny->data));
	} else {
		TRACE("No access deny in acl configuration");
	}


		
	acl = parse_acl(acl_allow, TRUE);
	g_slist_foreach(acl, acl_display, NULL);
	acl = g_slist_concat(acl, parse_acl(acl_deny, FALSE));

	namespace_info_free(ns_info);

	/* register the message handler */
	message_handler_add_v2("acl", plugin_matcher, plugin_handler, NULL, error);

	/* register callback for update ns_info */
	gint64 i64;
	guint64 acl_period_refresh_conf;
	gchar *str = NULL;
	str = g_hash_table_lookup(params, ACL_REFRESH_CONF_OPTION);
	if(!str) {	
		DEBUG("Option [%s] not found in acl config, setting default value", ACL_REFRESH_CONF_OPTION);
		acl_period_refresh_conf = DEFAULT_ACL_REFRESH_RATE;
	} else {
		i64 = g_ascii_strtoll(str, NULL, 10);
		acl_period_refresh_conf = i64 / 1000UL;
	}

	if (acl_period_refresh_conf < LIMIT_MIN_REFRESH_RATE || acl_period_refresh_conf > LIMIT_MAX_REFRESH_RATE) {
		WARN("[acl_refresh_rate] parameter out of range [%u,%u]", LIMIT_MIN_REFRESH_RATE,
				LIMIT_MAX_REFRESH_RATE);
		acl_period_refresh_conf =
			CLAMP(acl_period_refresh_conf, LIMIT_MIN_REFRESH_RATE, LIMIT_MAX_REFRESH_RATE);
	}
        NOTICE("acl_refresh_rate set to [%lu] s", acl_period_refresh_conf);

	srvtimer_register_regular(MODULE_NAME " refresh configuration",
                        acl_refresh_conf, NULL, NULL,
                        acl_period_refresh_conf);

	return 1;
}

static gint
plugin_close (GError **err)
{
	(void) err;
	return 1;
}

struct exported_api_s exported_symbol =
{
	MODULE_NAME,
	plugin_init,
	plugin_close,
	NULL,
	NULL
};

