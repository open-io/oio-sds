#define MODULE_NAME "fallback"

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN MODULE_NAME".plugin"
#endif

#include <string.h>
#include <sys/time.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <gridd/main/plugin.h>
#include <gridd/main/message_handler.h>


static gint
plugin_matcher(MESSAGE m, void *param, GError ** err)
{
	(void)m;
	(void)param;
	(void)err;
	return 1;
}


static gint
plugin_handler(MESSAGE m, gint fd, void *param, GError ** err)
{
	gint rc;
	struct request_context_s req_ctx;
	struct reply_context_s ctx;

	(void) param;
	memset(&req_ctx, 0x00, sizeof(struct request_context_s));
	memset(&ctx, 0x00, sizeof(struct reply_context_s));
	gettimeofday(&(req_ctx.tv_start), NULL);
	req_ctx.fd = fd;
	req_ctx.request = m;
	ctx.req_ctx = &req_ctx;

	reply_context_set_message(&ctx, 404, "No message handler found, check your NS configuration");
	reply_context_log_access(&ctx, "");

	rc = reply_context_reply(&ctx, err);
	reply_context_clear(&ctx, TRUE);

	return rc;
}


static gint
plugin_init(GHashTable * params, GError ** err)
{
	(void)params;
	return message_handler_add("fallback", plugin_matcher, plugin_handler, err);
}


static gint
plugin_close(GError ** err)
{
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

struct exported_api_s exported_symbol_v2 = {
	MODULE_NAME,
	plugin_init,
	plugin_close,
	NULL,
	NULL
};
