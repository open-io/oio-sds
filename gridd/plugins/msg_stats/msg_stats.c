#define MODULE_NAME "stats"

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN MODULE_NAME".plugin"
#endif

#include <string.h>
#include <sys/time.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <gridd/main/plugin.h>
#include <gridd/main/message_handler.h>
#include <gridd/main/srvtimer.h>
#include <gridd/main/srvstats.h>

#include "./msg_stats.h"

#define JUMPERR(C,M) do { code=(C) ; msg=(M); goto errorLabel; } while (0);


static gint
plugin_matcher (MESSAGE m, void *param, GError **err)
{
	void *field = NULL;
	gsize nameLen=0;
	
	(void) param;

	if (!m) {
		GSETERROR(err, "invalid parameter");
		return -1;
	}
	
	if (!message_has_NAME(m,err)) {
		DEBUG("the message has no NAME field");
		return 0;
	}
	
	message_get_NAME(m, &field, &nameLen, err);
	if (!field || nameLen<=0) {
		INFO("cannot get the NAME field of the message");
		return 0;
	}
	
	return (nameLen==sizeof(MSG_NAME)-1)
		&& !g_ascii_strncasecmp((gchar*)field, MSG_NAME, sizeof(MSG_NAME)-1);
}


static gint
handler_get_stats(struct request_context_s *req_ctx, const char* pattern, GError **err)
{
	gint rc;
	struct reply_context_s ctx;

	memset(&ctx, 0x00, sizeof(struct reply_context_s));
	ctx.req_ctx = req_ctx;
	
	void msg_append_field(gpointer u, const gchar *name, GVariant *gv) {
		gchar *n, *v;
		(void) u;

		if (!gv)
			return;

		n = g_strdup_printf("%s%s", MSGFIELD_STATPREFIX, name);
		v = g_variant_print(gv, FALSE);

		reply_context_add_strheader_in_reply(&ctx, n, v);

		g_free(n);
		g_free(v);
	}

	srvstat_foreach_gvariant(pattern, msg_append_field, NULL);

	reply_context_set_message(&ctx, 200, "OK");
	reply_context_log_access(&ctx, "%s", pattern);

	rc = reply_context_reply(&ctx, err);
	reply_context_clear(&ctx, TRUE);

	return rc;
}


static gint
plugin_handler (MESSAGE m, gint fd, void *param, GError **err)
{
	gint rc;
	gchar tmpPattern[256];
	void *pattern=NULL;
	gsize patternLen=0;
	struct request_context_s ctx;

	(void) param;
	memset(tmpPattern, 0X00, sizeof(tmpPattern));
	memset(&ctx, 0x00, sizeof(struct request_context_s));
	gettimeofday(&(ctx.tv_start), NULL);
	ctx.fd = fd;
	ctx.request = m;

	rc = message_get_field(m, MSGKEY_PATTERN, sizeof(MSGKEY_PATTERN)-1, &pattern, &patternLen, err);
	switch (rc) {

		case -1:
			GSETERROR(err,"Cannot lookup the parameter %s", MSGKEY_PATTERN);
			return 0;
		case 0:
			GSETERROR(err,"no pattern provided %s", MSGKEY_PATTERN);
			return 0;
		case 1:
			DEBUG("pattern found under key %s : %.*s (length=%"G_GSIZE_FORMAT")",
				MSGKEY_PATTERN, (int)patternLen, (char*)pattern, patternLen);
			if (patternLen > sizeof(tmpPattern)-1) {
				GSETERROR(err,"pattern too long, maximum %u characters", sizeof(tmpPattern)-1);
				return 0;
			}
			memcpy(tmpPattern, pattern, patternLen);
			return handler_get_stats (&ctx, tmpPattern, err);
	}

	GSETERROR(err,"bad return code from message_get_field : %d", rc);
	return 0;
}


/* ------------------------------------------------------------------------- */


static gint plugin_init (GHashTable *params, GError **err)
{
	if (!params) {
		GSETERROR(err,"invalid parameter");
		return 0;
	}
	
	message_handler_add ("stats", plugin_matcher, plugin_handler, err);

	return 1;
}


static gint plugin_close (GError **err)
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

struct exported_api_s exported_symbol_v2 = 
{
	MODULE_NAME,
	plugin_init,
	plugin_close,
	NULL,
	NULL
};

