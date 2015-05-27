/*
OpenIO SDS gridd
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
	(void)param, (void)err;
	gsize len = 0;
	void *n = message_get_NAME(m, &len);
	if (!n || len != sizeof("REQ_STATS")-1)
		return 0;
	return 0 == memcmp(n, "REQ_STATS", sizeof("REQ_STATS")-1);
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
	(void) param;
	struct request_context_s ctx;
	memset(&ctx, 0x00, sizeof(struct request_context_s));
	gettimeofday(&(ctx.tv_start), NULL);
	ctx.fd = fd;
	ctx.request = m;

	gchar *pattern = message_extract_string_copy(m, MSGKEY_PATTERN);
	if (!pattern) {
		GSETERROR(err,"no pattern provided %s", MSGKEY_PATTERN);
		return 0;
	} else {
		gint rc = handler_get_stats (&ctx, pattern, err);
		g_free (pattern);
		return rc;
	}
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

