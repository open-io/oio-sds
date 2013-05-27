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

#define MODULE_NAME "ping"

#ifndef LOG_DOMAIN
#define LOG_DOMAIN MODULE_NAME".plugin"
#endif

#include <string.h>
#include <sys/time.h>

#include <glib.h>

#include <metautils.h>
#include <metacomm.h>

#include "../../main/plugin.h"
#include "../../main/message_handler.h"

static gint
plugin_matcher(MESSAGE m, void *param, GError ** err)
{
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

	return ((nameLen >= 4)
	    && (*(name) == 'P' || *(name) == 'p')
	    && (*(name + 1) == 'I' || *(name + 1) == 'i')
	    && (*(name + 2) == 'N' || *(name + 2) == 'n')
	    && (*(name + 3) == 'G' || *(name + 3) == 'g')
	    )? 1 : 0;
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

	reply_context_set_message(&ctx, 200, "OK");
	reply_context_log_access(&ctx, "");

	rc = reply_context_reply(&ctx, err);
	reply_context_clear(&ctx, TRUE);

	return rc;
}


static gint
plugin_init(GHashTable * params, GError ** err)
{
	(void)params;
	return message_handler_add("ping", plugin_matcher, plugin_handler, err);
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
