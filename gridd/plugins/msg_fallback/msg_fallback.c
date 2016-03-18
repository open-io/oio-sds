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

#define MODULE_NAME "fallback"

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
	struct request_context_s req_ctx = {0};
	struct reply_context_s ctx = {0};

	(void) param, (void) err;
	gettimeofday(&(req_ctx.tv_start), NULL);
	req_ctx.fd = fd;
	req_ctx.request = m;
	ctx.req_ctx = &req_ctx;

	reply_context_set_message(&ctx, CODE_NOT_FOUND, "no handler found");
	reply_context_log_access(&ctx, NULL);
	reply_context_reply(&ctx, NULL);
	reply_context_clear(&ctx, TRUE);
	return 1;
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
