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

#define MODULE_NAME "ping"

#include <sys/time.h>

#include <metautils/lib/metautils.h>

#include <gridd/main/plugin.h>
#include <gridd/main/message_handler.h>

static gint
_match_PING(MESSAGE m, void *param UNUSED, GError ** err UNUSED)
{
	gsize len = 0;
	void *n = metautils_message_get_NAME(m, &len);
	GRID_WARN("%.*s", (gint)len, (gchar*)n);
	return n && len == 8 && !memcmp(n, "REQ_PING", 8);
}

static gint
_handle_PING(MESSAGE m, gint fd, void *param UNUSED, GError ** err UNUSED)
{
	struct request_context_s req_ctx = {0};
	struct reply_context_s ctx = {0};

	gettimeofday(&(req_ctx.tv_start), NULL);
	req_ctx.fd = fd;
	req_ctx.request = m;
	ctx.req_ctx = &req_ctx;

	reply_context_set_message(&ctx, 200, "OK");
	reply_context_reply(&ctx, err);
	reply_context_clear(&ctx, TRUE);
	return 1;
}

static gint
plugin_init(GHashTable * params UNUSED, GError ** err UNUSED)
{
	message_handler_add("ping", _match_PING, _handle_PING);
	return 1;
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
