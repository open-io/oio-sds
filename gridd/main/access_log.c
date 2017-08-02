/*
OpenIO SDS gridd
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#include <string.h>
#include <sys/time.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include "./server_internals.h"
#include "./message_handler.h"

static void
_log_addr(GString *gs, int fd)
{
	struct sockaddr_storage ss = {0};
	socklen_t ss_len = sizeof(ss);
	char buf_addr[STRLEN_ADDRINFO];
	char buf_port[8];

	if (0 != getsockname(fd, (struct sockaddr*)&ss, &ss_len))
		g_string_append_c(gs, '?');
	else {
		memset(buf_port, 0, sizeof(buf_port));
		memset(buf_addr, 0, sizeof(buf_addr));
		format_addr((struct sockaddr*)&ss, buf_addr, sizeof(buf_addr), buf_port, sizeof(buf_port), NULL);

		g_string_append(gs, buf_addr);
		g_string_append_c(gs, ':');
		g_string_append(gs, buf_port);
	}

	g_string_append_c(gs, ' ');

	if (0 != getpeername(fd, (struct sockaddr*)&ss, &ss_len))
		g_string_append_c(gs, '?');
	else {
		memset(buf_port, 0, sizeof(buf_port));
		memset(buf_addr, 0, sizeof(buf_addr));
		format_addr((struct sockaddr*)&ss, buf_addr, sizeof(buf_addr), buf_port, sizeof(buf_port), NULL);

		g_string_append(gs, buf_addr);
		g_string_append_c(gs, ':');
		g_string_append(gs, buf_port);
	}
}

static void
_log_reqid(GString *gs, MESSAGE req)
{
	g_string_append_c(gs, ' ');

	gsize field_len=0;
	void *field = metautils_message_get_ID (req, &field_len);
	if (!field || !field_len)
		g_string_append_c(gs, '-');
	else for (gsize i=0; i<field_len ;++i)
		g_string_append_c (gs, ((gchar*)field)[i]);
}

static void
_log_reqname(GString *gs, MESSAGE req)
{
	gsize field_len=0;
	void *field = metautils_message_get_NAME(req, &field_len);
	if (!field) {
		g_string_append_c(gs, ' ');
		g_string_append_c(gs, '-');
	}
	else {
		int i_len = field_len;
		g_string_append_printf(gs, " %.*s", i_len, (char*)field);
	}
}

void
reply_context_log_access (struct reply_context_s *ctx, const gchar *fmt, ...)
{
	struct timeval tvnow, tvdiff;
	gettimeofday (&tvnow, NULL);
	timersub(&tvnow, &(ctx->req_ctx->tv_start), &tvdiff);

	EXTRA_ASSERT(NULL != ctx);
	EXTRA_ASSERT(NULL != ctx->req_ctx);

	GString *gs = g_string_sized_new(256);
	_log_addr(gs, ctx->req_ctx->fd);
	_log_reqname(gs, ctx->req_ctx->request);

	gint64 d = tvdiff.tv_sec;
	d = d * 1000000;
	d += tvdiff.tv_usec;
	g_string_append_printf(gs, " %d %"G_GINT64_FORMAT" 0 ", ctx->header.code, d);

	if (!fmt)
		g_string_append_c(gs, '-');
	else {
		va_list va;
		va_start(va, fmt);
		g_string_append_vprintf(gs, fmt, va);
		va_end(va);
	}
	_log_reqid(gs, ctx->req_ctx->request);

	g_string_append_printf(gs, " %s", ctx->header.msg ? ctx->header.msg : "OK");

	INCOMING("%s", gs->str);
	g_string_free(gs, TRUE);
}

