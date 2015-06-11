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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "server.msg"
#endif /*G_LOG_DOMAIN*/

#include <string.h>
#include <sys/time.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include "./server_internals.h"
#include "./message_handler.h"

static void
_log_addr(GString *gs, int fd)
{
	struct sockaddr_storage ss;
	socklen_t ss_len;
	char buf_addr[STRLEN_ADDRINFO];
	char buf_port[8];

	memset(&ss, 0, sizeof(ss));
	ss_len = sizeof(ss);

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
_log_time(GString *gs, struct request_context_s *req_ctx)
{
	struct timeval tvnow, tvdiff;

	gettimeofday(&tvnow, NULL);
	timersub(&tvnow, &(req_ctx->tv_start), &tvdiff);

	g_string_append_printf(gs, " %lu.%06lu", tvdiff.tv_sec, tvdiff.tv_usec);
}

static void
_log_reqid(GString *gs, MESSAGE req)
{
	g_string_append_c(gs, ' ');

	gsize field_len=0;
	void *field = metautils_message_get_ID(req, &field_len);
	if (!field || !field_len)
		g_string_append_c(gs, '_');
	else {
		gsize max = field_len * 2 + 2;
		char *hex;
		
		hex = g_alloca(max);
		memset(hex, 0, max);
		buffer2str(field, field_len, hex, max);
		g_string_append(gs, (gchar*)hex);
	}
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

static void
_log_args(GString *gs, const gchar *fmt, va_list vargs)
{
	g_string_append_c(gs, ' ');
	g_string_append_c(gs, '[');
	if (fmt)
		g_string_append_vprintf(gs, fmt, vargs);
	g_string_append_c(gs, ']');
}

static void
_log_message(GString *gs, struct reply_context_s *ctx)
{
	if (!ctx->header.msg)
		g_string_append(gs, " 200 OK");
	else
		g_string_append_printf(gs, " %d %s", ctx->header.code, ctx->header.msg);
}

void
reply_context_log_access (struct reply_context_s *ctx, const gchar *fmt, ...)
{
	va_list va;
	GString *gs;

	if (!ctx)
		return;
	if (!ctx->req_ctx)
		return;

	gs = g_string_sized_new(2048);
	_log_addr(gs, ctx->req_ctx->fd);
	_log_time(gs, ctx->req_ctx);
	_log_reqid(gs, ctx->req_ctx->request);
	_log_reqname(gs, ctx->req_ctx->request);

	va_start(va, fmt);
	_log_args(gs, fmt, va);
	va_end(va);

	_log_message(gs, ctx);

	g_log("access", GRID_LOGLVL_INFO, gs->str);
	(void) g_string_free(gs, TRUE);
}

