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
	char buf_addr[128];
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
	void *field=NULL;
	gsize field_len=0;

	g_string_append_c(gs, ' ');

	if (0 >= message_get_ID(req, &field, &field_len, NULL))
		g_string_append_c(gs, '_');
	else if (!field_len)
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
	void *field=NULL;
	gsize field_len=0;

	if (0 > message_get_NAME(req, &field, &field_len, NULL)) {
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

