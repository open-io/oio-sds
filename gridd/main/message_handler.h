/*
OpenIO SDS gridd
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__gridd__main__message_handler_h
# define OIO_SDS__gridd__main__message_handler_h 1

# include <sys/time.h>
# include <metautils/lib/metacomm.h>

struct request_context_s {
	MESSAGE request;
	gint fd;
	addr_info_t* remote_addr;
	addr_info_t* local_addr;
	struct timeval tv_start;
};

typedef gint (*message_matcher_f) (MESSAGE m, void *param, GError **err);
typedef gint (*message_handler_f) (MESSAGE m, gint cnx, void *param, GError **err);
typedef gint (*message_handler_v2_f) (struct request_context_s *ctx, GError **err);

void message_handler_add (const char *name, message_matcher_f m, message_handler_f h);

#define GO_ON 2
#define DONE 1
#define FAIL 0
#define REPLYCTX_DESTROY_ON_CLEAN 0x000000001
#define REPLYCTX_COPY 0x000000002

struct reply_context_s {
	struct request_context_s *req_ctx;
	GError *warning;
	struct {
		gint code;
		gchar *msg;
	} header;
	struct {
		void *buffer;
		gsize size;
		gboolean copy;
	} body;
	GHashTable *extra_headers;/* (char*) -> (GByteArray*) */
};

void reply_context_clear (struct reply_context_s *ctx, gboolean all);

void reply_context_set_message (struct reply_context_s *ctx, gint code, const gchar *msg);

void reply_context_set_body (struct reply_context_s *ctx, void *body, gsize bodySize, guint32 flags);

gint reply_context_reply (struct reply_context_s *ctx, GError **err);

void reply_context_log_access (struct reply_context_s *ctx,
	const gchar *fmt, ...);

void request_context_clear(struct request_context_s* ctx);

void request_context_free(struct request_context_s* ctx);

struct request_context_s* request_context_create(int fd, addr_info_t *fd_peer);

#endif /*OIO_SDS__gridd__main__message_handler_h*/
