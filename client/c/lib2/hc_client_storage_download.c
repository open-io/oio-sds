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

#include "./hc_client_internals.h"
#include <autogen.h>

#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>
#include <neon/ne_uri.h>

struct dl_context_s
{
	enum dl_mode_e { DL_RAIN, DL_NORMAL } mode;
	struct hc_client_s *client;
	struct hc_url_s *url;
	struct hc_download_s *user;
	GSList *beans;
	sqlite3 *view;

	/* counter for the download process */
	gboolean caller_stopped;
	gint64 content_already_dl; /*!< number of bytes already read in the
								* expected content */
};

typedef int (*output_wrapper_f) (void *u, const char *b, const size_t bsize);

/* RAWX download function -------------------------------------------------- */

static GError*
_neon_create_structures(const gchar *url,
		ne_session **psession, ne_request **prequest)
{
	ne_uri uri;
	ne_session *session;
	ne_request *request;

	memset(&uri, 0, sizeof(uri));
	if (0 != ne_uri_parse(url, &uri))
		return NEWERROR(500, "HTTP client error: %s", "invalid URI");

	if (!(session = ne_session_create(uri.scheme, uri.host, uri.port))) {
		ne_uri_free(&uri);
		return NEWERROR(500, "HTTP client error: %s", "session creation failure");
	}

	if (!(request = ne_request_create(session, "GET", uri.path))) {
		GError *err = NEWERROR(500, "HTTP client error: %s", ne_get_error(session));
		ne_session_destroy(session);
		ne_uri_free(&uri);
		return err;
	}

	ne_uri_free(&uri);
	*prequest = request;
	*psession = session;
	return NULL;
}

static GError*
_rawx_download(const gchar *url, output_wrapper_f hook, gpointer hook_data, ...)
{
	va_list args;
	GError *err = NULL;
	ne_session *session = NULL;
	ne_request *request = NULL;

	if (NULL != (err = _neon_create_structures(url, &session, &request)))
		return err;
	g_assert(session != NULL);
	g_assert(request != NULL);

	va_start(args, hook_data);
	for (;;) {
		char *k, *v;
		k = va_arg(args, char *);
		if (!k)
			break;
		v = va_arg(args, char *);
		if (!v)
			break;
		if (*k && *v)
			ne_add_request_header(request, k, v);
	}
	va_end(args);

	/* then execute the request */
	ne_add_response_body_reader(request, ne_accept_2xx, hook, hook_data);
	switch (ne_request_dispatch(request)) {
		case NE_OK:
			if (ne_get_status(request)->klass != 2)
				err = NEWERROR(1000 + ne_get_status(request)->code,
					"HTTP download error: %s", ne_get_error(session));
			break;
		case NE_ERROR:
			err = NEWERROR(500, "HTTP request error: caller error");
			break;
		case NE_TIMEOUT:
		case NE_CONNECT:
		case NE_AUTH:
		default:
			err = NEWERROR(500, "HTTP download error: %s", ne_get_error(session));
			break;
	}

	/* Finally, Clean the structures then return the error/success */
	ne_request_destroy(request);
	ne_session_destroy(session);
	return err;
}

/* NORMAL download --------------------------------------------------------- */

static GError*
_checksum_check(struct bean_CHUNKS_s *chunk, GChecksum *checksum)
{
	guint8 *buf;
	gsize bufsize;
	GByteArray *gba;

	bufsize = g_checksum_type_get_length(G_CHECKSUM_MD5);
	buf = g_alloca(bufsize);
	g_checksum_get_digest(checksum, buf, &bufsize);

	if (!(gba = CHUNKS_get_hash(chunk))) {
		GRID_TRACE("No Checksum to check");
		return NULL;
	}

	if (gba->len != bufsize)
		return NEWERROR(CODE_CONTENT_CORRUPTED, "Hash length differ "
				"(%u vs. %"G_GSIZE_FORMAT")", gba->len, bufsize);

	if (0!=memcmp(gba->data, buf, bufsize))
		return NEWERROR(CODE_CONTENT_CORRUPTED, "Hash differ");

	return NULL;
}

static GError*
_download_chunk(struct dl_context_s *ctx, struct bean_CHUNKS_s *chunk,
		gint64 offset, gint64 *size)
{
	GError *err = NULL;
	gint64 size_downloaded = 0;
	gchar str_range[128], str_reqid[128];
	GChecksum *checksum = NULL;

	/* callback expected by libneon */
	int output_wrapper (void *u, const char *b, const size_t bsize) {
		if (!bsize)
			return 0;
		if (checksum)
			g_checksum_update(checksum, (guint8*)b, bsize);
		if (!ctx->caller_stopped) {
			if (!ctx->user->output.hook(u, (guint8*)b, bsize))
				ctx->caller_stopped = TRUE;
		}
		size_downloaded += bsize;
		return 0;
	}

	g_assert(chunk != NULL);
	g_assert(offset >= 0);
	g_assert(*size > 0);

	memset(str_reqid, 0, sizeof(str_reqid));
	if (offset <= 0 && *size <= 0) {
		memset(str_range, 0, sizeof(str_range));
		checksum = g_checksum_new(G_CHECKSUM_MD5);
	}
	else {
		g_snprintf(str_range, sizeof(str_range),
				"bytes=%"G_GINT64_FORMAT"-%"G_GINT64_FORMAT,
				offset, offset+*size-1);
	}

	err = _rawx_download(CHUNKS_get_id(chunk)->str,
			output_wrapper, ctx->user->output.hook_data,
			"ReqId", str_reqid, "Range", str_range, NULL);

	if (!err) {
		*size = size_downloaded;
		if (checksum)
			err = _checksum_check(chunk, checksum);
	}
	else {
		g_prefix_error(&err, "RAWX error: ");
	}

	if (checksum) {
		g_checksum_free(checksum);
		checksum = NULL;
	}

	return err;
}

static struct bean_CHUNKS_s *
_get_chunk_for_content(struct dl_context_s *ctx, struct bean_CONTENTS_s *content)
{
	struct bean_CHUNKS_s *chunk = NULL;
	void on_bean(gpointer u, gpointer bean) { *((gpointer*)u) = bean; }
	_db_get_FK_by_name(content, "chunk", ctx->view, on_bean, &chunk);
	return chunk;
}

/*! @todo TODO */
static GError*
_download_chunk_position(struct dl_context_s *ctx, guint position)
{
	GError *err = NULL;
	GSList *contents, *l;

	gint _locator(gconstpointer p, gconstpointer u) {
		(void) u;
		if (!p || DESCR(p) != &descr_struct_CONTENTS)
			return 1;
		return atoi(CONTENTS_get_position(p)->str) != (gint)position;
	}

	contents = g_slist_find_custom(ctx->beans, NULL, _locator);

	for (l=contents; l && !err ;l=l->next) {
		struct bean_CONTENTS_s *content;
		struct bean_CHUNKS_s *chunk;
		gint64 offset = 0, size = 0;

		content = l->data;
		chunk = _get_chunk_for_content(ctx, content);
		err = _download_chunk(ctx, chunk, offset, &size);
		if (!err) {
			ctx->content_already_dl += size;
			break;
		}
		else {
			/** @todo TODO check the code, we can maybe retry the download */
		}
	}

	g_slist_free(contents);
	return err;
}

static guint
_get_max_position(struct dl_context_s *ctx)
{
	guint result = 0;
	int rc;
	const gchar *sql = "SELECT MAX(position) FROM content_v2";

	int _cb(void *u, int nbcols, char **cols, char **names) {
		(void) u;
		(void) nbcols;
		(void) names;
		g_assert(nbcols == 1);
		result = atoi(cols[0]);
		return 0;
	}
	
	rc = sqlite3_exec(ctx->view, sql, _cb, NULL, NULL);
	g_assert(rc == SQLITE_OK || rc == SQLITE_DONE);
	return result;
}

static GError*
_download_NORMAL(struct dl_context_s *ctx)
{
	GError *err = NULL;
	guint position, position_max;

	position_max = _get_max_position(ctx);

	for (position=0; !err && position < position_max ;position++) {
		err = _download_chunk_position(ctx, position);
	}

	if (!err) {
		GRID_TRACE("Download done");
	}

	return err;
}

/* RAIN download ----------------------------------------------------------- */

/** @todo TODO RAIN download */
static GError*
_download_RAIN(struct dl_context_s *ctx)
{
	(void) ctx;
	return NEWERROR(500, "RAIN download not implemented");
}

/* ------------------------------------------------------------------------- */

/** @todo TODO */
static GError*
_get_storage_policy(struct dl_context_s *ctx)
{
	ctx->mode = DL_NORMAL;
	return NULL;
}

/* build a view, check the beans, then continue to download */
static GError*
_download(struct dl_context_s *ctx)
{
	GError *err = NULL;

	if (!(err = m2db_create_view(&(ctx->view)))) {
		if (!(err = m2db_save_beans_list(ctx->view, ctx->beans))) {
			if (!(err = m2db_check_alias_view(ctx->view, ctx->url))) {
				if (!(err = _get_storage_policy(ctx))) {
					switch (ctx->mode) {
						case DL_RAIN:
							err = _download_RAIN(ctx);
							break;
						case DL_NORMAL:
							err = _download_NORMAL(ctx);
							break;
					}
				}
			}
		}
		(void) sqlite3_close(ctx->view);
		ctx->view = NULL;
	}

	return err;
}

GError*
hc_client_storage_get_url(struct hc_client_s *hc, struct hc_url_s *u,
		struct hc_download_s *out)
{
	GError* _action(gchar **targets) {
		struct dl_context_s ctx;
		GError *err;
		GSList *beans = NULL;

		if (!(err = m2v2_remote_execute_GET(targets[0], NULL, u, 0, &beans))) {
			if (!beans) {
				err = NEWERROR(CODE_CONTENT_NOTFOUND, "No bean found");
			}
			else {
				memset(&ctx, 0, sizeof(ctx));
				ctx.client = hc;
				ctx.url = u;
				ctx.user = out;
				ctx.beans = beans;
				err = _download(&ctx);
			}
		}
		_bean_cleanl2(beans);
		return err;
	}

	return _meta2v2_action(hc, u, _action);
}

