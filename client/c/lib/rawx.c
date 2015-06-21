/*
OpenIO SDS client
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "client.c.rawx"
#endif

#include "./gs_internals.h"

#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include <metautils/lib/metatypes.h>
#include <metautils/lib/metautils.h>

#include "./rawx.h"

#define WEBDAV_TIMEOUT 1
#define RAWX_DELETE   "DELETE"
#define RAWX_UPLOAD   "PUT"
#define RAWX_DOWNLOAD "GET"

static void add_req_id_header(ne_request *request, gchar *dst, gsize dst_size);
static void add_req_system_metadata_header (ne_request *request, GByteArray *system_metadata);

static void
chunk_id2str (const gs_chunk_t *chunk, char *d, size_t dS)
{
	EXTRA_ASSERT(chunk);
	EXTRA_ASSERT(d);
	buffer2str (chunk->ci->id.id, sizeof(chunk->ci->id.id), d, dS);
}

static void
chunk_getpath (const gs_chunk_t *chunk, char *cPath, size_t s)
{
	size_t cPathLen;

	EXTRA_ASSERT(chunk);
	EXTRA_ASSERT(cPath);

	cPathLen = snprintf (cPath, MAX(s, sizeof(chunk->ci->id.vol)), "%s/",
			chunk->ci->id.vol);
	chunk_id2str (chunk, cPath+cPathLen, s-cPathLen);
}

ne_session *
opensession_common(const addr_info_t *addr_info,
		int connect_timeout, int read_timeout, GError **err)
{
	ne_session *session=NULL;
	gchar host[STRLEN_ADDRINFO] = "";
	guint16 port = 0;

	if (!addr_info) {
		GSETERROR (err, "Invalid parameter");
		return NULL;
	}

	if (!addr_info_get_addr(addr_info, host, sizeof(host), &port)) {
		GSETERROR(err, "AddrInfo printing error");
		return NULL;
	}

	session = ne_session_create ("http", host, port);
	if (!session) {
		GSETERROR(err,"cannot create a new WebDAV session");
		return NULL;
	}

	ne_set_connect_timeout (session, connect_timeout);
	ne_set_read_timeout (session, read_timeout);
	return session;
}

/**
 * Create one webdav session associated to the given chunk
 */
static ne_session* rawx_opensession (gs_chunk_t *chunk, GError **err)
{
	/**@todo TODO manage a proxy HERE*/
	int to_cnx = MAX(C1_RAWX_TO_CNX(chunk->content)/1000, 1);
	int to_op = MAX(C1_RAWX_TO_OP(chunk->content)/1000, 1);
	return opensession_common(&(chunk->ci->id.addr), to_cnx, to_op, err);
}

/* ------------------------------------------------------------------------- */

char*
create_rawx_request_common(ne_request **req, ne_request_param_t *param, GError **err)
{
	ne_request *request = NULL;
	char str_req_id[LIMIT_LENGTH_REQID];

	if (NULL == param->session || NULL == param->method || NULL == param->cPath) {
		GSETERROR(err, "Invalid parameter");
		*req = NULL;
		return NULL;
	}

	if (NULL == (request = ne_request_create (param->session, param->method, param->cPath))) {
		GSETERROR(err, "cannot create a new WebDAV request (%s)", ne_get_error(param->session));
		*req = NULL;
		return NULL;
	}

	/* add additionnal headers */
	ne_add_request_header  (request, "containerid", param->containerid);
	ne_add_request_header  (request, "contentpath", param->contentpath);
	ne_print_request_header(request, "chunkpos",    "%u", param->chunkpos);
	ne_print_request_header(request, "chunknb",     "%u", param->chunknb);
	ne_print_request_header(request, "chunksize",   "%"G_GINT64_FORMAT, param->chunksize);
	ne_print_request_header(request, "contentsize", "%"G_GINT64_FORMAT, param->contentsize);

	/* Add request header */
	add_req_id_header(request, str_req_id, sizeof(str_req_id)-1);

	*req = request;
	return g_strdup(str_req_id);
}

ne_request_param_t* new_request_param()
{
	return g_malloc0(sizeof(ne_request_param_t));
}

void free_request_param(ne_request_param_t *param)
{
	g_free((gpointer)param->cPath);
	g_free((gpointer)param->containerid);
	g_free((gpointer)param->contentpath);
	g_free((gpointer)param->method);
	// session must not be freed (should not be created especially for use with request_param)

	g_free(param);
}

char*
create_rawx_request_from_chunk(ne_request **p_req, ne_session *session,
		const char *method, gs_chunk_t *chunk, GByteArray *system_metadata,
		GError **err)
{
	char str_ci[STRLEN_CHUNKID], cPath[CI_FULLPATHLEN], *str_req_id;
	ne_request_param_t *params = new_request_param();

	if (NULL == chunk) {
		GSETERROR(err, "No chunk given");
		return NULL;
	}

	params->session = session;
	params->method = g_strdup(method);
	chunk_getpath (chunk, cPath, sizeof(cPath));
	params->cPath = g_strdup(cPath);
	params->containerid = g_strdup(C1_IDSTR(chunk->content));
	params->contentpath = g_strdup(C1_PATH(chunk->content));
	params->chunkpos = chunk->ci->position;
	params->chunknb = chunk->ci->nb;
	params->chunksize = chunk->ci->size;
	params->contentsize = chunk->content->info.size;

	str_req_id = create_rawx_request_common(p_req, params, err);
	free_request_param(params);
	if (*p_req) {
		if (system_metadata && system_metadata->data && system_metadata->len>0)
			add_req_system_metadata_header(*p_req, system_metadata);
		chunk_id2str(chunk, str_ci, sizeof(str_ci));
		GRID_DEBUG("chunkid=%s", str_ci);
		ne_add_request_header(*p_req, "chunkid", str_ci);
		return str_req_id;
	}

	g_free(str_req_id);
	return NULL;
}

static void
rawx_dl_advance_status(struct dl_status_s *status, size_t s)
{
	int64_t nbW64 = s;
	status->content_dl = status->content_dl + nbW64;
	status->chunk_dl = status->chunk_dl + nbW64;
	status->chunk_dl_offset = status->chunk_dl_offset + nbW64;
	status->chunk_dl_size = status->chunk_dl_size - nbW64;
}

static gboolean
_rawx_update_chunk_attrs(chunk_id_t *cid, GSList *attrs, GError **err)
{
	ne_session *s = NULL;
	ne_request *r = NULL;
	int ne_rc;
	gboolean result = FALSE;

	gchar dst[128];
	guint16 port = 0;
	GString *req_str = NULL;
	char idstr[65];

	if (!addr_info_get_addr(&(cid->addr), dst, sizeof(dst), &port))
		return result;

	s = ne_session_create("http", dst, port);
	if (!s) {
		GSETERROR(err, "Failed to create session to rawx %s:%d", dst, port);
		return result;
	}

	ne_set_connect_timeout(s, 10);
	ne_set_read_timeout(s, 30);

	req_str =g_string_new("/rawx/chunk/set/");
	buffer2str(&(cid->id), sizeof(cid->id), idstr, sizeof(idstr));
	req_str = g_string_append(req_str, idstr);
	GRID_TRACE("Calling %s", req_str->str);

	r = ne_request_create (s, "GET", req_str->str);
	if (!r) {
		goto end_attr;
	}

	for (; attrs != NULL; attrs = attrs->next) {
		struct chunk_attr_s *attr = attrs->data;
		ne_add_request_header(r, attr->key, attr->val);
	}

	switch (ne_rc = ne_request_dispatch(r)) {
		case NE_OK:
			result = TRUE;
			break;
		case NE_ERROR:
			GSETCODE(err, CODE_INTERNAL_ERROR, "Request NE_ERROR");
			break;
		case NE_TIMEOUT:
			GSETCODE(err, CODE_INTERNAL_ERROR, "Request Timeout");
			break;
		case NE_CONNECT:
			GSETCODE(err, CODE_INTERNAL_ERROR, "Request Connection timeout");
			break;
		default:
			GSETCODE(err, CODE_INTERNAL_ERROR, "Request failed");
			break;
	}

end_attr:
	if (NULL != req_str)
		g_string_free(req_str, TRUE);
	if (NULL != r)
		ne_request_destroy (r);
	if (NULL != s)
		ne_session_destroy (s);

	return result;
}

gboolean
rawx_update_chunk_attr(struct meta2_raw_chunk_s *c, const char *name,
		const char *val, GError **err)
{
	struct chunk_attr_s attr = {name, val};
	GSList l = {&attr, NULL};
	return _rawx_update_chunk_attrs(&(c->id), &l, err);
}

gboolean
rawx_update_chunk_attrs(const gchar *chunk_url, GSList *attrs, GError **err)
{
	chunk_id_t cid;
	fill_chunk_id_from_url(chunk_url, &cid);
	return _rawx_update_chunk_attrs(&cid, attrs, err);
}

gboolean
rawx_download (gs_chunk_t *chunk, GError **err, struct dl_status_s *status,
		GSList **p_broken_rawx_list)
{
	char cPath[CI_FULLPATHLEN];
	char str_ci[STRLEN_CHUNKID];
	char str_req_id[256];
	ne_session *session=NULL;
	ne_request *request=NULL;
	int ne_rc;

	int flag_md5 = 0;
	hash_md5_t md5;
	GChecksum *checksum = NULL;

	int output_wrapper (void *uData, const char *b, const size_t bSize) {
		size_t offset;

		(void) uData;
		if (bSize==0)
			return 0;

		if (flag_md5)
			g_checksum_update (checksum, (guint8*)b, bSize);

		if (status->caller_stopped) { /* for looping puposes */
			rawx_dl_advance_status(status, bSize);
			return 0;
		}

		for (offset = 0; offset < bSize ;) {
			int nbW;

			nbW = status->dl_info.writer(status->dl_info.user_data, b+offset, bSize-offset);
			if (nbW < 0) {
				return -1;
			}
			if (nbW == 0) {
				status->caller_stopped = TRUE;
				rawx_dl_advance_status(status, bSize - offset);
				return 0;
			}

			offset = offset + nbW;
			rawx_dl_advance_status(status, nbW);
		}

		return 0;
	}

	chunk_getpath (chunk, cPath, sizeof(cPath));
	chunk_id2str (chunk, str_ci, sizeof(str_ci));
	TRACE("about to download '%s' from '%s'", str_ci, cPath);

	/*create a webdav session, a request with good headers */
	session = rawx_opensession (chunk, err);
	if (!session) {
		GSETERROR(err, "Cannot open a new WebDAV session");
		goto error_label;
	}

	request = ne_request_create (session, RAWX_DOWNLOAD, cPath);
	if (!request) {
		GSETERROR(err, "WebDAV request creation error (%s)", ne_get_error(session));
		goto error_label;
	}

	add_req_id_header(request, str_req_id, sizeof(str_req_id)-1);
	ne_add_request_header(request,  "containerid", C1_IDSTR(chunk->content));
	ne_print_request_header(request, "Range", "bytes=%"G_GINT64_FORMAT"-%"G_GINT64_FORMAT, status->chunk_dl_offset,
			status->chunk_dl_offset + status->chunk_dl_size - 1);
	ne_add_response_body_reader(request, ne_accept_2xx, output_wrapper, status->dl_info.user_data);

	/* if the whole chunk is to be downloaded, check we may compute
	 * the MD5 sum (if the whole chunk must be downloaded)*/
	flag_md5 = (status->chunk_dl_offset == 0) &&
		(status->chunk_dl_size == chunk->ci->size);
	if (flag_md5)
		checksum = g_checksum_new (G_CHECKSUM_MD5);

	/* Now send the request */
	switch (ne_rc=ne_request_dispatch(request)) {
		case NE_OK:
			if (ne_get_status(request)->klass != 2) {
				GSETCODE(err, 1000 + ne_get_status(request)->code,
					"cannot download '%s' (%s) (ReqId:%s)", cPath, ne_get_error(session), str_req_id);
				*p_broken_rawx_list = g_slist_prepend(*p_broken_rawx_list, chunk->ci);
				goto error_label;
			}
			if (flag_md5) {
				gsize md5_len = sizeof(hash_md5_t);
				g_checksum_get_digest (checksum, md5, &md5_len);
				if (memcmp(chunk->ci->hash, md5, md5_len)) {
					GSETCODE(err, CODE_CONTENT_CORRUPTED, "%s Chunk downloaded corrupted [%s] :"
							" checksum mismatch", str_req_id, cPath);
					*p_broken_rawx_list = g_slist_prepend(*p_broken_rawx_list, chunk->ci);
					goto error_label;
				}
			}
			break;

		case NE_ERROR:
			GSETCODE(err, CODE_INTERNAL_ERROR, "Caller error '%s' (%s) (ReqId:%s)",
					cPath, ne_get_error(session), str_req_id);
			status->caller_error = TRUE;
			goto error_label;

		case NE_TIMEOUT:
		case NE_CONNECT:
			GSETCODE(err, CODE_NETWORK_ERROR, "Service unavailable, cannot download '%s' (%s) (ReqId:%s)",
					cPath, ne_get_error(session), str_req_id);
			*p_broken_rawx_list = g_slist_prepend(*p_broken_rawx_list, chunk->ci);
			goto error_label;
		case NE_AUTH:
		default:
			GSETERROR(err, "cannot download '%s' (%s) (ReqId:%s)",
					cPath, ne_get_error(session), str_req_id);
			goto error_label;
	}

	TRACE("%s downloaded (%"G_GINT64_FORMAT" bytes) (%i %s) (ReqId:%s)",
		cPath, status->chunk_dl, ne_get_status(request)->code, ne_get_status(request)->reason_phrase, str_req_id);

	/*destroy the webdav structures*/
	ne_request_destroy (request);
	ne_session_destroy (session);
	if (checksum) {
		g_checksum_free (checksum);
		checksum = NULL;
	}

	return TRUE;

error_label:

	if (request)
		ne_request_destroy (request);
	if (session)
		ne_session_destroy (session);
	if (checksum) {
		g_checksum_free (checksum);
		checksum = NULL;
	}

	INFO("could not download %s (%s)", cPath, str_req_id);

	return FALSE;
}

int rawx_init (void)
{
	static volatile int init_done = 0;
	if (!init_done)
	{
		ne_debug_init(stderr, ~0);
		init_done = 1;
	}
	return 1;
}

void gen_req_id_header(gchar *dst, gsize dst_size) {
	pid_t pid;
	gsize i, s=16;
	char idRequest[LIMIT_LENGTH_REQID];
	guint8 idBuf[s+sizeof(int)];

	EXTRA_ASSERT(dst != NULL);
	EXTRA_ASSERT(dst_size > 0);

	memset(idBuf, 0, sizeof(idBuf));

	pid = getpid();
	memcpy (idBuf, (guint8*)(&pid), sizeof(pid));
	for (i=sizeof(int); i<s ;i+=sizeof(int)) {
		int r = random();
		memcpy(idBuf+i, (guint8*)(&r), sizeof(int));
	}

	buffer2str(idBuf, sizeof(idBuf), idRequest, sizeof(idRequest));

	g_strlcpy(dst, idRequest, dst_size);
}

void add_req_id_header(ne_request *request, gchar *dst, gsize dst_size) {
	char idRequest[LIMIT_LENGTH_REQID];

	gen_req_id_header(idRequest, sizeof(idRequest));

	DEBUG("Adding ReqId header to HTTP request => [%s:%s]", "GSReqId", idRequest);

	ne_add_request_header(request, "GSReqId", idRequest);
	if (dst && dst_size>0)
		g_strlcpy(dst, idRequest, dst_size);
}

void add_req_system_metadata_header (ne_request *request, GByteArray *system_metadata)
{
	gchar *escaped = NULL;
	gchar *unescaped = NULL;

	if (!system_metadata)
		return;
	if (!request)
		return;

	/* ensure the URL is NULL terminated */
	unescaped = g_malloc0(system_metadata->len + 1);
	g_memmove(unescaped, system_metadata->data, system_metadata->len);

	/*and add the escaped string as a header*/
	escaped = g_strescape( unescaped, "");
	ne_add_request_header( request, "contentmetadata-sys", escaped);
	g_free(escaped);
	g_free(unescaped);
}

