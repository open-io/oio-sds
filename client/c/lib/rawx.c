#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "client.c.rawx"
#endif

#include "./gs_internals.h"

// TODO FIXME replace with GLib equivalent
#include <openssl/md5.h>

#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include <metautils/lib/metautils.h>

#include "./rawx.h"

#define WEBDAV_TIMEOUT 1
#define RAWX_DELETE   "DELETE"
#define RAWX_UPLOAD   "PUT"
#define RAWX_DOWNLOAD "GET"

static void add_req_id_header(ne_request *request, gchar *dst, gsize dst_size);
static void add_req_system_metadata_header (ne_request *request, GByteArray *system_metadata);


static void chunk_id2str (const gs_chunk_t *chunk, char *d, size_t dS)
{
	MYASSERT(chunk);
	MYASSERT(d);
	buffer2str (chunk->ci->id.id, sizeof(chunk->ci->id.id), d, dS);
}

static void chunk_gethash (const gs_chunk_t *chunk, char *d, size_t dS)
{
	MYASSERT(chunk);
	MYASSERT(d);
	buffer2str (chunk->ci->hash, sizeof(chunk->ci->hash), d, dS);
}

static void chunk_getpath (const gs_chunk_t *chunk, char *cPath, size_t s)
{
	size_t cPathLen;

	MYASSERT(chunk);
	MYASSERT(cPath);

	cPathLen = snprintf (cPath, MAX(s, sizeof(chunk->ci->id.vol)), "%s/",
			chunk->ci->id.vol);
	chunk_id2str (chunk, cPath+cPathLen, s-cPathLen);
}

ne_session *
opensession_common(const addr_info_t *addr_info,
		int connect_timeout, int read_timeout, GError **err)
{
	ne_session *session=NULL;
	gchar host[1024];
	guint16 port;

	if (!addr_info) {
		GSETERROR (err, "Invalid parameter");
		return NULL;
	}

	port = 0;
	memset(host, 0x00, sizeof(host));
	if (!addr_info_get_addr(addr_info, host, sizeof(host)-1, &port)) {
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
	register int to_cnx, to_op;
	to_cnx = C1_RAWX_TO_CNX(chunk->content)/1000;
	to_op = MAX(C1_RAWX_TO_OP(chunk->content)/1000, 1);

	return opensession_common(&(chunk->ci->id.addr), to_cnx, to_op, err);
}


/* ------------------------------------------------------------------------- */


gs_status_t rawx_delete (gs_chunk_t *chunk, GError **err)
{
	char str_req_id [1024];
	char str_addr [STRLEN_ADDRINFO];
	char str_ci [STRLEN_CHUNKID];
	char cPath [CI_FULLPATHLEN];
	char str_hash[STRLEN_CHUNKHASH];

	ne_request *request=NULL;
	ne_session *session=NULL;
	
	memset(str_req_id, 0x00, sizeof(str_req_id));

	if (!chunk || !chunk->ci || !chunk->content)
	{
		GSETERROR (err,"Invalid parameter (bad chunk structure)");
		goto error_label;
	}

	addr_info_to_string (&(chunk->ci->id.addr), str_addr, sizeof(str_addr));
	chunk_id2str(chunk, str_ci, sizeof(str_ci));
	chunk_getpath (chunk, cPath, sizeof(cPath));
	DEBUG("about to delete %s on %s", str_ci, cPath);

	gscstat_tags_start(GSCSTAT_SERVICE_RAWX, GSCSTAT_TAGS_REQPROCTIME);

	session = rawx_opensession (chunk, err);
	if (!session)
	{
		GSETERROR (err, "Cannot open a webdav session");
		goto error_label;
	}

	/*Create a webdav request*/
	do {
		request = ne_request_create (session, RAWX_DELETE, cPath);
		if (!request)
		{
			GSETERROR (err, "cannot create a %s WebDAV request", RAWX_DELETE);
			goto error_label;
		}

	} while (0);

	chunk_id2str (chunk, str_ci, sizeof(str_ci));
	chunk_gethash (chunk, str_hash, sizeof(str_hash));

	/* Add request header */
	add_req_id_header(request, str_req_id, sizeof(str_req_id)-1);


	ne_add_request_header  (request, "chunkid",     str_ci);
	ne_add_request_header  (request, "chunkhash",   str_hash);
	ne_add_request_header  (request, "containerid", C1_IDSTR(chunk->content));
	ne_add_request_header  (request, "contentpath", chunk->content->info.path);
	ne_print_request_header(request, "chunkpos",    "%"G_GUINT32_FORMAT, chunk->ci->position);
	ne_print_request_header(request, "chunknb",     "%"G_GUINT32_FORMAT, chunk->ci->nb);
	ne_print_request_header(request, "chunksize",   "%"G_GINT64_FORMAT, chunk->ci->size);
	ne_print_request_header(request, "contentsize", "%"G_GINT64_FORMAT, chunk->content->info.size);

	/*now perform the request*/
	switch (ne_request_dispatch (request))
	{
		case NE_OK:
			if (ne_get_status(request)->klass != 2) {
				GSETERROR (err, "cannot delete '%s' (%s) (ReqId:%s)", cPath, ne_get_error(session), str_req_id);
				goto error_label;
			}
			DEBUG("chunk deletion finished (success) : %s", cPath);
			break;
		case NE_AUTH:
		case NE_CONNECT:
		case NE_TIMEOUT:
		case NE_ERROR:
			GSETERROR (err, "unexpected error from the WebDAV server (%s) (ReqId:%s)", ne_get_error(session), str_req_id);
			goto error_label;
	}

	ne_request_destroy (request);
	ne_session_destroy (session);
	
	TRACE("%s deleted (ReqId:%s)", cPath, str_req_id);

	gscstat_tags_end(GSCSTAT_SERVICE_RAWX, GSCSTAT_TAGS_REQPROCTIME);

	return 1;
error_label:
	TRACE("could not delete %s", cPath);
	if (request)
		ne_request_destroy (request);
	if (session)
		ne_session_destroy (session);

	gscstat_tags_end(GSCSTAT_SERVICE_RAWX, GSCSTAT_TAGS_REQPROCTIME);

	return 0;
}

static gboolean _delete_request(const char *host, int port,
		const char *target, GError **err)
{
	GRID_TRACE("%s", __FUNCTION__);
	gboolean result = FALSE;
	ne_session* session = ne_session_create("http", host, port);
	ne_set_connect_timeout(session, 10);
	ne_set_read_timeout(session, 30);

	GRID_DEBUG("DELETE http://%s:%d%s", host, port, target);
	ne_request* req = ne_request_create(session, "DELETE", target);
	if (NULL != req) {
		switch (ne_request_dispatch(req)) {
			case NE_OK:
				if (ne_get_status(req)->klass != 2) {
					*err = NEWERROR(0, "cannot delete '%s' (%s)", target,
							ne_get_error(session));
				} else {
					result = TRUE;
				}
				break;
			case NE_AUTH:
			case NE_CONNECT:
			case NE_TIMEOUT:
			case NE_ERROR:
			default:
				*err = NEWERROR(0,
						"unexpected error from the WebDAV server (%s)",
						ne_get_error(session));
				break;
		}
		ne_request_destroy(req);
	} else {
		// This should be an assertion
		*err = NEWERROR(0, "Failed to create request");
	}
	ne_session_destroy (session);
	return result;
}

gboolean rawx_delete_v2(gpointer chunk, GError **err)
{
	gchar *cid = NULL;
	gchar **toks = NULL;
	gchar **hp = NULL;

	g_assert(chunk != NULL);
	g_assert(err != NULL);
	g_clear_error(err);

	if (DESCR(chunk) == &descr_struct_CHUNKS) {
		cid = CHUNKS_get_id((struct bean_CHUNKS_s*)chunk)->str;
	} else if (DESCR(chunk) == &descr_struct_CONTENTS) {
		cid = CONTENTS_get_chunk_id((struct bean_CONTENTS_s*)chunk)->str;
	} else {
		*err = NEWERROR(0, "Invalid 'chunk' argument, must be "
				"(struct bean_CHUNKS_s*) or (struct bean_CONTENTS_s*)");
		goto end;
	}

	toks = g_strsplit(cid + 7, "/", 2); // skip "http://" and get "host:port"
	if (!toks || g_strv_length(toks) != 2) {
		*err = NEWERROR(0, "Unparsable chunk URL format: '%s'", cid);
		goto end;
	}
	hp = g_strsplit(toks[0], ":", 2); // split host and port
	if (!hp || g_strv_length(hp) != 2) {
		*err = NEWERROR(0, "Could not extract host and port: '%s'", toks[0]);
		goto end;
	}

	_delete_request(hp[0], atoi(hp[1]), strrchr(cid, '/'), err);

end:
	g_strfreev(hp);
	g_strfreev(toks);
	return (*err == NULL);
}


char*
create_rawx_request_common(ne_request **req, ne_request_param_t *param, GError **err)
{
	ne_request *request = NULL;
	char str_req_id[1024];

	memset(str_req_id, 0x00, sizeof(str_req_id));

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

	gscstat_tags_start(GSCSTAT_SERVICE_RAWX, GSCSTAT_TAGS_REQPROCTIME);

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
create_rawx_request_from_chunk(ne_request **p_req, ne_session *session, const char *method, gs_chunk_t *chunk, GByteArray *system_metadata, GError **err)
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
	bzero(idstr, sizeof(idstr));
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
			GSETCODE(err, 500, "Request NE_ERROR");
			break;
		case NE_TIMEOUT:
			GSETCODE(err, 500, "Request Timeout");
			break;
		case NE_CONNECT:
			GSETCODE(err, 500, "Request Connection timeout");
			break;
		default:
			GSETCODE(err, 500, "Request failed");
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
	char str_req_id[1024];
	ne_session *session=NULL;
	ne_request *request=NULL;
	int ne_rc;

	int flag_md5 = 0;
	MD5_CTX md5_ctx;

	int output_wrapper (void *uData, const char *b, const size_t bSize) {
		size_t offset;

		(void) uData;
		if (bSize==0)
			return 0;

		if (flag_md5)
			MD5_Update(&md5_ctx, b, bSize);

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

	bzero(cPath, sizeof(cPath));
	bzero(str_ci, sizeof(str_ci));
	bzero(str_req_id, sizeof(str_req_id));

	chunk_getpath (chunk, cPath, sizeof(cPath));
	chunk_id2str (chunk, str_ci, sizeof(str_ci));
	TRACE("about to download '%s' from '%s'", str_ci, cPath);


	gscstat_tags_start(GSCSTAT_SERVICE_RAWX, GSCSTAT_TAGS_REQPROCTIME);


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
		MD5_Init(&md5_ctx);

	/* Now send the request */
	switch (ne_rc=ne_request_dispatch(request)) {
		case NE_OK:
			if (ne_get_status(request)->klass != 2) {
				GSETCODE(err, 1000 + ne_get_status(request)->code,
					"cannot download '%s' (%s) (ReqId:%s)", cPath, ne_get_error(session), str_req_id);
				goto error_label;
			}
			if (flag_md5) {
				unsigned char md5[MD5_DIGEST_LENGTH];

				bzero(md5, sizeof(md5));
				MD5_Final(md5, &md5_ctx);
				if (memcmp(chunk->ci->hash, md5, MD5_DIGEST_LENGTH) != 0) {
					char hash_str[MD5_DIGEST_LENGTH*2+1];
					char md5_str[MD5_DIGEST_LENGTH*2+1];
					bzero(hash_str, sizeof(hash_str));
					bzero(md5_str, sizeof(md5_str));
					buffer2str(chunk->ci->hash, sizeof(chunk->ci->hash), hash_str, sizeof(hash_str));
					buffer2str(md5, sizeof(md5), md5_str, sizeof(md5_str));
					GSETCODE(err, CODE_CONTENT_CORRUPTED, "Chunk downloaded [%s] was corrupted"
							" (md5 does not match meta2) : %s/%s (%s)", cPath, hash_str,
							md5_str, str_req_id);
					goto error_label;
				}
			}
			break;

		case NE_ERROR:
			GSETCODE(err, 500, "Caller error '%s' (%s) (ReqId:%s)",
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

	gscstat_tags_end(GSCSTAT_SERVICE_RAWX, GSCSTAT_TAGS_REQPROCTIME);

	return TRUE;

error_label:

	if (request)
		ne_request_destroy (request);
	if (session)
		ne_session_destroy (session);

	INFO("could not download %s (%s)", cPath, str_req_id);

	gscstat_tags_end(GSCSTAT_SERVICE_RAWX, GSCSTAT_TAGS_REQPROCTIME);

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
	char idRequest[256];
	guint8 idBuf[s+sizeof(int)];

	g_assert(dst != NULL);
	g_assert(dst_size > 0);

	memset(idBuf, 0, sizeof(idBuf));
	memset(idRequest, 0, sizeof(idRequest));

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
	char idRequest[256];

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

