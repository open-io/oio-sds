#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.lib.content_check_tools"
#endif

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>

#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include <event.h>
#include <evdns.h>
#include <evhttp.h>
#include <evutil.h>

// TODO FIXME replace the MD5 computation by the GLib way
#include <openssl/md5.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>
#include <meta2/remote/meta2_remote.h>

#include "./content_check.h"

/* chunk_transfer_s structure utils */
static GQuark gquark_log = 0;

struct chunk_transfer_s *
chunk_transfer_new(void)
{
	struct chunk_transfer_s *ct = NULL;
	ct = g_malloc0(sizeof(struct chunk_transfer_s));
	ct->src_status = CNX_NONE;
	ct->dst_status = CNX_NONE;
	ct->evt_base = event_base_new();
	ct->evt_dns = evdns_base_new(ct->evt_base, 1);
	return ct;
}

struct dup_chunk_info_s *
dup_chunk_info_new(void)
{
	struct dup_chunk_info_s *dci = NULL;
	dci = g_malloc0(sizeof(struct dup_chunk_info_s));
	dci->chunks = NULL;
	dci->used_loc = NULL;
	return dci;
}

void
dup_chunk_info_clear(struct dup_chunk_info_s *dup_chunk)
{
	if(!dup_chunk)
		return;
	if(dup_chunk->used_loc) {
		g_slist_foreach(dup_chunk->used_loc, g_free1, NULL);
		g_slist_free(dup_chunk->used_loc);
	}
	g_free(dup_chunk);
}

void
dup_chunk_info_add_chunk(struct dup_chunk_info_s *dup_chunk, meta2_raw_chunk_t *chunk, gchar *location)
{
	if(!dup_chunk || !chunk || !location)
		return;
	dup_chunk->chunks = g_slist_prepend(dup_chunk->chunks, chunk);
	dup_chunk->used_loc = g_slist_prepend(dup_chunk->used_loc, location);
}

guint
dup_chunk_info_get_copy_count(struct dup_chunk_info_s *dup_chunk)
{
	if(!dup_chunk)
		return 0;
	return g_slist_length(dup_chunk->chunks);
}

GSList*
dup_chunk_info_get_used_locations(struct dup_chunk_info_s *dup_chunk)
{
	return dup_chunk->used_loc;
}

GSList*
dup_chunk_info_get_chunks(struct dup_chunk_info_s *dup_chunk)
{
	return dup_chunk->chunks;
}

void
chunk_transfer_set_source_uri(struct chunk_transfer_s *ct, gchar *source)
{
	ct->source_path = source;
}

void
chunk_transfer_set_source_chunk_attrinfo(struct chunk_transfer_s *ct, chunk_attrinfo_t *src_info)
{
	ct->attrs = src_info;
}

void
chunk_transfer_set_source_chunk(struct chunk_transfer_s *ct, meta2_raw_chunk_t *src_chunk)
{
	ct->source_chunk = src_chunk;
}

gint64
chunk_transfer_get_content_size(struct chunk_transfer_s *ct)
{
	return (*(ct->attrs)).content_size;
}

guint32
chunk_transfer_get_content_nb_chunks(struct chunk_transfer_s *ct)
{
	return (*(ct->attrs)).nb_chunks;
}

gchar*
chunk_transfer_get_content_path(struct chunk_transfer_s *ct)
{
	return ct->attrs->content_path;
}

void
chunk_transfer_get_container_id(struct chunk_transfer_s *ct, container_id_t cid)
{
	memcpy(cid, (*(ct->attrs)).cid, sizeof(container_id_t));
}

gchar*
chunk_transfer_get_content_sys_metadata(struct chunk_transfer_s *ct)
{
	return ct->attrs->sys_metadata;
}

gchar*
chunk_transfer_get_content_usr_metadata(struct chunk_transfer_s *ct)
{
	return ct->attrs->usr_metadata;
}

void
chunk_transfer_set_target_rawx(struct chunk_transfer_s *ct, GSList *rawx)
{
	ct->dst_rawx = rawx;
}

void
chunk_transfer_init_base_conn(struct chunk_transfer_s *ct, const gchar *host, short port)
{
	ct->src_cnx = evhttp_connection_base_new(ct->evt_base, ct->evt_dns, host, port);
	evhttp_connection_set_retries(ct->src_cnx, 3);
        evhttp_connection_set_timeout(ct->src_cnx, 60);
}

void
chunk_transfer_set_base_conn_close_cb(struct chunk_transfer_s *ct, void (*cb)(struct evhttp_connection *, void *), void *arg)
{
	evhttp_connection_set_closecb(ct->src_cnx, cb, arg);
}

void
chunk_transfer_init_req(struct chunk_transfer_s *ct, void (*cb)(struct evhttp_request *, void *), void *arg)
{
	ct->src_req = evhttp_request_new(cb, arg);
        ct->src_req->major = 1;
        ct->src_req->minor = 0;
}

void
chunk_transfer_set_req_chunked_cb(struct chunk_transfer_s *ct, void (*cb)(struct evhttp_request *, void *))
{
	evhttp_request_set_chunked_cb(ct->src_req, cb);
}

int
chunk_transfer_make_request(struct chunk_transfer_s *ct)
{
	int rc;
	rc = evhttp_make_request(ct->src_cnx, ct->src_req, EVHTTP_REQ_GET, ct->source_path);
        if(rc == 0) {
		GRID_DEBUG("Input started");
		ct->src_status = CNX_STARTED;
	}
	return rc;
}

void
chunk_transfer_generate_chunks_path(struct chunk_transfer_s *ct)
{
	static guint64 i = 0;

	struct {
		GTimeVal now;
		gint64 seq;
		pid_t pid;
		pid_t ppid;
		uid_t uid;
		guint32 r[4];
		gpointer p[2];
	} bulk;

	guint8 buf[128];
	gsize buf_size;

	memset(&bulk, 0, sizeof(bulk));
	bulk.uid = getuid();
	bulk.pid = getpid();
	bulk.ppid = getppid();

	GSList *l;
	GChecksum *h = g_checksum_new(G_CHECKSUM_SHA256);

	for (l=ct->dst_rawx; l ;l=l->next) {

		g_get_current_time(&(bulk.now));
		bulk.p[0] = l;
		bulk.p[1] = l->data;
		bulk.seq = (i++);
		bulk.r[0] = rand();
		bulk.r[1] = rand();
		bulk.r[2] = rand();
		bulk.r[3] = rand();

		g_checksum_reset(h);
		g_checksum_update(h, (guchar*)&bulk, sizeof(bulk));
		buf_size = sizeof(buf);
		g_checksum_get_digest(h, buf, &buf_size);
		ct->dst_chunks = g_slist_prepend(ct->dst_chunks, g_memdup(buf, buf_size));
	}

	g_checksum_free(h);
}

struct evbuffer*
chunk_transfer_get_input_buffer(struct chunk_transfer_s *ct)
{
	return evhttp_request_get_input_buffer(ct->src_req);
}

void
chunk_transfer_write_to_dst(struct chunk_transfer_s *ct, gchar *buf, size_t size)
{
	GSList *l = NULL;
	for(l = ct->dst_bevents; l && l->data; l = l->next) {
		bufferevent_write(l->data, buf, size);
		bufferevent_enable(l->data, EV_WRITE);
	}
}

void
chunk_transfer_set_dst_remaining_size(struct chunk_transfer_s *ct, gint64 size)
{
	ct->dst_size_remaining = size;
}

void
chunk_transfer_flush_dst(struct chunk_transfer_s *ct)
{
	GSList *l = NULL;
	for(l = ct->dst_bevents; l && l->data; l = l->next) {
		bufferevent_flush(l->data, EV_WRITE, BEV_FINISHED);
		bufferevent_disable(l->data, EV_WRITE|EV_READ);
		bufferevent_enable(l->data, EV_WRITE|EV_READ);
	}
	GRID_DEBUG("Flush asked to output, enabling reading");
}

const char *
chunk_transfer_find_req_header(struct chunk_transfer_s *ct, const gchar *header)
{
	return evhttp_find_header(ct->src_req->input_headers, header);
}

guint
chunk_transfer_get_target_rawx_count(struct chunk_transfer_s *ct)
{
	return g_slist_length(ct->dst_rawx);
}

enum cnx_status_e
chunk_transfer_get_dst_status(struct chunk_transfer_s *ct)
{
	return ct->dst_status;
}

static gchar *
_get_volume_from_rawx(service_info_t *rawx)
{
        struct service_tag_s * vol_tag = NULL;
        gchar vol[1024];

        bzero(vol, sizeof(vol));
	vol_tag = service_info_get_tag(rawx->tags, NAME_TAGNAME_RAWX_VOL);

	if(!vol_tag)
		return NULL;
	service_tag_get_value_string(vol_tag, vol, sizeof(vol), NULL);

        if(strlen(vol) > 0)
                return g_strdup(vol);
	
	return NULL;
}

GSList*
chunk_transfer_build_target_chunk_list(struct chunk_transfer_s *ct)
{
	GSList *result = NULL;
	GSList *rawx = ct->dst_rawx;
	GSList *path = ct->dst_chunks;
	meta2_raw_chunk_t *chunk = NULL;
	gchar *vol;

	for (; rawx && path && rawx->data && path->data ; rawx = rawx->next,path = path->next) {
		chunk = meta2_raw_chunk_dup(ct->source_chunk);

		/* Modify the id (hash, address and volume */
		memset(&(chunk->id), 0, sizeof(chunk->id));
		memcpy(&(chunk->id.addr), &(((service_info_t*)rawx->data)->addr), sizeof(addr_info_t));
		chunk->id.vol[0] = '/';
		if ((vol = _get_volume_from_rawx((service_info_t*)rawx->data))) {
			g_strlcpy(chunk->id.vol, vol, sizeof(chunk->id.vol));
			g_free(vol);
		}
		memcpy(&(&(chunk->id))->id, path->data, sizeof(hash_sha256_t));

		result = g_slist_prepend(result, chunk);
	}
	return result;
}

static void chunk_attrinfo_clean(chunk_attrinfo_t *attrs)
{
	if(!attrs)
		return;
	if(attrs->content_path)
		g_free(attrs->content_path);
	if(attrs->sys_metadata)
		g_free(attrs->sys_metadata);
	if(attrs->usr_metadata)
		g_free(attrs->usr_metadata);
	g_free(attrs);
}

void chunk_transfer_clear(struct chunk_transfer_s *ct)
{
	/* dst rawx will be cleared by the caller */
	if(!ct)
		return;
	if(ct->source_path)
		g_free(ct->source_path);
	if(ct->dst_chunks) {
		g_slist_foreach(ct->dst_chunks, g_free1, NULL);
		g_slist_free(ct->dst_chunks);
	}
	if(ct->attrs)
		chunk_attrinfo_clean(ct->attrs);
	if(ct->source_chunk)
		meta2_raw_chunk_clean(ct->source_chunk);
        if (ct->src_status == CNX_NONE)
                evhttp_request_free(ct->src_req);

	if(ct->src_cnx)
		evhttp_connection_free(ct->src_cnx);
	if(ct->evt_dns)
		evdns_base_free(ct->evt_dns, 1);
	if(ct->evt_base)
		event_base_free(ct->evt_base);
	if(ct->dst_bevents)
		g_slist_free(ct->dst_bevents);
	g_free(ct);
	
}

/*************************************************/

void
srv_info_debug_display(gpointer data, gpointer udata)
{
	gchar *level = (gchar*) udata;
	gchar *tmp = NULL;
	tmp = service_info_to_string((service_info_t*)data);
	if(level && g_ascii_strcasecmp(level, "INFO"))
		GRID_INFO("Available service : %s",tmp);
	else
		GRID_DEBUG("Available service : %s",tmp);
	g_free(tmp);
}

void
raw_chunk_debug_display(gpointer data, gpointer udata)
{
	gchar *level = (gchar*) udata;
	gchar *tmp = NULL;
	tmp = meta2_raw_chunk_to_string((meta2_raw_chunk_t*)data);
	if(level && g_ascii_strcasecmp(level, "INFO"))
		GRID_INFO("chunk : %s", tmp);
	else
		GRID_DEBUG("chunk : %s", tmp);
	g_free(tmp);
}

service_info_t *
get_rawx_from_raw_chunk(meta2_raw_chunk_t *c, GSList *rawx)
{
        GSList *l = NULL;
        for (l = rawx; l && l->data; l = l->next) {
                if(!addr_info_equal(&((&(c->id))->addr), &((service_info_t *) l->data)->addr))
                        continue;
                GRID_DEBUG("Found rawx for an in place chunk :");
                srv_info_debug_display(l->data, NULL);
                return ((service_info_t *) l->data);
        }
        return NULL;
}

chunk_attrinfo_t*
build_chunk_attrinfo_from_content(meta2_raw_content_t *content)
{
	GRID_DEBUG("Building chunk_attrinfo");
	chunk_attrinfo_t* result = NULL;
	result = g_malloc0(sizeof(chunk_attrinfo_t));
	GRID_DEBUG("content_path => %s", content->path);
	result->content_path = g_strndup(content->path, strlen(content->path));
	GRID_DEBUG("result->content_path => [%s]", result->content_path);
	memcpy(result->cid, content->container_id, sizeof(container_id_t));
	result->nb_chunks = content->nb_chunks;
	result->content_size = content->size;
	if(content->metadata && content->metadata->data && content->metadata->len > 0)
		result->usr_metadata = g_strndup((gchar*)content->metadata->data, content->metadata->len);
	if(content->system_metadata && content->system_metadata->data && content->system_metadata->len > 0)
	result->sys_metadata = g_strndup((gchar*)content->system_metadata->data, content->system_metadata->len);
	return result;
}

void
content_check_ctx_clear(struct meta2_ctx_s *ctx)
{
	if(!ctx)
		return;
	if(ctx->ns)
		g_free(ctx->ns);
	if(ctx->content)
		meta2_raw_content_clean(ctx->content);

	if (ctx->loc)
		gs_container_location_free(ctx->loc);
	if (ctx->m2_cnx) {
		metacnx_close(ctx->m2_cnx);
		metacnx_destroy(ctx->m2_cnx);
	}
	
	if(ctx->hc) {
		gs_grid_storage_free(ctx->hc);
	}
	if(ctx->sp) {
		storage_policy_clean(ctx->sp);
	}

	g_free(ctx);
}

static gboolean
_check_sysmd_and_comp_info(const struct storage_policy_s *sp, const char *sysmd, const char *comp_info) 
{
	if(!sysmd)
		return FALSE;

	char *p = NULL;

	/* search storage-policy in sys-metadata */
	p = g_strrstr(sysmd, "storage-policy");
	if(!p)
		return FALSE;
	p = strchr(p, '=');
	p++;
	uint s = strlen(storage_policy_get_name(sp));
	if(strlen(p) < s || g_ascii_strncasecmp(storage_policy_get_name(sp), p, s)) {
		return FALSE;
	}

	/* check comp_info match sp */
	const struct data_treatments_s *dt = storage_policy_get_data_treatments(sp);
	if(!comp_info) {
		if(!dt || DT_NONE == data_treatments_get_type(dt)) {
			return TRUE;
		}
		return FALSE;
	} else {
		if(!dt || DT_NONE == data_treatments_get_type(dt)) {
			if(g_str_has_prefix(comp_info, "compression=off")) {
				return TRUE;
			}
			return FALSE;
		}
		p = g_strrstr(comp_info, "compression_algorithm=");
		p = strchr(p, '=');
		p++;
		s = strlen(data_treatments_get_param(dt, DT_KEY_ALGO));
		if(strlen(p) < s || g_ascii_strncasecmp(p, data_treatments_get_param(dt, DT_KEY_ALGO), s)) {
			return FALSE;
		}
		p = g_strrstr(comp_info, "compression_algorithm=");
		p = strchr(p, '=');
		p++;
		s = strlen(data_treatments_get_param(dt, DT_KEY_BLOCKSIZE));
		if(strlen(p) < s || g_ascii_strncasecmp(p, data_treatments_get_param(dt, DT_KEY_BLOCKSIZE), s)) {
			return FALSE;
		}
		return TRUE;
	}
}

GError*
download_and_check_chunk(const meta2_raw_chunk_t *rc, struct storage_policy_s *sp)
{
	GError *result = NULL;
	ne_session *session=NULL;
	ne_request *request=NULL;
	ne_request *request_update=NULL;
	char chunk_hash_str[128];
	char *update_uri = NULL;
	int ne_rc;

	MD5_CTX md5_ctx;

	int data_handler (void *uData, const char *b, const size_t bSize) {

		(void) uData;
		if (bSize==0)
			return 0;

		MD5_Update(&md5_ctx, b, bSize);

		return 0;
	}

	gchar dst[128];
	guint16 port = 0;

	addr_info_get_addr(&(rc->id.addr), dst, sizeof(dst), &port);

	session = ne_session_create("http", dst, port);

	if (!session) {
		g_set_error(&result, gquark_log, 500, "Cannot open a new WebDAV session");
		goto error_label;
	}

	ne_set_connect_timeout(session, 10);
	ne_set_read_timeout(session, 30);

	bzero(chunk_hash_str, sizeof(chunk_hash_str));
	chunk_hash_str[0] = '/';
	buffer2str(rc->id.id, sizeof(rc->id.id), chunk_hash_str + 1, sizeof(chunk_hash_str) - 2);

	request = ne_request_create (session, "GET", chunk_hash_str);
	if (!request) {
		g_set_error(&result, gquark_log, 500, "WebDAV request creation error (%s)", ne_get_error(session));
		goto error_label;
	}

	ne_add_response_body_reader(request, ne_accept_2xx, data_handler, NULL);

	MD5_Init(&md5_ctx);

	/* Now send the request */
	switch (ne_rc = ne_request_dispatch(request)) {
		case NE_OK:
			GRID_DEBUG("Chunk check request correctly send to the rawx");
			if (ne_get_status(request)->klass != 2) {
				g_set_error(&result, gquark_log, 1000 + ne_get_status(request)->code, 
					"Cannot download '%s' (%s)", chunk_hash_str, ne_get_error(session));
				GRID_DEBUG("Error while downloading chunk");
				goto error_label;
			}
			unsigned char md5[MD5_DIGEST_LENGTH];

			bzero(md5, sizeof(md5));
			MD5_Final(md5, &md5_ctx);
			char hash_str[MD5_DIGEST_LENGTH*2+1];
			char md5_str[MD5_DIGEST_LENGTH*2+1];
			bzero(hash_str, sizeof(hash_str));
			bzero(md5_str, sizeof(md5_str));
			buffer2str(rc->hash, sizeof(rc->hash), hash_str, sizeof(hash_str));
			buffer2str(md5, sizeof(md5), md5_str, sizeof(md5_str));

			GRID_DEBUG("md5 calculated for downloaded chunk = %s, get from meta2 = %s", md5_str, hash_str);

			if (memcmp(rc->hash, md5, MD5_DIGEST_LENGTH) != 0) {
				g_set_error(&result, gquark_log, CODE_CONTENT_CORRUPTED, "Chunk downloaded [%s] was corrupted"
						" (md5 does not match meta2) : %s/%s", chunk_hash_str, hash_str, md5_str);
				goto error_label;
			}
			break;

		case NE_ERROR:
			GRID_DEBUG("Chunk check request error (NE_ERROR)");
			g_set_error(&result, gquark_log, 500, "Caller error '%s' (%s)",
					chunk_hash_str, ne_get_error(session));
			goto error_label;

		case NE_TIMEOUT:
			GRID_DEBUG("Chunk check request timeout (NE_TIMEOUT)");
			g_set_error(&result, gquark_log, 10060, "Cannot download '%s' (%s) ",
					chunk_hash_str, ne_get_error(session));
			goto error_label;
		case NE_CONNECT:
			GRID_DEBUG("Chunk check request error (NE_CONNECT)");
			g_set_error(&result, gquark_log, 10061, "Caller error '%s' (%s)",
					chunk_hash_str, ne_get_error(session));
			goto error_label;
		case NE_AUTH:
			GRID_DEBUG("Chunk check request error (NE_CONNECT)");
			g_set_error(&result, gquark_log, 500, "Caller error '%s' (%s)",
					chunk_hash_str, ne_get_error(session));
			goto error_label;
		default:
			g_set_error(&result, gquark_log, 500, "Cannot download '%s' (%s) ",
					chunk_hash_str, ne_get_error(session));
			goto error_label;
	}
	/* ensure chunk data treat */
	const char *comp_info = ne_get_response_header(request, "metadatacompress");
	const char *sysmd = ne_get_response_header(request, "content_metadata-sys");
	if (sp && !_check_sysmd_and_comp_info(sp, sysmd, comp_info)) {
		update_uri = g_strconcat(chunk_hash_str, "/update", NULL);
		request_update = ne_request_create (session, "GET", update_uri);
		if (!request) {
			g_set_error(&result, gquark_log, 500, "WebDAV request creation error (%s)", ne_get_error(session));
			goto error_label;
		}

		ne_add_request_header(request_update, "storage-policy", storage_policy_get_name(sp));
		/* Now send the request */
		switch (ne_rc = ne_request_dispatch(request_update)) {
			case NE_OK:
				GRID_DEBUG("Chunk storage update ok");
				break;
			default:
				GRID_DEBUG("Chunk update storage ko");
				break;
		}
	}

error_label:

	if (update_uri)
		g_free(update_uri);

	if (request_update)
		ne_request_destroy (request_update);
	if (request)
		ne_request_destroy (request);
	if (session)
		ne_session_destroy (session);

	return result;
}

GError*
delete_chunk(const meta2_raw_chunk_t *rc)
{
	GError *result = NULL;
	ne_session *session=NULL;
	ne_request *request=NULL;
	char chunk_hash_str[128];

	gchar dst[128];
	guint16 port = 0;

	addr_info_get_addr(&(rc->id.addr), dst, sizeof(dst), &port);

	session = ne_session_create("http", dst, port);

	if (!session) {
		g_set_error(&result, gquark_log, 500, "Cannot open a new WebDAV session");
		goto error_label;
	}

	ne_set_connect_timeout(session, 10);
	ne_set_read_timeout(session, 30);

	bzero(chunk_hash_str, sizeof(chunk_hash_str));
	chunk_hash_str[0] = '/';
	buffer2str(rc->id.id, sizeof(rc->id.id), chunk_hash_str + 1, sizeof(chunk_hash_str) - 2);

	request = ne_request_create (session, "DELETE", chunk_hash_str);
	if (!request) {
		g_set_error(&result, gquark_log, 500, "WebDAV request creation error (%s)", ne_get_error(session));
		goto error_label;
	}

	switch (ne_request_dispatch (request))
	{
		case NE_OK:
			if (ne_get_status(request)->klass != 2) {
				g_set_error(&result, gquark_log, 1000 + ne_get_status(request)->code,
						"cannot delete '%s' (%s)", chunk_hash_str, ne_get_error(session));
				goto error_label;
			}
			break;
		case NE_AUTH:
		case NE_CONNECT:
		case NE_TIMEOUT:
		case NE_ERROR:
			g_set_error(&result, gquark_log, 500, "unexpected error from the WebDAV server (%s)", ne_get_error(session));
			goto error_label;
	}

	GRID_DEBUG("%s deleted", chunk_hash_str);

error_label:

	if (request)
		ne_request_destroy (request);
	if (session)
		ne_session_destroy (session);

	return result;
}

gboolean
is_rawx_reachable(const service_info_t *rawx)
{
	ne_session *session=NULL;
	ne_request *request=NULL;
	int ne_rc;
	gboolean result = FALSE;

	int data_handler_no_op (void *uData, const char *b, const size_t bSize) {

		(void) uData;
		(void) b;
		(void) bSize;

		return 0;
	}

	gchar dst[128];
	guint16 port = 0;

	if (!addr_info_get_addr(&(rawx->addr), dst, sizeof(dst), &port)) {
		GRID_DEBUG("Failed to extract address info from rawx");
		goto end;
	}

	GRID_DEBUG("Checking if %s:%d is reachable", dst, port);

	session = ne_session_create("http", dst, port);

	if (!session) {
		GRID_DEBUG("Failed to create neon session");
		goto end;
	}

	ne_set_connect_timeout(session, 10);
	ne_set_read_timeout(session, 30);

	request = ne_request_create (session, "GET", "PING");
	if (!request) {
		GRID_DEBUG("Failed to create neon request");
		goto end;
	}

	/* Now send the request */
	switch (ne_rc = ne_request_dispatch(request)) {
		case NE_OK:
			GRID_DEBUG("Rawx response ok, reachable");
			result = TRUE;
			break;
		case NE_ERROR:
			GRID_DEBUG("Chunk check request error (NE_ERROR)");
			break;
		case NE_TIMEOUT:
			GRID_DEBUG("Chunk check request timeout (NE_TIMEOUT)");
			break;
		case NE_CONNECT:
			GRID_DEBUG("Chunk check request error (NE_CONNECT)");
			break;
		case NE_AUTH:
			GRID_DEBUG("Chunk check request error (NE_AUTH)");
			break;
		default:
			GRID_DEBUG("Unknown rawx response status code");
			break;
	}

end:

	if (request)
		ne_request_destroy (request);
	if (session)
		ne_session_destroy (session);

	return result;
}
