#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.lib.content_check"
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

#include <glib.h>

#include <event.h>
#include <evdns.h>
#include <evhttp.h>
#include <evutil.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>
#include <grid_client.h>
#include <rawx-lib/src/rawx.h>
#include <meta2/remote/meta2_remote.h>

#include "content_check.h"
#include "check.h"

#define MSG_INCONSISTENT_CHUNK \
	"Chunk %s cannot be associated to any rawx returned by namespace"
#define MSG_DONT_MATCH_CRITERIA \
	"Rawx don't match search criteria (%s)"

static GQuark gquark_log = 0;

typedef gboolean (*policy_check_f)(GSList *chunk_list);

static int
tcpip_open(const gchar *h, const gchar *p)
{

	GRID_DEBUG("opening tcp ip connection");
	struct evutil_addrinfo ai_hint, *ai_res = NULL;

	int rc;
	socklen_t ss_len;
	struct sockaddr_storage ss;
	int fd;

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		GRID_ERROR("accept error on fd=%d : %s", fd, strerror(errno));
		return -1;
	}

	sock_set_linger_default(fd);
	sock_set_reuseaddr(fd, TRUE);

	bzero(&ai_hint, sizeof(ai_hint));
	ai_hint.ai_flags = AI_NUMERICHOST;
	ai_hint.ai_family = PF_INET;
	ai_hint.ai_socktype = SOCK_STREAM;
	rc = evutil_getaddrinfo(h, p, &ai_hint, &ai_res);
	if (rc != 0) {
		errno = rc;
		return -1;
	}

	bzero(&ss, sizeof(ss));
	ss_len = ai_res->ai_addrlen;
	g_memmove(&ss, (ai_res->ai_addr), ss_len);
	evutil_freeaddrinfo(ai_res);

	switch (connect(fd, (struct sockaddr *) &ss, ss_len)) {
		case 0:
			return fd;
		case -1:
			if (errno==EALREADY || errno==EAGAIN || errno==EINPROGRESS || errno==EWOULDBLOCK) {
				errno = 0;
				return fd;
			}
			return -1;
		default:/* unexpected */
			return -1;
	}
}

static void
_extract_location(gpointer data, gpointer udata)
{
	GRID_DEBUG("extracting services locations");
	struct service_tag_s * loc_tag = NULL;
	gchar loc[1024];
	GSList **used_loc = (GSList **) udata;

	bzero(loc, sizeof(loc));

	if(data)
		loc_tag = service_info_get_tag(((service_info_t*)data)->tags, NAME_TAGNAME_RAWX_LOC);

	GRID_DEBUG("service tag extracted");
	if(!loc_tag)
		return;

	service_tag_get_value_string(loc_tag, loc, sizeof(loc), NULL);

	if(strlen(loc) > 0)
		*used_loc = g_slist_prepend(*used_loc, g_strdup(loc));
}

static gboolean
__test_location(gchar *loc, GSList *used_loc, gint64 distance)
{
	GRID_DEBUG("Required distance is %ld", distance);
	GSList *l = NULL;
	for (l = used_loc; l && l->data; l = l->next) {
		gint64 d = distance_between_location(loc, (gchar*) l->data);
		GRID_DEBUG("-> found distance %ld", d);
		if(d < distance)
			return FALSE;
	}
	return TRUE;
}

static gboolean
_is_rawx_in_garbage(service_info_t *rawx, GSList *garbage) {
	/* ensure service not in garbage */
	GSList *r = NULL;
	for(r = garbage; r && r->data; r = r->next) {
		if(addr_info_equal(&(rawx->addr), &(((service_info_t*)r->data)->addr))) {
			return TRUE;
		}
	}
	return FALSE;
}

static service_info_t *
_find_matching_rawx(GSList *rawx, GSList *used_loc, gint64 distance,
		const gchar *stg_class, GSList **rawx_garbage)
{
	GRID_DEBUG("Searching rawx distant of %"G_GINT64_FORMAT
			" with storage class '%s'", distance, stg_class);
	GSList *l = NULL;
	gchar loc[1024];
	struct service_tag_s * loc_tag = NULL;
	GRID_DEBUG("Checking for an available rawx in a list of %d elements",
			g_slist_length(rawx));
	for (l = rawx; l && l->data; l = l->next) {
		GRID_DEBUG("Checking one rawx...");
		/* ensure service score */
		if(((service_info_t*)l->data)->score.value <= 0) {
			GRID_DEBUG("Rawx score <= 0");
			continue;
		}
		/* ensure not spotted as unreachable */
		if(_is_rawx_in_garbage((service_info_t*)l->data, *rawx_garbage)) {
			GRID_DEBUG("Rawx already in unreachable list");
			continue;
		}
		/* check rawx reachable */
		if(!is_rawx_reachable((service_info_t*)l->data)) {
			GRID_DEBUG("Rawx unreachable");
			*rawx_garbage = g_slist_prepend(*rawx_garbage, l->data);
			continue;
		}

		/* check rawx has appropriate storage class (strictly) */
		if (!service_info_check_storage_class(l->data, stg_class)) {
			GRID_DEBUG(MSG_DONT_MATCH_CRITERIA, "storage class");
			continue;
		}

		/* ensure distance match with our policy */
		bzero(loc, sizeof(loc));
		loc_tag = service_info_get_tag(((service_info_t*)l->data)->tags, NAME_TAGNAME_RAWX_LOC);
		GRID_DEBUG("service tag extracted");
		if(!loc_tag) {
			if(distance > 1) {
				continue;
			}
			return ((service_info_t*)l->data);
		}
		service_tag_get_value_string(loc_tag, loc, sizeof(loc), NULL);
		if(__test_location(loc, used_loc, distance)) {
			return ((service_info_t*)l->data);
		} else {
			GRID_DEBUG(MSG_DONT_MATCH_CRITERIA, "distance");
		}
	}
	return NULL;
}

static void
__dst_cb_out(struct bufferevent *bev, void *ctx)
{
        gint64 buffer_size;

	struct chunk_transfer_s *ct = (struct chunk_transfer_s *) ctx;

        /* Called only because there are no bytes to write ... well,
         * we choose to disable the event, that is the input request
         * that will fill it and re-enable it */

        buffer_size = evbuffer_get_length(bufferevent_get_output(bev));
        GRID_DEBUG("Output waiting for data. Low watermark reached "
                        "with %"G_GINT64_FORMAT", %"G_GINT64_FORMAT" expected",
                        buffer_size, ct->dst_size_remaining);

        if (ct->dst_size_remaining <= 0) {
                bufferevent_disable(bev, EV_WRITE|EV_READ);
                bufferevent_enable(bev, EV_READ);
        }
}

static void
__dst_cb_in(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *dst_in;
	struct chunk_transfer_s *ct = (struct chunk_transfer_s *) ctx;

	bufferevent_disable(bev, EV_WRITE);
	dst_in = bufferevent_get_input(bev);
	for (;;) {
		if (ct->reply_parsing == PARSE_STATUS) {
			char *status_line;
			size_t status_line_length;
			status_line_length = 0;
			status_line = evbuffer_readln(dst_in, &status_line_length, EVBUFFER_EOL_CRLF);
			if (!status_line) {
				GRID_DEBUG("Output status line not ready, %"G_GSIZE_FORMAT" bytes remaining",
					evbuffer_get_length(dst_in));
				return;
			} else {
				GRID_DEBUG("Output status line [%s]", status_line);
				free(status_line);
				ct->reply_parsing = PARSE_HEADER;
				bufferevent_enable(bev, EV_READ);
			}
		}
		if (ct->reply_parsing == PARSE_HEADER) {
			char *header_line;
			size_t header_line_length;
			header_line_length = 0;
			header_line = evbuffer_readln(dst_in, &header_line_length, EVBUFFER_EOL_CRLF);
			if (!header_line) {
				GRID_DEBUG("Output header line not ready, %"G_GSIZE_FORMAT" bytes remaining",
						evbuffer_get_length(dst_in));
				return;
			} else {
				if (!header_line_length) {
					GRID_DEBUG("Output header end");
					ct->reply_parsing = PARSE_BODY;
				}
				else {
					GRID_DEBUG("Output header line [%s]", header_line);
					free(header_line);
					bufferevent_enable(bev, EV_READ);
				}
			}
		}
		if (ct->reply_parsing == PARSE_BODY) {
			size_t s;
			s = evbuffer_get_length(dst_in);
			if (!s)
				return;
			evbuffer_drain(dst_in, s);
			GRID_DEBUG("Output body drained of %"G_GSIZE_FORMAT" bytes", s);
			bufferevent_enable(bev, EV_READ);
		}
	}
}

static void
__dst_cb_error(struct bufferevent *bev, short what, void *ctx)
{
        (void) ctx;

        if (what & BEV_EVENT_CONNECTED) {
                GRID_DEBUG("Output connected");
                bufferevent_disable(bev, EV_READ);
                bufferevent_enable(bev, EV_WRITE);
        }
        if (what & BEV_EVENT_EOF) {
                GRID_DEBUG("Output EOF");
                bufferevent_disable(bev, EV_WRITE|EV_READ);
                return;
        }
       
       	/* Must tag dst error */
        if (what & (~BEV_EVENT_CONNECTED))
                GRID_DEBUG("Output error!");
        else
                GRID_DEBUG("Output AAaaaaaAAAaAAaaargl!");
        bufferevent_disable(bev, EV_READ|EV_WRITE);
}

static void
__out_start(struct chunk_transfer_s *ct)
{
	gint64 header_size = 0;
	int dst_fd;
	struct evkeyval *kv;
	struct evkeyvalq *src;
	GSList *dsts_out = NULL; /* struct evbuffer */
	GSList *lc = NULL;
	GSList *lb = NULL;
	struct timeval tv_read, tv_write;
	GSList *l = NULL;

	if (chunk_transfer_get_dst_status(ct) != CNX_NONE)
		return;
	GRID_DEBUG("Starting the output...");
	const char *content_length = chunk_transfer_find_req_header(ct, "Content-Length");

	ct->dst_size = ct->dst_size_remaining = g_ascii_strtoll(content_length, NULL, 10);
	if(chunk_transfer_get_target_rawx_count(ct) < 1) {
		GRID_ERROR("ERROR, no destination rawx...");	
		return;
	}

	GRID_DEBUG("ok we have targets, prepare to send data");

	for(l = ct->dst_rawx; l && l->data; l = l->next) {
		gchar dst[128];
		gchar port_str[16];
		guint16 port = 0;
		struct bufferevent* bevent = NULL;

		addr_info_get_addr(&(((service_info_t*)l->data)->addr), dst, sizeof(dst), &port);
		bzero(port_str, sizeof(port_str));
		g_snprintf(port_str, sizeof(port_str), "%d", port);


		GRID_DEBUG("addr extracted: %s %s", dst, port_str);

		dst_fd = tcpip_open(dst, port_str);

		GRID_DEBUG("Destination opened");
		/* ***** */
		bevent = bufferevent_socket_new(ct->evt_base, dst_fd, 0);
		GRID_DEBUG("buffer event created");
		tv_write.tv_sec = 3;
		tv_write.tv_usec = 0;
		tv_read.tv_sec = 3;
		tv_read.tv_usec = 0;
		bufferevent_set_timeouts(bevent, &tv_read, &tv_write);
		bufferevent_setcb(bevent, __dst_cb_in, __dst_cb_out, __dst_cb_error, ct);
		bufferevent_disable(bevent, EV_READ|EV_WRITE);

		/* Write the HTTP request and the grid headers */
		/* WARN: don't do prepend if you want to keep all in good order !! */
		dsts_out = g_slist_append(dsts_out, bufferevent_get_output(bevent));
		ct->dst_bevents = g_slist_append(ct->dst_bevents, bevent);
	}

	if(ct->dst_chunks) {
		GRID_DEBUG("dst_chunks filled, its ok");
	} else {
		GRID_DEBUG("no dst_chunks defined");
	}

	for (lc = ct->dst_chunks, lb = dsts_out; lc && lc->data && lb && lb->data; lc = lc->next, lb = lb->next) {
		gchar idstr[65];
		bzero(idstr, sizeof(idstr));
		container_id_to_string(lc->data, idstr, sizeof(idstr));

		evbuffer_add_printf(lb->data, "PUT /%s HTTP/1.0\r\n", idstr);
		GRID_DEBUG("Sending put order");
		/* Add missing headers (xattr not returned by rawx) */
		evbuffer_add_printf(lb->data, "chunkid: %s\n", idstr);
		evbuffer_add_printf(lb->data, "chunkpos: %"G_GUINT32_FORMAT"\n", ct->source_chunk->position);
		evbuffer_add_printf(lb->data, "chunksize: %"G_GINT64_FORMAT"\n", ct->source_chunk->size);
		/* container id str */
		gchar cidstr[65];
		bzero(cidstr, sizeof(cidstr));
		container_id_t cid;
		chunk_transfer_get_container_id(ct, cid);
		container_id_to_string(cid, cidstr, sizeof(cidstr));

		evbuffer_add_printf(lb->data, "containerid: %s\n", cidstr);
		evbuffer_add_printf(lb->data, "contentpath: %s\n", chunk_transfer_get_content_path(ct)); 
		evbuffer_add_printf(lb->data, "chunknb: %"G_GUINT32_FORMAT"\n", chunk_transfer_get_content_nb_chunks(ct)); 
		evbuffer_add_printf(lb->data, "contentsize: %"G_GINT64_FORMAT"\n", chunk_transfer_get_content_size(ct)); 
		if(ct->attrs->usr_metadata)
			evbuffer_add_printf(lb->data, "contentmetadata: %s\n", ct->attrs->usr_metadata); 
		if(ct->attrs->sys_metadata)
			evbuffer_add_printf(lb->data, "contentmetadata-sys: %s\n", ct->attrs->sys_metadata); 
		/* **** */

		evbuffer_add_printf(lb->data, "Connection: close\r\n");
		evbuffer_add_printf(lb->data, "Content-Type: application/octet-stream\r\n");
		evbuffer_add_printf(lb->data, "Content-Length: %"G_GINT64_FORMAT"\r\n", ct->dst_size);
	}

	src = ct->src_req->input_headers;
	TAILQ_FOREACH(kv, src, next) {
		GRID_DEBUG("headers found : %s | %s", kv->key, kv->value);
		if (g_str_has_prefix(kv->key, "X-Grid-")
				|| g_str_has_prefix(kv->key, "container")
				|| g_str_has_prefix(kv->key, "content")
				|| g_str_has_prefix(kv->key, "chunk")) {
			for(lb = dsts_out; lb && lb->data; lb = lb->next) {	
				evbuffer_add_printf(lb->data, "%s: %s\r\n", kv->key, kv->value);
			}
		}
	}
	for(lb = dsts_out; lb && lb->data; lb = lb->next) {	
		evbuffer_add_printf(lb->data, "\r\n");
		header_size = evbuffer_get_length(lb->data);
	}

        ct->dst_status = CNX_STARTED;
	
	for (lb = ct->dst_bevents; lb && lb->data ; lb = lb->next) {
		bufferevent_enable(lb->data, EV_WRITE);
	}
        GRID_DEBUG("Output started! (%"G_GINT64_FORMAT" bytes expected, already"
                        " %"G_GINT64_FORMAT" bytes of headers)", ct->dst_size, header_size);
}

static void
__transfer(struct chunk_transfer_s *ct, gboolean finished)
{
	struct evbuffer *in_buffer;

	in_buffer = chunk_transfer_get_input_buffer(ct);

	__out_start(ct);       

        GRID_DEBUG("Input buffer has %"G_GSIZE_FORMAT" bytes", evbuffer_get_length(in_buffer));

        while (0 < evbuffer_get_length(in_buffer)) {
                gint i64;
                size_t s;
                ev_ssize_t nb_read;
                gchar buf[5120];

                nb_read = evbuffer_copyout(in_buffer, buf, sizeof(buf));
                if (!nb_read)
                        break;

                s = nb_read;
		chunk_transfer_write_to_dst(ct, buf,s);

                GRID_DEBUG("Output received %"G_GSIZE_FORMAT" bytes", s);

                evbuffer_drain(in_buffer, s);
                i64 = nb_read;
                chunk_transfer_set_dst_remaining_size(ct, ct->dst_size_remaining - i64);
        }

        if (finished) {
		chunk_transfer_flush_dst(ct);
	}
}

static void
__cb_cnx_in_closed(struct evhttp_connection *cnx, void *udata)
{
        (void) cnx;
        (void) udata;
        GRID_DEBUG("Input connection closed");
}

static void
__cb_req_in_final(struct evhttp_request *req, void *udata)
{
        struct chunk_transfer_s *ct = (struct chunk_transfer_s *) udata;

        if (!req || req->response_code < 200 || req->response_code > 299) {
                GRID_ERROR("input request error : %d (%s)",
                                (req) ? req->response_code : -1, (req) ? req->response_code_line : NULL);
                ct->src_status = CNX_FAILED;
        }
        else {
		const char *metadata_sys = chunk_transfer_find_req_header(ct, "content_path");
		GRID_DEBUG("Found sys-metadata header : %s", metadata_sys);
		ct->src_status = CNX_SUCCEEDED;
                GRID_DEBUG("input request finished : %d (%s)",
                                req->response_code, req->response_code_line);
                __transfer(ct, TRUE);
        }
}

static void
__cb_req_in_ready(struct evhttp_request *req, void *udata)
{
	(void) req;
        struct chunk_transfer_s *ct = (struct chunk_transfer_s *) udata;

	if (!req->response_code) {
		GRID_ERROR("Input error (network)");
		return ;
	}
        if (req->response_code < 200 || req->response_code >= 300) {
                GRID_ERROR("Input error : %d (%s)",
                                req->response_code, req->response_code_line);
                return ;
        }

        GRID_DEBUG("Input data ready");
        __transfer(ct, FALSE);
}

static int
__in_start(struct chunk_transfer_s *ct, const gchar *h, short p)
{
	/* init connection to the source rawx */
	chunk_transfer_init_base_conn(ct, h ,p);
	/* define close callback */
	chunk_transfer_set_base_conn_close_cb(ct, __cb_cnx_in_closed, NULL);
	/* init the request to send */
	chunk_transfer_init_req(ct, __cb_req_in_final, ct);
	/* define callback called while getting part of response */
	chunk_transfer_set_req_chunked_cb(ct, __cb_req_in_ready);
	/* start request */
	return chunk_transfer_make_request(ct);
}

static guint
_count_active_connections(struct chunk_transfer_s *ct)
{
        guint count = 0;
	GSList *l = NULL;
        if (ct->src_status == CNX_STARTED)
                count ++;
	for( l =ct->dst_bevents; l && l->data; l = l->next) {
		if (bufferevent_get_enabled(l->data)) {
			count ++;
		}
	}
        return count;
}

static GError*
_copy_chunk_data(meta2_raw_content_t *content, meta2_raw_chunk_t *src_chunk, GSList *dest)
{
	struct chunk_transfer_s *ct = NULL;
	GSList *new_chunks = NULL;
	GError *local_error = NULL;
	chunk_attrinfo_t *attrs = NULL;
	int req_status = -1;

	gchar str[2048];
	bzero(str, sizeof(str));
	chunk_id_to_string(&(src_chunk->id), str, sizeof(str));
	gchar **tokens = g_strsplit(str, ":", 2);
	gchar uri[strlen(tokens[0]) + 2];
	bzero(uri, sizeof(uri));
	g_snprintf(uri, sizeof(uri), "/%s", tokens[0]);
	/* Build attr infos */
	attrs = build_chunk_attrinfo_from_content(content);

	/* Init the transfer structure (libevent objects) */
	ct = chunk_transfer_new();
	chunk_transfer_set_source_uri(ct, g_strdup(uri));
	chunk_transfer_set_source_chunk(ct, meta2_raw_chunk_dup(src_chunk));
	chunk_transfer_set_source_chunk_attrinfo(ct, attrs);
	g_strfreev(tokens);
	chunk_transfer_set_target_rawx(ct, dest);

	/* get chunk id's for the new chunks */
	chunk_transfer_generate_chunks_path(ct);

	gchar src[128];
	guint16 port = 0;

	addr_info_get_addr(&((&(src_chunk->id))->addr), src, sizeof(src), &port);

	req_status = __in_start(ct, src, port);

	GRID_DEBUG("Copy started, waiting for all connections closed");

	while (_count_active_connections(ct) > 0) {
		int rc;
                rc = event_base_loop(ct->evt_base, EVLOOP_ONCE);
                if (rc == 1)
                        break;
        }

	GRID_DEBUG("Ok, no more connection opened, continue");

	/* Add new uploaded chunks to the content if the upload works */
	if(req_status == 0 && ct->src_status == CNX_SUCCEEDED) {	
		new_chunks = chunk_transfer_build_target_chunk_list(ct);
		content->raw_chunks = g_slist_concat(content->raw_chunks, new_chunks);
	} else {
		GRID_DEBUG("Chunk upload failed on rawx, don't add it to meta2");
		g_set_error(&local_error, gquark_log, 500, "Destination rawx connection error");
	}

	chunk_transfer_clear(ct);

	return local_error; 
}

static GError*
_upload_new_copy(struct meta2_ctx_s *ctx, GSList *rawx,
		GSList **rawx_garbage, struct dup_chunk_info_s *dci, guint nb_dup,
		meta2_raw_chunk_t* src_chunk)
{
	GError *result = NULL;
	GRID_DEBUG("uploading %d new copy of a chunk", nb_dup);
	guint i = 0;
	const struct data_security_s *ds = storage_policy_get_data_security(ctx->sp);
	const char *tmp = data_security_get_param(ds, DS_KEY_DISTANCE);
	gint64 distance = (NULL != tmp) ? g_ascii_strtoll(tmp, NULL, 10) : 1;
	const gchar *stgclass = storage_class_get_name(storage_policy_get_storage_class(ctx->sp));
	GSList *dest = NULL;
	GSList *used_loc = dup_chunk_info_get_used_locations(dci);

	/* search for new available location */
	// FIXME: this looks like grid_lb_iterator_next_set() from metautils/lib/lb.c
	GRID_DEBUG("Try to find %d matching & available rawx", nb_dup);
	for (i = 0; i < nb_dup; i++) {
		struct service_info_s *si;

		if (!(si = _find_matching_rawx(rawx, used_loc, distance, stgclass, rawx_garbage))) {
			GRID_DEBUG("Failed to find a rawx which matches with duplication criteria");
			ctx->fail = TRUE;
			if (g_slist_length(dest) > 0) {
				break; // We can do something
			} else {
				g_set_error(&result, gquark_log, CODE_POLICY_NOT_SATISFIABLE,
						"Cannot add missing copies, no matching rawx available");
				goto clean_up; // Impossible to repair anything
			}
		}

		GRID_DEBUG("Available rawx found");
		dest = g_slist_prepend(dest, si);
		_extract_location(si, &used_loc);
		GRID_DEBUG("Rawx location added to locations list");
	}

	/* ok, here we have a list of rawx operational to store our chunks, now go go go! */
	GRID_DEBUG("New destinations :");
	/* display informations (debugging) */
	g_slist_foreach(dest, srv_info_debug_display, NULL);

	/* Pipe one of the existing chunks to the mandatory copies */
	if (src_chunk == NULL) {
		GSList *chunks = dup_chunk_info_get_chunks(dci);
		src_chunk = (meta2_raw_chunk_t*)chunks->data;
	}

	if ((result = _copy_chunk_data(ctx->content, src_chunk, dest)) != NULL) {
		g_prefix_error(&result, "Failed to copy chunk data: ");
		goto clean_up;
	}

	if (g_slist_length(dest) == nb_dup) {
		GRID_DEBUG("Missing chunks correctly created and filled.");
	} else {
		g_set_error(&result, gquark_log, CODE_POLICY_NOT_SATISFIABLE,
				"Some copies are still missing (not enough matching rawx available)");
		GRID_DEBUG("No all missing copies have been created (%d/%d)",
				g_slist_length(dest), nb_dup);
	}

clean_up:

	return result;
}

static void
_restore_chunk_by_pos(guint pos, GSList **garbage)
{
	GSList *l = NULL;
	GSList *new = NULL;
	meta2_raw_chunk_t *rc = NULL;

	/* rebuild garbage without chunk at critical position */
	for(l = *garbage; l && l->data; l=l->next) {
		rc = (meta2_raw_chunk_t*)l->data;
		if(rc->position != pos) {
			new = g_slist_prepend(new, rc);
		}
	}
	if(*garbage)
		g_slist_free(*garbage);

	*garbage = new;
}

/**
 * Iterate over a list of chunks and adjusts the number of copies
 * for each position. Also tries to relocate chunks with wrong storage class.
 */
static void
_adjust_chunk_copies(struct meta2_ctx_s *ctx, GSList *rawx,
		struct dup_chunk_info_s **chunks, GSList **garbage, GSList **rawx_garbage,
		GSList **almost_good)
{
	guint32 size = 0;
	guint32 size2 = 0;
	guint i = 0;
	GSList *tmp = NULL;
	const char *str = data_security_get_param(storage_policy_get_data_security(ctx->sp), DS_KEY_COPY_COUNT);
	guint32 nb_copy = (NULL != str) ? atoi(str) : 1;
	GRID_DEBUG("adjust chunk copies, we have %d positions to scan", g_strv_length((gchar**)chunks));

	for (i = 0; i < g_strv_length((gchar**)chunks); i++) {
		GRID_DEBUG("Scanning chunks at position %d", i);
		size = dup_chunk_info_get_copy_count(chunks[i]);
		size2 = g_slist_length(almost_good[i]);
		GRID_DEBUG("%d valid chunks found at this position", size);
		GRID_DEBUG("%d almost valid chunks found at this position"
				" (incorrect distance or storage class)", size2);
		if (size == 0 && size2 == 0) {
			/* No valid chunk found at this position, remove all from garbage and log fatal error */
			GRID_ERROR("No valid chunk found at position %d, cannot repair anything", i);
			if (!ctx->check_only) {
				_restore_chunk_by_pos(i, garbage);
				ctx->fail = TRUE;
			}
			/* TODO: flag content to corrupted */
		} else {
			if (size > nb_copy) {
				GRID_DEBUG("Too many copies of chunk at position %"G_GUINT32_FORMAT" (%"G_GUINT32_FORMAT
						" copies, %"G_GUINT32_FORMAT" expected)" , i, size, nb_copy);
				if (!ctx->check_only) {
					/* add chunks to the unwanted list */
					guint j = 0;
					tmp = dup_chunk_info_get_chunks((struct dup_chunk_info_s*) chunks[i]);
					for (j = 0; j < size - nb_copy; j++) {
						if (tmp && tmp->data) {
							gchar *chunk_str = meta2_raw_chunk_to_string((meta2_raw_chunk_t*)tmp->data);
							GRID_INFO("%s marked for delete, too many copies.", chunk_str);
							*garbage = g_slist_prepend(*garbage, tmp->data);
							if (chunk_str)
								g_free(chunk_str);
							tmp = tmp->next;
						} else {
							break;
						}
					}
				}
			} else if (size < nb_copy) {
				GRID_INFO("Not enough copies of chunk at position %"G_GUINT32_FORMAT" (%"G_GUINT32_FORMAT
						" copies, %"G_GUINT32_FORMAT" expected)" , i, size, nb_copy);
				/* we want new chunks at this pos */
				GError *local_error = NULL;
				if (!ctx->check_only) {
					/* If there is no valid chunk, take the data from an 'almost valid' one */
					meta2_raw_chunk_t* src_chunk = (size > 0) ? NULL : almost_good[i]->data;
					local_error = _upload_new_copy(ctx, rawx, rawx_garbage, chunks[i], nb_copy - size, src_chunk);
					if (local_error) {
						GRID_ERROR("Error while creating new chunk copy: %s", local_error->message);
						/* don't touch to chunk at this position, we cannot create the other */
						_restore_chunk_by_pos(i, garbage);
						ctx->fail = TRUE;
						g_clear_error(&local_error);
						continue;
					}
					ctx->modified = TRUE;
				}
			}
		}
	}

	GRID_DEBUG("Chunk copies adjustement done");
}

static void
_delete_chunk(gpointer data, gpointer udata)
{
	(void) udata;
	GError *local_error = NULL;
	local_error = delete_chunk((meta2_raw_chunk_t*) data);
	if(local_error) {
		GRID_INFO("Failed to delete chunk from disk : %s", local_error->message);
		g_clear_error(&local_error);
	}
}

static gboolean
_check_duplicated_content_is_valid(struct meta2_ctx_s *ctx)
{
	GRID_DEBUG("Checking duplicated content");

	GRID_DEBUG("Creating array of %d list, (nb_chunks)", ctx->content->nb_chunks);

	struct dup_chunk_info_s* chunks[ctx->content->nb_chunks + 1];
	guint i = 0;
	GError *local_error = NULL;
	GSList *rawx = NULL;
	GSList *rawx_garbage = NULL;
	GSList *garbage = NULL;
	GSList *almost_good[ctx->content->nb_chunks + 1];
	GSList *l = NULL;
	const struct storage_class_s *stg_class = storage_policy_get_storage_class(ctx->sp);
	const char *str = data_security_get_param(storage_policy_get_data_security(ctx->sp), DS_KEY_DISTANCE);
	gint64 req_dst = (NULL != str) ? g_ascii_strtoll(str, NULL, 10) : 1;

	/* init */
	memset(chunks, 0, sizeof(void*) * (ctx->content->nb_chunks + 1));
	for(i = 0; i < ctx->content->nb_chunks; i++)
		chunks[i] = dup_chunk_info_new();
	memset(almost_good, 0, sizeof (GSList*) * (ctx->content->nb_chunks + 1));

	/* get the rawx service list */
	GRID_DEBUG("Ask for the namespace rawx list");

	rawx = list_namespace_services(ctx->ns, "rawx", &local_error);
	if(!rawx) {
		if(local_error) {
			GRID_ERROR("Cannot get rawx list from namespace : %s", local_error->message);
		} else {
			GRID_ERROR("Cannot work, namespace return an empty rawx list");
		}
		goto clean_up;
	}

	GRID_DEBUG("Rawx list ok");


	GRID_DEBUG("Checking content's chunks state");

	for (l = ctx->content->raw_chunks; l && l->data; l = l->next) {
		gchar *loc = NULL;
		gchar *chunk_str= NULL;
		service_info_t *si = NULL;
		meta2_raw_chunk_t *c = (meta2_raw_chunk_t*) l->data;
		chunk_str = meta2_raw_chunk_to_string(c);
		GRID_DEBUG("Checking chunk: %s", chunk_str);

		if(!(si = get_rawx_from_raw_chunk(c, rawx))) {
			/* inconsistent chunk */
			GRID_INFO(MSG_INCONSISTENT_CHUNK, chunk_str);
			if(!ctx->check_only)
				garbage = g_slist_prepend(garbage, c);
			g_free(chunk_str);
			continue;
		}

		/* check chunk availability and integrity */
		GRID_DEBUG("Checking chunk availability and integrity...");
		local_error = download_and_check_chunk(c, ctx->sp);
		if(local_error) {
			/* invalid chunk (corrupted, missing, rawx connection failed */
			GRID_INFO("Chunk %s marked for suppression: %s", chunk_str, local_error->message);
			/* if rawx unreachable, add it to garbage */
			if(local_error->code == 10060 || local_error->code == 10061)
				rawx_garbage = g_slist_prepend(rawx_garbage, si);
			g_clear_error(&local_error);
			if (!ctx->check_only) {
				garbage = g_slist_prepend(garbage, c);
			}
			g_free(chunk_str);
			continue;
		}
		GRID_DEBUG("Chunk available and not corrupted");

		if(!(loc = get_rawx_location(si))) {
			GRID_INFO("Cannot get location of rawx matching %s", chunk_str);
			/* inconsistant chunk */
			if(!ctx->check_only)
				garbage = g_slist_prepend(garbage, c);
			g_free(chunk_str);
			continue;
		}

		/* check chunk storage class */
		if (!service_info_check_storage_class(si, storage_class_get_name(stg_class))) {
			GRID_INFO("Wrong storage class for %s: expected '%s'",
					chunk_str, storage_class_get_name(stg_class));
			/* Add the chunk to the "almost good" list. These
			 * are not corrupted, but should be replaced if possible. */
			almost_good[c->position] = g_slist_prepend(almost_good[c->position], c);
			if (!ctx->check_only) {
				garbage = g_slist_prepend(garbage, c);
			}
			g_free(chunk_str);
			continue;
		} else {
			GRID_DEBUG("Chunk storage class is OK");
		}

		/* Add only if distance is respected with already added chunks */
		if(__test_location(loc, dup_chunk_info_get_used_locations(chunks[c->position]), req_dst)) {
			GRID_DEBUG("Chunk copy is ok and could be added to the valid chunk list.");
			dup_chunk_info_add_chunk(chunks[c->position], c, loc);
		} else {
			/* unwanted chunk */
			GRID_INFO("Chunk %s not compatible with configured duplication, and will be deleted", chunk_str);
			almost_good[c->position] = g_slist_prepend(almost_good[c->position], c);
			if(!ctx->check_only) {
				garbage = g_slist_prepend(garbage, c);
			}
		}
		g_free(chunk_str);
	}

	_adjust_chunk_copies(ctx, rawx, chunks, &garbage, &rawx_garbage, almost_good);

	if(ctx->modified) {
		GRID_DEBUG("Chunks modified, we need to update the content");
		/* send chunk modification to the meta2 */
		if(!meta2raw_remote_update_content(ctx->m2_cnx, &local_error, ctx->content, TRUE)) {
			if(NULL != local_error)
				GRID_DEBUG("Update content request failed (%d): %s", local_error->code, local_error->message);
			/* addition failed, cannot perfom deletion */
			ctx->fail = TRUE;
			goto clean_up;
		}
		GRID_DEBUG("Content modification correctly send to meta2");
	} else {
		GRID_DEBUG("No modification registered");
	}
	if(garbage) {
		GSList *tmp = ctx->content->raw_chunks;
		/* Modify content, set garbage instead of raw_chunks */
		GRID_DEBUG("Garbage of %d chunks to be deleted", g_slist_length(garbage));
		ctx->content->raw_chunks = garbage;

		if(!meta2raw_remote_delete_chunks(ctx->m2_cnx, &local_error, ctx->content)) {
			GRID_DEBUG("Meta2 delete failed");
			ctx->fail = TRUE;
			goto clean_up;
		}
		GRID_DEBUG("Chunk deletion correctly sent to meta2");
		ctx->content->raw_chunks = tmp;
	}

	/* delete unwanted chunks from rawx */
	g_slist_foreach(garbage, _delete_chunk, NULL);

	GRID_DEBUG("Duplicated content checked!");

clean_up:

	for (i = 0; i < ctx->content->nb_chunks; i++) {
		dup_chunk_info_clear(chunks[i]);
		g_slist_free(almost_good[i]);
	}

	if(local_error)
		g_clear_error(&local_error);

	if(rawx_garbage) {
		g_slist_free(rawx_garbage);
	}

	/* Clean the list */
	if (rawx) {
		g_slist_foreach(rawx, service_info_gclean, NULL);
		g_slist_free(rawx);
		rawx = NULL;
	}

	if(garbage) {
		/* chunks inside will be cleaned with the content */
		g_slist_free(garbage);
	}

	return !ctx->fail;
}

static gboolean
_check_rained_content_is_valid(struct meta2_ctx_s *ctx)
{
	(void) ctx;
			
			
	return TRUE;
}

gboolean
check_content_storage_policy(const gchar *namespace, const gchar *container_id, const gchar *content_name,
			gboolean check_only, GError **error)
{
	struct meta2_ctx_s *ctx = get_meta2_ctx(
			namespace, container_id, content_name, check_only, error);

	if (error && *error)
		goto clean_up;

	/* Check data_security is respected */
	switch(data_security_get_type(storage_policy_get_data_security(ctx->sp))) {
	case DUPLI:
		if(!_check_duplicated_content_is_valid(ctx)) {
			GSETERROR(error, "Duplicated content check return in error, content not completly valid");
			goto clean_up;
		}
		break;
	case RAIN:
		if(!_check_rained_content_is_valid(ctx)) {
			GSETERROR(error, "Duplicated content check return in error, content not completly valid");
			goto clean_up;
		}
		break;
	default:
		/* No duplication = duplication with 1 copy and distance of 1 */
		if(!_check_duplicated_content_is_valid(ctx)) {
			GSETERROR(error, "Duplicated content check return in error, content not completly valid");
			goto clean_up;
		}
		break;
	}

clean_up:

	if(ctx)
		content_check_ctx_clear(ctx);

	return error == NULL;
}

gboolean
check_content_info(struct content_textinfo_s *content, GError **p_error)
{
	CHECK_INFO(content->path,			p_error, "Missing mandatory content path");
	CHECK_INFO(content->size,			p_error, "Missing mandatory content size");
	CHECK_INFO(content->chunk_nb,		p_error, "Missing mandatory chunk number");
	CHECK_INFO(content->container_id,	p_error, "Missing mandatory container identifier");
	return TRUE;
}
