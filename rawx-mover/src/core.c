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

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef  LOG_DOMAIN
# define LOG_DOMAIN "mover.core"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <attr/xattr.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include <metatypes.h>
#include <metautils.h>
#include <metacomm.h>
#include <gridcluster.h>
#include <meta2_remote.h>
#include "../../rawx-lib/src/rawx.h"
#include <grid_client.h>

#include "./mover.h"

#define DOM() g_quark_from_static_string("mover")
#define PREFIX(E) g_prefix_error(&(E), "%s(%d) ", __FUNCTION__, __LINE__)

struct upload_info_s {
	int fd;
	struct stat64 fd_stat;
	gchar *ns_name;
	gchar *path;
	gchar *basename;
	
	/* Destination info */
	const struct service_info_s *dst_rawx;
	gchar dst_path[1024];
	gchar *dst_host;
	gchar *dst_volume;
	gint  dst_port;
	gchar dst_descr[2048];/* handy namespace url */

	/* Source info */
	const struct service_info_s *src_rawx;
	gchar src_path[1024];
	gchar *src_host;
	gchar *src_volume;
	gint  src_port;
	gchar src_descr[2048];/* handy namespace url */
	
	/* Chunk attributes under several forms */
	struct chunk_textinfo_s chunk;
	struct content_textinfo_s content;
	struct meta2_raw_content_s *raw_new;
	struct meta2_raw_content_s *raw_old;
	struct gs_container_location_s *location;

	/* Compression informations to set in request query part */
	gchar *comp;
	gchar *algo;
	gchar *blocksize;
	
	GByteArray *chunk_buffer;
};

static void
_free_raw_chunk_content(struct meta2_raw_chunk_s *chunk)
{
	if (!chunk)
		return;
	if (chunk->metadata)
		g_byte_array_free(chunk->metadata, TRUE);
	memset(chunk, 0x00, sizeof(struct meta2_raw_chunk_s));
}

static gchar*
rawx_get_volume(const struct service_info_s *si)
{
	gchar volname[1024];
	struct service_tag_s *tag;

	if (!si->tags)
		return g_strdup("/");

	tag = service_info_get_tag(si->tags, NAME_TAGNAME_RAWX_VOL);
	if (!tag)
		return g_strdup("/");

	if (!service_tag_get_value_string(tag, volname, sizeof(volname), NULL))
		return g_strdup("/");
	
	return g_strdup(volname);
}

static gchar*
rawx_get_host(const struct service_info_s *si)
{
	gchar *str, str_addr[STRLEN_ADDRINFO];
	
	if (!si)
		return g_strdup("");

	memset(str_addr, 0, sizeof(str_addr));
	addr_info_to_string(&(si->addr), str_addr, sizeof(str_addr));
	str = strrchr(str_addr, ':');
	if (str)
		*str = '\0';
	return g_strdup(str_addr);
}

static gint
rawx_get_port(const struct service_info_s *si)
{
	return htons(si->addr.port);
}

/* ------------------------------------------------------------------------- */

static void
populate_request_headers(ne_request *request, struct upload_info_s *info)
{
	const gchar *ns_name;
	struct chunk_textinfo_s *chunk;
	struct content_textinfo_s *content;

	inline void set_header(const char *n, const char *v) {
		if (v)
			ne_add_request_header(request, n, v);
	}

	ns_name = info->ns_name;
	chunk = &(info->chunk);
	content = &(info->content);
	
	/* add v1.1 headers */
	set_header("chunkid",     chunk->id);
	set_header("chunkhash",   chunk->hash);
	set_header("containerid", content->container_id);
	set_header("contentpath", content->path);
	set_header("contentmetadata",     content->metadata);
	set_header("contentmetadata-sys", content->system_metadata);
	set_header("chunkpos",    chunk->position);
	set_header("chunknb",     content->chunk_nb);
	set_header("chunksize",   chunk->size);
	set_header("contentsize", content->size);

	/* overwrite with v1.4 rawx headers */
	set_header("content_path",         content->path);
	set_header("content_size",         content->size);
	set_header("content_chunksnb",     content->chunk_nb);
	set_header("content_metadata",     content->metadata);
	set_header("content_metadata-sys", content->system_metadata);
	set_header("content_containerid",  content->container_id);

	set_header("chunk_id",          chunk->id);
	set_header("chunk_path",        chunk->path);
	set_header("chunk_size",        chunk->size);
	set_header("chunk_hash",        chunk->hash);
	set_header("chunk_position",    chunk->position);
	set_header("chunk_metadata",    chunk->metadata);
	set_header("chunk_containerid", chunk->container_id);

	set_header("namespace",         ns_name);
}

static gchar *
build_request_uri(struct upload_info_s *info)
{
	return g_strdup_printf("%s?comp=%s&algo=%s&bs=%s", info->dst_path,
			info->comp, info->algo, info->blocksize);
}

static const char *
check_attributes(struct chunk_textinfo_s *chunk, struct content_textinfo_s *content)
{
	if (!chunk->path)
		return "Missing mandatory content path";

	if (!chunk->id)
		return "Missing mandatory chunk ID";

	if (!chunk->size)
		return "Missing mandatory chunk size";

	if (!chunk->hash)
		return "Missing mandatory chunk hash";

	if (!chunk->position)
		return "Missing mandatory chunk position";

	if (!content->path)
		return "Missing mandatory content path";

	if (!content->size)
		return "Missing mandatory content size";

	if (!content->chunk_nb)
		return "Missing mandatory chunk number";

	if (!content->container_id)
		return "Missing mandatory container identifier";
		
	return NULL;
}

static GError *
insert_chunk_in_one_meta2(const char *str_addr, struct meta2_raw_content_s *raw_new)
{
	gboolean m2_rc=FALSE;
	GError *gerr = NULL;
	struct metacnx_ctx_s ctx;

	metacnx_clear(&ctx);
	if (!metacnx_init_with_url(&ctx, str_addr, &gerr)) {
		g_prefix_error(&gerr, "invalid address: ");
		goto label_clean;
	}
	ctx.timeout.cnx = 30000;
	ctx.timeout.req = 60000;

	m2_rc = meta2_remote_container_open(&(ctx.addr), MAX(ctx.timeout.cnx, ctx.timeout.req),
			&gerr, raw_new->container_id);
	if (!m2_rc) {
		g_prefix_error(&gerr, "open failure: ");
		goto label_error;
	}

	m2_rc = meta2raw_remote_update_chunks(&ctx, &gerr, raw_new, TRUE);
	if (!m2_rc) {
		g_prefix_error(&gerr, "insertion failure: ");
		goto label_error;
	}

	meta2_remote_container_close(&(ctx.addr), MAX(ctx.timeout.cnx, ctx.timeout.req), NULL, raw_new->container_id);
	metacnx_close(&ctx);
	metacnx_clear(&ctx);
	return NULL;

label_error:
	meta2_remote_container_close(&(ctx.addr), MAX(ctx.timeout.cnx, ctx.timeout.req), NULL, raw_new->container_id);
label_clean:
	metacnx_close(&ctx);
	metacnx_clear(&ctx);
	return gerr;
}

static GError *
remove_chunk_in_one_meta2(const char *str_addr, struct meta2_raw_content_s *raw_old)
{
	gboolean m2_rc=FALSE;
	GError *gerr = NULL;
	struct metacnx_ctx_s ctx;

	metacnx_clear(&ctx);
	if (!metacnx_init_with_url(&ctx, str_addr, &gerr)) {
		g_prefix_error(&gerr, "invalid address: ");
		goto label_clean;
	}

	ctx.timeout.cnx = 30000;
	ctx.timeout.req = 60000;

	m2_rc = meta2_remote_container_open(&(ctx.addr), MAX(ctx.timeout.cnx, ctx.timeout.req),
			&gerr, raw_old->container_id);
	if (!m2_rc) {
		g_prefix_error(&gerr, "open failure: ");
		goto label_error;
	}

	/* Delete the old chunk */
	m2_rc = meta2raw_remote_delete_chunks(&ctx, &gerr, raw_old);
	if (!m2_rc) {
		g_prefix_error(&gerr, "removal failed: ");
		goto label_error;
	}

	meta2_remote_container_close(&(ctx.addr), MAX(ctx.timeout.cnx, ctx.timeout.req), NULL, raw_old->container_id);
	metacnx_close(&ctx);
	metacnx_clear(&ctx);
	return NULL;

label_error:
	meta2_remote_container_close(&(ctx.addr), MAX(ctx.timeout.cnx, ctx.timeout.req), NULL, raw_old->container_id);
label_clean:
	metacnx_close(&ctx);
	metacnx_clear(&ctx);
	return gerr;
}

static GError *
insert_chunk_in_all_meta2(struct upload_info_s *info,
		gboolean *possible_successes)
{
	gchar **url;
	gboolean rc = TRUE;

	for (url=info->location->m2_url; url && *url ;url++) {
		GError *local_error;

		g_debug("About to insert the new reference in meta2 at [%s]", *url);
		local_error = insert_chunk_in_one_meta2(*url, info->raw_new);
		if (!local_error)
			*possible_successes = TRUE;
		else {
			PREFIX(local_error);
			if (local_error->code == ERRCODE_CONN_TIMEOUT
					|| local_error->code == ERRCODE_CONN_RESET
					|| local_error->code == ERRCODE_CONN_CLOSED)
				*possible_successes = TRUE;
			g_message("Insertion failed in [%s] : code=%d %s", *url, local_error->code, local_error->message);
			rc = FALSE;
		}
	}

	if (!rc)
		return g_error_new(DOM(), 0, "Validation failed");
	return NULL;
}

static GError *
remove_chunk_in_all_meta2(struct upload_info_s *info)
{
	gchar **url;
	gboolean rc = TRUE;

	for (url=info->location->m2_url; url && *url ;url++) {
		GError *local_error;

		g_debug("About to remove the old reference in meta2 at [%s]", *url);
		local_error = remove_chunk_in_one_meta2(*url, info->raw_old);
		if (local_error != NULL) {
			PREFIX(local_error);
			g_message("Removal failed in [%s] : code=%d %s", *url, local_error->code, local_error->message);
			rc = FALSE;
		}
	}

	if (!rc)
		return g_error_new(DOM(), 0, "Validation failed");
	return NULL;
}

static int
ne_reader__md5_computer(void *userdata, const char *buf, size_t len)
{
	if (buf && len)
		g_checksum_update((GChecksum*)userdata, (guint8*)buf, len);
	return 0;
}

static GError *
download_and_check_chunk(struct upload_info_s *info)
{
	GError *rc = NULL;
	GChecksum *checksum;
	ne_session *session;
	ne_request *request;
	const gchar *md5_hash_str;

	g_debug("Downloading the target...");
	checksum = g_checksum_new(G_CHECKSUM_MD5);

	session = ne_session_create("http", rawx_get_host(info->dst_rawx), rawx_get_port(info->dst_rawx));
	ne_set_connect_timeout(session, 60);
	ne_set_read_timeout(session, 60);

	request = ne_request_create(session, "GET", info->dst_path);
	populate_request_headers(request, info);
	ne_add_response_body_reader(request, ne_accept_2xx, ne_reader__md5_computer, checksum);

	switch (ne_request_dispatch(request)) {
		case NE_OK:
			if (ne_get_status(request)->klass != 2)
				rc = g_error_new(DOM(), ne_get_status(request)->code, "Server error : %s", ne_get_error(session));
			else
				g_debug("Download done!");
			break;
		case NE_AUTH:
			rc = g_error_new(DOM(), ne_get_status(request)->code, "Unexpected authentication : %s", ne_get_error(session));
			goto label_exit;
		case NE_CONNECT:
			rc = g_error_new(DOM(), ne_get_status(request)->code, "Connection error : %s", ne_get_error(session));
			goto label_exit;
		case NE_TIMEOUT:
			rc = g_error_new(DOM(), ne_get_status(request)->code, "Connection/Read timeout : %s", ne_get_error(session));
			goto label_exit;
		case NE_ERROR:
			rc = g_error_new(DOM(), ne_get_status(request)->code, "Connection error : %s", ne_get_error(session));
			goto label_exit;
		default:
			rc = g_error_new(DOM(), ne_get_status(request)->code, "Unexpected error : %s", ne_get_error(session));
			goto label_exit;
	}

	if (!rc) {
		g_debug("Checking the MD5 sum...");
		md5_hash_str = g_checksum_get_string(checksum);
		if (!g_ascii_strcasecmp(md5_hash_str, info->chunk.hash))
			g_debug("MD5SUM match with META2!");
		else
			rc = g_error_new(DOM(), 101, "MD5SUM mismatch (%s/%s) src[%s] dst[%s]",
					info->chunk.hash, md5_hash_str, info->src_descr, info->dst_descr);
	}
	
label_exit:
	ne_request_destroy(request);
	ne_session_destroy(session);
	g_checksum_free(checksum);
	return rc;
}

static int
delete_uploaded_chunk(struct upload_info_s *info)
{
	int rc = 0;
	ne_session *session;
	ne_request *request;

	(void) info;

	g_debug("Deleting [%s]", info->dst_descr);

	session = ne_session_create("http", rawx_get_host(info->dst_rawx), rawx_get_port(info->dst_rawx));
	ne_set_connect_timeout(session, 60);
	ne_set_read_timeout(session, 60);

	request = ne_request_create(session, "DELETE", info->dst_path);
	ne_set_request_body_fd(request, info->fd, 0, info->fd_stat.st_size);
	populate_request_headers(request, info);

	switch (ne_request_dispatch(request)) {
		case NE_OK:
			if (ne_get_status(request)->klass == 2) {
				g_debug("Deleted %s", info->dst_descr);
				rc = ~0;
				break;
			}
			g_debug("Server error : %s", ne_get_error(session));
			break;
		case NE_AUTH:
			g_debug("Unexpected authentication : %s", ne_get_error(session));
			break;
		case NE_CONNECT:
			g_debug("Connection error : %s", ne_get_error(session));
			break;
		case NE_TIMEOUT:
			g_debug("Connection/Read timeout : %s", ne_get_error(session));
			break;
		case NE_ERROR:
			g_debug("Connection error : %s", ne_get_error(session));
			break;
		default:
			g_debug("Unexpected error : %s", ne_get_error(session));
			break;

	}

	ne_request_destroy(request);
	ne_session_destroy(session);
	return rc;
}

static GError *
upload_chunk(struct upload_info_s *info)
{
	GError *rc = NULL;
	ne_session *session;
	ne_request *request;

	g_debug("Uploading to the target...");

	session = ne_session_create("http", rawx_get_host(info->dst_rawx), rawx_get_port(info->dst_rawx));
	ne_set_connect_timeout(session, 60);
	ne_set_read_timeout(session, 60);

	if (info->comp && 0 == g_ascii_strcasecmp("true", info->comp)) {
		gchar *uri = NULL;
		uri = build_request_uri(info); 
		request = ne_request_create(session, "PUT", uri);
		if(uri)
			g_free(uri);
	} else 
		request = ne_request_create(session, "PUT", info->dst_path);

	gsize bufsize = 0;
	bufsize = info->chunk_buffer->len;
	ne_set_request_body_buffer(request, ((char *)info->chunk_buffer->data), bufsize);
	populate_request_headers(request, info);

	switch (ne_request_dispatch(request)) {
		case NE_OK:
			if (ne_get_status(request)->klass == 2)
				g_debug("Upload done!");
			else
				rc = g_error_new(DOM(), ne_get_status(request)->code, "Server error : %s", ne_get_error(session));
			break;
		case NE_AUTH:
			rc = g_error_new(DOM(), ne_get_status(request)->code, "Unexpected authentication : %s", ne_get_error(session));
			break;
		case NE_CONNECT:
			rc = g_error_new(DOM(), ne_get_status(request)->code, "Connection error : %s", ne_get_error(session));
			break;
		case NE_TIMEOUT:
			rc = g_error_new(DOM(), ne_get_status(request)->code, "Connection/Read timeout : %s", ne_get_error(session));
			break;
		case NE_ERROR:
			rc = g_error_new(DOM(), ne_get_status(request)->code, "Connection error : %s", ne_get_error(session));
			break;
		default:
			rc = g_error_new(DOM(), ne_get_status(request)->code, "Unexpected error : %s", ne_get_error(session));
			break;

	}

	ne_request_destroy(request);
	ne_session_destroy(session);
	return rc;
}

static int
ne_reader__chunk_computer(void *userdata, const char *buf, size_t len)
{
	if (buf && len)
		g_byte_array_append((GByteArray*)userdata, (guint8*)buf, len);
	return 0;
}

static GError *
download_old_chunk(struct upload_info_s *info)
{
	GError *rc = NULL;
	ne_session *session;
	ne_request *request;

	g_debug("Downloading the full source chunk ...");

	session = ne_session_create("http", rawx_get_host(info->src_rawx), rawx_get_port(info->src_rawx));
	ne_set_connect_timeout(session, 60);
	ne_set_read_timeout(session, 60);

	request = ne_request_create(session, "GET", info->src_path);
	populate_request_headers(request, info);
	ne_add_response_body_reader(request, ne_accept_2xx, ne_reader__chunk_computer, info->chunk_buffer);

	switch (ne_request_dispatch(request)) {
		case NE_OK:
			if (ne_get_status(request)->klass == 2)
				g_debug("Download done!");
			else
				rc = g_error_new(DOM(), ne_get_status(request)->code,
						"RAWX server error (%s)",
						ne_get_status(request)->reason_phrase);
			break;
		case NE_AUTH:
			rc = g_error_new(DOM(), 0, "Unexpected authentication (%s)", ne_get_error(session));
			break;
		case NE_CONNECT:
			rc = g_error_new(DOM(), 0, "Connection error (%s)", ne_get_error(session));
			break;
		case NE_TIMEOUT:
			rc = g_error_new(DOM(), 0, "Connection/Read timeout : %s", ne_get_error(session));
			break;
		case NE_ERROR:
			rc = g_error_new(DOM(), 0, "Connection error : %s", ne_get_error(session));
			break;
		default:
			rc = g_error_new(DOM(), 0, "Unexpected error : %s", ne_get_error(session));
			break;
	}

	ne_request_destroy(request);
	ne_session_destroy(session);
	return rc;
}

static struct meta2_raw_content_s*
load_raw_chunk(struct upload_info_s *info, addr_info_t *addr, const gchar *vol)
{
	GError *gerr = NULL;
	struct meta2_raw_chunk_s raw_chunk;
	struct meta2_raw_content_s *raw_content;

	raw_content = g_malloc0(sizeof(*raw_content));
	memset(&raw_chunk, 0, sizeof(raw_chunk));

	if (!convert_content_text_to_raw(&(info->content), raw_content, &gerr)) {
		g_debug("Invalid content fields : %s", gerror_get_message(gerr));
		g_error_free(gerr);
		goto label_error;
	}
	if (gerr)
		g_clear_error(&gerr);

	if (!convert_chunk_text_to_raw(&(info->chunk), &raw_chunk, &gerr)) {
		g_debug("Invalid chunk fields : %s", gerror_get_message(gerr));
		g_error_free(gerr);
		goto label_error;
	}
	if (gerr)
		g_clear_error(&gerr);

	g_strlcpy(raw_chunk.id.vol, vol, sizeof(raw_chunk.id.vol)-1);
	memcpy(&(raw_chunk.id.addr), addr, sizeof(addr_info_t));

	/* COPY the chunk then destroy the original */
	meta2_maintenance_add_chunk(raw_content, &raw_chunk);
	_free_raw_chunk_content(&raw_chunk);

	return raw_content;

label_error:
	_free_raw_chunk_content(&raw_chunk);
	meta2_maintenance_destroy_content(raw_content);
	return NULL;
}

static void
load_compression(struct upload_info_s *info)
{
#ifndef HAVE_COMPRESSION
	(void) info;
	g_debug("Compression support disabled");
#else
	GError *err = NULL;
	GHashTable *compress_opt = NULL;

	compress_opt = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	if (!get_compression_info_in_attr(info->path, &err, &compress_opt)) {
		g_message("Compression disabled (error) : %s", err->message);
		g_clear_error(&err);
	}
	else {
		gchar *tmp, *compression;
		compression = g_hash_table_lookup(compress_opt, NS_COMPRESSION_OPTION);
		if (compression && !g_ascii_strcasecmp(compression, NS_COMPRESSION_ON)) {

			g_free(info->comp);
			info->comp = g_strdup("true");

			tmp = g_hash_table_lookup(compress_opt, NS_COMPRESS_ALGO_OPTION);
			if (tmp) {
				g_free(info->algo);
				info->algo = g_strdup(tmp);
			}

			tmp = g_hash_table_lookup(compress_opt, NS_COMPRESS_BLOCKSIZE_OPTION);
			if (tmp) {
				g_free(info->blocksize);
				info->blocksize = g_strdup(tmp);
			}
		}
	}

	g_hash_table_destroy(compress_opt);
#endif
}

static GError *
load_chunk(gs_grid_storage_t *gs_client, struct upload_info_s *info,
		const gchar *path,
		struct service_info_s *src_rawx, struct service_info_s *dst_rawx)
{
	GError *err = NULL;
	gs_error_t *gserr;

	memset(info, 0, sizeof(*info));
	info->fd = -1;

	info->chunk_buffer = g_byte_array_new();
	info->ns_name = g_strdup(src_rawx->ns_name);
	info->path = g_strdup(path);
	info->basename = g_path_get_basename(info->path);

	/* Fill the source */
	info->src_rawx = src_rawx;
	info->src_host = rawx_get_host(src_rawx);
	info->src_port = rawx_get_port(src_rawx);
	info->src_volume = rawx_get_volume(src_rawx);
	g_snprintf(info->src_path, sizeof(info->src_path), "%s/%s", info->src_volume, info->basename);
	g_snprintf(info->src_descr, sizeof(info->src_descr), "%s|rawx|%s:%d|%s",
			info->ns_name, info->src_host, info->src_port, info->src_path);

	/* Fill the destination */
	info->dst_rawx = dst_rawx;
	info->dst_host = rawx_get_host(dst_rawx);
	info->dst_port = rawx_get_port(dst_rawx);
	info->dst_volume = rawx_get_volume(dst_rawx);
	g_snprintf(info->dst_path, sizeof(info->dst_path), "%s/%s", info->dst_volume, info->basename);
	g_snprintf(info->dst_descr, sizeof(info->dst_descr), "%s|rawx|%s:%d|%s",
			info->ns_name, info->dst_host, info->dst_port, info->dst_path);

	g_debug("Source [%s]", info->src_descr);
	g_debug("Target [%s]", info->dst_descr);

	/* Ensure the file can be opened */
	info->fd = open(info->path, O_LARGEFILE|O_RDONLY);
	if (info->fd < 0)
		return g_error_new(DOM(), errno, "open/read error (%s) on src[%s]", strerror(errno), info->src_descr);
	fstat64(info->fd, &(info->fd_stat));

	/* Now load the chunk's attributes */
	if (!get_rawx_info_in_attr(info->path, &err, &(info->content), &(info->chunk))) {
		PREFIX(err);
		return err;
	}
	else {
		const char *str_err;
		if (NULL != (str_err = check_attributes(&(info->chunk), &(info->content))))
			return g_error_new(DOM(), 0, "attributes conversion error (%s)", str_err);
	}

	/* Compression purpose */
	info->comp = g_strdup("false");
	info->algo = g_strdup("none");
	info->blocksize = g_strdup("65536");
	load_compression(info);

	if (NULL != (err = download_old_chunk(info))) {
		g_prefix_error(&err, "download failed :");
		return err;
	}

	/* for further META2 request, we will need the raw_content forms of the
	 * source and destination chunk */
	info->raw_old = load_raw_chunk(info, &(src_rawx->addr), info->src_volume);
	info->raw_new = load_raw_chunk(info, &(dst_rawx->addr), info->dst_volume);
	if (!info->raw_old || !info->raw_new)
		return g_error_new(DOM(), 0, "invalid attributes src[%s] dst[%s]", info->src_descr, info->dst_descr);

	/* Check the sizes match between the local chunks stats and its attributes */
	do {
		gint64 chunk_size = -1;
#ifdef HAVE_COMPRESSION
		if (info->comp && 0 == g_ascii_strcasecmp(info->comp, "true")) {
			guint32 size32 = info->fd_stat.st_size;
			guint32 attr_size = 0;
			if(!get_chunk_compressed_size_in_attr(info->path ,&err, &attr_size) || (size32 != attr_size))
				return g_error_new(DOM(), 0, "Local/Meta2 sizes mismatch"
						" (local=%"G_GINT64_FORMAT" xattr=%"G_GINT64_FORMAT") src[%s] dst[%s]",
						info->fd_stat.st_size, chunk_size, info->src_descr, info->dst_descr);
		} else {
#endif
			chunk_size = ((struct meta2_raw_chunk_s*)info->raw_new->raw_chunks->data)->size;
			if (info->fd_stat.st_size != chunk_size)
				return g_error_new(DOM(), 0, "Local/Meta2 sizes mismatch"
						" (local=%"G_GINT64_FORMAT" xattr=%"G_GINT64_FORMAT") src[%s] dst[%s]",
						info->fd_stat.st_size, chunk_size, info->src_descr, info->dst_descr);
#ifdef HAVE_COMPRESSION
		}
#endif
	} while (0);

	gserr = NULL;
	info->location = gs_locate_container_by_hexid(gs_client, info->content.container_id, &gserr);
	if (!info->location || !info->location->m2_url || !info->location->m2_url[0])
		return g_error_new(DOM(), 0, "container not found [%s/%s] (%s)",
				info->ns_name, info->content.container_id, gs_error_get_message(gserr));

	g_debug("Content name [%s/%s/%s]",
			info->ns_name, info->content.container_id, info->content.path);
	g_debug("Container location [%s|meta2|%s]",
			info->ns_name, info->location->m2_url[0]);
	return NULL;
}

static void
free_chunk(struct upload_info_s *info)
{
	if (info->fd >= 0)
		close(info->fd);

	if (info->path)
		g_free(info->path);
	if (info->basename)
		g_free(info->basename);

	if (info->src_host)
		g_free(info->src_host);
	if (info->src_volume)
		g_free(info->src_volume);

	if (info->dst_host)
		g_free(info->dst_host);
	if (info->dst_volume)
		g_free(info->dst_volume);
	
	chunk_textinfo_free_content(&(info->chunk));
	content_textinfo_free_content(&(info->content));
	
	if (info->raw_old)
		meta2_maintenance_destroy_content(info->raw_old);
	if (info->raw_new)
		meta2_maintenance_destroy_content(info->raw_new);

	if (info->location)
		gs_container_location_free(info->location);

	if (info->comp)
		g_free(info->comp);
	if (info->algo)
		g_free(info->algo);
	if (info->blocksize)
		g_free(info->blocksize);

	if (info->chunk_buffer)
		g_byte_array_free(info->chunk_buffer, TRUE);

	memset(info, 0, sizeof(*info));
	info->fd = -1;
}

GError *
move_chunk(gs_grid_storage_t *gs_client,
		const gchar *path,
		struct service_info_s *src_rawx,
		struct service_info_s *dst_rawx,
		guint32 options)
{
	GTimer *timer;
	gboolean flag_unlink, flag_download, flag_fake, flag_dereference;
	struct upload_info_s info;
	GError *rc;
	
	rc = NULL;
	flag_unlink = options & GS_MOVER_UNLINK;
	flag_download = options & GS_MOVER_DOWNLOAD;
	flag_dereference = options & GS_MOVER_DEREFERENCE;
	flag_fake = options & GS_MOVER_DRYRUN;
	timer = g_timer_new();

	if (NULL != (rc = load_chunk(gs_client, &info, path, src_rawx, dst_rawx))) {
		PREFIX(rc);
		goto label_exit;
	}

	if (flag_fake) { /* The flag fake only run and resolve the chunks */
		g_debug("chunk=[%s] resolved", path);
		goto label_exit;
	}

	if (NULL != (rc = upload_chunk(&info))) {
		g_prefix_error(&rc, "upload failed: ");
		goto label_exit;
	}

	if (flag_download && NULL != (rc = download_and_check_chunk(&info))) {
		g_prefix_error(&rc, "download-check failed: ");
		delete_uploaded_chunk(&info);
		goto label_exit;
	}

	/* Try to add the information in all META2 */
	gboolean possible_successes = FALSE;
	if (NULL != (rc = insert_chunk_in_all_meta2(&info, &possible_successes))) {
		g_prefix_error(&rc, "reference insertion failed: ");
		if (!possible_successes)
			delete_uploaded_chunk(&info);
		goto label_exit;
	}

	/* Now remove the local reference */
	if (flag_unlink && flag_dereference) {
		if (NULL != (rc = remove_chunk_in_all_meta2(&info))) {
			g_prefix_error(&rc, "reference ramoval failed: ");
			goto label_exit;
		}
	}

	if (!flag_unlink)
		g_debug("Removal disabled");
	else {
		if (-1 == unlink(path))
			g_message("unlink failed (%d %s)", errno, strerror(errno));
		else
			g_debug("Unlinked %s", path);
	}

label_exit:
	g_debug("Elapsed time: %.03fs", g_timer_elapsed(timer, NULL));
	if (!rc)
		g_message("migration successful src[%s] dst[%s]", info.src_descr, info.dst_descr);
	g_timer_destroy(timer);
	free_chunk(&info);
	return rc;
}

