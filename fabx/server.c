/*
OpenIO SDS fabx
Copyright (C) 2018-2019 CEA "CEA <info@cea.fr>"
Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS

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

#include <fcntl.h>
#include <unistd.h>
#include <sys/xattr.h>

#include <glib.h>
#include <rdma/fabric.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_cm.h>

#include <core/oio_core.h>
#include <metautils/lib/metautils.h>

#include "protocol.h"
#include "common.h"
#include "../rawx-lib/src/rawx.h"

static gboolean config_system = TRUE;
static GSList *config_paths = NULL;
static gchar config_host[256];
static gchar config_port[32];
static gchar config_ns[LIMIT_LENGTH_NSNAME];
static gchar config_basedir[1024];

static GThreadPool *pool_workers = NULL;

/* ------------------------------------------------------------------------- */

static struct fi_info *info = NULL;
static struct fid_fabric *fabric = NULL;
static struct fid_domain *domain = NULL;
static struct fid_eq *event_queue = NULL;
static struct fid_pep *passive_endpoint = NULL;

/* ------------------------------------------------------------------------- */

static gboolean
_getxattr(int fd, const char *k, gchar *out_buf, gsize out_len)
{
	out_buf[out_len-1] = 0;
	gsize size = fgetxattr(fd, k, out_buf, out_len);
	if (size <= 0)
		return FALSE;
	out_buf[size] = 0;
	return TRUE;
}

#define GET(fd,K,R) _getxattr(fd, ATTR_DOMAIN "." K, (R), sizeof(R))

struct active_cnx_context_s
{
	/* Some timers to monitor the service health */
	struct {
		/* The connection event happened */
		gint64 cnx;
		/* The connection enters the queue, waiting for a ready worker */
		gint64 queue;
		/* The request has its own worker */
		gint64 worker;
		/* The request has been managed */
		gint64 done;
		/* The connection has been closed */
		gint64 end;
	} when;

	const char *cmd;
	gint64 bytes_in;
	gint64 bytes_out;
	gint status;
	gchar chunk_id[STRLEN_CHUNKID];
	gchar peer_local[128];
	gchar peer_remote[128];

	struct fid_ep *endpoint;
	struct fid_cq *cq_tx;
	struct fid_cq *cq_rx;
	struct fid_av *av;
	struct fid_eq *eq;
};

/**
 * Return a pointer to a region aligned on a "long", just after the region
 * pointed by the given `s` pointer.
 * @param s
 * @return
 */
static guint8 *
_base(register guint8 *s)
{
	return s + sizeof(long) - ((unsigned long)s % sizeof(long));
}

static guint8 *
_realloc(guint8 **pblob, gsize *plength, gsize minlen)
{
	if (minlen + sizeof(long) > *plength) {
		*plength = minlen;
		*pblob = g_realloc(*pblob, *plength + sizeof(long));
	}
	return _base(*pblob);
}

static gboolean
_prepare_path(const char *chunk_id, GString **path_final, GString **path_temp)
{
	// TODO(jfs): ensure the chunkid is hexa
	if (path_final) {
		*path_final = g_string_new(config_basedir);
		g_string_append_c(*path_final, G_DIR_SEPARATOR);
		// TODO(jfs): use a hashed directory
		g_string_append(*path_final, chunk_id);
		if (path_temp) {
			*path_temp = g_string_new((*path_final)->str);
			g_string_append_static(*path_temp, ".pending");
		}
	}
	return TRUE;
}

static void
_reply_error_get(struct active_cnx_context_s *ctx,
				 guint8 **blob, gsize *length)
{
	gsize _l = sizeof(struct fabx_reply_header_s);
	guint8 *base = _realloc(blob, length, _l);
	memset(base, 0, sizeof(struct fabx_reply_header_s));

	struct fabx_reply_header_s *reply = (struct fabx_reply_header_s*) base;
	reply->version = g_htons(FABX_VERSION);
	reply->type = g_htons(FABX_REP_GET);
	/* TODO(jfs): populate the headers */
	reply->actual.get.status = g_htonl(ctx->status);
	ssize_t sz = fi_send(ctx->endpoint,
						 base, _l,
						 NULL,  /* descriptor */
				         0,     /* destination address */
				         NULL   /* context */);
	g_assert(sz == 0);

	ctx->bytes_out += _l;

	struct fi_cq_entry cq_entry = {NULL};
	sz = fi_cq_sread(ctx->cq_tx, &cq_entry, 1, NULL, -1);
	g_assert(sz == 1);
}

static void
_reply_error_put(struct active_cnx_context_s *ctx,
				 guint8 **blob, gsize *length)
{
	gsize _l = sizeof(struct fabx_reply_header_s);

	guint8 *base = _realloc(blob, length, _l);
	memset(base, 0, _l);

	struct fabx_reply_header_s *reply = (struct fabx_reply_header_s*) base;
	reply->version = g_htons(FABX_VERSION);
	reply->type = g_htons(FABX_REP_PUT);
	reply->actual.put.status = g_htonl(ctx->status);
	ssize_t sz = fi_send(ctx->endpoint,
						 base, _l,
						 NULL,  /* descriptor */
				         0,     /* destination address */
				         NULL   /* context */);
	g_assert(sz == 0);

	ctx->bytes_out += _l;

	struct fi_cq_entry cq_entry = {NULL};
	sz = fi_cq_sread(ctx->cq_tx, &cq_entry, 1, NULL, -1);
	g_assert(sz == 1);
}

static void
_reply_error_del(struct active_cnx_context_s *ctx,
				 guint8 **blob, gsize *length)
{
	gsize _l = sizeof(struct fabx_reply_header_s);
	guint8 *base = _realloc(blob, length, _l);
	memset(base, 0, _l);

	struct fabx_reply_header_s *reply = (struct fabx_reply_header_s*) base;
	reply->version = g_htons(FABX_VERSION);
	reply->type = g_htons(FABX_REP_DEL);
	reply->actual.del.status = g_htonl(ctx->status);
	ssize_t sz = fi_send(ctx->endpoint,
						 base, _l,
						 NULL,  /* descriptor */
				         0,     /* destination address */
				         NULL   /* context */);
	g_assert(sz == 0);

	ctx->bytes_out += _l;

	struct fi_cq_entry cq_entry = {NULL};
	sz = fi_cq_sread(ctx->cq_tx, &cq_entry, 1, NULL, -1);
	g_assert(sz == 1);
}

static int
_manage_put(struct active_cnx_context_s *ctx,
			const struct fabx_request_header_PUT_s *hdr,
			guint8 **blob, gsize *length)
{
	GString *path = NULL, *path_temp = NULL;

	g_strlcpy(ctx->chunk_id, hdr->chunk_id, sizeof(ctx->chunk_id));

	if (!_prepare_path(hdr->chunk_id, &path, &path_temp)) {
		ctx->status = 400;
		_reply_error_put(ctx, blob, length);
		return -1;
	}

	/* Ensure a sufficient buffer to work with */
	guint8 *base = _realloc(blob, length, hdr->block_size);

	int fd = metautils_syscall_open(path_temp->str, 0644, O_CREAT|O_EXCL|O_WRONLY);
	if (fd > 0) {
		gboolean commit = TRUE;
		for (gboolean running = TRUE; running ;) {
			/* read a chunk of data */
			fi_addr_t src_addr = {0};
			ssize_t sz = fi_recv(ctx->endpoint, base, *length, NULL, src_addr, ctx);
			g_assert(sz == 0);
			struct fi_cq_entry cq_entry = {NULL};
			sz = fi_cq_sread(ctx->cq_rx, &cq_entry, 1, NULL, -1);
			g_assert(sz == 1);

			/* An empty chunk mark the end of the sequence */
			const guint32 chunk_size = g_ntohl(*((guint32*)base));
			if (0 == chunk_size) {
				GRID_TRACE("Final block detected");
				break;
			}

			ctx->bytes_in += chunk_size;

			/* A chunk announced longer than the block is illegal */
			if (chunk_size + 4 > *length) {
				GRID_WARN("Chunk (%u) too large (max %lu - 4)", chunk_size, *length);
				commit = FALSE;
				running = FALSE;
				break;
			}

			/* Append the block to the file */
			for (guint32 total = 0; total < chunk_size ;) {
				sz = write(fd, base + 4 + total, chunk_size - total);
				if (sz < 0) {
					commit = FALSE;
					running = FALSE;
					break;
				} else {
					total += sz;
				}
			}
		}

		/* Validate the blob on the persistent media */
		if (commit) {
			rename(path_temp->str, path->str);
		} else {
			unlink(path_temp->str);
		}
		metautils_pclose(&fd);

		/* Emit the reply to the client */
		ctx->status = commit ? 201 : 500;
		_reply_error_put(ctx, blob, length);
	}

	g_string_free(path, TRUE);
	g_string_free(path_temp, TRUE);
	return -1;
}

static int
_manage_del(struct active_cnx_context_s *ctx,
			const struct fabx_request_header_DEL_s *hdr,
			guint8 **blob, gsize *length)
{
	GString *path = NULL;

	g_strlcpy(ctx->chunk_id, hdr->chunk_id, sizeof(ctx->chunk_id));

	if (!_prepare_path(hdr->chunk_id, &path, NULL)) {
		ctx->status = 404;
		_reply_error_del(ctx, NULL, 0);
		return -1;
	}

	// No check necessary unlink will return a error on not found
	if (0 == unlink(path->str)) {
		if (errno == ENOENT) {
			ctx->status = 404;
			_reply_error_del(ctx, blob, length);
		} else {
			ctx->status = 500;
			_reply_error_del(ctx, blob, length);
		}
	} else {
		ctx->status = 204;
		_reply_error_del(ctx, blob, length);
	}

	g_string_free(path, TRUE);
	return -1;
}

static int
_manage_get_body(struct active_cnx_context_s *ctx,
		int fd,
		guint8 **blob, gsize *length,
		guint32 block_size)
{
	guint8 *base = _realloc(blob, length, block_size + 4);

	for (gboolean running = TRUE; running;) {
		ssize_t sz = read(fd, base + 4, block_size);
		guint32 chunk_size = 0;
		if (sz > 0) {
			chunk_size = sz;
		} else if (!sz) {
			running = FALSE;
		} else {
			break;
		}

		*((guint32*)base) = g_htonl(chunk_size);

		sz = fi_send(ctx->endpoint, base, sz + 4, NULL, 0, NULL);
		g_assert(sz == 0);

		ctx->bytes_out += chunk_size;

		struct fi_cq_entry cq_entry = {NULL};
		sz = fi_cq_sread(ctx->cq_tx, &cq_entry, 1, NULL, -1);
		g_assert(sz == 1);
	}

	g_free(base);
	return -1;
}

#define COPY(Dst,Src) \
	g_strlcpy(reply->actual.get.Dst, oio_url_get(url, Src), sizeof(reply->actual.get.Dst))

static int
_manage_get(struct active_cnx_context_s *ctx,
			const struct fabx_request_header_GET_s *hdr,
			guint8 **blob, gsize *length,
			gboolean body)
{
	GString *path = NULL;
	int rc = -1;

	g_strlcpy(ctx->chunk_id, hdr->chunk_id, sizeof(ctx->chunk_id));

	if (!_prepare_path(hdr->chunk_id, &path, NULL)) {
		ctx->status = 400;
		_reply_error_get(ctx, NULL, 0);
		return -1;
	}

	int fd = open(path->str, O_RDONLY);
	if (fd > 0) {
		const gsize block_size = 1024*1024;
		guint8 *base = _realloc(blob, length, sizeof(struct fabx_reply_header_s));
		memset(base, 0, sizeof(struct fabx_reply_header_s));

		struct fabx_reply_header_s *reply = (struct fabx_reply_header_s*) base;
		reply->version = g_htons(FABX_VERSION);
		reply->type = g_htons(FABX_REP_GET);
		reply->actual.get.status = g_htonl(200);
		reply->actual.get.block_size = g_htonl(block_size);

		/* extract and decode the fullpath */
		gchar fullpath[LIMIT_LENGTH_FULLPATH];
		GET(fd, ATTR_NAME_CONTENT_FULLPATH, fullpath);
		struct oio_url_s *url = oio_url_empty();
		oio_url_set(url, OIOURL_NS, config_ns);
		oio_url_set(url, OIOURL_FULLPATH, fullpath);

		COPY(account_name, OIOURL_ACCOUNT);
		COPY(user_name, OIOURL_USER);
		COPY(content_path, OIOURL_PATH);
		COPY(content_id, OIOURL_CONTENTID);
		COPY(content_version, OIOURL_VERSION);

		ctx->status = 200;
		_reply_error_get(ctx, blob, length);
		rc = body ? _manage_get_body(ctx, fd, blob, length, block_size) : 0;
	} else {
		rc = -1;
		if (errno == ENOENT) {
			ctx->status = 404;
			_reply_error_get(ctx, NULL, 0);
		} else {
			ctx->status = 500;
			_reply_error_get(ctx, NULL, 0);
		}
	}

	g_string_free(path, TRUE);
	metautils_pclose(&fd);
	return rc;
}

static void
_access_log(struct active_cnx_context_s *ctx)
{
	const gint64 diff_total = ctx->when.end - ctx->when.cnx;
	const gint64 diff_handler = ctx->when.done - ctx->when.worker;

	GString *gstr = g_string_sized_new(256);

	/* mandatory */
	g_string_append(gstr, ctx->peer_local);
	g_string_append_c(gstr, ' ');
	g_string_append(gstr, ctx->peer_remote);
	g_string_append_c(gstr, ' ');
	g_string_append(gstr, ctx->cmd);
	g_string_append_printf(gstr, " %d %"G_GINT64_FORMAT" %"G_GSIZE_FORMAT" ",
						   ctx->status, diff_total, ctx->bytes_out);
	g_string_append(gstr, "UID");
	g_string_append_c(gstr, ' ');
	g_string_append(gstr, "REQID");

	/* arbitrary */
	g_string_append_c(gstr, ' ');
	g_string_append(gstr, ctx->chunk_id);
	g_string_append_printf(gstr, " t=%"G_GINT64_FORMAT" ", diff_handler);

	INCOMING("%s", gstr->str);
	g_string_free(gstr, TRUE);
}

static void
_worker(gpointer data, gpointer context UNUSED) {
	struct active_cnx_context_s *ctx = data;
	g_assert(ctx != NULL);

	ctx->when.worker = oio_ext_monotonic_time();

	gsize length = sizeof(struct fabx_request_header_s);
	guint8 *blob = g_malloc(length + sizeof(long));
	guint8 *base = _base(blob);

	/* Post a read order for the header, and wait for the completion */
	fi_addr_t src_addr = {0};
	ssize_t sz = fi_recv(ctx->endpoint, base, length, NULL, src_addr, ctx);
	g_assert(sz == 0);
	struct fi_cq_entry cq_entry = {NULL};
	sz = fi_cq_sread(ctx->cq_rx, &cq_entry, 1, NULL, -1);
	g_assert(sz == 1);

	ctx->bytes_in += length;

	int rc = -1;
	struct fabx_request_header_s *hdr = (struct fabx_request_header_s *) base;
	hdr->type = g_ntohl(hdr->type);

	switch (hdr->type) {
		case FABX_REQ_PUT:
			ctx->cmd = "PUT";
			hdr->actual.put.block_size = g_ntohl(hdr->actual.put.block_size);
			rc = _manage_put(ctx, &hdr->actual.put, &blob, &length);
			break;
		case FABX_REQ_DEL:
			ctx->cmd = "DEL";
			rc = _manage_del(ctx, &hdr->actual.del, &blob, &length);
			break;
		case FABX_REQ_GET:
			ctx->cmd = "GET";
			rc = _manage_get(ctx, &hdr->actual.get, &blob, &length, TRUE);
			break;
		case FABX_REQ_HEAD:
			ctx->cmd = "HEAD";
			rc = _manage_get(ctx, &hdr->actual.get, &blob, &length, FALSE);
			break;
	}

	ctx->when.done = oio_ext_monotonic_time();
	g_free(blob);

	if (!rc)
		GRID_WARN("Request error");

	rc = fi_shutdown(ctx->endpoint, FI_RECV|FI_SEND);
	g_assert(rc == 0);

	rc = fi_close(&ctx->endpoint->fid);
	g_assert(rc == 0);

	ctx->when.end = oio_ext_monotonic_time();
	_access_log(ctx);
}

static void
_manage_cnx_event(struct fi_eq_cm_entry *cm_entry)
{
	struct active_cnx_context_s ctx = {};
	guint32 event;
	int rc;
	ssize_t sz;

	GRID_INFO("%s", __FUNCTION__);

	ctx.when.cnx = oio_ext_monotonic_time();
	strcpy(ctx.peer_remote, "-");
	strcpy(ctx.peer_local, "-");
	ctx.cmd = "-";
	ctx.status = 599;

	/* Allocate an new endpoint for the connection */
	if (!cm_entry->info->domain_attr->domain) {
		rc = fi_domain(fabric, cm_entry->info, &domain, NULL);
		g_assert(rc == 0);
	}
	rc = fi_endpoint(domain, cm_entry->info, &ctx.endpoint, NULL);
	g_assert(rc == 0);

	struct fi_eq_attr eq_attr = {};
	eq_attr.size = 1;
	eq_attr.wait_obj = FI_WAIT_UNSPEC;
	rc = fi_eq_open(fabric, &eq_attr, &ctx.eq, NULL);
	g_assert(rc == 0);
	rc = fi_ep_bind(ctx.endpoint, &ctx.eq->fid, 0);
	g_assert(rc == 0);
	//ctx.eq = event_queue;
	//rc = fi_ep_bind(ctx.endpoint, &ctx.eq->fid, 0);
	g_assert(rc == 0);


	struct fi_cq_attr cq_attr = {};
	cq_attr.wait_obj = FI_WAIT_UNSPEC;
	cq_attr.format = FI_CQ_FORMAT_CONTEXT;
	cq_attr.size = info->tx_attr->size;
	rc = fi_cq_open(domain, &cq_attr, &ctx.cq_tx, NULL);
	g_assert(rc == 0);
	rc = fi_ep_bind(ctx.endpoint, &ctx.cq_tx->fid, FI_TRANSMIT);
	g_assert(rc == 0);

	cq_attr.wait_obj = FI_WAIT_UNSPEC;
	cq_attr.format = FI_CQ_FORMAT_CONTEXT;
	cq_attr.size = info->rx_attr->size;
	rc = fi_cq_open(domain, &cq_attr, &ctx.cq_rx, NULL);
	g_assert(rc == 0);
	rc = fi_ep_bind(ctx.endpoint, &ctx.cq_rx->fid, FI_RECV);
	g_assert(rc == 0);


	struct fi_av_attr av_attr = {};
	av_attr.type = info->domain_attr->av_type;
	av_attr.count = 1;
	rc = fi_av_open(domain, &av_attr, &ctx.av, NULL);
	g_assert(rc == 0);

	rc = fi_accept(ctx.endpoint, NULL, 0);
	g_assert(rc == 0);
	rc = fi_enable(ctx.endpoint);
	g_assert(rc == 0);

	GRID_WARN("Polling the connection confirmation");
	struct fi_eq_cm_entry cm_entry1 = {};
	sz = fi_eq_sread(
			ctx.eq, &event,
			&cm_entry1, sizeof(cm_entry1), -1, 0);
	GRID_WARN("Event rc %ld "
			  "event %" G_GINT32_MODIFIER "d/%" G_GINT32_MODIFIER "x",
			  sz, event, event);
	g_assert(event == FI_CONNECTED);

	/* Defer to a worker thread */
	ctx.when.queue = oio_ext_monotonic_time();
	g_thread_pool_push(pool_workers, g_memdup(&ctx, sizeof(ctx)), NULL);
}

static void
_manage_passive_events(void)
{
	struct fi_eq_cm_entry cm_entry = {};
	guint32 event = 0;

	ssize_t sz = fi_eq_sread(event_queue,
			&event, &cm_entry, sizeof(cm_entry), -1, 0);
	GRID_WARN("fi_eq_sread rc %ld "
			"event %" G_GINT32_MODIFIER "d/%" G_GINT32_MODIFIER "x",
			sz, event, event);
	switch (event) {
		case FI_CONNREQ:
			return _manage_cnx_event(&cm_entry);
		default:
			return;
	}
}

static void
_action (void)
{
	while (grid_main_is_running())
		_manage_passive_events();
	GRID_WARN("Exiting");
}

static gboolean
_configure (int argc, char **argv)
{
	if (argc != 3) {
		GRID_ERROR("Missing argument");
		return FALSE;
	} else {
		gchar url[256], *p_colon = NULL;
		g_strlcpy(config_ns, argv[0], sizeof(config_ns));
		g_strlcpy(url, argv[1], sizeof(url));
		g_strlcpy(config_basedir, argv[2], sizeof(config_basedir));
		if (!(p_colon = strrchr(url, ':'))) {
			GRID_ERROR("Malformed URL");
			return FALSE;
		} else {
			*p_colon = 0;
			g_strlcpy(config_host, url, sizeof(config_host));
			g_strlcpy(config_port, p_colon + 1, sizeof(config_port));
		}
	}

	/* Load the env and ensure the NS exists */
	if (!oio_var_value_with_files(config_ns, config_system, config_paths)) {
		GRID_ERROR("NS [%s] unknown in the configuration", config_ns);
		return FALSE;
	}

	/* Prepare the concurrency context */
	GError *err = NULL;
	pool_workers = g_thread_pool_new(_worker, NULL, -1, FALSE, &err);
	if (!pool_workers) {
		GRID_ERROR("ThreadPool creation error: %s", err->message);
		return FALSE;
	}

	/* Prepare the libfabric context */
	int rc;

	rc = fi_lookup(config_host, config_port, TRUE, &info);
	g_assert(rc == 0);
	rc = fi_fabric(info->fabric_attr, &fabric, NULL);
	g_assert(rc == 0);
	rc = fi_domain(fabric, info, &domain, NULL);
	g_assert(rc == 0);
	rc = fi_passive_ep(fabric, info, &passive_endpoint, NULL);
	g_assert(rc == 0);

	struct fi_eq_attr eq_attr = {};
	//eq_attr.size = 1;
	eq_attr.wait_obj = FI_WAIT_UNSPEC;
	rc = fi_eq_open(fabric, &eq_attr, &event_queue, NULL);
	g_assert(rc == 0);
	rc = fi_pep_bind(passive_endpoint, &event_queue->fid, 0);
	g_assert(rc == 0);
	rc = fi_listen(passive_endpoint);
	g_assert(rc == 0);

	GRID_INFO("Passive Endpoint listening - provider:%s domain:%s fabric:%s",
			info->fabric_attr->prov_name,
			info->domain_attr->name,
			info->fabric_attr->name);

	return TRUE;
}

static struct grid_main_option_s *
_get_options (void)
{
	static struct grid_main_option_s options[] = {
		{"SysConfig", OT_BOOL, {.b = &config_system},
			"Load the system configuration and overload the central variables"},

		{"Config", OT_LIST, {.lst = &config_paths},
			"Load the given file and overload the central variables"},

		{NULL, 0, {.i = 0}, NULL}
	};

	return options;
}

static void
_specific_fini (void)
{
	if (pool_workers != NULL) {
		g_thread_pool_free(pool_workers, FALSE, TRUE);
		pool_workers = NULL;
	}
	if (config_paths) {
		g_slist_free_full(config_paths, g_free);
		config_paths = NULL;
	}
}

static void
_set_defaults (void)
{
	config_system = TRUE;
	config_paths = NULL;
	memset(config_host, 0, sizeof(config_host));
	memset(config_port, 0, sizeof(config_port));
	memset(config_ns, 0, sizeof(config_ns));
	pool_workers = NULL;
}

static void _specific_stop (void) {}

static const char * _get_usage (void) { return "IP:PORT NS"; }

static struct grid_main_callbacks main_callbacks =
{
	.options = _get_options,
	.action = _action,
	.set_defaults = _set_defaults,
	.specific_fini = _specific_fini,
	.configure = _configure,
	.usage = _get_usage,
	.specific_stop = _specific_stop,
};

#define dump_size(S) g_printerr("sizeof(" #S ") = %ld\n", sizeof(S))
int
main (int argc, char **argv)
{
	dump_size(struct fabx_request_header_s);
	dump_size(struct fabx_reply_header_s);
	return grid_main (argc, argv, &main_callbacks);
}
