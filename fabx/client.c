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

#include "client.h"
#include "common.h"
#include "protocol.h"

/* ------------------------------------------------------------------------- */

enum  oio_fabx_upload_target_state_e
{
	/* Headers to be sent */
	OIO_FABX_UTS_HEADER = 0,
	OIO_FABX_UTS_HEADER_SENT = 1,
	/* Headers sending to be completed */
	OIO_FABX_UTS_BODY = 2,
	OIO_FABX_UTS_BODY_SENT = 3,
	/* Trailing block sending to be completed */
	OIO_FABX_UTS_FINAL_SENT = 4,
	/* Reply to be consumed */
	OIO_FABX_UTS_REPLY = 5,
	/* Sequence terminated */
	OIO_FABX_UTS_DONE = 6,
	OIO_FABX_UTS_FAILED = 7,
};

struct oio_fabx_upload_target_s
{
	enum oio_fabx_upload_target_state_e state;
	struct oio_url_s *url;
	guint32 block_size;
	GBytes *block_in_flight;
	gchar chunk_id[STRLEN_CHUNKID];

	struct fi_info *info;
	struct fid_fabric *fabric;
	struct fid_domain *domain;
	struct fid_ep *endpoint;
	struct fid_cq *cq_tx;
	struct fid_cq *cq_rx;
	struct fid_av *av;
	struct fid_eq *event_queue;
};

struct oio_fabx_upload_s
{
	struct oio_url_s *url;
	GPtrArray *targets;
};

static gboolean
_upload_target_active(struct oio_fabx_upload_target_s *t)
{
	return t->state != OIO_FABX_UTS_FAILED
		&& t->state != OIO_FABX_UTS_DONE;
}

#define SET(Rf,Uf) do { \
    const char *_s = oio_url_get(t->url, Uf); \
    if (_s) \
		g_strlcpy(req->actual.put.Rf, _s, sizeof(req->actual.put.Rf)); \
} while (0)

static void
_upload_target_send_header(struct oio_fabx_upload_target_s *t)
{
	g_assert_nonnull(t);
	g_assert_null(t->block_in_flight);
	g_assert(t->state == OIO_FABX_UTS_HEADER);

	struct fabx_request_header_s *req = valloc(sizeof *req);

	req->version = FABX_VERSION;
	req->type = g_htons(FABX_REP_PUT);
	const char *reqid = oio_ext_get_reqid();
	if (reqid)
		g_strlcpy(req->request_id, reqid, sizeof(req->request_id));

	/* TODO(jfs): authenticate the PUT request */
	memset(req->auth_token, 0, sizeof(req->auth_token));

	req->actual.put.block_size = g_htonl(t->block_size);

	g_strlcpy(req->actual.put.chunk_id,
			t->chunk_id, sizeof(req->actual.put.chunk_id));
	SET(ns_name, OIOURL_NS);
	SET(account_name, OIOURL_ACCOUNT);
	SET(user_name, OIOURL_USER);
	SET(content_id, OIOURL_CONTENTID);
	SET(content_path, OIOURL_PATH);
	SET(content_version, OIOURL_VERSION);

	t->block_in_flight = g_bytes_new_with_free_func(req, sizeof *req, free, req);

	ssize_t sz = fi_send(t->endpoint, req, sizeof(*req),
			NULL,  /* descriptor */
			0,     /* destination address */
			NULL   /* context */);
	g_assert(sz == 0);

	t->state = OIO_FABX_UTS_HEADER_SENT;
}

static void
_upload_target_push(struct oio_fabx_upload_target_s *t, GBytes *block)
{
	g_assert_nonnull(t);
	g_assert(t->state == OIO_FABX_UTS_BODY);
	g_assert_null(t->block_in_flight);

	t->block_in_flight = g_bytes_ref(block);

	gsize len = 0;
	gconstpointer buf = g_bytes_get_data(block, &len);
	ssize_t sz = fi_send(t->endpoint, buf, len,
			NULL,  /* descriptor */
			0,     /* destination address */
			NULL   /* context */);
	g_assert(sz == 0);

	t->state = len ? OIO_FABX_UTS_BODY_SENT : OIO_FABX_UTS_FINAL_SENT;
}

static void
_upload_target_wait(struct oio_fabx_upload_target_s *t)
{
	g_assert(t->state == OIO_FABX_UTS_HEADER_SENT
			|| t->state == OIO_FABX_UTS_BODY_SENT
			|| t->state == OIO_FABX_UTS_FINAL_SENT);

	struct fi_cq_entry cq_entry = {NULL};
	ssize_t sz = fi_cq_sread(t->cq_tx, &cq_entry, 1, NULL, -1);
	g_assert(sz == 1);

	g_bytes_unref(t->block_in_flight);
	t->block_in_flight = NULL;

	switch (t->state) {
		case OIO_FABX_UTS_HEADER_SENT:
		case OIO_FABX_UTS_BODY_SENT:
			t->state = OIO_FABX_UTS_BODY;
			return;
		case OIO_FABX_UTS_FINAL_SENT:
			t->state = OIO_FABX_UTS_REPLY;
			return;
		default:
			g_assert_not_reached();
	}
}

static struct oio_fabx_upload_target_s *
_upload_target_open(const char *to)
{
	int rc;
	struct oio_fabx_upload_target_s *target;

	struct fi_cq_attr cq_attr = {};
	struct fi_av_attr av_attr = {};
	struct fi_eq_attr eq_attr = {};

	gchar **tokens = g_strsplit(to, ":", 2);

	target = g_malloc0(sizeof(*target));
	target->state = OIO_FABX_UTS_HEADER;

	rc = fi_lookup(tokens[0], tokens[1], FALSE, &target->info);
	g_strfreev(tokens);

	g_assert(rc == 0);
	rc = fi_fabric(target->info->fabric_attr, &target->fabric, NULL);
	g_assert(rc == 0);
	rc = fi_domain(target->fabric, target->info, &target->domain, NULL);
	g_assert(rc == 0);
	rc = fi_endpoint(target->domain, target->info, &target->endpoint, NULL);
	g_assert(rc == 0);

	//eq_attr.size = 1;
	eq_attr.wait_obj = FI_WAIT_UNSPEC;
	rc = fi_eq_open(target->fabric, &eq_attr, &target->event_queue, NULL);
	g_assert(rc == 0);
	rc = fi_ep_bind(target->endpoint, &target->event_queue->fid, 0);
	g_assert(rc == 0);

	av_attr.type = target->info->domain_attr->av_type;
	av_attr.count = 1;
	rc = fi_av_open(target->domain, &av_attr, &target->av, 0);
	g_assert(rc == 0);
	rc = fi_ep_bind(target->endpoint, &target->av->fid, 0);
	g_assert(rc == 0);

	cq_attr.wait_obj = FI_WAIT_NONE;
	cq_attr.format = FI_CQ_FORMAT_CONTEXT;
	cq_attr.size = target->info->tx_attr->size;
	rc = fi_cq_open(target->domain, &cq_attr, &target->cq_tx, NULL);
	g_assert(rc == 0);
	rc = fi_ep_bind(target->endpoint, &target->cq_tx->fid, FI_TRANSMIT);
	g_assert(rc == 0);

	cq_attr.wait_obj = FI_WAIT_NONE;
	cq_attr.format = FI_CQ_FORMAT_CONTEXT;
	cq_attr.size = target->info->rx_attr->size;
	rc = fi_cq_open(target->domain, &cq_attr, &target->cq_rx, NULL);
	g_assert(rc == 0);
	rc = fi_ep_bind(target->endpoint, &target->cq_rx->fid, FI_RECV);
	g_assert(rc == 0);

	rc = fi_enable(target->endpoint);
	g_assert(rc == 0);

	rc = fi_connect(target->endpoint, target->info->dest_addr, NULL, 0);
	g_assert(rc == 0);

	// Waiting for the connection establishment
	struct fi_eq_cm_entry entry = {};
	uint32_t evt = 0;
	ssize_t evtlen = fi_eq_sread(target->event_queue,
			&evt, &entry, sizeof(entry), -1, 0);
	g_assert(evtlen != 0);
	g_assert(evt == FI_CONNECTED);
	g_assert(entry.fid == &target->endpoint->fid);

	return target;
}

static void
_upload_target_read_reply(struct oio_fabx_upload_target_s *t)
{
	g_assert_nonnull(t);
	g_assert(t->state == OIO_FABX_UTS_REPLY);

	gsize length = sizeof(struct fabx_reply_header_s);
	guint8 *base = valloc(length);

	/* Post a read command */
	fi_addr_t src_addr = {0};
	ssize_t sz = fi_recv(t->endpoint, base, length, NULL, src_addr, t);
	g_assert(sz == 0);

	/* Wait for the command to complete */
	struct fi_cq_entry cq_entry = {NULL};
	sz = fi_cq_sread(t->cq_rx, &cq_entry, 1, NULL, -1);
	g_assert(sz == 1);

	struct fabx_reply_header_s *rep = (struct fabx_reply_header_s*) base;
	rep->actual.put.status = g_ntohl(rep->actual.put.status);
	t->state = rep->actual.get.status == 200
			? OIO_FABX_UTS_DONE : OIO_FABX_UTS_FAILED;
}

static void
_upload_target_close(struct oio_fabx_upload_target_s *t)
{
	if (t->state != OIO_FABX_UTS_DONE)
		t->state = OIO_FABX_UTS_DONE;
	ssize_t rc = fi_shutdown(t->endpoint, FI_SEND|FI_RECV);
	g_assert(rc == 0);
}

static void
_upload_target_clean(struct oio_fabx_upload_target_s *t)
{
	ssize_t rc;

	rc = fi_close(&t->endpoint->fid);
	g_assert(rc == 0);

	g_free(t);
}

struct oio_fabx_upload_s* oio_fabx_upload_create(
		struct oio_url_s *url)
{
	struct oio_fabx_upload_s *ul = g_malloc0(sizeof *ul);
	ul->url = oio_url_dup(url);
	ul->targets = g_ptr_array_sized_new(8);
	return ul;
}

void oio_fabx_upload_target(
		struct oio_fabx_upload_s *ul,
		const char *host_port,
		const char *chunk_id)
{
	g_assert_nonnull(ul);
	g_assert_nonnull(ul->url);
	g_assert_nonnull(ul->targets);

	struct oio_fabx_upload_target_s *target = _upload_target_open(host_port);
	target->url = oio_url_dup(ul->url);
	g_strlcpy(target->chunk_id, chunk_id, sizeof(target->chunk_id));
	target->block_size = 1024 * 1024;

	g_ptr_array_add(ul->targets, target);
}

void
oio_fabx_upload_push(
		struct oio_fabx_upload_s *ul,
		GBytes *block)
{
	// Lazily send the request headers, then wait for them
	for (guint i = 0; i < ul->targets->len; i++) {
		struct oio_fabx_upload_target_s *t = ul->targets->pdata[i];
		if (!t || !_upload_target_active(t))
			continue;
		if (t->state == OIO_FABX_UTS_HEADER)
			_upload_target_send_header(t);
	}
	for (guint i = 0; i < ul->targets->len; i++) {
		struct oio_fabx_upload_target_s *t = ul->targets->pdata[i];
		if (!t || !_upload_target_active(t))
			continue;
		if (t->state == OIO_FABX_UTS_HEADER_SENT)
			_upload_target_wait(t);
	}

	// Push the block on each target, then wait for the completion
	for (guint i = 0; i < ul->targets->len; i++) {
		struct oio_fabx_upload_target_s *t = ul->targets->pdata[i];
		if (!t || !_upload_target_active(t))
			continue;
		_upload_target_push(t, g_bytes_ref(block));
	}
	for (guint i = 0; i < ul->targets->len; i++) {
		struct oio_fabx_upload_target_s *t = ul->targets->pdata[i];
		if (!t || !_upload_target_active(t))
			continue;
		_upload_target_wait(t);
	}

	g_bytes_unref(block);
}

void
oio_fabx_upload_finalize(
		struct oio_fabx_upload_s *ul)
{
	g_assert_nonnull(ul);
	g_assert_nonnull(ul->targets);

	// Send the final chunk, and wait for the completion
	static guint8 byte = 0;
	GBytes *bfinal = g_bytes_new_static(&byte, 0);
	for (guint i = 0; i < ul->targets->len; i++) {
		struct oio_fabx_upload_target_s *t = ul->targets->pdata[i];
		if (!t || !_upload_target_active(t))
			continue;
		if (t->state == OIO_FABX_UTS_BODY)
			_upload_target_push(t, g_bytes_ref(bfinal));
	}
	for (guint i = 0; i < ul->targets->len; i++) {
		struct oio_fabx_upload_target_s *t = ul->targets->pdata[i];
		if (!t || !_upload_target_active(t))
			continue;
		_upload_target_wait(t);
	}
	g_bytes_unref(bfinal);

	// Wait for the reply
	for (guint i = 0; i < ul->targets->len; i++) {
		struct oio_fabx_upload_target_s *t = ul->targets->pdata[i];
		if (!t || !_upload_target_active(t))
			continue;
		if (t->state == OIO_FABX_UTS_REPLY)
			_upload_target_read_reply(t);
	}
}

void
oio_fabx_upload_close(
		struct oio_fabx_upload_s *ul)
{
	for (guint i = 0; i < ul->targets->len; i++) {
		struct oio_fabx_upload_target_s *t = ul->targets->pdata[i];
		if (t)
			_upload_target_close(t);
	}
	g_ptr_array_set_free_func(ul->targets, (GDestroyNotify) _upload_target_clean);
	g_ptr_array_free(ul->targets, TRUE);
	oio_url_pclean(&ul->url);
	g_free(ul);
}

/* ------------------------------------------------------------------------- */

enum  oio_fabx_download_source_state_e
{
	/* Request to be sent */
	OIO_FABX_DSS_REQUEST = 0,
	/* Reply headers to be read */
	OIO_FABX_DSS_REPLY_HEADER = 2,
	/* Reply payload to be read */
	OIO_FABX_DSS_REPLY_BODY = 2,
	/* Sequence terminated */
	OIO_FABX_DSS_DONE = 3,
	OIO_FABX_DSS_FAILED = 4,
};

struct oio_fabx_download_source_s
{
	enum oio_fabx_download_source_state_e state;
	struct oio_url_s *url;
	guint32 block_size;
	GBytes *block_in_flight;
	gchar chunk_id[STRLEN_CHUNKID];
	guint64 offset;
	guint64 size;

	struct fi_info *info;
	struct fid_fabric *fabric;
	struct fid_domain *domain;
	struct fid_ep *endpoint;
	struct fid_cq *cq_tx;
	struct fid_cq *cq_rx;
	struct fid_av *av;
	struct fid_eq *event_queue;
};

struct oio_fabx_download_s
{
	struct oio_url_s *url;
	GPtrArray *sources;
};

static void
_download_source_close(struct oio_fabx_download_source_s *t)
{
	if (t->state != OIO_FABX_DSS_DONE)
		t->state = OIO_FABX_DSS_DONE;
	ssize_t rc = fi_shutdown(t->endpoint, FI_SEND|FI_RECV);
	g_assert(rc == 0);
}

static void
_download_source_clean(struct oio_fabx_download_source_s *t)
{
	ssize_t rc;
	rc = fi_close(&t->endpoint->fid);
	g_assert(rc == 0);
	g_free(t);
}

static GError *
_download_source_send_header(struct oio_fabx_download_source_s *t)
{
	g_assert_nonnull(t);
	g_assert_null(t->block_in_flight);

	struct fabx_request_header_s *req = valloc(sizeof *req);

	req->version = FABX_VERSION;
	req->type = g_htons(FABX_REP_GET);
	const char *reqid = oio_ext_get_reqid();
	if (reqid)
		g_strlcpy(req->request_id, reqid, sizeof(req->request_id));

	/* TODO(jfs): authenticate the PUT request */
	memset(req->auth_token, 0, sizeof(req->auth_token));

	req->actual.get.block_size = g_htonl(t->block_size);
	req->actual.get.offset = g_htonl(t->offset);
	req->actual.get.size = g_htonl(t->size);

	g_strlcpy(req->actual.get.chunk_id,
			t->chunk_id, sizeof(req->actual.put.chunk_id));

	/* Post a message sending order */
	ssize_t sz;
	sz = fi_send(t->endpoint, req, sizeof(*req),
			NULL,  /* descriptor */
			0,     /* destination address */
			NULL   /* context */);
	g_assert(sz == 0);

	/* Then wait for the completion of the order */
	struct fi_cq_entry cq_entry = {NULL};
	sz = fi_cq_sread(t->cq_tx, &cq_entry, 1, NULL, -1);
	g_assert(sz == 1);

	return NULL;
}

static GError *
_download_source_read_header(struct oio_fabx_download_source_s *t)
{
	g_assert_nonnull(t);
	g_assert_null(t->block_in_flight);

	gsize length = sizeof(struct fabx_reply_header_s);
	guint8 *base = valloc(length);

	/* Post a read command */
	fi_addr_t src_addr = {0};
	ssize_t sz = fi_recv(t->endpoint, base, length, NULL, src_addr, t);
	g_assert(sz == 0);

	/* Wait for the command to complete */
	struct fi_cq_entry cq_entry = {NULL};
	sz = fi_cq_sread(t->cq_rx, &cq_entry, 1, NULL, -1);
	g_assert(sz == 1);

	struct fabx_reply_header_s *rep = (struct fabx_reply_header_s*) base;
	rep->actual.get.status = g_ntohl(rep->actual.get.status);
	g_assert_cmpint(rep->actual.get.status, ==, 200);

	return NULL;
}

static GError *
_download_source_read_payload(struct oio_fabx_download_source_s *t, GBytes **block)
{
	gsize length = t->block_size;
	guint8 *base = valloc(length);
	ssize_t sz;

	/* Post a read command */
	fi_addr_t src_addr = {0};
	sz = fi_recv(t->endpoint, base, length, NULL, src_addr, t);
	g_assert(sz == 0);

	/* Wait for the command to complete */
	struct fi_cq_entry cq_entry = {NULL};
	sz = fi_cq_sread(t->cq_rx, &cq_entry, 1, NULL, -1);
	g_assert(sz == 1);

	guint32 datalen = *((guint32*)base);
	datalen = g_ntohl(datalen);
	/* TODO(jfs): check the input fits in the buffer */
	*block = g_bytes_new_with_free_func(base + 4, datalen, free, base);
	return NULL;
}

static GError *
_download_source_read(struct oio_fabx_download_source_s *s, GBytes **block)
{
	/* Lazily send the request header */
	if (s->state == OIO_FABX_DSS_REQUEST) {
		_download_source_send_header(s);
		s->state = OIO_FABX_DSS_REPLY_HEADER;
	}

	/* Lazily read the reply header */
	if (s->state == OIO_FABX_DSS_REPLY_HEADER) {
		_download_source_read_header(s);
		s->state = OIO_FABX_DSS_REPLY_BODY;
	}

	if (s->state != OIO_FABX_DSS_REPLY_BODY)
		return SYSERR("BUG: stream already consumed");

	GError *err = _download_source_read_payload(s, block);
	if (err != NULL)
		s->state = OIO_FABX_DSS_FAILED;
	else if (g_bytes_get_size(*block) == 0)
		s->state = OIO_FABX_DSS_DONE;
	return err;
}

static struct oio_fabx_download_source_s *
_download_source_open(const char *to)
{
	int rc;
	struct oio_fabx_download_source_s *source;

	struct fi_cq_attr cq_attr = {};
	struct fi_av_attr av_attr = {};
	struct fi_eq_attr eq_attr = {};

	gchar **tokens = g_strsplit(to, ":", 2);

	source = g_malloc0(sizeof(*source));
	source->state = OIO_FABX_DSS_REQUEST;

	rc = fi_lookup(tokens[0], tokens[1], FALSE, &source->info);
	g_strfreev(tokens);

	g_assert(rc == 0);
	rc = fi_fabric(source->info->fabric_attr, &source->fabric, NULL);
	g_assert(rc == 0);
	rc = fi_domain(source->fabric, source->info, &source->domain, NULL);
	g_assert(rc == 0);
	rc = fi_endpoint(source->domain, source->info, &source->endpoint, NULL);
	g_assert(rc == 0);

	//eq_attr.size = 1;
	eq_attr.wait_obj = FI_WAIT_UNSPEC;
	rc = fi_eq_open(source->fabric, &eq_attr, &source->event_queue, NULL);
	g_assert(rc == 0);
	rc = fi_ep_bind(source->endpoint, &source->event_queue->fid, 0);
	g_assert(rc == 0);

	av_attr.type = source->info->domain_attr->av_type;
	av_attr.count = 1;
	rc = fi_av_open(source->domain, &av_attr, &source->av, 0);
	g_assert(rc == 0);
	rc = fi_ep_bind(source->endpoint, &source->av->fid, 0);
	g_assert(rc == 0);

	cq_attr.wait_obj = FI_WAIT_NONE;
	cq_attr.format = FI_CQ_FORMAT_CONTEXT;
	cq_attr.size = source->info->tx_attr->size;
	rc = fi_cq_open(source->domain, &cq_attr, &source->cq_tx, NULL);
	g_assert(rc == 0);
	rc = fi_ep_bind(source->endpoint, &source->cq_tx->fid, FI_TRANSMIT);
	g_assert(rc == 0);

	cq_attr.wait_obj = FI_WAIT_NONE;
	cq_attr.format = FI_CQ_FORMAT_CONTEXT;
	cq_attr.size = source->info->rx_attr->size;
	rc = fi_cq_open(source->domain, &cq_attr, &source->cq_rx, NULL);
	g_assert(rc == 0);
	rc = fi_ep_bind(source->endpoint, &source->cq_rx->fid, FI_RECV);
	g_assert(rc == 0);

	rc = fi_enable(source->endpoint);
	g_assert(rc == 0);

	rc = fi_connect(source->endpoint, source->info->dest_addr, NULL, 0);
	g_assert(rc == 0);

	// Waiting for the connection establishment
	struct fi_eq_cm_entry entry = {};
	uint32_t evt = 0;
	ssize_t evtlen = fi_eq_sread(source->event_queue,
			&evt, &entry, sizeof(entry), -1, 0);
	g_assert(evtlen != 0);
	g_assert(evt == FI_CONNECTED);
	g_assert(entry.fid == &source->endpoint->fid);

	return source;
}

struct oio_fabx_download_s*
oio_fabx_download_create(struct oio_url_s *url)
{
	if (!url || !oio_url_has_fq_path(url))
		return NULL;

	struct oio_fabx_download_s *dl = g_malloc0(sizeof(*dl));
	dl->url = oio_url_dup(url);
	dl->sources = g_ptr_array_sized_new(8);
	return dl;
}

void
oio_fabx_download_close(
		struct oio_fabx_download_s *dl)
{
	for (guint i = 0; i < dl->sources->len; i++) {
		struct oio_fabx_download_source_s *t = dl->sources->pdata[i];
		if (t)
			_download_source_close(t);
	}
	g_ptr_array_set_free_func(dl->sources, (GDestroyNotify) _download_source_clean);
	g_ptr_array_free(dl->sources, TRUE);
	oio_url_pclean(&dl->url);
	g_free(dl);
}

void
oio_fabx_download_source(
		struct oio_fabx_download_s *dl,
		const char *host_port,
		const char *chunk_id,
		guint64 offset,
		guint64 size)
{
	g_assert_nonnull(dl);
	g_assert_nonnull(dl->url);
	g_assert_nonnull(dl->sources);

	struct oio_fabx_download_source_s *src = _download_source_open(host_port);
	src->url = oio_url_dup(dl->url);
	g_strlcpy(src->chunk_id, chunk_id, sizeof(src->chunk_id));
	src->block_size = 1024 * 1024;
	src->offset = offset;
	src->size = size;

	g_ptr_array_add(dl->sources, src);
}

GError*
oio_fabx_download_consume(
		struct oio_fabx_download_s *dl,
		GBytes **block)
{
	g_assert_nonnull(dl);
	g_assert_nonnull(dl->sources);
	g_assert_nonnull(block);
	g_assert(dl->sources->len > 0);

	struct oio_fabx_download_source_s *t = dl->sources->pdata[0];
	return _download_source_read(t, block);
}

