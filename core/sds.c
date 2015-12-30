/*
OpenIO SDS core library
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <glib.h>
#include <json.h>
#include <curl/curl.h>
#include <curl/curlver.h>

#include "oio_core.h"
#include "oio_sds.h"
#include "http_put.h"
#include "http_internals.h"
#include "internals.h"

#include <metautils/lib/metautils.h>

struct oio_sds_s
{
	gchar *session_id;
	gchar *ns;
	gchar *proxy;
	gchar *proxy_local;
	struct {
		int proxy;
		int rawx;
	} timeout;
	gboolean sync_after_download;
	CURL *h;
};

struct oio_error_s;
struct oio_url_s;

static CURL *
_curl_get_handle_proxy (struct oio_sds_s *sds)
{
	CURL *h = _curl_get_handle ();
#if (LIBCURL_VERSION_MAJOR > 7) || ((LIBCURL_VERSION_MAJOR == 7) && (LIBCURL_VERSION_MINOR >= 40))
	if (sds->proxy_local)
		curl_easy_setopt (h, CURLOPT_UNIX_SOCKET_PATH, sds->proxy_local);
#else
	(void) sds;
#endif
	//curl_easy_setopt (h, CURLOPT_FORBID_REUSE, 0L);
	//curl_easy_setopt (h, CURLOPT_FRESH_CONNECT, 0L);
	curl_easy_setopt (h, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
	return h;
}

/* Chunk parsing helpers (JSON) --------------------------------------------- */

struct chunk_s
{
	gsize size;
	struct chunk_position_s {
		guint meta;
		guint intra;
		gboolean ec : 8; /* composite position ? */
		gboolean parity : 8;
	} position;
	gchar hexhash[STRLEN_CHUNKHASH];
	gchar url[1];
};

struct metachunk_s
{
	guint meta;
	/* size of the originl content's segment */
	gsize size;
	/* offset in the original segment */
	gsize offset;
	/* TRUE==rain, FALSE==replication */
	gboolean ec;
	GSList *chunks;
};

static gint
_compare_chunks (const struct chunk_s *c0, const struct chunk_s *c1)
{
	g_assert(c0 != NULL && c1 != NULL);
	int c = CMP(c0->position.meta,c1->position.meta);
	if (c) return c;
	c = CMP(c0->position.intra,c1->position.intra);
	if (c) return c;
	return CMP(c0->position.parity,c1->position.parity);
}

static void
_metachunk_clean (struct metachunk_s *mc)
{
	if (!mc)
		return;
	g_slist_free (mc->chunks);
	g_free (mc);
}

static void
_metachunk_cleanv (struct metachunk_s **tab)
{
	if (!tab)
		return;
	for (struct metachunk_s **p=tab; *p ;++p)
		_metachunk_clean (*p);
	g_free (tab);
}

static struct chunk_s *
_load_one_chunk (struct json_object *jurl, struct json_object *jsize,
		struct json_object *jpos)
{
	const char *s = json_object_get_string(jurl);
	struct chunk_s *result = g_malloc0 (sizeof(struct chunk_s) + strlen(s));
	strcpy (result->url, s);
	result->size = json_object_get_int64(jsize);
	s = json_object_get_string(jpos);
	result->position.meta = atoi(s);
	if (NULL != (s = strchr(s, '.'))) {
		result->position.ec = 1;
		if (*(s+1) == 'p') {
			result->position.parity = 1;
			result->position.intra = atoi(s+2);
		} else {
			result->position.intra = atoi(s+1);
		}
	}
	return result;
}

static const char *
_chunk_pack_position (struct chunk_s *c, gchar *buf, gsize len)
{
	if (c->position.ec)
		g_snprintf (buf, len, "%u.%u%s",
				c->position.meta, c->position.intra,
				c->position.parity ? "p" : "");
	else
		g_snprintf (buf, len, "%u", c->position.meta);
	return buf;
}

static void
_chunks_pack (GString *gs, GSList *chunks)
{
	gchar strpos[32];

	g_string_append (gs, "[");
	for (GSList *l=chunks; l ;l=l->next) {
		struct chunk_s *c = l->data;
		if (gs->str[gs->len - 1] != '[')
			g_string_append_c (gs, ',');
		_chunk_pack_position (c, strpos, sizeof(strpos));
		g_string_append_printf (gs,
				"{\"url\":\"%s\","
				"\"size\":%"G_GINT64_FORMAT","
				"\"pos\":\"%s\","
				"\"hash\":\"%s\"}",
				c->url, c->size, strpos, c->hexhash);
	}
	g_string_append (gs, "]");
}

static GError *
_chunks_load (GSList **out, struct json_object *jtab)
{
	GSList *chunks = NULL;
	GError *err = NULL;

	for (int i=json_object_array_length(jtab); i>0 && !err ;i--) {
		struct json_object *jurl = NULL, *jpos = NULL, *jsize = NULL, *jhash = NULL;
		struct oio_ext_json_mapping_s m[] = {
			{"url",  &jurl,  json_type_string, 1},
			{"pos",  &jpos,  json_type_string, 1},
			{"size", &jsize, json_type_int,    1},
			{"hash", &jhash, json_type_string, 1},
			{NULL,NULL,0,0}
		};
		err = oio_ext_extract_json (json_object_array_get_idx (jtab, i-1), m);
		if (err) continue;

		const char *h = json_object_get_string(jhash);
		if (!oio_str_ishexa(h, 2*sizeof(chunk_hash_t)))
			err = NEWERROR(0, "JSON: invalid chunk hash: not hexa of %"G_GSIZE_FORMAT,
					2*sizeof(chunk_hash_t));
		else {
			struct chunk_s *c = _load_one_chunk (jurl, jsize, jpos);
			g_strlcpy (c->hexhash, h, sizeof(c->hexhash));
			oio_str_upper(c->hexhash);
			chunks = g_slist_prepend (chunks, c);
		}
	}

	if (!err)
		*out = g_slist_reverse (chunks);
	else
		g_slist_free_full (chunks, g_free);
	return err;
}

static guint
_get_meta_bound (GSList *lchunks)
{
	if (!lchunks)
		return 0;
	guint highest_meta = 0;
	for (GSList *l=lchunks; l ;l=l->next) {
		struct chunk_s *c = l->data;
		highest_meta = MAX(highest_meta, c->position.meta);
	}
	return highest_meta + 1;
}

static GError *
_organize_chunks (GSList *lchunks, struct metachunk_s ***result)
{
	*result = NULL;

	if (!lchunks)
		return NEWERROR(CODE_INTERNAL_ERROR, "No chunk received");
	const guint meta_bound = _get_meta_bound (lchunks);

	/* build the metachunk */
	struct metachunk_s **out = g_malloc0 ((meta_bound+1) * sizeof(void*));
	for (guint i=0; i<meta_bound ;++i) {
		out[i] = g_malloc0 (sizeof(struct metachunk_s));
		out[i]->meta = i;
	}
	for (GSList *l=lchunks; l ;l=l->next) {
		struct chunk_s *c = l->data;
		guint i = c->position.meta;
		out[i]->chunks = g_slist_prepend (out[i]->chunks, c);
		if (c->position.ec)
			out[i]->ec = TRUE;
	}
	for (guint i=0; i<meta_bound ;++i) {
		if (!out[i]->chunks || out[i]->ec)
			continue;
		struct chunk_s *first = out[i]->chunks->data;
		for (GSList *l=out[i]->chunks; l ;l=l->next) {
			struct chunk_s *c = l->data;
			if (c->position.intra != first->position.intra)
				out[i]->ec = TRUE;
		}
	}

	/* check the sequence of metachunks has no gap */
	for (guint i=0; i<meta_bound ;++i) {
		if (!out[i]->chunks) {
			_metachunk_cleanv (out);
			return NEWERROR (0, "Invalid chunk sequence: gap found at [%u]", i);
		}
	}

	for (guint i=0; i<meta_bound ;++i) {
		if (out[i]->ec)
			out[i]->chunks = g_slist_sort (out[i]->chunks, (GCompareFunc)_compare_chunks);
		else {
			if (!oio_sds_no_shuffle)
				out[i]->chunks = oio_ext_gslist_shuffle (out[i]->chunks);
		}
	}

	/* Compute each metachunk's size */
	for (guint i=0; i<meta_bound ;++i) {
		if (out[i]->ec) {
			for (GSList *l=out[i]->chunks; l ;l=l->next) {
				if (((struct chunk_s*)(l->data))->position.parity)
					continue;
				out[i]->size += ((struct chunk_s*)(l->data))->size;
			}
		} else {
			out[i]->size = ((struct chunk_s*)(out[i]->chunks->data))->size;
		}
	}

	/* Compute each metachunk's offset in the main content */
	gint64 offset = 0;
	for (guint i=0; i<meta_bound ;++i) {
		out[i]->offset = offset;
		offset += out[i]->size;
	}

	*result = out;
	return NULL;
}

/* Logging helpers ---------------------------------------------------------- */

void
oio_log_to_syslog (void)
{
	oio_log_lazy_init ();
	g_log_set_default_handler(oio_log_syslog, NULL);
}

void
oio_log_to_stderr (void)
{
	oio_log_lazy_init ();
	g_log_set_default_handler (oio_log_stderr, NULL);
}

void
oio_log_more (void)
{
	oio_log_lazy_init ();
	oio_log_verbose_default ();
}

void
oio_log_nothing (void)
{
	oio_log_lazy_init ();
	oio_log_quiet ();
}

/* error management --------------------------------------------------------- */

void
oio_error_free (struct oio_error_s *e)
{
	if (!e) return;
	g_error_free ((GError*)e);
}

void
oio_error_pfree (struct oio_error_s **pe)
{
	if (!pe || !*pe) return;
	oio_error_free (*pe);
	*pe = NULL;
}

int
oio_error_code (const struct oio_error_s *e)
{
	if (!e) return 0;
	return ((GError*)e)->code;
}

const char *
oio_error_message (const struct oio_error_s *e)
{
	if (!e) return "?";
	return ((GError*)e)->message;
}

/* client management -------------------------------------------------------- */

struct oio_error_s *
oio_sds_init (struct oio_sds_s **out, const char *ns)
{
	oio_ext_set_random_reqid ();
	oio_log_lazy_init ();

	g_assert (out != NULL);
	g_assert (ns != NULL);
	*out = SLICE_NEW0 (struct oio_sds_s);
	(*out)->session_id = g_strdup(oio_ext_get_reqid());
	(*out)->ns = g_strdup (ns);
	(*out)->proxy_local = oio_cfg_get_proxylocal (ns);
	(*out)->proxy = oio_cfg_get_proxy_containers (ns);
	(*out)->sync_after_download = TRUE;
	(*out)->h = _curl_get_handle_proxy (*out);
	return NULL;
}

void
oio_sds_free (struct oio_sds_s *sds)
{
	if (!sds) return;
	oio_str_clean (&sds->session_id);
	oio_str_clean (&sds->ns);
	oio_str_clean (&sds->proxy);
	oio_str_clean (&sds->proxy_local);
	if (sds->h)
		curl_easy_cleanup (sds->h);
	SLICE_FREE (struct oio_sds_s, sds);
}

void
oio_sds_pfree (struct oio_sds_s **psds)
{
	if (!psds) return;
	oio_sds_free (*psds);
	*psds = NULL;
}

int
oio_sds_configure (struct oio_sds_s *sds, enum oio_sds_config_e what,
		void *pv, unsigned int vlen)
{
	if (!sds || !pv)
		return EFAULT;
	switch (what) {
		case OIOSDS_CFG_TIMEOUT_PROXY:
			if (vlen != sizeof(int))
				return EINVAL;
			sds->timeout.proxy = *(int*)pv;
			return 0;
		case OIOSDS_CFG_TIMEOUT_RAWX:
			if (vlen != sizeof(int))
				return EINVAL;
			sds->timeout.rawx = *(int*)pv;
			return 0;
		case OIOSDS_CFG_FLAG_SYNCATDOWNLOAD:
			if (vlen != sizeof(int))
				return EINVAL;
			sds->sync_after_download = BOOL(*(int*)pv);
			return 0;
		default:
			return EBADSLT;
	}
}

/* Download ----------------------------------------------------------------- */

struct _download_ctx_s
{
	struct oio_sds_s *sds;
	struct oio_sds_dl_src_s *src;
	struct oio_sds_dl_dst_s *dst;

	struct metachunk_s **metachunks;
	GSList *chunks;
};

static void
_dl_debug (const char *caller, struct oio_sds_dl_src_s *src,
		struct oio_sds_dl_dst_s *dst)
{
	if (!GRID_DEBUG_ENABLED())
		return;
	GString *out = g_string_new("");

	g_string_append_printf (out, "SRC{%s", oio_url_get(src->url, OIOURL_WHOLE));
	if (src->ranges && src->ranges[0]) {
		g_string_append (out, ",[");
		for (struct oio_sds_dl_range_s **p=src->ranges; *p ;++p)
			g_string_append_printf (out,
					"[%"G_GSIZE_FORMAT",%"G_GSIZE_FORMAT"]",
					(*p)->offset, (*p)->size);
		g_string_append (out, "]}");
	}

	g_string_append (out, " -> ");

	if (dst->type == OIO_DL_DST_FILE)
		g_string_append_printf (out, "DST{FILE,%s}", dst->data.file.path);
	else if (dst->type == OIO_DL_DST_BUFFER)
		g_string_append_printf (out, "DST{BUFF,%"G_GSIZE_FORMAT"}", dst->data.buffer.length);
	else
		g_string_append_printf (out, "DST{HOOK,[%p,%p]}", dst->data.hook.cb, dst->data.hook.ctx);

	GRID_DEBUG("%s (%s)", caller, out->str);
	g_string_free (out, TRUE);
}

/* The range is relative to the chunk */
static GError *
_download_range_from_chunk (struct _download_ctx_s *dl,
		const struct oio_sds_dl_range_s *range, struct chunk_s *c0,
		size_t *p_nbread)
{
	size_t _write_wrapper (void *data, size_t s, size_t n, void *ignored) {
		(void) ignored;
		size_t total = s*n;
		/* TODO compute a MD5SUM */
		/* TODO guard against to many bytes received from the rawx */
		if (0 == dl->dst->data.hook.cb (dl->dst->data.hook.ctx, data, total)) {
			GRID_TRACE("user callback managed %"G_GSIZE_FORMAT" bytes", total);
			*p_nbread += total;
			return total;
		} else {
			GRID_WARN("user callback failed");
			return 0;
		}
	}

	GError *err = NULL;
	gchar str_range[64];

	g_snprintf (str_range, sizeof(str_range),
			"bytes=%"G_GSIZE_FORMAT"-%"G_GSIZE_FORMAT,
			range->offset, range->offset + range->size - 1);

	GRID_DEBUG ("%s Range:%s/%"G_GSIZE_FORMAT" %s", __FUNCTION__,
			str_range, c0->size, c0->url);

	CURL *h = _curl_get_handle ();
	struct oio_headers_s headers = {NULL,NULL};
	oio_headers_common (&headers);
	oio_headers_add (&headers, "Range", str_range);
	curl_easy_setopt (h, CURLOPT_HTTPHEADER, headers.headers);
	curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "GET");
	curl_easy_setopt (h, CURLOPT_URL, c0->url);
	curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_wrapper);
	curl_easy_setopt (h, CURLOPT_WRITEDATA, dl->dst->data.hook.ctx);

	CURLcode rc = curl_easy_perform (h);
	if (rc != CURLE_OK) {
		err = NEWERROR(0, "CURL: download error [%s] : (%d) %s", c0->url,
				rc, curl_easy_strerror(rc));
	} else {
		long code = 0;
		rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
		if (2 != (code/100))
			err = NEWERROR(0, "Download: (%ld)", code);
	}

	curl_easy_cleanup (h);
	oio_headers_clear (&headers);
	return err;
}

/* the range is relative to the segment of the metachunk
 * Until there are available chunks, take the next chunk (they are equally
 * capable replicas) and attempt a read. */
static GError *
_download_range_from_metachunk_replicated (struct _download_ctx_s *dl,
		const struct oio_sds_dl_range_s *range, struct metachunk_s *meta)
{
	GRID_DEBUG("%s", __FUNCTION__);
	struct oio_sds_dl_range_s r0 = *range;
	GSList *tail_chunks = meta->chunks;

	while (r0.size > 0) {
		GRID_DEBUG("%s at %"G_GSIZE_FORMAT"+%"G_GSIZE_FORMAT, __FUNCTION__, r0.offset, r0.size);

		if (!tail_chunks)
			return NEWERROR (CODE_PLATFORM_ERROR, "Too many failures");
		struct chunk_s *chunk = tail_chunks->data;
		tail_chunks = tail_chunks->next;

		/* Attempt a read */
		size_t nbread = 0;
		GError *err = _download_range_from_chunk (dl, range, chunk, &nbread);
		g_assert (nbread <= r0.size);
		if (err) {
			/* TODO manage the error kind to allow a retry */
			return err;
		}
		r0.offset += nbread;
		r0.size -= nbread;
	}

	return NULL;
}

static GError *
_download_range_from_metachunk_rained (struct _download_ctx_s *dl,
		struct oio_sds_dl_range_s *range, struct metachunk_s *meta)
{
	GRID_TRACE("%s", __FUNCTION__);
	struct oio_sds_dl_range_s r0 = *range;
	GSList *tail_chunks = meta->chunks;

	while (r0.size > 0) {

		if (!tail_chunks)
			return NEWERROR (CODE_PLATFORM_ERROR, "Range not satisfiable");
		struct chunk_s *chunk = tail_chunks->data;
		tail_chunks = tail_chunks->next;

		gchar strpos[32];
		GRID_TRACE("Range %"G_GSIZE_FORMAT"+%"G_GSIZE_FORMAT
				" CHUNK size=%"G_GSIZE_FORMAT" pos=%s %s",
				r0.offset, r0.size, chunk->size,
				_chunk_pack_position(chunk, strpos, sizeof(strpos)),
				chunk->url);

		if (chunk->position.parity) {
			GRID_TRACE2("Skipped: parity");
			continue;
		}

		if (r0.offset >= chunk->size) {
			GRID_TRACE2("Skipped: out of range");
			r0.offset -= chunk->size;
			continue;
		}

		/* adjust the range to the chunk's boundaries */
		struct oio_sds_dl_range_s r1 = r0;
		r1.size = MIN(r1.size, chunk->size);

		size_t nbread = 0;
		GError *err = _download_range_from_chunk (dl, &r1, chunk, &nbread);
		g_assert (nbread <= r0.size);
		if (err)
			return err;
		r0.size -= nbread;
	}

	return NULL;
}

/* The range is relative to the metachunk, not the whole content */
static GError *
_download_range_from_metachunk (struct _download_ctx_s *dl,
		struct oio_sds_dl_range_s *range, struct metachunk_s *meta)
{
	GRID_TRACE ("%s %"G_GSIZE_FORMAT"+%"G_GSIZE_FORMAT
			" from [%i] ec=%d #=%u %"G_GSIZE_FORMAT"+%"G_GSIZE_FORMAT,
			__FUNCTION__, range->offset, range->size,
			meta->meta, meta->ec, g_slist_length (meta->chunks),
			meta->offset, meta->size);

	g_assert (meta->chunks != NULL);
	g_assert (range->offset < meta->size);
	g_assert (range->size <= meta->size);
	g_assert (range->offset + range->size <= meta->size);

	if (meta->ec)
		return _download_range_from_metachunk_rained (dl, range, meta);
	return _download_range_from_metachunk_replicated (dl, range, meta);
}

/* The range is relative to the whole content */
static GError *
_download_range (struct _download_ctx_s *dl, struct oio_sds_dl_range_s *range)
{
	GRID_TRACE ("%s %"G_GSIZE_FORMAT"+%"G_GSIZE_FORMAT,
			__FUNCTION__, range->offset, range->size);

	struct oio_sds_dl_range_s r0 = *range;

	for (struct metachunk_s **p=dl->metachunks; *p ;++p) {
		if ((r0.offset >= (*p)->offset) && (r0.offset < (*p)->offset + (*p)->size)) {
			struct oio_sds_dl_range_s r1;
			r1.offset = r0.offset - (*p)->offset;
			gsize maxsize = (*p)->size - r1.offset;
			r1.size = MIN(maxsize, r0.size);

			GError *err = _download_range_from_metachunk (dl, &r1, *p);
			if (NULL != err)
				return err;
			r0.offset += r1.size;
			r0.size -= r1.size;
		}
	}

	g_assert (r0.size == 0);
	g_assert (r0.offset == range->offset + range->size);
	return NULL;
}

static GError *
_download (struct _download_ctx_s *dl)
{
	g_assert (dl->dst->type == OIO_DL_DST_HOOK_SEQUENTIAL);
	struct oio_sds_dl_range_s **ranges = dl->src->ranges;
	struct oio_sds_dl_range_s range_auto = {0,0};
	struct oio_sds_dl_range_s *range_autov[2] = {&range_auto, NULL};

	/* Compute the total number of bytes in the content. We will need it for
	 * subsequent checks. */
	size_t total = 0;
	for (struct metachunk_s **p=dl->metachunks; *p ;++p)
		total += (*p)->size;
	GRID_TRACE2("computed size = %"G_GSIZE_FORMAT, total);

	/* validate the ranges do not point out of the content, or ensure at least
	 * a range is none is set. */
	if (dl->src->ranges && dl->src->ranges[0]) {
		for (struct oio_sds_dl_range_s **p=dl->src->ranges; *p ;++p) {
			if ((*p)->offset >= total)
				return NEWERROR (CODE_BAD_REQUEST, "Range not satisfiable");
			if ((*p)->size > total)
				return NEWERROR (CODE_BAD_REQUEST, "Range not satisfiable");
			if ((*p)->offset + (*p)->size > total)
				return NEWERROR (CODE_BAD_REQUEST, "Range not satisfiable");
		}
	} else {
		if (dl->dst->data.hook.length == (size_t)-1) {
			range_auto.size = total;
		} else {
			range_auto.size = MIN(dl->dst->data.hook.length, total);
		}
		dl->src->ranges = range_autov;
	}

	/* Ok, let's download each range sequentially */
	GError *err = NULL;
	for (struct oio_sds_dl_range_s **p=dl->src->ranges; *p ;++p) {
		if (NULL != (err = _download_range (dl, *p)))
			break;
	}

	/* restore the caller's ranges, then cleanup */
	dl->src->ranges = ranges;
	return err;
}

static int
_write_FILE (gpointer ctx, const guint8 *buf, gsize len)
{
	FILE *out = ctx;
	gsize total = 0;
	while (total < len) {
		if (ferror(out))
			return -1;
		size_t w = fwrite (buf, 1, len-total, out);
		total += w;
	}
	return 0;
}

static struct oio_error_s*
_download_to_hook (struct oio_sds_s *sds, struct oio_sds_dl_src_s *src,
		struct oio_sds_dl_dst_s *dst)
{
	g_assert (dst->type == OIO_DL_DST_HOOK_SEQUENTIAL);
	dst->out_size = 0;
	if (!dst->data.hook.cb)
		return (struct oio_error_s*) NEWERROR (CODE_BAD_REQUEST, "Missing callback");
	_dl_debug (__FUNCTION__, src, dst);

	GError *err = NULL;

	GSList *chunks = NULL;
	GString *reply_body = g_string_new("");

	/* Get the beans */
	if (!err)
		err = oio_proxy_call_content_show (sds->h, src->url, reply_body);

	/* Parse the beans */
	if (!err) {
		GRID_TRACE("Body: %s", reply_body->str);
		struct json_tokener *tok = json_tokener_new ();
		struct json_object *jbody = json_tokener_parse_ex (tok,
				reply_body->str, reply_body->len);
		json_tokener_free (tok);
		if (!json_object_is_type(jbody, json_type_array)) {
			err = NEWERROR(0, "Invalid JSON from the OIO proxy");
		} else {
			if (NULL != (err = _chunks_load (&chunks, jbody))) {
				g_prefix_error (&err, "Parsing: ");
			} else {
				GRID_DEBUG("%s Got %u beans", __FUNCTION__, g_slist_length (chunks));
			}
		}
		json_object_put (jbody);
	}

	if (!err) {
		struct _download_ctx_s dl = {
			.sds = sds, .dst = dst, .src = src, .chunks = chunks,
			.metachunks = NULL
		};
		if (!(err = _organize_chunks(chunks, &dl.metachunks))) {
			g_assert (dl.metachunks != NULL);
			err = _download (&dl);
			_metachunk_cleanv (dl.metachunks);
		}
	}

	/* cleanup and exit */
	g_string_free (reply_body, TRUE);
	g_slist_free_full (chunks, g_free);
	return (struct oio_error_s*) err;
}

static struct oio_error_s*
_download_to_file (struct oio_sds_s *sds, struct oio_sds_dl_src_s *src,
		struct oio_sds_dl_dst_s *dst)
{
	int fd = -1;
	FILE *out = NULL;
	struct oio_error_s *err = NULL;

	_dl_debug (__FUNCTION__, src, dst);

	fd = open (dst->data.file.path, O_CREAT|O_EXCL|O_WRONLY, 0644);
	if (fd < 0) {
		err = (struct oio_error_s*) NEWERROR (CODE_INTERNAL_ERROR,
				"open() error: (%d) %s", errno, strerror(errno));
	} else {
		out = fdopen(fd, "a");
		if (out) {
			struct oio_sds_dl_dst_s snk0 = {
				.out_size = 0,
				.type = OIO_DL_DST_HOOK_SEQUENTIAL,
				.data = { .hook = {
					.cb = _write_FILE,
					.ctx = out,
					.length = (size_t)-1,
				} }
			};
			err = _download_to_hook (sds, src, &snk0);
			dst->out_size = snk0.out_size;
			fclose (out);
		}
		if (!err) {
			posix_fadvise (fd, 0, 0, POSIX_FADV_DONTNEED);
			if (sds->sync_after_download)
				fsync(fd);
		}
		close(fd);
	}
	return err;
}

static struct oio_error_s*
_download_to_buffer (struct oio_sds_s *sds, struct oio_sds_dl_src_s *src,
		struct oio_sds_dl_dst_s *dst)
{
	FILE *out = NULL;
	struct oio_error_s *err = NULL;

	_dl_debug (__FUNCTION__, src, dst);

	if (src->ranges != NULL && src->ranges[0] != NULL) {
		/* Validate all the range can fit into the buffer */
		size_t total = 0;
		for (struct oio_sds_dl_range_s **p=src->ranges; *p ;++p)
			total += (*p)->size;
		if (total > dst->data.buffer.length)
			return (struct oio_error_s*) NEWERROR (CODE_BAD_REQUEST,
					"Buffer too small for the specified ranges");
	} else {
		/* No range specified: we need more information to fake a range, e.g.
		 * the first 'dst->data.buffer.length' of the content. */
	}

	out = fmemopen(dst->data.buffer.ptr, dst->data.buffer.length, "w");
	if (!out) {
		err = (struct oio_error_s*) NEWERROR (CODE_INTERNAL_ERROR,
				"fmemopen() error: (%d) %s", errno, strerror(errno));
	} else {
		struct oio_sds_dl_dst_s dst0 = {
			.out_size = 0,
			.type = OIO_DL_DST_HOOK_SEQUENTIAL,
			.data = { .hook = {
				.cb = _write_FILE,
				.ctx = out,
				.length = dst->data.buffer.length,
			} }
		};
		err = _download_to_hook (sds, src, &dst0);
		if (out)
			fclose (out);
		dst->out_size = dst0.out_size;
	}
	return err;
}

struct oio_error_s*
oio_sds_download (struct oio_sds_s *sds, struct oio_sds_dl_src_s *dl,
		struct oio_sds_dl_dst_s *snk)
{
	if (!sds || !dl || !snk || !dl->url)
		return (struct oio_error_s*) BADREQ("Missing argument");
	oio_ext_set_reqid (sds->session_id);

	snk->out_size = 0;

	if (snk->type == OIO_DL_DST_HOOK_SEQUENTIAL)
		return _download_to_hook (sds, dl, snk);
	if (snk->type == OIO_DL_DST_FILE)
		return _download_to_file (sds, dl, snk);
	if (snk->type == OIO_DL_DST_BUFFER)
		return _download_to_buffer (sds, dl, snk);
	return (struct oio_error_s*) NEWERROR (CODE_INTERNAL_ERROR, "Sink type not supported");
}

struct oio_error_s*
oio_sds_download_to_file (struct oio_sds_s *sds, struct oio_url_s *url,
		const char *local)
{
	if (!local)
		return (struct oio_error_s*) BADREQ("Missin local path");
	struct oio_sds_dl_src_s dl = {
		.url = url,
		.ranges = NULL,
	};
	struct oio_sds_dl_dst_s snk = {
		.out_size = 0,
		.type = OIO_DL_DST_FILE,
		.data = { .file = {.path = local}},
	};
	return oio_sds_download (sds, &dl, &snk);
}

/* Upload ------------------------------------------------------------------- */

struct oio_sds_ul_s
{
	gboolean finished;
	gboolean ready_for_data;

	/* set at _init() */
	struct oio_sds_s *sds;
	struct oio_sds_ul_dst_s *dst;
	GChecksum *checksum_content;
	GQueue *buffer_tail;
	GQueue *metachunk_ready;
	GList *metachunk_done;
	GSList *chunks_done;
	GSList *chunks_failed;

	/* set at the first prepare */
	gint64 chunk_size;
	gint64 version;
	gchar *hexid;
	gchar *stgpol;
	gchar *chunk_method;
	gchar *mime_type;

	/* current upload */
	struct metachunk_s *mc;
	GSList *chunks;
	struct http_put_s *put;
	GSList *http_dests;
	size_t local_done;
	GChecksum *checksum_chunk;
};

static void
_assert_no_upload (struct oio_sds_ul_s *ul)
{
	g_assert (NULL != ul);
	g_assert (NULL == ul->mc);
	g_assert (NULL == ul->chunks);
	g_assert (NULL == ul->put);
	g_assert (NULL == ul->http_dests);
	g_assert (NULL == ul->checksum_chunk);
	g_assert (0 == ul->local_done);
}

static void
_sds_upload_reset (struct oio_sds_ul_s *ul)
{
	if (ul->checksum_chunk)
		g_checksum_free (ul->checksum_chunk);
	ul->checksum_chunk = NULL;
	_metachunk_clean (ul->mc);
	ul->mc = NULL;
	g_slist_free (ul->chunks);
	ul->chunks = NULL;
	http_put_destroy (ul->put);
	ul->put = NULL;
	g_slist_free (ul->http_dests);
	ul->http_dests = NULL;
	ul->local_done = 0;
}

struct oio_sds_ul_s *
oio_sds_upload_init (struct oio_sds_s *sds, struct oio_sds_ul_dst_s *dst)
{
	if (!sds || !dst)
		return NULL;
	oio_ext_set_reqid (sds->session_id);

	struct oio_sds_ul_s *ul = g_malloc0 (sizeof(*ul));
	ul->finished = FALSE;
	ul->ready_for_data = TRUE;
	ul->sds = sds;
	ul->dst = dst;
	ul->checksum_content = g_checksum_new (G_CHECKSUM_MD5);
	ul->checksum_chunk = NULL;
	ul->buffer_tail = g_queue_new ();
	ul->metachunk_ready = g_queue_new ();
	return ul;
}

void
oio_sds_upload_clean (struct oio_sds_ul_s *ul)
{
	if (!ul)
		return;

	if (ul->checksum_content)
		g_checksum_free (ul->checksum_content);
	if (ul->buffer_tail)
		g_queue_free (ul->buffer_tail);
	if (ul->metachunk_ready)
		g_queue_free_full (ul->metachunk_ready, (GDestroyNotify)_metachunk_clean);
	g_slist_free_full (ul->chunks_done, g_free);
	g_slist_free_full (ul->chunks_failed, g_free);
	oio_str_clean (&ul->hexid);
	oio_str_clean (&ul->stgpol);
	oio_str_clean (&ul->chunk_method);
	oio_str_clean (&ul->mime_type);
	_sds_upload_reset (ul);

	g_free (ul);
}

int
oio_sds_upload_done (struct oio_sds_ul_s *ul)
{
#ifdef HAVE_EXTRA_DEBUG
	g_assert (ul != NULL);
	if (ul->finished)
		_assert_no_upload (ul);
#endif
	return !ul || ul->finished;
}

int
oio_sds_upload_greedy (struct oio_sds_ul_s *ul)
{
	return NULL != ul && !ul->finished && ul->ready_for_data;
}

struct oio_error_s *
oio_sds_upload_prepare (struct oio_sds_ul_s *ul, size_t size)
{
	g_assert (ul != NULL);

	GError *err = NULL;
	GString *request_body = g_string_new("");
	GString *reply_body = g_string_new ("");

	/* get the beans from the proxy, for the size announced.
	 * The reply will only carry the official chunk_size and
	 * some places. */
	do {
		struct oio_proxy_content_prepare_out_s out = {
			.body = reply_body,
			.header_chunk_size = NULL,
			.header_version = NULL,
			.header_content = NULL,
			.header_stgpol = NULL,
			.header_chunk_method = NULL,
			.header_mime_type = NULL,
		};
		err = oio_proxy_call_content_prepare (ul->sds->h, ul->dst->url,
				size, ul->dst->autocreate, &out);
		if (err)
			g_prefix_error (&err, "Proxy: ");
		else {
			if (out.header_chunk_size && !ul->chunk_size)
				ul->chunk_size = g_ascii_strtoll (out.header_chunk_size, NULL, 10);
			if (out.header_version && !ul->version)
				ul->version = g_ascii_strtoll (out.header_version, NULL, 10);
			if (out.header_content)
				oio_str_replace (&ul->hexid, out.header_content);
			if (out.header_stgpol)
				oio_str_replace (&ul->stgpol, out.header_stgpol);
			if (out.header_chunk_method)
				oio_str_replace (&ul->chunk_method, out.header_chunk_method);
			if (out.header_mime_type)
				oio_str_replace (&ul->mime_type, out.header_mime_type);
		}
		oio_str_clean (&out.header_chunk_size);
		oio_str_clean (&out.header_version);
		oio_str_clean (&out.header_content);
		oio_str_clean (&out.header_stgpol);
		oio_str_clean (&out.header_chunk_method);
		oio_str_clean (&out.header_mime_type);
	} while (0);

	/* Parse the output, as a JSON array of objects with fields
	 * depicting chunks */
	if (!err) {
		struct json_tokener *tok = json_tokener_new ();
		struct json_object *jbody = json_tokener_parse_ex (tok,
				reply_body->str, reply_body->len);
		if (!json_object_is_type(jbody, json_type_array))
			err = NEWERROR(0, "Invalid JSON from the OIO proxy");
		else if (NULL != (err = _chunks_load (&ul->chunks, jbody)))
			g_prefix_error (&err, "Parsing: ");
		json_object_put (jbody);
		json_tokener_free (tok);
	}

	/* prepare the set of chunks to detect replication or erasure coding. */
	if (!err) {
		struct metachunk_s **out = NULL;
		ul->chunks = g_slist_sort (ul->chunks, (GCompareFunc)_compare_chunks);
		if (NULL != (err = _organize_chunks (ul->chunks, &out)))
			g_prefix_error (&err, "Logic: ");
		else for (struct metachunk_s **p=out; *p ;++p)
			g_queue_push_tail (ul->metachunk_ready, *p);
		if (out)
			g_free(out);
	}

	/* some values can be guessed if the proxy didn't reply */
	if (!err) {
#define LAZYSET(R,V) do { if (!R) R = g_strdup(V); } while (0)
		if (!ul->version) ul->version = oio_ext_real_time();
		LAZYSET(ul->hexid, "0000");
		LAZYSET(ul->stgpol, OIO_DEFAULT_STGPOL);
		LAZYSET(ul->chunk_method, OIO_DEFAULT_CHUNKMETHOD);
		LAZYSET(ul->mime_type, OIO_DEFAULT_MIMETYPE);
#undef LAZYSET
	}

	g_string_free (request_body, TRUE);
	g_string_free (reply_body, TRUE);
	return (struct oio_error_s*) err;
}

struct oio_error_s *
oio_sds_upload_feed (struct oio_sds_ul_s *ul,
		const unsigned char *buf, size_t len)
{
	GRID_TRACE("%s (%p) <- %"G_GSIZE_FORMAT, __FUNCTION__, ul, len);
	g_assert (ul != NULL);
	g_assert (!ul->finished);
	g_assert (ul->ready_for_data);
	g_queue_push_tail (ul->buffer_tail, g_bytes_new (buf, len));
	if (!len)
		ul->ready_for_data = FALSE;
	return NULL;
}

static GError *
_sds_upload_finish (struct oio_sds_ul_s *ul)
{
	GRID_TRACE("%s (%p)", __FUNCTION__, ul);
	g_assert (ul->mc != NULL);
	GError *err = NULL;

	guint failures = http_put_get_failure_number (ul->put);
	guint total = g_slist_length (ul->http_dests);
	GRID_TRACE("%s uploads %u/%u failed", __FUNCTION__, failures, total);

	if (failures >= total) {
		err = NEWERROR(CODE_PLATFORM_ERROR, "No upload succeeded");
	} else {
		/* patch the chunk sizes and positions */
		ul->mc->size = ul->local_done;
		for (GSList *l=ul->mc->chunks; l ;l=l->next) {
			struct chunk_s *c = l->data;
			c->size = ul->mc->size;
			g_assert (c->position.meta == ul->mc->meta);
		}

		if (ul->checksum_chunk) {
			const char *h = g_checksum_get_string (ul->checksum_chunk);
			for (GSList *l=ul->mc->chunks; l ;l=l->next) {
				struct chunk_s *c = l->data;
				g_strlcpy (c->hexhash, h, sizeof(c->hexhash));
				oio_str_upper (c->hexhash);
			}
		}

		/* store the structure in holders for further commit/abort */
		ul->chunks_done = g_slist_concat (ul->chunks_done, ul->chunks);
		GRID_TRACE("%s > chunks +%u -> %u", __FUNCTION__,
				g_slist_length(ul->chunks),
				g_slist_length(ul->chunks_done));

		ul->metachunk_done = g_list_append (ul->metachunk_done, ul->mc);
		GRID_TRACE("%s > metachunks +1 -> %u (%"G_GINT64_FORMAT")", __FUNCTION__,
				g_list_length(ul->metachunk_done),
				ul->mc->size);
		ul->mc = NULL;
		ul->chunks = NULL;
	}

	_sds_upload_reset (ul);
	return err;
}

static GError *
_sds_upload_renew (struct oio_sds_ul_s *ul)
{
	GRID_TRACE("%s (%p)", __FUNCTION__, ul);

	struct oio_error_s *err = NULL;

	g_assert (NULL == ul->put);
	g_assert (NULL == ul->http_dests);
	g_assert (NULL == ul->checksum_chunk);

	/* ensure we have a new destination (metachunk) */
	if (!ul->mc) {
		if (g_queue_is_empty (ul->metachunk_ready)) {
			if (NULL != (err = oio_sds_upload_prepare (ul, 1)))
				return (GError*) err;
		}
		ul->mc = g_queue_pop_head (ul->metachunk_ready);
	}
	g_assert (NULL != ul->mc);

	/* patch the metachunk characteristics (position now known) */
	if (ul->metachunk_done) {
		struct metachunk_s *last = (g_list_last (ul->metachunk_done))->data;
		ul->mc->offset = last->offset + last->size;
		ul->mc->meta = last->meta + 1;
	} else {
		ul->mc->offset = 0;
		ul->mc->meta = 0;
	}
	/* then patch each chunk with the same meta-position */
	for (GSList *l=ul->mc->chunks; l ;l=l->next) {
		struct chunk_s *c = l->data;
		c->position.meta = ul->mc->meta;
	}

	/* Initiate the PolyPut (c) with all its targets */
	ul->put = http_put_create (-1, ul->chunk_size);
	for (GSList *l=ul->mc->chunks; l ;l=l->next) {
		struct chunk_s *c = l->data;
		struct http_put_dest_s *dest = http_put_add_dest (ul->put, c->url, c);

		http_put_dest_add_header (dest, PROXYD_HEADER_REQID,
				"%s", oio_ext_get_reqid());

		http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "container-id",
				"%s", oio_url_get (ul->dst->url, OIOURL_HEXID));

		gchar *escaped = g_uri_escape_string (oio_url_get (
					ul->dst->url, OIOURL_PATH), NULL, TRUE);
		http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "content-path",
				"%s", escaped);
		g_free (escaped);

		http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "content-version",
				"%" G_GINT64_FORMAT, ul->version);
		http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "content-id",
				"%s", ul->hexid);

		http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "content-storage-policy",
				"%s", ul->stgpol);
		http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "content-chunk-method",
				"%s", ul->chunk_method);
		http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "content-mime-type",
				"%s", ul->mime_type);

		http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "chunk-id",
				"%s", strrchr(c->url, '/')+1);

		gchar strpos[32];
		_chunk_pack_position (c, strpos, sizeof(strpos));
		http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "chunk-pos",
				"%s", strpos);

		ul->http_dests = g_slist_append (ul->http_dests, dest);
	}

	ul->checksum_chunk = g_checksum_new (G_CHECKSUM_MD5);
	GRID_TRACE("%s (%p) upload ready!", __FUNCTION__, ul);
	return NULL;
}

struct oio_error_s *
oio_sds_upload_step (struct oio_sds_ul_s *ul)
{
	static const char *end = "";
	GRID_TRACE("%s (%p)", __FUNCTION__, ul);
	g_assert (ul != NULL);

	if (ul->finished) {
		GRID_TRACE("%s (%p) finished!", __FUNCTION__, ul);
		return NULL;
	}

	if (ul->put) {
		/* maybe finish the previous upload */
		gsize max = http_put_expected_bytes (ul->put);
		GRID_TRACE("%s (%p) upload running, expecting %"G_GSIZE_FORMAT" bytes",
				__FUNCTION__, ul, max);
		if (0 == max) {
			GError *err;
			while (!http_put_done(ul->put)) {
				http_put_feed (ul->put, g_bytes_new_static (end, 0));
				if (NULL != (err = http_put_step (ul->put)))
					return (struct oio_error_s*) err;
			}
			if (NULL != (err = _sds_upload_finish (ul)))
				return (struct oio_error_s*) err;
			_assert_no_upload (ul);
			return NULL;
		}
	} else {
		/* No upload running ... */
		g_assert (NULL == ul->http_dests);
		g_assert (NULL == ul->checksum_chunk);
		g_assert (0 == ul->local_done);

		/* Check if we need to start a new one */
		GRID_TRACE("%s (%p) No upload currently running", __FUNCTION__, ul);
		if (g_queue_is_empty (ul->buffer_tail)) {
			/* no need to start an upload now */
			if (!ul->ready_for_data) {
				GRID_TRACE("%s (%p) not expecting data anymore, finishing", __FUNCTION__, ul);
				ul->finished = TRUE;
			} else {
				GRID_TRACE("%s (%p) No data pending, nothing to do", __FUNCTION__, ul);
			}
			return NULL;
		} else {
			/* maybe we received the termination buffer */
			GBytes *buf = g_queue_pop_head (ul->buffer_tail);
			if (0 >= g_bytes_get_size (buf)) {
				ul->ready_for_data = FALSE;
				ul->finished = TRUE;
				g_bytes_unref (buf);
				return NULL;
			} else {
				g_queue_push_head (ul->buffer_tail, buf);
			}
		}

		/* We have all the clues it is necessary to kick a new upload off */
		GError *err = _sds_upload_renew (ul);
		if (NULL != err) {
			GRID_TRACE("%s (%p) Failed to renew the upload", __FUNCTION__, ul);
			return (struct oio_error_s*) err;
		}
	}

	g_assert (ul->put != NULL);
	g_assert (0 != http_put_expected_bytes (ul->put));

	/* An upload is really running, maybe feed it */
	if (!g_queue_is_empty (ul->buffer_tail)) {
		GRID_TRACE("%s (%p) Data ready!", __FUNCTION__, ul);
		GBytes *buf = g_queue_pop_head (ul->buffer_tail);

		gsize len = g_bytes_get_size (buf);
		gsize max = http_put_expected_bytes (ul->put);
		g_assert (max != 0);

		/* the upload still wants to more bytes */
		if (!len) {
			GRID_TRACE("%s (%p) tail buffer", __FUNCTION__, ul);
			g_assert (FALSE == ul->ready_for_data);
		} else if (max > 0 && len > max) {
			GRID_TRACE("%s (%p) %"G_GSIZE_FORMAT" accepted at most", __FUNCTION__, ul, max);
			GBytes *first = g_bytes_new_from_bytes (buf, 0, max);
			GBytes *second = g_bytes_new_from_bytes (buf, max, len-max);
			g_queue_push_head (ul->buffer_tail, second);
			g_bytes_unref (buf);
			buf = first;
		} else {
			GRID_TRACE("%s (%p) %"G_GSIZE_FORMAT" pushed at once", __FUNCTION__, ul, len);
		}

		/* Update local counters and checksums */
		gsize l = 0;
		const void *b = g_bytes_get_data (buf, &l);
		if (l) {
			if (ul->checksum_chunk)
				g_checksum_update (ul->checksum_chunk, b, l);
			g_checksum_update (ul->checksum_content, b, l);
			ul->local_done += l;
		}

		/* then feed the upload with the chunk of data */
		http_put_feed (ul->put, buf);
	}

	/* Now do the I/O things */
	GError *err = http_put_step (ul->put);
	if (NULL != err)
		return (struct oio_error_s*) err;

	return NULL;
}

static void
_chunks_remove (CURL *h, GSList *chunks)
{
	(void) h, (void) chunks;
	/* TODO JFS */
}

struct oio_error_s *
oio_sds_upload_commit (struct oio_sds_ul_s *ul)
{
	GRID_TRACE("%s (%p)", __FUNCTION__, ul);
	g_assert (ul != NULL);

	if (ul->put && !http_put_done (ul->put))
		return (struct oio_error_s *) SYSERR("RAWX upload not completed");

	gint64 size = 0;
	for (GList *l=g_list_first(ul->metachunk_done); l ;l=g_list_next(l))
		size += ((struct metachunk_s*) l->data)->size;

	GString *request_body = g_string_new("");
	GString *reply_body = g_string_new ("");
	_chunks_pack (request_body, ul->chunks_done);

	gchar hash[STRLEN_CHUNKHASH];
	g_strlcpy (hash, g_checksum_get_string (ul->checksum_content), sizeof(hash));
	oio_str_upper (hash);
	struct oio_proxy_content_create_in_s in = {
		.size = size,
		.version = ul->version,
		.content = ul->hexid,
		.chunks = request_body,
		.hash = hash,
	};

	GRID_TRACE("%s (%p) Saving %s", __FUNCTION__, ul, request_body->str);
	GError *err = oio_proxy_call_content_create (ul->sds->h, ul->dst->url,
			&in, reply_body);

	if (ul->chunks_failed)
		_chunks_remove (ul->sds->h, ul->chunks_failed);

	g_string_free (request_body, TRUE);
	g_string_free (reply_body, TRUE);
	return (struct oio_error_s*) err;
}

struct oio_error_s *
oio_sds_upload_abort (struct oio_sds_ul_s *ul)
{
	GRID_TRACE("%s (%p)", __FUNCTION__, ul);
	g_assert (ul != NULL);
	if (ul->chunks_failed)
		_chunks_remove (ul->sds->h, ul->chunks_failed);
	return (struct oio_error_s *) NEWERROR(CODE_NOT_IMPLEMENTED, "NYI");
}

static void
_ul_debug (const char *caller, struct oio_sds_ul_src_s *src,
		struct oio_sds_ul_dst_s *dst)
{
	if (!GRID_DEBUG_ENABLED())
		return;
	GString *out = g_string_new("");

	if (src->type == OIO_UL_SRC_HOOK_SEQUENTIAL)
		g_string_append_printf (out, "SRC{HOOK,%p}", src->data.hook.cb);
	else
		g_string_append_printf (out, "SRC{XXX,%d}", src->type);

	g_string_append_printf (out, " -> DST{%s,%d}", oio_url_get(dst->url, OIOURL_WHOLE), dst->autocreate);

	GRID_DEBUG ("%s (%s)", caller, out->str);
	g_string_free (out, TRUE);
}

static GError *
_upload_sequential (struct oio_sds_s *sds, struct oio_sds_ul_dst_s *dst,
		struct oio_sds_ul_src_s *src)
{
	_ul_debug(__FUNCTION__, src, dst);
	if (!src->data.hook.cb)
		return BADREQ("Missing hook");

	struct oio_sds_ul_s *ul = oio_sds_upload_init (sds, dst);
	if (!ul)
		return SYSERR("Resource allocation failure");

	struct oio_error_s *err = NULL;

	/* If a size is specified, then prepare enough chunks.
	 * Specifying no size, then preparing no chunks, will require to
	 * call the proxy as soon as a new chunk is necessary, then issuing
	 * several calls to the proxy. */
	if (src->data.hook.size > 0 && src->data.hook.size != (size_t)-1)
		err = oio_sds_upload_prepare (ul, src->data.hook.size);

	while (!err && !oio_sds_upload_done (ul)) {
		GRID_TRACE("%s (%p) not done yet", __FUNCTION__, ul);

		/* feed the upload queue */
		if (oio_sds_upload_greedy (ul)) {
			GRID_TRACE("%s (%p) greedy!", __FUNCTION__, ul);
			guint8 b[8192];
			size_t l = src->data.hook.cb (src->data.hook.ctx, b, sizeof(b));
			switch (l) {
				case OIO_SDS_UL__ERROR:
					err = (struct oio_error_s*) SYSERR("data hook error");
					break;
				case OIO_SDS_UL__DONE:
					err = oio_sds_upload_feed (ul, b, 0);
					break;
				case OIO_SDS_UL__NODATA:
					GRID_INFO("%s No data ready from user's hook", __FUNCTION__);
					break;
				default:
					err = oio_sds_upload_feed (ul, b, l);
					break;
			}
		}

		/* do the I/O things */
		if (!err)
			err = oio_sds_upload_step (ul);
	}

	if (!err)
		err = oio_sds_upload_commit (ul);
	else {
		struct oio_error_s *e = oio_sds_upload_abort (ul);
		if (e) {
			GRID_WARN("Upload abort failed: (%d) %s",
					oio_error_code (e), oio_error_message (e));
			oio_error_free (e);
		}
	}

	oio_sds_upload_clean (ul);
	return (GError*) err;
}

struct oio_error_s*
oio_sds_upload (struct oio_sds_s *sds, struct oio_sds_ul_src_s *src,
		struct oio_sds_ul_dst_s *dst)
{
	if (!sds || !src || !dst)
		return (struct oio_error_s*) BADREQ("Missing parameter");

	if (src->type == OIO_UL_SRC_HOOK_SEQUENTIAL)
		return (struct oio_error_s*) _upload_sequential (sds, dst, src);

	return (struct oio_error_s*) NEWERROR(0, "Invalid argument: %s",
			"source type not managed");
}

static size_t
_read_FILE (void *u, unsigned char *ptr, size_t len)
{
	FILE *in = u;
	GRID_TRACE("Reading at most %"G_GSIZE_FORMAT, len);
	if (ferror(in))
		return OIO_SDS_UL__ERROR;
	if (feof(in))
		return OIO_SDS_UL__DONE;
	size_t r = fread(ptr, 1, len, in);
	return (r == 0) ? OIO_SDS_UL__NODATA : r;
}

struct oio_error_s*
oio_sds_upload_from_file (struct oio_sds_s *sds, struct oio_sds_ul_dst_s *dst,
		const char *local, size_t off, size_t len)
{
	if (!sds || !dst || !local)
		return (struct oio_error_s*) BADREQ("Invalid argument");

	int fd = -1;
	FILE *in = NULL;
	GError *err = NULL;
	struct stat st;

	if (0 > (fd = open (local, O_RDONLY, 0644)))
		err = SYSERR("open() error: (%d) %s", errno, strerror(errno));
	else if (0 > fstat (fd, &st))
		err = SYSERR("fstat() error: (%d) %s", errno, strerror(errno));
	else if (!(in = fdopen(fd, "r")))
		err = SYSERR("fdopen() error: (%d) %s", errno, strerror(errno));
	else {
		lseek (fd, off, SEEK_SET);
		if (len == 0 || len == (size_t)-1)
			len = st.st_size;
		struct oio_sds_ul_src_s src0 = {
			.type = OIO_UL_SRC_HOOK_SEQUENTIAL, .data = { .hook = {
				.cb = _read_FILE,
				.ctx = in,
				.size = len
			}}
		};

		err = _upload_sequential (sds, dst, &src0);
	}

	if (in)
		fclose (in);
	if (fd >= 0)
		close (fd);
	return (struct oio_error_s*) err;
}

struct oio_error_s*
oio_sds_upload_from_buffer (struct oio_sds_s *sds,
		struct oio_sds_ul_dst_s *dst, void *base, size_t len)
{
	if (!sds || !dst || !base)
		return (struct oio_error_s*) BADREQ("Invalid argument");

	FILE *in = NULL;
	GError *err = NULL;

	if (!(in = fmemopen (base, len, "r")))
		err = SYSERR("fmemopen() error: (%d) %s", errno, strerror(errno));
	else {
		struct oio_sds_ul_src_s src0 = {
			.type = OIO_UL_SRC_HOOK_SEQUENTIAL, .data = { .hook = {
				.cb = _read_FILE,
				.ctx = in,
				.size = len
			}},
		};

		err = _upload_sequential (sds, dst, &src0);
	}

	if (in)
		fclose (in);
	return (struct oio_error_s*) err;
}

/* List --------------------------------------------------------------------- */

static GError *
_notify_list_prefix (struct oio_sds_list_listener_s *listener,
		struct json_object *jitem)
{
	if (listener->on_prefix)
		listener->on_prefix (listener->ctx, json_object_get_string (jitem));
	return NULL;
}

static GError *
_notify_list_item (struct oio_sds_list_listener_s *listener,
		struct json_object *jitem)
{
	struct json_object *jn, *jh, *js, *jv;
	struct oio_ext_json_mapping_s m[] = {
		{"name", &jn, json_type_string, 1},
		{"hash", &jh, json_type_string, 1},
		{"size", &js, json_type_int, 1},
		{"ver",  &jv, json_type_int, 1},
		{NULL, NULL, 0, 0}
	};
	GError *err = oio_ext_extract_json (jitem, m);
	if (err) {
		g_prefix_error (&err, "Invalid item: ");
		return err;
	}

	struct oio_sds_list_item_s item;
	item.name = json_object_get_string (jn);
	item.hash = json_object_get_string (jh);
	item.size = json_object_get_int64 (js);
	item.version = json_object_get_int64 (jv);
	if (listener->on_item)
		listener->on_item (listener->ctx, &item);
	return NULL;
}

static GError *
_notify_list_result (struct oio_sds_list_listener_s *listener,
		struct json_object *jbody, size_t *pcount)
{
	struct json_object *jobjects = NULL, *jprefixes = NULL;
	struct oio_ext_json_mapping_s m[] = {
		{"objects",  &jobjects,  json_type_array, 1},
		{"prefixes", &jprefixes, json_type_array, 1},
		{NULL,NULL,0,0}
	};
	GError *err = oio_ext_extract_json (jbody, m);
	if (err) {
		g_prefix_error (&err, "Invalid body: ");
		return err;
	}

	GRID_TRACE2 ("Found %u items, %u prefixes",
			json_object_array_length(jobjects),
			json_object_array_length(jprefixes));

	*pcount = json_object_array_length(jobjects);
	for (int i=*pcount; i>0 && !err ;i--) {
		struct json_object *jitem = json_object_array_get_idx (jobjects, i-1);
		err = _notify_list_item (listener, jitem);
	}
	for (int i=json_object_array_length(jprefixes); i>0 && !err ;i--) {
		struct json_object *jitem = json_object_array_get_idx (jprefixes, i-1);
		err = _notify_list_prefix (listener, jitem);
	}

	return err;
}

static GError *
_single_list (struct oio_sds_list_param_s *param,
		struct oio_sds_list_listener_s *listener, CURL *h)
{
	GRID_TRACE("%s prefix %s marker %s end %s max %"G_GSIZE_FORMAT,
		__FUNCTION__, param->prefix, param->marker, param->end,
		param->max_items);

	listener->out_count = 0;
	listener->out_truncated = FALSE;
	GString *reply_body = g_string_new ("");

	// Query the proxy
	GError *err = oio_proxy_call_content_list (h, param->url, reply_body,
			param->prefix, param->marker, param->end, param->max_items, 0);

	// Unpack the reply
	if (!err) {
		GRID_TRACE("Parsing (%"G_GSIZE_FORMAT") %s", reply_body->len, reply_body->str);
		struct json_tokener *tok = json_tokener_new ();
		struct json_object *jbody = json_tokener_parse_ex (tok,
				reply_body->str, reply_body->len);
		if (!json_object_is_type(jbody, json_type_object)) {
			err = NEWERROR(0, "Invalid JSON from the OIO proxy");
		} else {
			size_t count_items = 0;
			if (!(err = _notify_list_result (listener, jbody, &count_items)))
				listener->out_count = count_items;
		}
		json_object_put (jbody);
		json_tokener_free (tok);
	}

	g_string_free (reply_body, TRUE);
	return err;
}

struct oio_error_s *
oio_sds_list (struct oio_sds_s *sds, struct oio_sds_list_param_s *param,
		struct oio_sds_list_listener_s *listener)
{
	if (!sds || !param || !listener || !param->url)
		return (struct oio_error_s*) NEWERROR(CODE_BAD_REQUEST, "Missing argument");
	if (!oio_url_has_fq_container (param->url))
		return (struct oio_error_s*) NEWERROR(CODE_BAD_REQUEST, "Partial URI");
	oio_ext_set_reqid (sds->session_id);

	GRID_DEBUG("LIST prefix %s marker %s end %s max %"G_GSIZE_FORMAT,
		param->prefix, param->marker, param->end, param->max_items);

	gchar *next = param->marker ? g_strdup (param->marker) : NULL;
	listener->out_truncated = 0;
	listener->out_count = 0;
	GError *err = NULL;

	for (;;) {
		gchar *nextnext = NULL;
		int _hook_bound (void *ctx, const char *next_marker) {
			(void) ctx;
			oio_str_replace (&nextnext, next_marker);
			return 0;
		}
		struct oio_sds_list_listener_s l0 = {
			.ctx = listener->ctx,
			.on_item = listener->on_item,
			.on_prefix = listener->on_prefix,
			.on_bound = _hook_bound,
			.out_count = 0,
			.out_truncated = FALSE,
		};
		struct oio_sds_list_param_s p0 = *param;
		p0.marker = next;
		p0.max_items = param->max_items
			? param->max_items - listener->out_count : 0;

		if (NULL != (err = _single_list (&p0, &l0, sds->h))) {
			oio_str_clean (&next);
			oio_str_clean (&nextnext);
			break;
		}
		listener->out_count += l0.out_count;
		GRID_TRACE("list > %"G_GSIZE_FORMAT" (+%"G_GSIZE_FORMAT")"
				" max=%"G_GSIZE_FORMAT"/%"G_GSIZE_FORMAT" trunc=%d next=%s",
				listener->out_count, l0.out_count,
				p0.max_items, param->max_items,
				l0.out_truncated, nextnext);
		if (!l0.out_truncated) {
			oio_str_clean (&next);
			oio_str_clean (&nextnext);
			break;
		}
		/* truncated */
		if (!nextnext) {
			err = NEWERROR(CODE_PLATFORM_ERROR, "Proxy replied a truncated"
					" list, but no end marker present");
			oio_str_clean (&next);
			oio_str_clean (&nextnext);
			break;
		}
		oio_str_reuse (&next, nextnext);
		nextnext = NULL;
		/* truncated and tail known */
		if (param->max_items && param->max_items <= listener->out_count) {
			/* stop if we have the count */
			listener->out_truncated = TRUE;
			break;
		}
	}

	if (next) {
		if (!err && listener->on_bound)
			listener->on_bound (listener->ctx, next);
		oio_str_clean (&next);
	}

	return (struct oio_error_s*) err;
}

/* Misc. -------------------------------------------------------------------- */

struct oio_error_s*
oio_sds_link (struct oio_sds_s *sds, struct oio_url_s *url, const char *content_id)
{
	if (!sds || !url || !content_id)
		return (struct oio_error_s*) BADREQ("Missing argument");
	oio_ext_set_reqid (sds->session_id);
	return (struct oio_error_s*) oio_proxy_call_content_link (sds->h, url, content_id);
}

struct oio_error_s*
oio_sds_link_or_upload (struct oio_sds_s *sds, struct oio_sds_ul_src_s *src,
		struct oio_sds_ul_dst_s *dst)
{
	if (!sds || !src || !dst)
		return (struct oio_error_s*) BADREQ("Missing argument");
	if (!dst->content_id)
		return (struct oio_error_s*) BADREQ("Missing content ID");

	struct oio_error_s *err = oio_sds_link (sds, dst->url, dst->content_id);
	if (!err)
		return NULL;
	int code = oio_error_code(err);
	if (code == CODE_CONTENT_NOTFOUND || code == CODE_NOT_IMPLEMENTED)
		oio_error_pfree (&err);
	return oio_sds_upload (sds, src, dst);
}

struct oio_error_s*
oio_sds_delete (struct oio_sds_s *sds, struct oio_url_s *url)
{
	if (!sds || !url)
		return (struct oio_error_s*) BADREQ("Missing argument");
	oio_ext_set_reqid (sds->session_id);
	return (struct oio_error_s*) oio_proxy_call_content_delete (sds->h, url);
}

struct oio_error_s*
oio_sds_has (struct oio_sds_s *sds, struct oio_url_s *url, int *phas)
{
	if (!sds || !url || !phas)
		return (struct oio_error_s*) BADREQ("Missing argument");
	oio_ext_set_reqid (sds->session_id);
	GError *err = oio_proxy_call_content_show (sds->h, url, NULL);
	*phas = (err == NULL);
	if (err && (CODE_IS_NOTFOUND(err->code) || err->code == CODE_NOT_FOUND))
		g_clear_error(&err);
	return (struct oio_error_s*) err;
}

char **
oio_sds_get_compile_options (void)
{
	GPtrArray *tmp = g_ptr_array_new ();
	void _add (const gchar *k, const gchar *v) {
		g_ptr_array_add (tmp, g_strdup(k));
		g_ptr_array_add (tmp, g_strdup(v));
	}
	void _add_double (const gchar *k, gdouble v) {
		gchar s[32];
		_add (k, g_ascii_dtostr (s, sizeof(s), v));
	}
	void _add_integer (const gchar *k, gint64 v) {
		gchar s[24];
		g_snprintf (s, sizeof(s), "%"G_GINT64_FORMAT, v);
		_add (k, s);
	}
#define _ADD_STR(S) _add(#S,S)
#define _ADD_DBL(S) _add_double(#S,S)
#define _ADD_INT(S) _add_integer(#S,S)
	_ADD_STR (PROXYD_PREFIX2);
	_ADD_STR (PROXYD_HEADER_PREFIX);
	_ADD_STR (PROXYD_HEADER_REQID);
	_ADD_STR (PROXYD_HEADER_NOEMPTY);
	_ADD_INT (PROXYD_PATH_MAXLEN);
	_ADD_DBL (PROXYD_DEFAULT_TTL_CSM0);
	_ADD_DBL (PROXYD_DEFAULT_TTL_SERVICES);
	_ADD_INT (PROXYD_DEFAULT_MAX_CSM0);
	_ADD_INT (PROXYD_DEFAULT_MAX_SERVICES);
	_ADD_DBL (PROXYD_DIR_TIMEOUT_GLOBAL);
	_ADD_DBL (PROXYD_DIR_TIMEOUT_SINGLE);

	_ADD_STR (GCLUSTER_RUN_DIR);
	_ADD_STR (OIO_ETC_DIR);
	_ADD_STR (OIO_CONFIG_FILE_PATH);
	_ADD_STR (OIO_CONFIG_DIR_PATH);
	_ADD_STR (OIO_CONFIG_LOCAL_PATH);
	_ADD_STR (GCLUSTER_AGENT_SOCK_PATH);

	_ADD_DBL (M0V2_CLIENT_TIMEOUT);
	_ADD_DBL (M1V2_CLIENT_TIMEOUT);
	_ADD_DBL (M2V2_CLIENT_TIMEOUT);

	char **out = calloc (1+tmp->len, sizeof(void*));
	for (guint i=0; i<tmp->len ;++i)
		out[i] = strdup((char*) tmp->pdata[i]);
	for (guint i=0; i<tmp->len ;++i)
		g_free (tmp->pdata[i]);
	g_ptr_array_free (tmp, TRUE);
	return out;
}

