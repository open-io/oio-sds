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
#include <curl/multi.h>
#include <curl/curlver.h>

#include "oio_core.h"
#include "oio_sds.h"
#include "http_put.h"
#include "http_internals.h"

// used for macros
#include <metautils/lib/metautils.h>

struct oio_sds_s
{
	gchar *ns;
	gchar *proxy;
	gchar *proxy_local;
	struct {
		int proxy;
		int rawx;
	} timeout;
	gboolean sync_after_download;
};

struct oio_error_s;
struct oio_url_s;

volatile int oio_sds_default_autocreate = 0;

volatile int oio_sds_no_shuffle = 0;

static CURL *
_curl_get_handle_proxy (struct oio_sds_s *sds)
{
	CURL *h = _curl_get_handle ();
#if (LIBCURL_VERSION_MAJOR >= 7) && (LIBCURL_VERSION_MINOR >= 40)
	if (sds->proxy_local)
		curl_easy_setopt (h, CURLOPT_UNIX_SOCKET_PATH, sds->proxy_local);
#else
	(void) sds;
#endif
	return h;
}

static void
_append_to_url (GString *to, struct oio_url_s *url, int what)
{
	const char *original = oio_url_get (url, what);
	if (!original) {
		g_string_append_c (to, '/');
	} else {
		gchar *s = g_uri_escape_string (original, NULL, FALSE);
		g_string_append_printf (to, "/%s", s);
		g_free (s);
	}
}

static GString *
_curl_set_url_content (struct oio_url_s *u)
{
	GString *hu = g_string_new("http://");

	const char *ns = oio_url_get (u, OIOURL_NS);
	if (!ns) {
		GRID_WARN ("BUG No namespace configured!");
		g_string_append (hu, "proxy");
	} else {
		gchar *s = oio_cfg_get_proxy_containers (ns);
		if (!s) {
			GRID_WARN ("No proxy configured!");
			g_string_append (hu, "proxy");
		} else {
			g_string_append (hu, s);
			g_free (s);
		}
	}

	g_string_append_printf (hu, "/%s/m2", PROXYD_PREFIX2);
	_append_to_url (hu, u, OIOURL_NS);
	_append_to_url (hu, u, OIOURL_ACCOUNT);
	_append_to_url (hu, u, OIOURL_USER);
	_append_to_url (hu, u, OIOURL_PATH);
	return hu;
}

static GString *
_curl_set_url_container (struct oio_url_s *u)
{
	GString *hu = g_string_new("http://");

	const char *ns = oio_url_get (u, OIOURL_NS);
	if (!ns) {
		GRID_WARN ("BUG No namespace configured!");
		g_string_append (hu, "proxy");
	} else {
		gchar *s = oio_cfg_get_proxy_containers (ns);
		if (!s) {
			GRID_WARN ("No proxy configured!");
			g_string_append (hu, "proxy");
		} else {
			g_string_append (hu, s);
			g_free (s);
		}
	}

	g_string_append_printf (hu, "/%s/m2", PROXYD_PREFIX2);
	_append_to_url (hu, u, OIOURL_NS);
	_append_to_url (hu, u, OIOURL_ACCOUNT);
	_append_to_url (hu, u, OIOURL_USER);
	return hu;
}


/* Body helpers ------------------------------------------------------------- */

static size_t
_write_GString(void *b, size_t s, size_t n, GString *out)
{
	g_string_append_len (out, (gchar*)b, s*n);
	return s*n;
}

struct view_GString_s
{
	GString *data;
	size_t done;
};

static size_t
_read_GString(void *b, size_t s, size_t n, struct view_GString_s *in)
{
	size_t remaining = in->data->len - in->done;
	size_t available = s * n;
	size_t len = MIN(remaining,available);
	if (len) {
		memcpy(b, in->data->str, len);
		in->done += len;
	}
	return len;
}

static size_t
_write_NOOP(void *data, size_t s, size_t n, void *ignored)
{
	(void) data, (void) ignored;
	return s*n;
}

static GError *
_body_parse_error (GString *b)
{
	g_assert (b != NULL);
	struct json_tokener *tok = json_tokener_new ();
	struct json_object *jbody = json_tokener_parse_ex (tok, b->str, b->len);
	json_tokener_free (tok);
	tok = NULL;

	if (!jbody)
		return NEWERROR(0, "No error explained");

	struct json_object *jcode, *jmsg;
	struct oio_ext_json_mapping_s map[] = {
		{"status", &jcode, json_type_int,    0},
		{"message",  &jmsg,  json_type_string, 0},
		{NULL, NULL, 0, 0}
	};
	GError *err =  oio_ext_extract_json(jbody, map);
	if (!err) {
		int code = 0;
		const char *msg = "Unknown error";
		if (jcode) code = json_object_get_int64 (jcode);
		if (jmsg) msg = json_object_get_string (jmsg);
		err = NEWERROR(code, "(code=%d) %s", code, msg);
	}
	json_object_put (jbody);
	return err;
}

/* Headers helpers ---------------------------------------------------------- */

struct headers_s
{
	GSList *gheaders;
	struct curl_slist *headers;
};

static void
_headers_clean (struct headers_s *h)
{
	if (h->headers) {
		curl_slist_free_all (h->headers);
		h->headers = NULL;
	}
	if (h->gheaders) {
		g_slist_free_full (h->gheaders, g_free);
		h->gheaders = NULL;
	}
}

static void
_headers_add (struct headers_s *h, const char *k, const char *v)
{
	gchar *s = g_strdup_printf("%s: %s", k, v);
	h->gheaders = g_slist_prepend (h->gheaders, s);
	h->headers = curl_slist_append (h->headers, h->gheaders->data);
}

static void
_headers_add_int64 (struct headers_s *h, const char *k, gint64 i64)
{
	gchar v[24];
	g_snprintf (v, sizeof(v), "%"G_GINT64_FORMAT, i64);
	_headers_add (h, k, v);
}

/* Chunk parsing helpers (JSON) --------------------------------------------- */

struct chunk_s
{
	gsize size;
	struct chunk_position_s {
		guint meta;
		guint intra;
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
_metachunk_cleanv (struct metachunk_s **tab)
{
	if (!tab)
		return;
	for (struct metachunk_s **p=tab; *p ;++p) {
		g_slist_free ((*p)->chunks);
		g_free (*p);
	}
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
		if (*(s+1) == 'p') {
			result->position.parity = 1;
			result->position.intra = atoi(s+2);
		} else {
			result->position.intra = atoi(s+1);
		}
	}
	return result;
}

static GError *
_load_chunks (GSList **out, struct json_object *jtab)
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
			for (char *p = c->hexhash; *h ;) // copies the hash as uppercase
				*(p++) = g_ascii_toupper (*(h++));
			chunks = g_slist_prepend (chunks, c);
		}
	}

	if (!err)
		*out = g_slist_reverse (chunks);
	else
		g_slist_free_full (chunks, g_free);
	return err;
}

static GError *
_organize_chunks (GSList *lchunks, struct metachunk_s ***result)
{
	*result = NULL;

	guint higher_meta = 0;
	for (GSList *l=lchunks; l ;l=l->next) {
		struct chunk_s *c = l->data;
		higher_meta = MAX(higher_meta, c->position.meta);
	}

	/* build the metachunk */
	struct metachunk_s **out = g_malloc0 ((higher_meta+2) * sizeof(void*));
	for (guint i=0; i<=higher_meta ;++i) {
		out[i] = g_malloc0 (sizeof(struct metachunk_s));
		out[i]->meta = i;
	}
	for (GSList *l=lchunks; l ;l=l->next) {
		struct chunk_s *c = l->data;
		guint i = c->position.meta;
		out[i]->chunks = g_slist_prepend (out[i]->chunks, c);
		if (c->position.parity)
			out[i]->ec = TRUE;
	}
	for (guint i=0; i<=higher_meta ;++i) {
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
	for (guint i=0; i<=higher_meta ;++i) {
		if (!out[i]->chunks) {
			_metachunk_cleanv (out);
			return NEWERROR (0, "Invalid chunk sequence: gap found at [%u]", i);
		}
	}

	for (guint i=0; i<=higher_meta ;++i) {
		if (out[i]->ec)
			out[i]->chunks = g_slist_sort (out[i]->chunks, (GCompareFunc)_compare_chunks);
		else {
			if (!oio_sds_no_shuffle)
				out[i]->chunks = oio_ext_gslist_shuffle (out[i]->chunks);
		}
	}

	/* Compute each metachunk's size */
	for (guint i=0; i<=higher_meta ;++i) {
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
	for (guint i=0; i<=higher_meta ;++i) {
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
	(*out)->ns = g_strdup (ns);
	(*out)->proxy_local = oio_cfg_get_proxylocal (ns);
	(*out)->proxy = oio_cfg_get_proxy_containers (ns);
	(*out)->sync_after_download = TRUE;
	return NULL;
}

void
oio_sds_free (struct oio_sds_s *sds)
{
	if (!sds) return;
	oio_str_clean (&sds->ns);
	oio_str_clean (&sds->proxy);
	oio_str_clean (&sds->proxy_local);
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
			*p_nbread += total;
			return total;
		}
		return 0;
	}

	GError *err = NULL;
	gchar str_range[64];

	g_snprintf (str_range, sizeof(str_range),
			"bytes=%"G_GSIZE_FORMAT"-%"G_GSIZE_FORMAT,
			range->offset, range->offset + range->size - 1);

	GRID_DEBUG ("%s Range:%s/%"G_GSIZE_FORMAT" %s", __FUNCTION__,
			str_range, c0->size, c0->url);

	CURL *h = _curl_get_handle ();
	struct headers_s headers = {NULL,NULL};
	_headers_add (&headers, "Expect", "");
	_headers_add (&headers, PROXYD_HEADER_REQID, oio_ext_get_reqid());
	_headers_add (&headers, "Range", str_range);
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
	_headers_clean (&headers);
	return err;
}

/* the range is relative to the segment of the metachunk
 * Until there are available chunks, take the next chunk (they are equally
 * capable replicas) and attempt a read. */
static GError *
_download_range_from_metachunk_replicated (struct _download_ctx_s *dl,
		const struct oio_sds_dl_range_s *range, struct metachunk_s *meta)
{
	GRID_TRACE("%s", __FUNCTION__);
	struct oio_sds_dl_range_s r0 = *range;
	GSList *tail_chunks = meta->chunks;

	while (r0.size > 0) {

		if (!tail_chunks)
			return NEWERROR (CODE_PLATFORM_ERROR, "Too many failure");
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

		GRID_TRACE("Range %"G_GSIZE_FORMAT"+%"G_GSIZE_FORMAT
				" CHUNK size=%"G_GSIZE_FORMAT" pos=%u.%u%s %s",
				r0.offset, r0.size,
				chunk->size, chunk->position.meta, chunk->position.intra,
				(chunk->position.parity ? "" : "p"), chunk->url);

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
			if ((*p)->size >= total)
				return NEWERROR (CODE_BAD_REQUEST, "Range not satisfiable");
			if ((*p)->offset + (*p)->size >= total)
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
	g_assert (sds != NULL);
	g_assert (src != NULL);
	g_assert (src->url != NULL);

	g_assert (dst->type == OIO_DL_DST_HOOK_SEQUENTIAL);
	dst->out_size = 0;
	if (!dst->data.hook.cb)
		return (struct oio_error_s*) NEWERROR (CODE_BAD_REQUEST, "Missing callback");
	_dl_debug (__FUNCTION__, src, dst);

	GError *err = NULL;
	CURLcode rc;

	GSList *chunks = NULL;
	GString *reply_body = g_string_new("");

	/* Get the beans */
	if (!err) {
		CURL *h = _curl_get_handle_proxy (sds);
		g_string_set_size (reply_body, 0);
		do {
			GString *http_url = _curl_set_url_content (src->url);
			rc = curl_easy_setopt (h, CURLOPT_URL, http_url->str);
			g_string_free (http_url, TRUE);
		} while (0);
		struct headers_s headers = {NULL,NULL};
		_headers_add (&headers, "Expect", "");
		_headers_add (&headers, PROXYD_HEADER_REQID, oio_ext_get_reqid());
		rc = curl_easy_setopt (h, CURLOPT_HTTPHEADER, headers.headers);
		rc = curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_GString);
		rc = curl_easy_setopt (h, CURLOPT_WRITEDATA, reply_body);
		rc = curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "GET");
		rc = curl_easy_perform (h);
		if (CURLE_OK != rc)
			err = NEWERROR(0, "Proxy error (get): (%d) %s", rc, curl_easy_strerror(rc));
		else {
			long code = 0;
			rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
			if (2 != (code/100))
				err = NEWERROR(0, "Get error: (%ld)", code);
		}
		_headers_clean (&headers);
		curl_easy_cleanup (h);
	}

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
			if (NULL != (err = _load_chunks (&chunks, jbody))) {
				g_prefix_error (&err, "Parsing: ");
			} else {
				GRID_DEBUG("Got %u beans", g_slist_length (chunks));
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
	g_assert (sds != NULL);
	g_assert (dl != NULL);
	g_assert (snk != NULL);

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
	g_assert (local != NULL);
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

static void
_ul_debug (const char *caller, struct oio_sds_ul_src_s *src,
		struct oio_sds_ul_dst_s *dst)
{
	if (!GRID_DEBUG_ENABLED())
		return;
	GString *out = g_string_new("");

	if (src->type == OIO_UL_SRC_HOOK_SEQUENTIAL)
		g_string_append_printf (out, "SRC{HOOK,%p}", src->data.hook.cb);
	else if (src->type == OIO_UL_SRC_BUFFER)
		g_string_append_printf (out, "SRC{BUFF,%"G_GSIZE_FORMAT"}", src->data.buffer.length);
	else if (src->type == OIO_UL_SRC_FILE)
		g_string_append_printf (out, "SRC{BUFF,%s,%"G_GSIZE_FORMAT"+%"G_GSIZE_FORMAT"}",
				src->data.file.path, src->data.file.offset, src->data.file.size);
	else
		g_string_append_printf (out, "SRC{XXX,%d}", src->type);
		
	g_string_append_printf (out, " -> DST{%s,%d}", oio_url_get(dst->url, OIOURL_WHOLE), dst->autocreate);

	GRID_DEBUG ("%s (%s)", caller, out->str);
	g_string_free (out, TRUE);
}

struct _upload_ctx_s
{
	struct oio_sds_s *sds;
	struct oio_sds_ul_dst_s *dst;
	struct oio_sds_ul_src_s *src;
	GChecksum *checksum_content;
	GSList *chunks;
};

static void
_upload_fini (struct _upload_ctx_s *upload)
{
	if (upload->checksum_content)
		g_checksum_free (upload->checksum_content);
	g_slist_free_full (upload->chunks, g_free);
}

static GError *
_upload_chunks_from_hook (struct _upload_ctx_s *upload)
{
	GError *err = NULL;
	size_t done = 0;

	_ul_debug(__FUNCTION__, upload->src, upload->dst);

	for (GSList *l=upload->chunks; l && !err ;l=l->next) {
		struct chunk_s *c0 = l->data;

		/* TODO no EC managed yet */
		if (c0->position.parity)
			continue;

		/* collect all the chunks at the same position */
		GSList *chunkset = g_slist_prepend (NULL, c0);
		for (; l->next ;l=l->next) {
			struct chunk_s *c1 = l->next->data;
			if (0 != memcmp(&c0->position, &c1->position, sizeof(c0->position)))
				break;
			chunkset = g_slist_prepend (chunkset, c1);
		}

		chunkset = metautils_gslist_shuffle (chunkset);
		c0 = chunkset->data;

		/* compute and patch the chunksize */
		gsize local_size = upload->src->data.hook.size - done;
		for (GSList *l1=chunkset; l1 ;l1=l1->next) {
			struct chunk_s *c1 = l1->data;
			local_size = MIN(local_size, c1->size);
		}
		for (GSList *l1=chunkset; l1 ;l1=l1->next) {
			struct chunk_s *c1 = l1->data;
			GRID_DEBUG("%"G_GSIZE_FORMAT" <- %"G_GSIZE_FORMAT" %s", local_size, c1->size, c1->url);
			c1->size = local_size;
		}

		if (DEBUG_ENABLED()) {
			for (GSList *l1=chunkset; l1 ;l1=l1->next) {
				struct chunk_s *c1 = l1->data;
				GRID_DEBUG(" > [%s] pos=%u.%u%c size=%"G_GSIZE_FORMAT, c1->url,
						c1->position.meta, c1->position.intra, c1->position.parity ? 'P' : ' ',
						c1->size);
			}
		}

		/* upload only the expected bytes */
		size_t local_done = 0;
		ssize_t _read_wrapper (void *u, char *ptr, size_t len) {
			(void) u;
			size_t remaining = local_size - local_done;
			len = MIN(len, remaining);
			ssize_t r = upload->src->data.hook.cb(upload->src->data.hook.ctx,
					(unsigned char*)ptr, len);
			if (r > 0)
				local_done += r;
			return r;
		}

		/* start a new upload */
		GSList *destset = NULL;
		struct http_put_s *put = http_put_create (_read_wrapper, NULL,
				local_size, upload->sds->timeout.proxy, upload->sds->timeout.proxy);
		for (GSList *l1=chunkset; l1 ;l1=l1->next) {
			struct chunk_s *c1 = l1->data;
			struct http_put_dest_s *dest = http_put_add_dest (put, c1->url, c1);
			http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "container-id", "%s", oio_url_get (upload->dst->url, OIOURL_HEXID));
			http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "content-path", "%s", oio_url_get (upload->dst->url, OIOURL_PATH));
			http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "content-size", "%" G_GINT64_FORMAT, c1->size);
			http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "content-chunksnb", "%u", g_slist_length(chunkset));
			http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "content-metadata-sys", "%s", "");
			http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "chunk-id", "%s", strrchr(c1->url, '/')+1);
			http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "chunk-pos", "%u", c1->position.meta);
			http_put_dest_add_header (dest, PROXYD_HEADER_REQID, "%s", oio_ext_get_reqid());
			destset = g_slist_append (destset, dest); 
		}
		err = http_put_run (put);

		/* check at least one chunk succeeded */
		if (!err) {
			if (http_put_get_failure_number (put) >= g_slist_length (destset))
				err = NEWERROR(0, "No chunk upload succeeded");
		}

		/* check the hash match (received vs. computed) */
		if (!err) {
			hash_md5_t bin;
			char computed[STRLEN_MD5];
			http_put_get_md5 (put, bin, sizeof(hash_md5_t));
			oio_str_bin2hex (bin, sizeof(hash_md5_t), computed, sizeof(computed));
			for (GSList *l1=chunkset; !err && l1 ;l1=l1->next) {
				const gchar *received = http_put_get_header (put, l1->data, RAWX_HEADER_PREFIX "chunk-hash");
				if (!received || g_ascii_strcasecmp(received, computed)) {
					err = NEWERROR(0, "Possible corruption: chunk hash mismatch "
						"computed[%s] received[%s]", computed, received);
				} else {
					struct chunk_s *c1 = l1->data;
					memcpy (c1->hexhash, computed, sizeof(c1->hexhash));
				}
			}
		}
		http_put_destroy (put);

		if (!err)
			done += local_size;
		g_slist_free (chunkset);
		g_slist_free (destset);
	}

	return err;
}

static void
_chunks_pack (GString *gs, GSList *chunks)
{
	g_string_append (gs, "[");
	for (GSList *l=chunks; l ;l=l->next) {
		struct chunk_s *c = l->data;
		if (gs->str[gs->len - 1] != '[')
			g_string_append_c (gs, ',');
		g_string_append_printf (gs,
				"{\"url\":\"%s\","
				"\"size\":%"G_GINT64_FORMAT","
				"\"pos\":\"%u\","
				"\"hash\":\"%s\"}",
				c->url, c->size, c->position.meta, c->hexhash);
	}
	g_string_append (gs, "]");
}

static struct oio_error_s *
_upload_from_hook (struct oio_sds_s *sds, struct oio_sds_ul_dst_s *dst,
		struct oio_sds_ul_src_s *src)
{
	GError *err = NULL;
	CURLcode rc;

	_ul_debug(__FUNCTION__, src, dst);

	/* check the local file */
	struct _upload_ctx_s upload;
	upload.sds = sds;
	upload.dst = dst;
	upload.src = src;
	upload.checksum_content = g_checksum_new (G_CHECKSUM_MD5);
	upload.chunks = NULL;

	GString *request_body = g_string_new(""), *reply_body = g_string_new ("");
	struct view_GString_s view_input = {.data=request_body, .done=0};

	/* get the beans */
	g_string_set_size (request_body, 0);
	g_string_set_size (reply_body, 0);
	if (!err) {
		GRID_DEBUG("Getting some BEANS from the proxy ...");
		CURL *h = _curl_get_handle_proxy (sds);
		do {
			GString *http_url = _curl_set_url_content (dst->url);
			g_string_append (http_url, "/action");
			rc = curl_easy_setopt (h, CURLOPT_URL, http_url->str);
			g_string_free (http_url, TRUE);
		} while (0);
		g_string_append (request_body, "{\"action\":\"Beans\",\"args\":{");
		g_string_append_printf (request_body, "\"size\":%"G_GINT64_FORMAT,
				(gint64) src->data.hook.size);
		g_string_append (request_body, "}}");
		view_input.done = 0;
		struct headers_s headers = {NULL,NULL};
		_headers_add (&headers, "Expect", "");
		_headers_add (&headers, PROXYD_HEADER_REQID, oio_ext_get_reqid());
		if (dst->autocreate)
			_headers_add (&headers, PROXYD_HEADER_MODE, "autocreate");
		rc = curl_easy_setopt (h, CURLOPT_READFUNCTION, _read_GString);
		rc = curl_easy_setopt (h, CURLOPT_READDATA, &view_input);
		rc = curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_GString);
		rc = curl_easy_setopt (h, CURLOPT_WRITEDATA, reply_body);
		rc = curl_easy_setopt (h, CURLOPT_UPLOAD, 1L);
		rc = curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "POST");
		rc = curl_easy_setopt (h, CURLOPT_INFILESIZE_LARGE, request_body->len);
		rc = curl_easy_setopt (h, CURLOPT_HTTPHEADER, headers.headers);
		rc = curl_easy_perform (h);
		if (rc != CURLE_OK)
			err = NEWERROR(0, "Proxy error (beans): (%d) %s", rc, curl_easy_strerror(rc));
		else {
			long code = 0;
			rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
			if (2 != (code/100)) {
				err = _body_parse_error (reply_body);
				g_prefix_error (&err, "Beans error: (%ld)", code);
				err->code = code;
			}
		}
		curl_easy_cleanup (h);
		_headers_clean (&headers);
	}

	/* parse the beans */
	if (!err) {
		GRID_DEBUG("Parsing the BEANS from %s", reply_body->str);
		struct json_tokener *tok = json_tokener_new ();
		struct json_object *jbody = json_tokener_parse_ex (tok,
				reply_body->str, reply_body->len);
		if (!json_object_is_type(jbody, json_type_array)) {
			err = NEWERROR(0, "Invalid JSON from the OIO proxy");
		} else {
			if (NULL != (err = _load_chunks (&upload.chunks, jbody))) {
				g_prefix_error (&err, "Parsing: ");
			} else {
				GRID_DEBUG("Got %u beans", g_slist_length (upload.chunks));
			}
		}
		json_object_put (jbody);
		json_tokener_free (tok);
	}

	/* upload the beans */
	if (!err) {
		upload.chunks = g_slist_sort (upload.chunks, (GCompareFunc)_compare_chunks);
		err = _upload_chunks_from_hook (&upload);
	}

	/* save the beans */
	g_string_set_size (request_body, 0);
	g_string_set_size (reply_body, 0);
	if (!err) {
		GRID_DEBUG("Saving the uploaded beans ...");
		CURL *h = _curl_get_handle_proxy (sds);
		do {
			GString *http_url = _curl_set_url_content (dst->url);
			rc = curl_easy_setopt (h, CURLOPT_URL, http_url->str);
			g_string_free (http_url, TRUE);
		} while (0);
		_chunks_pack (request_body, upload.chunks);
		view_input.done = 0;

		struct headers_s headers = {NULL,NULL};
		_headers_add (&headers, "Expect", "");
		_headers_add (&headers, PROXYD_HEADER_REQID, oio_ext_get_reqid());
		_headers_add (&headers, PROXYD_HEADER_PREFIX "content-meta-policy", "NONE");
		_headers_add (&headers, PROXYD_HEADER_PREFIX "content-meta-hash",
				g_checksum_get_string (upload.checksum_content));
		_headers_add_int64 (&headers, PROXYD_HEADER_PREFIX "content-meta-length",
				src->data.hook.size);
		if (dst->autocreate)
			_headers_add (&headers, PROXYD_HEADER_MODE, "autocreate");
		rc = curl_easy_setopt (h, CURLOPT_HTTPHEADER, headers.headers);

		rc = curl_easy_setopt (h, CURLOPT_READFUNCTION, _read_GString);
		rc = curl_easy_setopt (h, CURLOPT_READDATA, &view_input);
		rc = curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_GString);
		rc = curl_easy_setopt (h, CURLOPT_WRITEDATA, reply_body);
		rc = curl_easy_setopt (h, CURLOPT_UPLOAD, 1L);
		rc = curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "PUT");
		rc = curl_easy_setopt (h, CURLOPT_INFILESIZE_LARGE, request_body->len);
		rc = curl_easy_perform (h);
		if (rc != CURLE_OK)
			err = NEWERROR(0, "Proxy error (put): (%d) %s", rc, curl_easy_strerror(rc));
		else {
			long code = 0;
			rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
			if (2 != (code/100))
				err = NEWERROR(0, "Put error: (%ld)", code);
		}
		curl_easy_cleanup (h);
		_headers_clean (&headers);
	}

	/* cleanup and exit */
	g_string_free (request_body, TRUE);
	g_string_free (reply_body, TRUE);
	_upload_fini (&upload);
	GRID_DEBUG("UPLOAD %s", err?"KO":"ok");
	return (struct oio_error_s*) err;
}

static ssize_t
_read_FILE (void *u, unsigned char *ptr, size_t len)
{
	FILE *in = u;
	if (feof(in) || ferror(in))
		return -1;
	return fread(ptr, 1, len, in);
}

static struct oio_error_s *
_upload_from_file (struct oio_sds_s *sds, struct oio_sds_ul_dst_s *dst,
		struct oio_sds_ul_src_s *src)
{
	_ul_debug(__FUNCTION__, src, dst);
	if (!src->data.file.path)
		return (struct oio_error_s*) NEWERROR(0, "Invalid argument: %s", "no path");

	int fd = -1;
	FILE *in = NULL;
	struct oio_error_s *err = NULL;
	struct stat st;

	if (0 > (fd = open (src->data.file.path, O_RDONLY, 0644)))
		err = (struct oio_error_s*) NEWERROR(CODE_INTERNAL_ERROR, "open() error: (%d) %s", errno, strerror(errno));
	else if (0 > fstat (fd, &st))
		err = (struct oio_error_s*) NEWERROR(CODE_INTERNAL_ERROR, "fstat() error: (%d) %s", errno, strerror(errno));
	else if (!(in = fdopen(fd, "r")))
		err = (struct oio_error_s*) NEWERROR(CODE_INTERNAL_ERROR, "fdopen() error: (%d) %s", errno, strerror(errno));
	else {
		struct oio_sds_ul_src_s src0 = {
			.type = OIO_UL_SRC_HOOK_SEQUENTIAL, .data = { .hook = {
				.cb = _read_FILE,
				.ctx = in,
				.size = st.st_size
			}}
		};
		err = _upload_from_hook (sds, dst, &src0);
	}

	if (in)
		fclose (in);
	if (fd >= 0)
		close (fd);
	return err;
}

static struct oio_error_s *
_upload_from_buffer (struct oio_sds_s *sds, struct oio_sds_ul_dst_s *dst,
		struct oio_sds_ul_src_s *src)
{
	_ul_debug(__FUNCTION__, src, dst);
	if (!src->data.buffer.ptr)
		return (struct oio_error_s*) NEWERROR (0, "Invalid argument: %s", "no buffer");

	FILE *in = NULL;
	struct oio_error_s *err = NULL;

	if (!(in = fmemopen (src->data.buffer.ptr, src->data.buffer.length, "r")))
		err = (struct oio_error_s*) NEWERROR (CODE_INTERNAL_ERROR, "fmemopen() error: (%d) %s", errno, strerror(errno));
	else {
		struct oio_sds_ul_src_s src0 = {
			.type = OIO_UL_SRC_HOOK_SEQUENTIAL, .data = { .hook = {
				.cb = _read_FILE,
				.ctx = in,
				.size = src->data.buffer.length
			}},
		};
		err = _upload_from_hook (sds, dst, &src0);
	}

	if (in)
		fclose (in);
	return err;
}

struct oio_error_s*
oio_sds_upload (struct oio_sds_s *sds, struct oio_sds_ul_src_s *src,
		struct oio_sds_ul_dst_s *dst)
{
	g_assert (sds != NULL);
	g_assert (dst != NULL);
	g_assert (src != NULL);

	if (src->type == OIO_UL_SRC_HOOK_SEQUENTIAL)
		return _upload_from_hook (sds, dst, src);
	if (src->type == OIO_UL_SRC_FILE)
		return _upload_from_file (sds, dst, src);
	if (src->type == OIO_UL_SRC_BUFFER)
		return _upload_from_buffer (sds, dst, src);

	return (struct oio_error_s*) NEWERROR(0, "Invalid argument: %s",
			"source type not managed");
}

struct oio_error_s*
oio_sds_upload_from_file (struct oio_sds_s *sds, struct oio_url_s *url,
		const char *local)
{
	struct oio_sds_ul_src_s src = {
		.type = OIO_UL_SRC_FILE,
		.data = {
			.file = {
				.path = local,
				.offset = 0,
				.size = 0
			},
		},
	};
	struct oio_sds_ul_dst_s dst = {
		.autocreate = oio_sds_default_autocreate,
		.url = url,
	};
	return oio_sds_upload (sds, &src, &dst);
}

struct oio_error_s*
oio_sds_upload_from_source (struct oio_sds_s *sds, struct oio_url_s *url,
		struct oio_source_s *oldsrc)
{
	g_assert (sds != NULL);
	g_assert (url != NULL);
	g_assert (oldsrc != NULL);
	g_assert (oldsrc->type == OIO_SRC_FILE);
	g_assert (oldsrc->data.path != NULL);

	struct oio_sds_ul_src_s src = {
		.type = OIO_UL_SRC_FILE,
		.data = {
			.file = {
				.path = oldsrc->data.path
			},
		}
	};
	struct oio_sds_ul_dst_s dst = {
		.autocreate = oldsrc->autocreate,
		.url = url,
	};
	return oio_sds_upload (sds, &src, &dst);
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

static int
_has_prefix_len (char **pb, size_t *plen, const char *prefix)
{
	char *b = *pb;
	size_t blen = *plen;
	if (!b)
		return FALSE;
	while (blen && !g_ascii_isalnum(b[blen-1]))
		blen --;
	if (!blen)
		return FALSE;
	while (*prefix) {
		if (!(blen--) || g_ascii_tolower(*(b++)) != *(prefix++))
			return FALSE;
	}
	*pb = b;
	*plen = blen;
	return TRUE;
}

static size_t
_header_callback(char *b, size_t s, size_t n, void *u)
{
	struct oio_sds_list_listener_s *listener = u;
	g_assert (listener != NULL);

	size_t total = n*s;
	if (!_has_prefix_len (&b, &total, "x-oio-list-"))
		return total;

	if (_has_prefix_len (&b, &total, "truncated: ")) {
		gchar tmp[total+1];
		memcpy (tmp, b, total);
		tmp[total] = 0;
		listener->out_truncated = !g_ascii_strcasecmp(tmp, "true") || !g_ascii_strcasecmp(tmp, "yes");
	}
	else if (_has_prefix_len (&b, &total, "next: ")) {
		gchar tmp[total+1];
		memcpy (tmp, b, total);
		tmp[total] = 0;
		listener->on_bound (listener->ctx, tmp);
	}
	return n*s;
}

static gchar *
_url_build_for_list (struct oio_sds_list_param_s *param)
{
	gboolean first = TRUE;
	GString *http_url = _curl_set_url_container (param->url);
	void _append (const char *k, const char *v) {
		if (!v) return;
		g_string_append_printf (http_url, "%s%s=%s", first?"?":"&", k, v);
		first = FALSE;
	}
	_append ("prefix", param->prefix);
	_append ("marker", param->marker);
	_append ("end", param->end);
	if (param->max_items) {
		gchar tmp[32];
		g_snprintf (tmp, sizeof(tmp), "%"G_GSIZE_FORMAT, param->max_items);
		_append ("max", tmp);
	}
	return g_string_free(http_url, FALSE);
}

static GError *
_single_list (struct oio_sds_list_param_s *param,
		struct oio_sds_list_listener_s *listener, CURL *h)
{
	CURLcode rc;
	GError *err = NULL;
	struct headers_s headers = {NULL,NULL};

	GRID_TRACE("%s prefix %s marker %s end %s max %"G_GSIZE_FORMAT,
		__FUNCTION__, param->prefix, param->marker, param->end,
		param->max_items);

	listener->out_count = 0;
	listener->out_truncated = FALSE;
	GString *reply_body = g_string_new ("");

	// Query the proxy

	do {
		gchar *u = _url_build_for_list (param);
		curl_easy_setopt (h, CURLOPT_URL, u);
		g_free (u);
	} while (0);

	_headers_add (&headers, "Expect", "");
	_headers_add (&headers, PROXYD_HEADER_REQID, oio_ext_get_reqid());
	curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_GString);
	curl_easy_setopt (h, CURLOPT_WRITEDATA, reply_body);
	curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "GET");
	curl_easy_setopt (h, CURLOPT_HTTPHEADER, headers.headers);
	curl_easy_setopt (h, CURLOPT_HEADERDATA, listener);
	curl_easy_setopt (h, CURLOPT_HEADERFUNCTION, _header_callback);
	rc = curl_easy_perform (h);
	if (rc != CURLE_OK)
		err = NEWERROR(0, "Proxy error (beans): (%d) %s", rc, curl_easy_strerror(rc));
	else {
		long code = 0;
		rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
		if (2 != (code/100)) {
			err = _body_parse_error (reply_body);
			g_prefix_error (&err, "Beans error: (%ld)", code);
			err->code = code;
		}
	}

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
	_headers_clean (&headers);
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

	GRID_DEBUG("LIST prefix %s marker %s end %s max %"G_GSIZE_FORMAT,
		param->prefix, param->marker, param->end, param->max_items);

	CURL *h = _curl_get_handle_proxy (sds);
	
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
		
		if (NULL != (err = _single_list (&p0, &l0, h))) {
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
	
	curl_easy_cleanup (h);
	return (struct oio_error_s*) err;
}

/* Link --------------------------------------------------------------------- */

struct oio_error_s*
oio_sds_link (struct oio_sds_s *sds, struct oio_url_s *url, const char *iname)
{
	g_assert (sds != NULL);
	g_assert (url != NULL);
	g_assert (iname != NULL);

	return (struct oio_error_s*) NEWERROR(CODE_NOT_IMPLEMENTED, "Link not implemented yet");
}

struct oio_error_s*
oio_sds_link_or_put (struct oio_sds_s *sds, struct oio_sds_ul_dst_s *dst,
		struct oio_sds_ul_src_s *src, const char *iname)
{
	g_assert (sds != NULL);
	g_assert (dst != NULL);
	g_assert (src != NULL);
	g_assert (iname != NULL);

	struct oio_error_s *err = oio_sds_link (sds, dst->url, iname);
	if (!err)
		return NULL;
	int code = oio_error_code(err);
	if (code == CODE_CONTENT_NOTFOUND || code == CODE_NOT_IMPLEMENTED)
		oio_error_pfree (&err);
	return oio_sds_upload (sds, src, dst);
}

/* -------------------------------------------------------------------------- */

struct oio_error_s*
oio_sds_delete (struct oio_sds_s *sds, struct oio_url_s *url)
{
	g_assert (sds != NULL);
	g_assert (url != NULL);

	CURLcode rc;
	GError *err = NULL;
	
	GString *reply_body = g_string_new("");
	CURL *h = _curl_get_handle_proxy (sds);

	do {
		GString *http_url = _curl_set_url_content (url);
		rc = curl_easy_setopt (h, CURLOPT_URL, http_url->str);
		g_string_free (http_url, TRUE);
	} while (0);

	struct headers_s headers = {NULL,NULL};
	_headers_add (&headers, "Expect", "");
	_headers_add (&headers, PROXYD_HEADER_REQID, oio_ext_get_reqid());
	rc = curl_easy_setopt (h, CURLOPT_HTTPHEADER, headers.headers);

	rc = curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_GString);
	rc = curl_easy_setopt (h, CURLOPT_WRITEDATA, reply_body);
	rc = curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "DELETE");
	rc = curl_easy_perform (h);
	if (CURLE_OK != rc)
		err = NEWERROR(0, "Proxy error (delete): %s", curl_easy_strerror(rc));
	else {
		long code = 0;
		rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
		if (2 != (code/100))
			err = NEWERROR(0, "Delete error: (%ld)", code);
	}
	curl_easy_cleanup (h);
	_headers_clean (&headers);
	g_string_free (reply_body, TRUE);
	return (struct oio_error_s*) err;
}

struct oio_error_s*
oio_sds_has (struct oio_sds_s *sds, struct oio_url_s *url, int *phas)
{
	g_assert (sds != NULL);
	g_assert (url != NULL);
	g_assert (phas != NULL);

	CURLcode rc;
	GError *err = NULL;
	
	GString *reply_body = g_string_new("");
	CURL *h = _curl_get_handle_proxy (sds);

	do {
		GString *http_url = _curl_set_url_content (url);
		rc = curl_easy_setopt (h, CURLOPT_URL, http_url->str);
		g_string_free (http_url, TRUE);
	} while (0);

	struct headers_s headers = {NULL,NULL};
	_headers_add (&headers, "Expect", "");
	_headers_add (&headers, PROXYD_HEADER_REQID, oio_ext_get_reqid());
	rc = curl_easy_setopt (h, CURLOPT_HTTPHEADER, headers.headers);

	rc = curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_NOOP);
	rc = curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "HEAD");
	rc = curl_easy_perform (h);
	if (CURLE_OK != rc)
		err = NEWERROR(0, "Proxy error (head): %s", curl_easy_strerror(rc));
	else {
		long code = 0;
		rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
		*phas = (2 == (code/100));
		if (!*phas && 404 != code) {
			err = _body_parse_error (reply_body);
			g_prefix_error (&err, "Check error (%ld): ", code);
		}
	}
	curl_easy_cleanup (h);
	_headers_clean (&headers);
	g_string_free (reply_body, TRUE);
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

