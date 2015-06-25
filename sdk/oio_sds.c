/*
OpenIO SDS client
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

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "oio.sdk"
#endif

#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "metautils/lib/metautils.h"
#include "cluster/lib/gridcluster.h"
#include "metautils/lib/hc_url.h"

#include <glib.h>
#include <json.h>
#include <curl/curl.h>
#include <curl/multi.h>
#include <curl/curlver.h>

#include "oio_sds.h"
#include "http_put.h"
#include "http_internals.h"

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
struct hc_url_s;

static CURL *
_curl_get_handle_proxy (struct oio_sds_s *sds)
{
	CURL *h = _curl_get_handle ();
#if (LIBCURL_VERSION_MAJOR >= 7) && (LIBCURL_VERSION_MINOR >= 40)
	if (sds->proxy_local)
		curl_easy_setopt (h, CURLOPT_UNIX_SOCKET_PATH, sds->proxy_local);
#endif
	return h;
}

static GString *
_curl_set_url_content (struct hc_url_s *u)
{
	const char *ns = hc_url_get (u, HCURL_NS);
	GString *hu = g_string_new("http://");

	gchar *s = gridcluster_get_proxy (ns);
	if (!s)
		g_string_append_printf (hu, "proxy.%s.ns.openio.io", ns);
	else {
		g_string_append (hu, s);
		g_free (s);
	}

	g_string_append_printf (hu, "/%s/m2/%s/%s/%s", PROXYD_PREFIX, ns,
			hc_url_get(u, HCURL_USER), hc_url_get (u, HCURL_PATH));
	return hu;
}

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
	GRID_DEBUG(" + Feeding with [%"G_GSIZE_FORMAT"] -> [%"G_GSIZE_FORMAT"]"
			" -> [%"G_GSIZE_FORMAT"]", available, remaining, len);
	return len;
}

static size_t
_write_NOOP(void *data, size_t s, size_t n, void *ignored)
{
	(void) data, (void) ignored;
	return s*n;
}

/* -------------------------------------------------------------------------- */

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

/* -------------------------------------------------------------------------- */

struct chunk_s
{
	gint64 size;
	struct {
		guint meta;
		guint intra;
		gboolean parity : 8;
	} position;
	gchar hexhash[STRLEN_CHUNKHASH];
	gchar url[1];
};

static gint
_compare_chunks (const struct chunk_s *c0, const struct chunk_s *c1)
{
	assert(c0 != NULL && c1 != NULL);
	int c = CMP(c0->position.meta,c1->position.meta);
	if (!c)
		c = CMP(c0->position.intra,c1->position.intra);
	if (!c)
		c = CMP(c0->position.parity,c1->position.parity);
	return c;
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

	/* Decode the JSON description */
	for (int i=json_object_array_length(jtab); i>0 && !err ;i--) {
		struct json_object *jurl = NULL, *jpos = NULL, *jsize = NULL, *jhash = NULL;
		struct metautils_json_mapping_s m[] = {
			{"url",  &jurl,  json_type_string, 1},
			{"pos",  &jpos,  json_type_string, 1},
			{"size", &jsize, json_type_int,    1},
			{"hash", &jhash, json_type_string, 1},
			{NULL,NULL,0,0}
		};
		err = metautils_extract_json (json_object_array_get_idx (jtab, i-1), m);
		if (err) continue;

		const char *h = json_object_get_string(jhash);
		if (!metautils_str_ishexa(h, 2*sizeof(chunk_hash_t)))
			err = NEWERROR(0, "JSON: invalid chunk hash: not hexa of %"G_GSIZE_FORMAT,
					2*sizeof(chunk_hash_t));
		else {
			struct chunk_s *c = _load_one_chunk (jurl, jsize, jpos);
			for (char *p = c->hexhash; *h ;) // copies the hash as uppercase
				*(p++) = g_ascii_toupper (*(h++));
			chunks = g_slist_prepend (chunks, c);
		}
	}

	chunks = g_slist_sort (chunks, (GCompareFunc)_compare_chunks);

	/* Check the chunk sequence has no gap */
	struct { guint meta, intra; } last = {.meta=(guint)-1, .intra=(guint)-1};
	for (GSList *l=chunks; !err && l ;l=l->next) {
		const struct chunk_s *c = l->data;
		if (c->position.parity)
			continue;
		if (c->position.meta == last.meta) {
			if (c->position.intra != last.intra) {
				if (c->position.intra != last.intra+1) {
					err = NEWERROR(0, "Gap in the chunk sequence [%u.%u],[%u.%u]",
							last.meta, last.intra,
							c->position.meta, c->position.intra);
				}
			}
		} else if (c->position.meta != last.meta+1)
			err = NEWERROR(0, "Gap in the chunk sequence [%u.%u],[%u.%u]",
					last.meta, last.intra,
					c->position.meta, c->position.intra);
		else
			last.meta = c->position.meta, last.intra = c->position.intra;
	}

	if (!err)
		*out = chunks;
	else
		g_slist_free_full (chunks, g_free);
	return err;
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
	logger_lazy_init ();

	assert (out != NULL);
	assert (ns != NULL);
	*out = g_malloc0 (sizeof(struct oio_sds_s));
	(*out)->ns = g_strdup (ns);
	(*out)->proxy_local = gridcluster_get_proxylocal (ns);
	(*out)->proxy = gridcluster_get_proxy (ns);
	(*out)->sync_after_download = TRUE;
	return NULL;
}

void
oio_sds_free (struct oio_sds_s *sds)
{
	if (!sds) return;
	metautils_str_clean (&sds->ns);
	metautils_str_clean (&sds->proxy);
	metautils_str_clean (&sds->proxy_local);
	g_free (sds);
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

/* -------------------------------------------------------------------------- */

static GError *
_download_chunks (struct oio_sds_s *sds, GSList *chunks, const char *local)
{
	GError *err = NULL;
	CURLcode rc;

	int fd = open (local, O_CREAT|O_EXCL|O_WRONLY, 0644);
	if (fd < 0)
		return NEWERROR(0, "open error [%s]: (%d) %s", local, errno, strerror(errno));
	posix_fadvise (fd, 0, 0, POSIX_FADV_SEQUENTIAL);

	FILE *out = fdopen(fd, "a");
	if (!out) {
		close (fd);
		return NEWERROR(0, "fopen error [%s]: (%d) %s", local, errno, strerror(errno));
	}

	CURL *h = _curl_get_handle ();
	long code = 0, ok = 1;
	size_t _write_FILE(void *data, size_t s, size_t n, FILE *f) {
		if (!code) {
			rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
			if (!(ok = (2 == (code / 100)))) {
				rc = curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, NULL);
				rc = curl_easy_setopt (h, CURLOPT_WRITEDATA, NULL);
				return 0;
			}
		}
		assert (BOOL(ok));
		/* TODO compute a MD5SUM */
		/* TODO guard against to many bytes received from the rawx */
		return fwrite ((gchar*)data, s, n, f);
	}

	rc = curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "GET");

	GRID_DEBUG("Download to [%s] from ...", local);
	for (GSList *l=chunks; l && !err ;l=l->next) {
		struct chunk_s *c0 = l->data;

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

		/* skip the chunks with the same position */
		if (c0->position.parity) {
			g_slist_free (chunkset);
			continue;
		}

		/* start a new download */
		GRID_DEBUG(" < [%s] %u.%u %"G_GINT64_FORMAT" among %u", c0->url,
				c0->position.meta, c0->position.intra, c0->size,
				g_slist_length(chunkset));
		rc = curl_easy_setopt (h, CURLOPT_URL, c0->url);
		rc = curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_FILE);
		rc = curl_easy_setopt (h, CURLOPT_WRITEDATA, out);
		rc = curl_easy_perform (h);
		if (rc != CURLE_OK)
			err = NEWERROR(0, "CURL: download error [%s] : (%d) %s", c0->url,
					rc, curl_easy_strerror(rc));
		else {
			rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
			if (2 != (code/100))
				err = NEWERROR(0, "Beans: (%ld)", code);
		}
	}

	
	fflush(out);
	if (sds->sync_after_download)
		fsync(fd);
	posix_fadvise (fd, 0, 0, POSIX_FADV_DONTNEED);
	fclose(out);
	curl_easy_cleanup (h);
	return err;
}

struct oio_error_s*
oio_sds_download_to_file (struct oio_sds_s *sds, struct hc_url_s *url,
		const char *local)
{
	assert (sds != NULL),
	assert (url != NULL);

	GError *err = NULL;
	CURLcode rc;

	GSList *chunks = NULL;
	GString *reply_body = g_string_new("");
	CURL *h = _curl_get_handle_proxy (sds);

	/* Get the beans */
	if (!err) {
		g_string_set_size (reply_body, 0);
		do {
			GString *http_url = _curl_set_url_content (url);
			rc = curl_easy_setopt (h, CURLOPT_URL, http_url->str);
			g_string_free (http_url, TRUE);
		} while (0);
		rc = curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_GString);
		rc = curl_easy_setopt (h, CURLOPT_WRITEDATA, reply_body);
		rc = curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "GET");
		rc = curl_easy_perform (h);
		if (CURLE_OK != rc)
			err = NEWERROR(0, "Proxy: %s", curl_easy_strerror(rc));
		else {
			long code = 0;
			rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
			if (2 != (code/100))
				err = NEWERROR(0, "Get: (%ld)", code);
		}
	}

	/* Parse the beans */
	if (!err) {
		GRID_DEBUG("Body: %s", reply_body->str);
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

	/* download from the beans */
	if (!err)
		err = _download_chunks (sds, chunks, local);

	/* cleanup and exit */
	curl_easy_cleanup (h);
	g_string_free (reply_body, TRUE);
	g_slist_free_full (chunks, g_free);
	return (struct oio_error_s*)err;
}

/* -------------------------------------------------------------------------- */

struct local_upload_s
{
	const char *path;
	FILE *in;
	int fd;
	struct stat st;
	GChecksum *checksum_content;
};

static void
_upload_fini (struct local_upload_s *upload)
{
	if (upload->in) 
		fclose (upload->in);
	if (upload->fd >= 0)
		close (upload->fd);
	if (upload->checksum_content)
		g_checksum_free (upload->checksum_content);

	upload->in = NULL;
	upload->fd = -1;
	upload->checksum_content = NULL;
}

static GError *
_upload_init (struct local_upload_s *upload, const char *path)
{
	memset (upload, 0, sizeof(*upload));
	upload->path = path;
	if (0 > (upload->fd = open (upload->path, O_RDONLY)))
		return NEWERROR(0, "open error [%s]: (%d) %s", upload->path, errno, strerror(errno));
	if (0 > fstat (upload->fd, &upload->st))
		return NEWERROR(0, "stat error [%s]: (%d) %s", upload->path, errno, strerror(errno));
	if (!(upload->in = fdopen(upload->fd, "r")))
		return NEWERROR(0, "fdopen error [%s]: (%d) %s", upload->path, errno, strerror(errno));
	upload->checksum_content = g_checksum_new (G_CHECKSUM_MD5);
	posix_fadvise (upload->fd, 0, 0, POSIX_FADV_SEQUENTIAL|POSIX_FADV_WILLNEED);
	return NULL;
}

static GError *
_upload_chunks (struct oio_sds_s *sds, GSList *chunks, struct local_upload_s *upload)
{
	GError *err = NULL;
	off_t done = 0;

	CURL *h = _curl_get_handle ();
	curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "PUT");
	curl_easy_setopt (h, CURLOPT_UPLOAD, 1L);

	GRID_DEBUG("Upload from [%s] to ...", upload->path);
	for (GSList *l=chunks; l && !err ;l=l->next) {
		struct chunk_s *c0 = l->data;

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

		/* skip the chunks with the same position */
		if (c0->position.parity) {
			g_slist_free (chunkset);
			continue;
		}

		/* patch the chunksize */
		off_t sz = upload->st.st_size - done;
		for (GSList *l1=chunkset; l1 ;l1=l1->next) {
			struct chunk_s *c1 = l1->data;
			sz = (c1->size = MIN(c1->size, sz));
		}

		/* upload only the expected bytes */
		off_t done_local = 0;
		ssize_t _read_FILE(void *u, char *d, size_t max) {
			size_t remaining = sz - done_local;
			size_t r = fread ((gchar*)d, 1, MIN(max, remaining), (FILE*)u);
			if (r > 0) {
				done_local += r;
				return r;
			}
			if (ferror((FILE*)u))
				return -1;
			return 0;
		}

		if (DEBUG_ENABLED()) {
			for (GSList *l1=chunkset; l1 ;l1=l1->next) {
				struct chunk_s *c1 = l1->data;
				GRID_DEBUG(" > [%s] %u.%u%c %"G_GSIZE_FORMAT, c1->url,
						c1->position.meta, c1->position.intra, c1->position.parity ? 'P' : ' ',
						c1->size);
			}
		}

		/* start a new upload */
		GSList *destset = NULL;
		struct http_put_s *put = http_put_create (_read_FILE, upload->in,
				sz, sds->timeout.proxy, sds->timeout.proxy);
		for (GSList *l1=chunkset; l1 ;l1=l1->next) {
			struct chunk_s *c1 = l1->data;
			struct http_put_dest_s *dest = http_put_add_dest (put, c1->url, c1);
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
			buffer2str (bin, sizeof(hash_md5_t), computed, sizeof(computed));
			for (GSList *l1=chunkset; !err && l1 ;l1=l1->next) {
				const gchar *received = http_put_get_header (put, l1->data, "chunk_hash");
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
			done += sz;
		g_slist_free (chunkset);
		g_slist_free (destset);
	}

	curl_easy_cleanup (h);
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

struct oio_error_s*
oio_sds_upload_from_file (struct oio_sds_s *sds, struct hc_url_s *url,
		const char *local)
{
	assert (sds != NULL);
	assert (url != NULL);

	GError *err = NULL;
	CURLcode rc;

	/* check the local file */
	struct local_upload_s upload;
	if (NULL != (err = _upload_init (&upload, local))) {
		_upload_fini (&upload);
		return (struct oio_error_s*) err;
	}

	GSList *chunks = NULL;
	GString *request_body = g_string_new(""), *reply_body = g_string_new ("");
	CURL *h = _curl_get_handle_proxy (sds);
	struct view_GString_s view_input = {.data=request_body, .done=0};

	/* get the beans */
	g_string_set_size (request_body, 0);
	g_string_set_size (reply_body, 0);
	if (!err) {
		GRID_DEBUG("Getting some BEANS from the proxy ...");
		do {
			GString *http_url = _curl_set_url_content (url);
			g_string_append (http_url, "/action");
			rc = curl_easy_setopt (h, CURLOPT_URL, http_url->str);
			g_string_free (http_url, TRUE);
		} while (0);
		g_string_append (request_body, "{\"action\":\"Beans\",\"args\":{");
		g_string_append_printf (request_body, "\"size\":%"G_GINT64_FORMAT,
				(gint64)upload.st.st_size);
		g_string_append (request_body, "}}");
		view_input.done = 0;
		struct headers_s headers = {NULL,NULL};
		_headers_add (&headers, "Expect", "");
		rc = curl_easy_setopt (h, CURLOPT_READFUNCTION, _read_GString);
		rc = curl_easy_setopt (h, CURLOPT_READDATA, &view_input);
		rc = curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_GString);
		rc = curl_easy_setopt (h, CURLOPT_WRITEDATA, reply_body);
		rc = curl_easy_setopt (h, CURLOPT_UPLOAD, 1L);
		rc = curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "POST");
		rc = curl_easy_setopt (h, CURLOPT_INFILESIZE_LARGE, request_body->len);
		rc = curl_easy_setopt (h, CURLOPT_HTTPHEADER, headers);
		rc = curl_easy_perform (h);
		if (rc != CURLE_OK)
			err = NEWERROR(0, "Proxy: Beans: (%d) %s", rc, curl_easy_strerror(rc));
		else {
			long code = 0;
			rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
			if (2 != (code/100))
				err = NEWERROR(0, "Beans: (%ld)", code);
		}
		_headers_clean (&headers);
	}

	/* parse the beans */
	if (!err) {
		GRID_DEBUG("Parsing the BEANS from %s", reply_body->str);
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

	/* upload the beans */
	if (!err)
		err = _upload_chunks (sds, chunks, &upload);

	/* save the beans */
	g_string_set_size (request_body, 0);
	g_string_set_size (reply_body, 0);
	if (!err) {
		GRID_DEBUG("Saving the uploaded beans ...");
		do {
			GString *http_url = _curl_set_url_content (url);
			rc = curl_easy_setopt (h, CURLOPT_URL, http_url->str);
			g_string_free (http_url, TRUE);
		} while (0);
		_chunks_pack (request_body, chunks);
		view_input.done = 0;

		struct headers_s headers = {NULL,NULL};
		_headers_add (&headers, "Expect", "");
		_headers_add (&headers, PROXYD_HEADER_PREFIX "content-meta-policy", "NONE");
		_headers_add (&headers, PROXYD_HEADER_PREFIX "content-meta-hash",
				"00000000000000000000000000000000");
		_headers_add_int64 (&headers, PROXYD_HEADER_PREFIX "content-meta-length",
				upload.st.st_size);
		rc = curl_easy_setopt (h, CURLOPT_READFUNCTION, _read_GString);
		rc = curl_easy_setopt (h, CURLOPT_READDATA, &view_input);
		rc = curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_GString);
		rc = curl_easy_setopt (h, CURLOPT_WRITEDATA, reply_body);
		rc = curl_easy_setopt (h, CURLOPT_UPLOAD, 1L);
		rc = curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "PUT");
		rc = curl_easy_setopt (h, CURLOPT_INFILESIZE_LARGE, request_body->len);
		rc = curl_easy_setopt (h, CURLOPT_HTTPHEADER, headers);
		rc = curl_easy_perform (h);
		if (rc != CURLE_OK)
			err = NEWERROR(0, "Proxy: (%d) %s", rc, curl_easy_strerror(rc));
		else {
			long code = 0;
			rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
			if (2 != (code/100))
				err = NEWERROR(0, "Put: (%ld)", code);
		}
		_headers_clean (&headers);
	}

	/* cleanup and exit */
	g_string_free (request_body, TRUE);
	g_string_free (reply_body, TRUE);
	curl_easy_cleanup (h);
	_upload_fini (&upload);
	GRID_DEBUG("UPLOAD %s", err?"KO":"ok");
	return (struct oio_error_s*) err;
}

/* -------------------------------------------------------------------------- */

struct oio_error_s*
oio_sds_delete (struct oio_sds_s *sds, struct hc_url_s *url)
{
	assert (sds != NULL);
	assert (url != NULL);

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
	rc = curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_GString);
	rc = curl_easy_setopt (h, CURLOPT_WRITEDATA, reply_body);
	rc = curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "DELETE");
	rc = curl_easy_setopt (h, CURLOPT_HTTPHEADER, headers);
	rc = curl_easy_perform (h);
	if (CURLE_OK != rc)
		err = NEWERROR(0, "Proxy: %s", curl_easy_strerror(rc));
	else {
		long code = 0;
		rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
		if (2 != (code/100))
			err = NEWERROR(0, "Delete: (%ld)", code);
	}
	_headers_clean (&headers);

	curl_easy_cleanup (h);
	g_string_free (reply_body, TRUE);
	return (struct oio_error_s*) err;
}

struct oio_error_s*
oio_sds_has (struct oio_sds_s *sds, struct hc_url_s *url, int *phas)
{
	assert (sds != NULL);
	assert (url != NULL);
	assert (phas != NULL);

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
	rc = curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_NOOP);
	rc = curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "HEAD");
	rc = curl_easy_setopt (h, CURLOPT_HTTPHEADER, headers);
	rc = curl_easy_perform (h);
	if (CURLE_OK != rc)
		err = NEWERROR(0, "Proxy: Delete: %s", curl_easy_strerror(rc));
	else {
		long code = 0;
		rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
		*phas = (2 == (code/100));
	}
	_headers_clean (&headers);

	curl_easy_cleanup (h);
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
	_ADD_STR (PROXYD_PREFIX);
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
	_ADD_STR (GCLUSTER_ETC_DIR);
	_ADD_STR (GCLUSTER_CONFIG_FILE_PATH);
	_ADD_STR (GCLUSTER_CONFIG_DIR_PATH);
	_ADD_STR (GCLUSTER_CONFIG_LOCAL_PATH);
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

