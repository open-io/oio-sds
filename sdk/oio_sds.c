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

#ifndef  OIOSDS_http_agent
# define OIOSDS_http_agent "OpenIO-SDS/SDK-2.0"
#endif

struct oio_sds_s
{
	gchar *ns;
};

struct oio_error_s;
struct hc_url_s;

static int
_trace(CURL *h, curl_infotype t, char *data, size_t size, void *u)
{
	(void) h, (void) t, (void) u;
	GRID_TRACE("CURL %.*s", (int)size, data);
	return 0;
}

static CURL *
_curl_get_handle (void)
{
	CURL *h = curl_easy_init ();
	curl_easy_setopt (h, CURLOPT_USERAGENT, OIOSDS_http_agent);
	curl_easy_setopt (h, CURLOPT_NOPROGRESS, 1L);
	if (GRID_TRACE_ENABLED()) {
		curl_easy_setopt (h, CURLOPT_DEBUGFUNCTION, _trace);
		curl_easy_setopt (h, CURLOPT_VERBOSE, 1L);
	}
	return h;
}

static CURL *
_curl_get_handle_proxy (const char *ns)
{
	CURL *h = _curl_get_handle ();

#if (LIBCURL_VERSION_MAJOR >= 7) && (LIBCURL_VERSION_MINOR >= 40)
	gchar *s = gridcluster_get_proxylocal (ns);
	if (s) {
		GRID_DEBUG("proxy [%s]", s);
		curl_easy_setopt (h, CURLOPT_UNIX_SOCKET_PATH, s);
		g_free (s);
	}
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
	GRID_DEBUG(" + Feeding the upload with at most [%"G_GSIZE_FORMAT"] bytes", n*s);
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
_write_FILE(void *data, size_t s, size_t n, FILE *out)
{
	/* TODO compute a MD5SUM */
	/* TODO guard against to many bytes received from the rawx */
	return fwrite ((gchar*)data, s, n, out);
}

static size_t
_write_NOOP(void *data, size_t s, size_t n, void *ignored)
{
	(void) data, (void) ignored;
	return s*n;
}

static size_t
_read_FILE(void *data, size_t s, size_t n, FILE *in)
{
	/* TODO compute a MD5SUM */
	/* TODO guard against to many bytes received from the rawx */
	return fread ((gchar*)data, s, n, in);
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
	gchar url[1];
};

static gint
_compare_chunks (const struct chunk_s *c0, const struct chunk_s *c1)
{
	assert(c0 != NULL && c1 != NULL);
	int c = CMP(c0->position.meta,c1->position.meta);
	if (!c)
		c = CMP(c0->position.intra,c1->position.intra);
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
			result->position.parity = ~0;
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
		struct json_object *jchunk = json_object_array_get_idx (jtab, i-1);
		if (!json_object_is_type(jchunk, json_type_object))
			err = NEWERROR(0, "JSON: expected object for chunk");
		struct json_object *jurl = NULL, *jpos = NULL, *jsize = NULL, *jhash = NULL;
		(void) json_object_object_get_ex(jchunk, "url", &jurl);
		(void) json_object_object_get_ex(jchunk, "pos", &jpos);
		(void) json_object_object_get_ex(jchunk, "size", &jsize);
		(void) json_object_object_get_ex(jchunk, "hash", &jhash);
		if (!jurl || !jpos || !jsize || !jhash)
			err = NEWERROR(0, "JSON: missing chunk's field");
		else if (!json_object_is_type(jurl, json_type_string)
				|| !json_object_is_type(jpos, json_type_string)
				|| !json_object_is_type(jsize, json_type_int)
				|| !json_object_is_type(jhash, json_type_string)) {
			err = NEWERROR(0, "JSON: invalid chunk's field");
		} else {
			GByteArray *h = metautils_gba_from_hexstring(json_object_get_string(jhash));
			if (!h) {
				err = NEWERROR(0, "JSON: invalid chunk hash: not hexa");
			} else {
				if (h->len != g_checksum_type_get_length(G_CHECKSUM_MD5)
						&& h->len != g_checksum_type_get_length(G_CHECKSUM_SHA256)
						&& h->len != g_checksum_type_get_length(G_CHECKSUM_SHA512)
						&& h->len != g_checksum_type_get_length(G_CHECKSUM_SHA1)) {
					err = NEWERROR(0, "JSON: invalid chunk hash: invalid length");
				} else {
					struct chunk_s *c = _load_one_chunk (jurl, jsize, jpos);
					chunks = g_slist_prepend (chunks, c);
				}
				g_byte_array_free (h, TRUE);
			}
		}
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
	return NULL;
}

void
oio_sds_free (struct oio_sds_s *sds)
{
	if (!sds)
		return;
	metautils_str_clean (&sds->ns);
}

void
oio_sds_pfree (struct oio_sds_s **psds)
{
	if (!psds || !*psds) return;
	oio_sds_free (*psds);
	*psds = NULL;
}

/* -------------------------------------------------------------------------- */

static GError *
_download_chunks (GSList *chunks, const char *local)
{
	GError *err = NULL;
	CURLcode rc;

	int fd = open (local, O_CREAT|O_EXCL|O_WRONLY, 0644);
	if (fd < 0)
		return NEWERROR(0, "open error [%s]: (%d) %s", local, errno, strerror(errno));

	FILE *out = fdopen(fd, "a");
	if (!out) {
		close (fd);
		return NEWERROR(0, "fopen error [%s]: (%d) %s", local, errno, strerror(errno));
	}

	CURL *h = _curl_get_handle ();
	rc = curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "GET");

	GRID_DEBUG("Download to [%s] from ...", local);
	for (GSList *l=chunks; l && !err ;l=l->next) {
		const struct chunk_s *c = l->data;
		GRID_DEBUG(" < [%s] %u.%u %"G_GINT64_FORMAT, c->url, c->position.meta, c->position.intra, c->size);
		rc = curl_easy_setopt (h, CURLOPT_URL, c->url);
		rc = curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_FILE);
		rc = curl_easy_setopt (h, CURLOPT_WRITEDATA, out);
		rc = curl_easy_perform (h);
		if (rc != CURLE_OK)
			err = NEWERROR(0, "CURL: download error [%s] : (%d) %s", c->url,
					rc, curl_easy_strerror(rc));
	}

	fclose(out);
	curl_easy_cleanup (h);
	return err;
}

/* -------------------------------------------------------------------------- */

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
	CURL *h = _curl_get_handle_proxy (hc_url_get(url, HCURL_NS));

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
			err = NEWERROR(0, "Proxy error: %s", curl_easy_strerror(rc));
	}

	/* Parse the beans */
	if (!err) {
		GRID_DEBUG("Body: %s", reply_body->str);
		struct json_tokener *tok = json_tokener_new ();
		struct json_object *jbody = json_tokener_parse_ex (tok, reply_body->str, reply_body->len);
		json_tokener_free (tok);
		if (!json_object_is_type(jbody, json_type_array)) {
			err = NEWERROR(0, "Invalid JSON from the OIO proxy");
		} else {
			if (NULL != (err = _load_chunks (&chunks, jbody)))
				g_prefix_error (&err, "Parsing: ");
			else
				chunks = g_slist_sort (chunks, (GCompareFunc)_compare_chunks);
		}
		json_object_put (jbody);
	}

	/* download from the beans */
	if (!err)
		err = _download_chunks (chunks, local);

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
};

static void
_upload_fini (struct local_upload_s *upload)
{
	if (upload->in) 
		fclose (upload->in), upload->in = NULL;
	if (upload->fd >= 0)
		close (upload->fd), upload->fd = -1;
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
	return NULL;
}

static GError *
_upload_chunks (GSList *chunks, struct local_upload_s *upload)
{
	GError *err = NULL;
	CURLcode rc;
	struct { guint meta, intra; } last = {.meta=(guint)-1, .intra=(guint)-1};
	off_t done = 0;

	CURL *h = _curl_get_handle ();
	rc = curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "PUT");
	rc = curl_easy_setopt (h, CURLOPT_UPLOAD, 1L);

	GRID_DEBUG("Upload from [%s] to ...", upload->path);
	for (GSList *l=chunks; l && !err ;l=l->next) {
		struct chunk_s *c = l->data;
		if (c->position.parity)
			continue;
		if (c->position.meta == last.meta && c->position.intra == last.intra)
			continue;
		off_t local_size = upload->st.st_size - done;
		local_size = MIN(local_size, c->size);
		GRID_DEBUG(" > [%s] %u.%u %"G_GINT64_FORMAT, c->url, c->position.meta, c->position.intra, local_size);
		rc = curl_easy_setopt (h, CURLOPT_URL, c->url);
		rc = curl_easy_setopt (h, CURLOPT_READFUNCTION, _read_FILE);
		rc = curl_easy_setopt (h, CURLOPT_READDATA, upload->in);
		rc = curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_NOOP);
		rc = curl_easy_setopt (h, CURLOPT_WRITEDATA, NULL);
		rc = curl_easy_setopt (h, CURLOPT_INFILESIZE_LARGE, local_size);
		rc = curl_easy_perform (h);
		GRID_DEBUG("Upload rc=%d", rc);
		if (rc != CURLE_OK)
			err = NEWERROR(0, "CURL: upload error [%s] : (%d) %s", c->url,
					rc, curl_easy_strerror(rc));
		else {
			last.meta = c->position.meta;
			last.intra = c->position.intra;
			c->size = local_size;
		}
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
				"\"hash\":\"00000000000000000000000000000000\"}",
				c->url, c->size, c->position.meta);
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
	CURL *h = _curl_get_handle_proxy (hc_url_get(url, HCURL_NS));
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
				chunks = g_slist_sort (chunks, (GCompareFunc)_compare_chunks);
				GRID_DEBUG("Got %u beans", g_slist_length (chunks));
			}
		}
		json_object_put (jbody);
	}

	/* upload the beans */
	if (!err)
		err = _upload_chunks (chunks, &upload);

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
			err = NEWERROR(0, "Proxy: Put: (%d) %s", rc, curl_easy_strerror(rc));
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
	CURL *h = _curl_get_handle_proxy (hc_url_get(url, HCURL_NS));

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
		err = NEWERROR(0, "Proxy: Delete: %s", curl_easy_strerror(rc));
	_headers_clean (&headers);

	curl_easy_cleanup (h);
	g_string_free (reply_body, TRUE);
	return (struct oio_error_s*) err;
}

