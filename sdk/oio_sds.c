#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "oio.sdk"
#endif

#include <assert.h>

#include "metautils/lib/metautils.h"

#include "cluster/lib/gridcluster.h"
#include "metautils/lib/hc_url.h"
#include "client/c/lib/grid_client.h"
#include "client/c/lib/gs_internals.h"
#include "client/c/lib/hc.h"

#include <glib.h>
#include <json.h>
#include <curl/curl.h>
#include <curl/multi.h>

#include "oio_sds.h"

#ifndef  OIOSDS_http_agent
# define OIOSDS_http_agent "OpenIO-SDS/SDK-2.0"
#endif

struct oio_sds_s
{
	gchar *ns;
	gs_grid_storage_t *gs;
};

struct oio_error_s;
struct hc_url_s;

static int
_trace(CURL *h, curl_infotype t, char *data, size_t size, void *u)
{
	(void) h, (void) t, (void) u;
	GRID_DEBUG("CURL %.*s", (int)size, data);
	return 0;
}

static CURL *
_curl_get_handle (const char *ns)
{
	CURLcode rc;
	CURL *h = curl_easy_init ();
	rc = curl_easy_setopt (h, CURLOPT_USERAGENT, OIOSDS_http_agent);
	rc = curl_easy_setopt (h, CURLOPT_NOPROGRESS, 1L);
	rc = curl_easy_setopt (h, CURLOPT_DEBUGFUNCTION, _trace);

	gchar *s = gridcluster_get_proxylocal (ns);
	if (s) {
		GRID_DEBUG("proxy [%s]", s);
		rc = curl_easy_setopt (h, CURLOPT_UNIX_SOCKET_PATH, s);
		if (rc != CURLE_OK) GRID_WARN("setopt failed at %s +%u", __FILE__, __LINE__);
		g_free (s);
	}
	return h;
}

static void
_curl_set_url_content (CURL *h, struct hc_url_s *u)
{
	CURLcode rc;
	GString *hu = g_string_new("");
	g_string_append_printf (hu, "http://proxy.%s.ns.openio.io/%s/m2/%s/%s/%s",
			hc_url_get (u, HCURL_NS), PROXYD_PREFIX, hc_url_get (u, HCURL_NS),
			hc_url_get(u, HCURL_USER), hc_url_get (u, HCURL_PATH));
	rc = curl_easy_setopt (h, CURLOPT_URL, hu->str);
	if (rc != CURLE_OK) GRID_WARN("setopt failed at %s +%u", __FILE__, __LINE__);
	GRID_DEBUG("url [%s]", hu->str);
	g_string_free (hu, TRUE);
}

static size_t
_write_GString(void *data, size_t s, size_t n, GString *out)
{
	g_string_append_len (out, (gchar*)data, s*n);
	return s*n;
}

static size_t
_write_FILE(void *data, size_t s, size_t n, FILE *out)
{
	/* TODO compute a MD5SUM */
	/* TODO guard against to many bytes received from the rawx */
	return fwrite ((gchar*)data, s, n, out);
}

/* error management --------------------------------------------------------- */

void
oio_error_free (struct oio_error_s *e)
{
	if (!e) return;
	gs_error_free ((gs_error_t*)e);
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
	return ((gs_error_t*)e)->code;
}

const char *
oio_error_message (const struct oio_error_s *e)
{
	if (!e) return "?";
	return ((gs_error_t*)e)->msg;
}

/* client management -------------------------------------------------------- */

static struct oio_error_s *
_oio_sds_lazy_init (struct oio_sds_s *sds)
{
	assert (sds != NULL);
	if (sds->gs) return NULL;
	gs_error_t *err = NULL;
	sds->gs = gs_grid_storage_init (sds->ns, &err);
	return (struct oio_error_s*) err;	
}

struct oio_error_s *
oio_sds_init (struct oio_sds_s **out, const char *ns)
{
	logger_lazy_init ();
	logger_init_level(GRID_LOGLVL_TRACE2);
	g_log_set_default_handler(logger_stderr, NULL);

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
	if (sds->gs)
		gs_grid_storage_free (sds->gs);
}

void
oio_sds_pfree (struct oio_sds_s **psds)
{
	if (!psds || !*psds) return;
	oio_sds_free (*psds);
	*psds = NULL;
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

static gs_error_t *
_download_chunks (GSList *chunks, const char *local)
{
	gs_error_t *err = NULL;
	CURLcode rc;

	int fd = open (local, O_CREAT|O_EXCL|O_WRONLY, 0644);
	FILE *out = fdopen(fd, "a");
	if (!out) {
		GSERRORSET(&err, "fopen error [%s]: (%d) %s", local, errno, strerror(errno));
		return err;
	}

	CURL *h = curl_easy_init ();
	rc = curl_easy_setopt (h, CURLOPT_USERAGENT, OIOSDS_http_agent);
	rc = curl_easy_setopt (h, CURLOPT_NOPROGRESS, 1L);
	rc = curl_easy_setopt (h, CURLOPT_DEBUGFUNCTION, _trace);
	rc = curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "GET");
	/* no proxy here */

	GRID_DEBUG("Download to [%s] from ...", local);
	for (GSList *l=chunks; l ;l=l->next) {
		const struct chunk_s *c = l->data;
		GRID_DEBUG(" > [%s] %u.%u %"G_GINT64_FORMAT, c->url, c->position.meta, c->position.intra, c->size);
		rc = curl_easy_setopt (h, CURLOPT_URL, c->url);
		rc = curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_FILE);
		rc = curl_easy_setopt (h, CURLOPT_WRITEDATA, out);
		rc = curl_easy_perform (h);
		if (rc != CURLE_OK) {
			GSERRORSET(&err, "CURL: download error [%s] : (%d) %s", c->url, rc,
					curl_easy_strerror(rc));
			break;
		}
	}

	fclose(out);
	return err;
}

static struct chunk_s *
_load_one_chunk (struct json_object *jurl, struct json_object *jsize,
		struct json_object *jpos)
{
	const char *s;
	s = json_object_get_string(jurl);
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

static gs_error_t *
_load_chunks (GSList **out, struct json_object *jtab)
{
	GSList *chunks = NULL;
	gs_error_t *e = NULL;

	for (int i=json_object_array_length(jtab); i>0 && !e ;i--) {
		struct json_object *jchunk = json_object_array_get_idx (jtab, i-1);
		if (!json_object_is_type(jchunk, json_type_object)) {
			GSERRORSET(&e, "JSON: expected object for chunk");
			return e;
		}
		struct json_object *jurl = NULL, *jpos = NULL, *jsize = NULL, *jhash = NULL;
		(void) json_object_object_get_ex(jchunk, "url", &jurl);
		(void) json_object_object_get_ex(jchunk, "pos", &jpos);
		(void) json_object_object_get_ex(jchunk, "size", &jsize);
		(void) json_object_object_get_ex(jchunk, "hash", &jhash);
		if (!jurl || !jpos || !jsize || !jhash) {
			GSERRORSET(&e, "JSON: missing chunk's field");
		} else if (!json_object_is_type(jurl, json_type_string)
				|| !json_object_is_type(jpos, json_type_string)
				|| !json_object_is_type(jsize, json_type_int)
				|| !json_object_is_type(jhash, json_type_string)) {
			GSERRORSET(&e, "JSON: invalid chunk's field");
		} else {
			GByteArray *h = metautils_gba_from_hexstring(json_object_get_string(jhash));
			if (!h) {
				GSERRORSET(&e, "JSON: invalid chunk hash: not hexa");
			} else {
				if (h->len != g_checksum_type_get_length(G_CHECKSUM_MD5)
						&& h->len != g_checksum_type_get_length(G_CHECKSUM_SHA256)
						&& h->len != g_checksum_type_get_length(G_CHECKSUM_SHA512)
						&& h->len != g_checksum_type_get_length(G_CHECKSUM_SHA1)) {
					GSERRORSET(&e, "JSON: invalid chunk hash: invalid length");
				} else {
					struct chunk_s *c = _load_one_chunk (jurl, jsize, jpos);
					chunks = g_slist_prepend (chunks, c);
				}
				g_byte_array_free (h, TRUE);
			}
		}
	}

	*out = chunks;
	return NULL;
}

struct oio_error_s*
oio_sds_download_to_file (struct oio_sds_s *sds, struct hc_url_s *url,
		const char *local)
{
	assert (sds != NULL),
	assert (url != NULL);

	gs_error_t *e = NULL;

	CURLcode rc;
	GString *body = g_string_new("");
	CURL *h = _curl_get_handle (hc_url_get(url, HCURL_NS));
	_curl_set_url_content (h, url);
	rc = curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_GString);
	rc = curl_easy_setopt (h, CURLOPT_WRITEDATA, body);
	rc = curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "GET");
	rc = curl_easy_perform (h);
	if (CURLE_OK != rc)
		gs_error_set (&e, 0, "Proxy error: %s", curl_easy_strerror(rc));
	curl_easy_cleanup (h);

	if (!e) {
		GRID_WARN("Body: %s", body->str);
		struct json_tokener *tok = json_tokener_new ();
		struct json_object *jbody = json_tokener_parse_ex (tok, body->str, body->len);
		json_tokener_free (tok);
		if (!json_object_is_type(jbody, json_type_array)) {
			GSERRORSET(&e, "Invalid JSON from the OIO proxy");
		} else {
			GSList *chunks = NULL;
			if (!(e = _load_chunks (&chunks, jbody))) {
				chunks = g_slist_sort (chunks, (GCompareFunc)_compare_chunks);
				e = _download_chunks (chunks, local);
			}
			g_slist_free_full (chunks, g_free);
		}
		json_object_put (jbody);
	}

	g_string_free (body, TRUE);
	return (struct oio_error_s*)e;
}

struct oio_error_s*
oio_sds_upload_from_file (struct oio_sds_s *sds, struct hc_url_s *url,
		const char *local)
{
	assert (sds != NULL);
	assert (url != NULL);

	do {
		struct oio_error_s *err = NULL;
		if (!sds->gs)
			err = _oio_sds_lazy_init (sds);
		if (err) return err;
	} while (0);

	gs_error_t *e = NULL;
	(void) hc_ul_content_from_file (sds->gs, hc_url_get(url, HCURL_USER),
			hc_url_get(url, HCURL_PATH), local, &e);
	return (struct oio_error_s*)e;
}

struct oio_error_s*
oio_sds_delete (struct oio_sds_s *sds, struct hc_url_s *url)
{
	assert (sds != NULL);
	assert (url != NULL);

	gs_error_t *e = NULL;

	GString *body = g_string_new("");
	CURL *h = _curl_get_handle (hc_url_get(url, HCURL_NS));
	_curl_set_url_content (h, url);
	curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_GString);
	curl_easy_setopt (h, CURLOPT_WRITEDATA, body);
	curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "DELETE");
	CURLcode rc = curl_easy_perform (h);
	if (CURLE_OK != rc)
		gs_error_set (&e, 0, "Curl error: %s", curl_easy_strerror(rc));
	curl_easy_cleanup (h);

	g_string_free (body, TRUE);
	return (struct oio_error_s*)e;
}

