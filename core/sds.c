/*
OpenIO SDS core library
Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS

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

#include <core/oio_sds.h>

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <math.h>

#include <json.h>
#include <curl/curl.h>
#include <curl/curlver.h>
#include <erasurecode.h>

#include <core/client_variables.h>
#include <metautils/lib/metautils.h>

#include "http_put.h"
#include "http_del.h"
#include "http_internals.h"
#include "http_get.h"
#include "internals.h"

#define EC_SEGMENT_SIZE 1048576

static GTree *handle_cache_tree = NULL;

struct oio_sds_s
{
	gchar *session_id;
	gchar *ns;
	gchar *proxy;
	gchar *ecd;  // Erasure Coding Daemon
	struct {
		int proxy;
		int rawx;
	} timeout;
	gboolean sync_after_download;
	gboolean admin;
	gboolean no_shuffle;  // read the highest scored chunk instead of shuffling
	gchar *auth_token;

	GMutex curl_lock;
	CURL *curl_handle;
	gint64 chunk_size;
};

struct oio_error_s;
struct oio_url_s;

unsigned int oio_sds_version (void) { return OIO_SDS_VERSION; }

#define CURL_DO(Sds,Var,Action) do { \
	CURL *Var = _get_proxy_handle(Sds); \
	Action; \
	_release_proxy_handle(Sds,Var); \
} while (0)

/* glibc 2.22 removed binary mode of fmemopen.
 * With this statement, we ask the compiler to link to the old version. */
#ifdef OIO_USE_OLD_FMEMOPEN
# if __GLIBC_PREREQ(2, 22)
asm (".symver fmemopen, fmemopen@GLIBC_2.2.5");
# endif
#endif

static CURL *
_get_proxy_handle (struct oio_sds_s *sds)
{
	CURL *out = NULL;

	g_mutex_lock(&sds->curl_lock);
	if (sds->curl_handle)
		out = sds->curl_handle;
	sds->curl_handle = NULL;
	g_mutex_unlock(&sds->curl_lock);

	if (!out)
	   out = _curl_get_handle_proxy();
	return out;
}

static void
_release_proxy_handle(struct oio_sds_s *sds, CURL *h)
{
	CURL *old = NULL;

	g_mutex_lock(&sds->curl_lock);
	if (sds->curl_handle)
		old = sds->curl_handle;
	sds->curl_handle = h;
	g_mutex_unlock(&sds->curl_lock);

	if (old)
		curl_easy_cleanup(old);
}

/* Chunk parsing helpers (JSON) --------------------------------------------- */

struct chunk_position_s
{
	guint meta;
	guint intra;
};

struct chunk_s
{
	struct chunk_position_s position;
	gsize size;
	guint32 score;
	gchar hexhash[STRLEN_CHUNKHASH];
	guint8 flag_success : 1;  /* only used during an upload */
	gchar url[];
};

struct metachunk_s
{
	guint meta;
	/* size of original content's segment */
	gsize size;
	/* offset in the original segment */
	gsize offset;
	GSList *chunks;
	/* for each chunk URL, a string representing the quality of the chunk */
	GHashTable *chunks_qualities;
};

static gint
_compare_chunks (const struct chunk_s *c0, const struct chunk_s *c1)
{
	EXTRA_ASSERT(c0 != NULL && c1 != NULL);
	int c = CMP(c0->position.meta, c1->position.meta);
	if (c) return c;
	c = CMP(c0->position.intra, c1->position.intra);
	if (c) return c;
	return CMP(c0->score, c1->score);
}

static void
_metachunk_clean (struct metachunk_s *mc)
{
	if (!mc)
		return;
	g_slist_free(mc->chunks);
	mc->chunks = NULL;
	if (mc->chunks_qualities) {
		g_hash_table_destroy(mc->chunks_qualities);
		mc->chunks_qualities = NULL;
	}
	g_free (mc);
}

static void
_metachunk_cleanv (struct metachunk_s **tab)
{
	if (!tab)
		return;
	for (struct metachunk_s **p = tab; *p; ++p)
		_metachunk_clean (*p);
	g_free (tab);
}

static struct chunk_s *
_load_one_chunk (struct json_object *jurl, struct json_object *jsize,
		struct json_object *jpos, struct json_object *jscore)
{
	const char *s = json_object_get_string(jurl);
	const size_t len = strlen(s);
	struct chunk_s *result = g_malloc0 (sizeof(struct chunk_s) + len + 1);
	memcpy(result->url, s, len + 1);
	result->size = json_object_get_int64(jsize);
	if (jscore != NULL)
		result->score = (guint32)json_object_get_int64(jscore);
	s = json_object_get_string(jpos);

	result->position.meta = atoi(s);
	if (NULL != (s = strchr(s, '.')))
		result->position.intra = atoi(s+1);
	return result;
}

static const char *
_chunk_pack_position (const struct chunk_s *c, gchar *buf, gsize len)
{
	g_snprintf (buf, len, "%u.%u", c->position.meta, c->position.intra);
	return buf;
}

static void
_chunks_pack (GString *gs, GSList *chunks)
{
	gchar strpos[32];

	g_string_append_c (gs, '[');
	for (GSList *l = chunks; l; l = l->next) {
		struct chunk_s *c = l->data;
		if (gs->str[gs->len - 1] != '[')
			g_string_append_c (gs, ',');
		_chunk_pack_position (c, strpos, sizeof(strpos));
		g_string_append_printf (gs,
				"{\"url\":\"%s\","
				"\"size\":%"G_GSIZE_FORMAT","
				"\"pos\":\"%s\","
				"\"hash\":\"%s\"}",
				c->url, c->size, strpos, c->hexhash);
	}
	g_string_append_c (gs, ']');
}

static GError *
_chunks_load (GSList **out, struct json_object *jtab)
{
	GSList *chunks = NULL;
	GError *err = NULL;

	for (int i = json_object_array_length(jtab); i > 0 && !err; i--) {
		struct json_object *jurl = NULL, *jpos = NULL, *jsize = NULL,
				*jhash = NULL, *jscore = NULL, *jreal_url = NULL;
		struct oio_ext_json_mapping_s m[] = {
			{"url",      &jurl,      json_type_string, 1},
			{"pos",      &jpos,      json_type_string, 1},
			{"size",     &jsize,     json_type_int,    1},
			{"hash",     &jhash,     json_type_string, 1},
			{"score",    &jscore,    json_type_int,    0},
			{"real_url", &jreal_url, json_type_string, 0},
			{NULL,NULL,0,0}
		};
		err = oio_ext_extract_json (json_object_array_get_idx (jtab, i-1), m);
		if (err) continue;

		const char *h = json_object_get_string(jhash);
		if (!oio_str_ishexa(h, 2*sizeof(chunk_hash_t)))
			err = SYSERR("JSON: invalid chunk hash: not hexa of %"G_GSIZE_FORMAT,
					2*sizeof(chunk_hash_t));
		else {
			struct chunk_s *c = _load_one_chunk(jreal_url ? jreal_url : jurl, jsize, jpos, jscore);
			g_strlcpy (c->hexhash, h, sizeof(c->hexhash));
			oio_str_upper(c->hexhash);
			chunks = g_slist_prepend (chunks, c);
		}
	}

	if (!err)
		*out = chunks;
	else
		g_slist_free_full (chunks, g_free);
	return err;
}

/* Load properties from a JSON object.
 * `props` will be created if referencing a NULL pointer.
 * The array won't be NULL-terminated, thus this function may
 * be called several times with the same array. */
static void
_properties_load(GPtrArray **props, struct json_object *jprops,
		gchar *(*val_dup)(const gchar *))
{
	EXTRA_ASSERT(props != NULL);
	EXTRA_ASSERT(jprops != NULL);
	EXTRA_ASSERT(json_object_is_type(jprops, json_type_object));

	if (*props == NULL)
		*props = g_ptr_array_new();

	json_object_object_foreach(jprops, key, val) {
		g_ptr_array_add(*props, val_dup(key));
		g_ptr_array_add(*props, val_dup(json_object_get_string(val)));
	}
}

/* Load chunks and properties from a JSON dictionary.
 * {
 *   "chunks": [ <list of chunks> ],
 *   "properties": [ <dictionary of properties> ]
 * }
 */
static GError *
_chunks_load_ext(GSList **chunks, GPtrArray **props, struct json_object *jobj)
{
	GError *err = NULL;

	struct json_object *jchunks = NULL, *jproperties = NULL;

	struct oio_ext_json_mapping_s map[] = {
		{"chunks",     &jchunks,     json_type_array,  0},
		{"properties", &jproperties, json_type_object, 0},
		{NULL,NULL,0,0}
	};

	err = oio_ext_extract_json(jobj, map);
	if (!err)
		err = _chunks_load(chunks, jchunks);
	if (!err && jproperties)
		_properties_load(props, jproperties, g_strdup);
	return err;
}

static int
_chunk_method_is_EC(const char *chunk_method)
{
	return oio_str_prefixed(chunk_method, STGPOL_DSPREFIX_EC, "/");
}

static int
_chunk_method_needs_ecd(const char *chunk_method)
{
	return oio_str_prefixed(chunk_method, STGPOL_DSPREFIX_BACKBLAZE, "/") ||
			oio_str_prefixed(chunk_method, STGPOL_DSPREFIX_EC, "/");
}

static guint
_get_meta_bound (GSList *lchunks)
{
	if (!lchunks)
		return 0;
	guint highest_meta = 0;
	for (GSList *l = lchunks; l; l = l->next) {
		struct chunk_s *c = l->data;
		highest_meta = MAX(highest_meta, c->position.meta);
	}
	return highest_meta + 1;
}

static GError *
_organize_chunks (GSList *lchunks, struct metachunk_s ***result,
		gboolean no_shuffle, gint64 k)
{
	*result = NULL;

	if (!lchunks)
		return SYSERR("No chunk received");
	const guint meta_bound = _get_meta_bound (lchunks);
	if (meta_bound > 1024*1024)
		return SYSERR("Too many metachunks");

	/* build the metachunk */
	struct metachunk_s **out = g_malloc0 ((meta_bound+1) * sizeof(void*));
	for (guint i = 0; i < meta_bound; ++i) {
		out[i] = g_malloc0 (sizeof(struct metachunk_s));
		out[i]->meta = i;
	}
	for (GSList *l = lchunks; l; l = l->next) {
		struct chunk_s *c = l->data;
		guint i = c->position.meta;
		struct metachunk_s *mc = out[i];
		mc->chunks = g_slist_prepend(mc->chunks, c);
	}

	/* check the sequence of metachunks has no gap. In addition we
	 * apply a shuffling of the chunks to avoid preferring always the
	 * same 'first' chunk returned by the proxy. */
	for (guint i = 0; i < meta_bound; ++i) {
		struct metachunk_s *mc = out[i];
		if (!mc->chunks) {
			_metachunk_cleanv (out);
			return SYSERR("Invalid chunk sequence: gap found at [%u]", i);
		}
		if (!no_shuffle)
			mc->chunks = oio_ext_gslist_shuffle (mc->chunks);
		else
			mc->chunks = g_slist_sort(mc->chunks, (GCompareFunc)_compare_chunks);
	}

	/* Compute each metachunk's size */
	for (guint i = 0; i < meta_bound; ++i) {
		/* Even with EC, the value of the 'chunk_size' attribute stored with each
		 * chunk is the size of the metachunk. */
		out[i]->size = ((struct chunk_s*)(out[i]->chunks->data))->size;
	}

	(void)k;

	/* patch each metachunk-size and multiply it by K */
//	for (guint i = 0; i < meta_bound; ++i) {
//		struct metachunk_s *mc = out[i];
//		mc->size = mc->size * k;
//		// TODO: This is not correct, figure out where it's used
//		for (GSList *l=mc->chunks; l ;l=l->next) {
//			struct chunk_s *chunk = l->data;
//			chunk->size = mc->size;
//		}
//	}

	/* Compute each metachunk's offset in the main content */
	gsize offset = 0;
	for (guint i = 0; i < meta_bound; ++i) {
		out[i]->offset = offset;
		offset += out[i]->size;
	}

	*result = out;
	return NULL;
}

/**
 * A little structure to pack the EC parameters and handle.
 * Mainly added to make the EC parameters parsing/instantiation common
 * between download and upload.
 */
struct oio_sds_ec_s
{
	int ec_handle;
	int ec_k;
	int ec_m;
};

static bool oio_sds_ec_cache_check_for_handle(const char *chunk_method);

static GError *oio_sds_ec_cache_add_handle(const char *chunk_method);

/**
 * Parses a chunk method to extract the algorithm and the K/M parameters.
 *
 * @param chunk_method The chunk method should formatted as follows:
 * 			ec/algo=<algorithm>,k=<K>,m=<M>
 * @param k Pointer to the variable where we'll store the parsed K parameter.
 * @param m Pointer to the variable where we'll store the parsed M parameter.
 * @param algorithm Pointer to the variable where we'll store the parsed EC
 * 					 algorithm
 * @return A non-null GError if one occured, NULL otherwise.
 */
static GError *
oio_sds_ec_parse_method(const char *chunk_method, int *k, int *m,
		gchar ** algorithm)
{
	GRegex *regex;
	GMatchInfo *match_info;
	GError *err = NULL;
	const char *pattern =
			"^ec\\/algo=(?P<algo>[a-z_]+),k=(?P<ec_k>[0-9]+),m=(?P<ec_m>[0-9]+)";

	regex = g_regex_new(pattern, 0, 0, &err);
	if (regex == NULL && err != NULL) {
		return err;
	}

	int matches = g_regex_match(regex, chunk_method, 0, &match_info);
	if (!matches) {
		return NEWERROR(CODE_INTERNAL_ERROR,
				"[oio_sds_upload_ec_init_handle] Unable to parse "
				"chunk method! : %s", chunk_method);
	}

	*algorithm = g_match_info_fetch_named(match_info, (const gchar *) "algo");
	*k = atoi(g_match_info_fetch_named(match_info, (const gchar *) "ec_k"));
	*m = atoi(g_match_info_fetch_named(match_info, (const gchar *) "ec_m"));

	g_match_info_free(match_info);
	g_regex_unref(regex);

	return err;
}

/**
 * Select a backend ID from the algorithm passed as parameter.
 * @param algorithm The EC algorithm.
 * @param backend_id A pointer to the parsed backend id.
 * @return A non-null GError if one occured, NULL otherwise.
 */
static GError *
oio_sds_ec_backend_type(const char *algorithm, ec_backend_id_t * backend_id)
{
	// FIXME: Add the other backends supported by liberasurecode.
	if (strcmp(algorithm, "liberasurecode_rs_vand") == 0)
		*backend_id = EC_BACKEND_LIBERASURECODE_RS_VAND;
	else
		return NEWERROR(CODE_POLICY_NOT_SUPPORTED,
				"[oio_sds_upload_ec_init_handle] The chosen EC driver "
				"is not supported! : %s", algorithm);
	return NULL;
}


/**
 * Parses the chunk_method and fills an oio_sds_ec_s with corresponding values.
 * Fails if the chunk_method is received in a bad format, if the backend isn't
 * supported, or if the driver cannot be created.
 *
 * @param chunk_method
 * @param result
 * @return
 */
static GError *
oio_sds_ec_init_handle_nocache(const char *chunk_method,
		struct oio_sds_ec_s *result)
{
	int ec_k = 0, ec_m = 0;
	gchar *algorithm = NULL;
	ec_backend_id_t backend;
	GError *err = NULL;

	err = oio_sds_ec_parse_method(chunk_method, &ec_k, &ec_m, &algorithm);
	if (err) {
		g_free(algorithm);
		return err;
	}

	err = oio_sds_ec_backend_type(algorithm, &backend);
	if (err) {
		g_free(algorithm);
		return err;
	}

	result->ec_k = ec_k;
	result->ec_m = ec_m;

/*
 * The default behavior of pyECLib is to set hd to m, which is correct for
 *   Reed-Solomon based methods (most).
 * The default checksum algorithm in pyECLib is CHKSUM_NONE, keep track of
 *   breaking changes.
 * The other algorithms however may have other requirements. So it may
 *   actually be a good idea to first parse for the algorithm, then have a
 *   function for each algorithm that parses specific parameters for
 *   the algorithm and handles the creation of libec handles.
 * TODO: Maybe Make handle creation algorithm specific ?
 */
	struct ec_args args;
	args.k = ec_k;
	args.m = ec_m;
	args.hd = ec_m;
	args.ct = CHKSUM_NONE;
// Proper cleanup of this handle is done in _sds_upload_reset
	result->ec_handle = liberasurecode_instance_create(backend, &args);
//FIXME: Handle the error codes properly (?)
	if (result->ec_handle <= 0) {
		g_free(algorithm);
		return NEWERROR(CODE_INTERNAL_ERROR,
				"[%s] Unable to create EC" "driver instance!", __func__);
	}
	g_free(algorithm);
	return err;
}

/**
 * Parses the chunk_method and fills an oio_sds_ec_s with corresponding values.
 * Fails if the chunk_method is received in a bad format, if the backend isn't
 * supported, or if the driver cannot be created.
 *
 * Will check the dummy handles cache for a handle of the same type chunk
 * method. If no similar handle type is found, one will be cached independantly
 * from the one returned.
 *
 * @param chunk_method The chunk method should formatted as follows:
 * 			ec/algo=<algorithm>,k=<K>,m=<M>
 * @param result A pointer to the ec_handle that's contain the result.
 * @return A non-null GError if one occured, NULL otherwise.
 */
static GError *
oio_sds_ec_init_handle(const char *chunk_method, struct oio_sds_ec_s *result)
{
	GError *err = NULL;
	if (!oio_sds_ec_cache_check_for_handle(chunk_method)) {
		err = oio_sds_ec_cache_add_handle(chunk_method);
		if (err)
			return err;
	}
	return oio_sds_ec_init_handle_nocache(chunk_method, result);
}

/**
 * Used to free elements of the cached handles GTree.
 */
static GError *
oio_sds_ec_cache_destroy_handle(struct oio_sds_ec_s *handle)
{
	GError *err = NULL;
	int res;
	if (handle->ec_handle) {
		res = liberasurecode_instance_destroy(handle->ec_handle);
		if (res)
			return NEWERROR(CODE_INTERNAL_ERROR,
					"[%s] Unable to destroy EC handle !", __func__);
	}
	handle->ec_handle = 0;
	g_free(handle);
	return err;
}

/**
 * Allocates a new GTree to store dummy cache handles.
 */
static void
oio_sds_ec_cache_init()
{
	handle_cache_tree = g_tree_new_full(
			(GCompareDataFunc) g_strcmp0, NULL,
			g_free, (GDestroyNotify) oio_sds_ec_cache_destroy_handle);
}

/**
 * Checks wether there's already a dummy cached handle for this chunked method.
 */
static bool
oio_sds_ec_cache_check_for_handle(const char *chunk_method)
{
	return g_tree_lookup(handle_cache_tree, chunk_method) != NULL;
}

/**
 * Adds a dummy handle to the cache for the request chunk_method.
 *
 * See oio_sds_ec_init_handle_no_cache for the chunk_method format.
 */
static GError *
oio_sds_ec_cache_add_handle(const char *chunk_method)
{
	struct oio_sds_ec_s *cached_handle = NULL;
	GError *err = NULL;
	cached_handle = g_malloc(sizeof(struct oio_sds_ec_s));


	err = oio_sds_ec_init_handle_nocache(chunk_method, cached_handle);
	if (err) {
		g_free(cached_handle);
		return err;
	}
	g_tree_insert(handle_cache_tree, g_strdup(chunk_method), cached_handle);
	return err;
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
	if (!out)
		return (struct oio_error_s*) BADREQ("Invalid argument");
	if (!ns)
		return (struct oio_error_s*) BADREQ("No namespace");

	oio_ext_set_random_reqid ();
	oio_log_lazy_init ();

	EXTRA_ASSERT (out != NULL);
	EXTRA_ASSERT (ns != NULL);
	*out = g_slice_new0 (struct oio_sds_s);
	(*out)->session_id = g_strdup(oio_ext_get_reqid());
	(*out)->ns = g_strdup (ns);
	(*out)->proxy = oio_cfg_get_proxy_containers (ns);
	(*out)->ecd = oio_cfg_get_ecd(ns);
	(*out)->sync_after_download = TRUE;
	(*out)->no_shuffle = oio_sds_no_shuffle;
	(*out)->admin = FALSE;
	g_mutex_init(&((*out)->curl_lock));
	(*out)->chunk_size = 0;

	oio_sds_ec_cache_init();

	return NULL;
}

void
oio_sds_free (struct oio_sds_s *sds)
{
	if (!sds) return;
	oio_str_clean (&sds->session_id);
	oio_str_clean (&sds->ns);
	oio_str_clean (&sds->proxy);
	oio_str_clean(&sds->ecd);
	if (sds->curl_handle)
		curl_easy_cleanup (sds->curl_handle);
	g_mutex_clear(&(sds->curl_lock));
	g_slice_free (struct oio_sds_s, sds);
//	g_tree_destroy(handle_cache_tree);
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
		case OIOSDS_CFG_FLAG_ADMIN:
			if (vlen != sizeof(int))
				return EINVAL;
			sds->admin = BOOL(*(int*)pv);
			return 0;
		case OIOSDS_CFG_FLAG_NO_SHUFFLE:
			if (vlen != sizeof(int))
				return EINVAL;
			sds->no_shuffle = BOOL(*(int*)pv);
			return 0;
		case OIOSDS_CFG_FLAG_CHUNKSIZE:
			if (vlen != sizeof(int64_t))
				return EINVAL;
			sds->chunk_size = *(int64_t *)pv;
			return 0;
		default:
			return EBADSLT;
	}
}


/* Create / destroy --------------------------------------------------------- */

struct oio_error_s*
oio_sds_create (struct oio_sds_s *sds, struct oio_url_s *url)
{
	GError *err;
	CURL_DO(sds, H, err = oio_proxy_call_container_create(H, url));
	return (struct oio_error_s *) err;
}


/* Helper to show a content ------------------------------------------------- */

typedef void oio_sds_chunk_reporter_f (gpointer data, struct chunk_s *chunk);

static GError *
_show_content (struct oio_sds_s *sds, struct oio_url_s *url, void *cb_data,
		oio_sds_info_reporter_f cb_info,
		oio_sds_chunk_reporter_f cb_chunks,
		oio_sds_property_reporter_f cb_props)
{
	EXTRA_ASSERT (sds != NULL);
	EXTRA_ASSERT (url != NULL);

	GError *err = NULL;
	GSList *chunks = NULL;
	GString *reply_body = g_string_sized_new(2048);
	gchar **props = NULL;

	/* Get the beans */
	CURL_DO(sds, H, err = oio_proxy_call_content_show(H, url,
				cb_chunks ? reply_body : NULL,
				cb_props || cb_info ? &props : NULL));

	/* Parse the beans */
	if (!err && reply_body->len > 0) {
		GRID_TRACE("Body: %s", reply_body->str);
		struct json_tokener *tok = json_tokener_new ();
		struct json_object *jbody = json_tokener_parse_ex (tok,
				reply_body->str, reply_body->len);
		json_tokener_free (tok);
		if (!json_object_is_type(jbody, json_type_array)) {
			err = SYSERR("Invalid JSON from the OIO proxy");
		} else {
			if (NULL != (err = _chunks_load (&chunks, jbody))) {
				g_prefix_error (&err, "Parsing: ");
			} else {
				GRID_TRACE("%s Got %u beans", __FUNCTION__,
						g_slist_length (chunks));
			}
		}
		json_object_put (jbody);
	}

	if (!err) {

		/* First, report the user-properties */
		for (gchar **p = props; props && *p && *(p+1); p += 2) {
			if (!g_str_has_prefix(*p, "content-meta-"))
				continue;
			const char *k = *p + sizeof("content-meta-") - 1;
			if (g_str_has_prefix(k, "x-")) {
				if (cb_props)
					cb_props (cb_data, k+2, *(p+1));
			} else if (cb_info) {
				if (!strcmp(k, "hash"))
					cb_info (cb_data, OIO_SDS_CONTENT_HASH, *(p+1));
				else if (!strcmp(k, "id"))
					cb_info (cb_data, OIO_SDS_CONTENT_ID, *(p+1));
				else if (!strcmp(k, "version"))
					cb_info (cb_data, OIO_SDS_CONTENT_VERSION, *(p+1));
				else if (!strcmp(k, "length"))
					cb_info (cb_data, OIO_SDS_CONTENT_SIZE, *(p+1));
				else if (!strcmp(k, "chunk-method"))
					cb_info (cb_data, OIO_SDS_CONTENT_CHUNKMETHOD, *(p+1));
			}
		}

		/* Eventually the chunks */
		if (cb_chunks) {
			for (GSList *l = chunks; l; l = l->next)
				cb_chunks(cb_data, l->data);
			g_slist_free (chunks);
		} else {
			g_slist_free_full (chunks, g_free);
		}
		chunks = NULL;
	}

	g_slist_free_full (chunks, g_free);
	if (props) g_strfreev (props);
	g_string_free (reply_body, TRUE);
	return err;
}


/* Download ----------------------------------------------------------------- */

struct _download_ctx_s
{
	struct oio_sds_s *sds;
	struct oio_sds_dl_src_s *src;
	struct oio_sds_dl_dst_s *dst;
	char *chunk_method;

	struct metachunk_s **metachunks;
	GSList *chunks;
};

static void
_dl_debug (const char *caller, struct oio_sds_dl_src_s *src,
		struct oio_sds_dl_dst_s *dst)
{
	if (!GRID_DEBUG_ENABLED())
		return;
	GString *out = g_string_sized_new(128);

	g_string_append_printf (out, "SRC{%s", oio_url_get(src->url, OIOURL_WHOLE));
	if (src->ranges && src->ranges[0]) {
		g_string_append_static (out, ",[");
		for (struct oio_sds_dl_range_s **p = src->ranges; *p; ++p)
			g_string_append_printf (out,
					"[%"G_GSIZE_FORMAT",%"G_GSIZE_FORMAT"]",
					(*p)->offset, (*p)->size);
		g_string_append_static (out, "]}");
	}

	g_string_append_static (out, " -> ");

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
		const struct oio_sds_dl_range_s *range, const char *c0_url,
		const char * const *headers_opt, size_t *p_nbread)
{
	size_t _write_wrapper (char *data, size_t s, size_t n, void *ignored UNUSED) {
		size_t total = s*n;
		if (total + *p_nbread > range->size) {
			GRID_WARN("server gave us more data than expected "
					"(%"G_GSIZE_FORMAT"/%"G_GSIZE_FORMAT")",
					total, (size_t)(range->size - *p_nbread));
			total = range->size - *p_nbread;
		}

		/* TODO compute a MD5SUM */

		int sent = dl->dst->data.hook.cb(dl->dst->data.hook.ctx,
				(const unsigned char*)data, total);
		if ((size_t)sent == total) {
			GRID_TRACE("user callback managed %"G_GSIZE_FORMAT" bytes", total);
			*p_nbread += (size_t ) sent;
			return s*n;  // Make libcurl think we read the whole buffer
		} else {
			GRID_WARN("user callback failed: %d/%"G_GSIZE_FORMAT" bytes sent",
					  sent, total);
			return sent;
		}
	}

	GError *err = NULL;

	gchar str_range[64] = "";
	g_snprintf (str_range, sizeof(str_range),
			"bytes=%"G_GSIZE_FORMAT"-%"G_GSIZE_FORMAT,
			range->offset, range->offset + range->size - 1);
	GRID_TRACE ("%s Range:%s %s", __FUNCTION__, str_range, c0_url);

	CURL *h = _curl_get_handle_blob ();
	struct oio_headers_s headers = {NULL,NULL};
	oio_headers_common (&headers);
	oio_headers_add (&headers, "Range", str_range);
	if (headers_opt != NULL)
		for (; headers_opt[0] && headers_opt[1]; headers_opt += 2)
			oio_headers_add(&headers, headers_opt[0], headers_opt[1]);
	curl_easy_setopt (h, CURLOPT_HTTPHEADER, headers.headers);
	curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, "GET");
	curl_easy_setopt (h, CURLOPT_URL, c0_url);
	curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_wrapper);
	curl_easy_setopt (h, CURLOPT_WRITEDATA, dl->dst->data.hook.ctx);

	CURLcode rc = curl_easy_perform (h);
	if (rc != CURLE_OK) {
		err = SYSERR("CURL: download error [%s]: (%d) %s", c0_url,
				rc, curl_easy_strerror(rc));
	} else {
		long code = 0;
		rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
		if (2 != (code/100))
			err = SYSERR("Download: (%ld)", code);
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
	GRID_TRACE("%s", __FUNCTION__);
	struct oio_sds_dl_range_s r0 = *range;
	GSList *tail_chunks = meta->chunks;

	while (r0.size > 0) {
		GRID_TRACE("%s at %"G_GSIZE_FORMAT"+%"G_GSIZE_FORMAT,
				__FUNCTION__, r0.offset, r0.size);

		if (!tail_chunks)
			return ERRPTF("Too many failures");
		struct chunk_s *chunk = tail_chunks->data;
		tail_chunks = tail_chunks->next;

		/* Attempt a read */
		size_t nbread = 0;
		GError *err = _download_range_from_chunk (dl, range,
				chunk->url, NULL, &nbread);
		EXTRA_ASSERT (nbread <= r0.size);
		if (err) {
			/* TODO manage the error kind to allow a retry */
			return err;
		} else {
			dl->dst->out_size += nbread;
			if (r0.size == G_MAXSIZE) {
				r0.size = 0;
			} else {
				r0.offset += nbread;
				r0.size -= nbread;
			}
		}
	}

	return NULL;
}

static GError *
_download_range_from_metachunk_ec(struct _download_ctx_s *dl,
								  const struct oio_sds_dl_range_s *range, struct metachunk_s *meta)
{
	GError *err = NULL;
	// Cannot access members of foreign structs for some reason ...
	struct http_get_range *mc_range = http_get_range_convert(range);
	// Easier to cleanup this way.
	struct oio_sds_ec_s ec_info;
	oio_sds_ec_init_handle(dl->chunk_method, &ec_info);
	// We need to know the chunk-size.
	int frag_length = http_get_ec_get_fragment_size(ec_info.ec_handle,
													EC_SEGMENT_SIZE);
	int chunk_size = (int) meta->size / ec_info.ec_k;
	int segments_needed = round((double) chunk_size / (double) frag_length);
	chunk_size = frag_length * segments_needed;
	// We need this to add chunks
	struct http_get_s *mc_handle =
		http_get_create_with_ec(meta->size, chunk_size, mc_range,
								ec_info.ec_k, ec_info.ec_m, ec_info.ec_handle);

	// Now to add our chunks.
	for (GSList * el = meta->chunks; el; el = el->next) {
		struct chunk_s *curr_chunk = el->data;
		http_get_add_chunk(mc_handle, curr_chunk->url);
	}

	GBytes *resulting_data = NULL;
	err = http_get_process_metachunk_range(mc_handle, &resulting_data);

	if (err)
		goto exit;

	gsize data_len = 0;
	const char *data = g_bytes_get_data(resulting_data, &data_len);

	//FIXME: Not sure why there is a cast to unsigned char
	int sent = dl->dst->data.hook.cb(dl->dst->data.hook.ctx,
									 (const unsigned char *) data, data_len);

	if (sent != (int) data_len)
		err = NEWERROR(ERRCODE_UNKNOWN_ERROR,
					   "[_download_range_from_metachunk_ec] Unable to write"
					   " all the data available ! Pushed %d bytes, only %d written.",
					   (int) data_len, sent);
	exit:
	g_bytes_unref(resulting_data);
	http_get_clean_mc_handle(mc_handle);

	return err;
}

/* The range is relative to the metachunk, not the whole content */
static GError *
_download_range_from_metachunk (struct _download_ctx_s *dl,
		struct oio_sds_dl_range_s *range, struct metachunk_s *meta)
{
	GRID_TRACE ("%s %"G_GSIZE_FORMAT"+%"G_GSIZE_FORMAT
			" chunk-method=%s from [%i] #=%u %"G_GSIZE_FORMAT"+%"G_GSIZE_FORMAT,
			__FUNCTION__, range->offset, range->size, dl->chunk_method,
			meta->meta, g_slist_length (meta->chunks),
			meta->offset, meta->size);

	EXTRA_ASSERT (meta->chunks != NULL);
	EXTRA_ASSERT (range->offset < meta->size);
	EXTRA_ASSERT (range->size <= meta->size);
	EXTRA_ASSERT (range->offset + range->size <= meta->size);

	if (_chunk_method_needs_ecd(dl->chunk_method))
		return _download_range_from_metachunk_ec(dl, range, meta);

	return _download_range_from_metachunk_replicated (dl, range, meta);
}

/* The range is relative to the whole content */
static GError *
_download_range (struct _download_ctx_s *dl, struct oio_sds_dl_range_s *range)
{
	GRID_TRACE ("%s %"G_GSIZE_FORMAT"+%"G_GSIZE_FORMAT,
			__FUNCTION__, range->offset, range->size);

	struct oio_sds_dl_range_s r0 = *range;

	for (struct metachunk_s **p = dl->metachunks; *p; ++p) {
		if ((r0.offset >= (*p)->offset)
				&& (r0.offset < (*p)->offset + (*p)->size)) {
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

	EXTRA_ASSERT (r0.size == 0);
	EXTRA_ASSERT (r0.offset == range->offset + range->size);
	return NULL;
}

static GError *
_download (struct _download_ctx_s *dl)
{
	EXTRA_ASSERT (dl->dst->type == OIO_DL_DST_HOOK_SEQUENTIAL);

	if (!oio_str_is_set(dl->chunk_method))
		return SYSERR("Download impossible: chunk-method not set");

	struct oio_sds_dl_range_s **ranges = dl->src->ranges;
	struct oio_sds_dl_range_s range_auto = {0,0};
	struct oio_sds_dl_range_s *range_autov[2] = {&range_auto, NULL};

	/* Compute the total number of bytes in the content. We will need it for
	 * subsequent checks. */
	size_t total = 0;
	for (struct metachunk_s **p = dl->metachunks; *p; ++p)
		total += (*p)->size;
	GRID_TRACE2("computed size = %"G_GSIZE_FORMAT, total);

	/* validate the ranges do not point out of the content, or ensure at least
	 * a range is set. */
	if (dl->src->ranges && dl->src->ranges[0]) {
		for (struct oio_sds_dl_range_s **p = dl->src->ranges; *p; ++p) {
			if ((*p)->offset >= total)
				return BADREQ("Range (%zd+%zd)/%zd not satisfiable: %s",
						(*p)->offset, (*p)->size, total,
						"offset bigger than content size");
			if ((*p)->size > total)
				return BADREQ("Range (%zd+%zd)/%zd not satisfiable: %s",
						(*p)->offset, (*p)->size, total,
						"range size bigger than content size");
			if ((*p)->offset + (*p)->size > total)
				return BADREQ("Range (%zd+%zd)/%zd not satisfiable: %s",
						(*p)->offset, (*p)->size, total,
						"end position bigger than content size");
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
	for (struct oio_sds_dl_range_s **p = dl->src->ranges; *p; ++p) {
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
	gsize sent = 0;
	errno = 0;
	while (sent < len) {
		size_t w = fwrite (buf+sent, 1, len-sent, out);
		if (w > 0)
			sent += w;
		else {
			if (ferror(out))
				break;
			if (feof(out))
				break;
		}
	}
	return sent;
}

static struct oio_error_s*
_download_to_hook (struct oio_sds_s *sds, struct oio_sds_dl_src_s *src,
		struct oio_sds_dl_dst_s *dst)
{
	EXTRA_ASSERT (dst->type == OIO_DL_DST_HOOK_SEQUENTIAL);
	dst->out_size = 0;
	if (!dst->data.hook.cb)
		return (struct oio_error_s*) BADREQ("Missing callback");
	_dl_debug (__FUNCTION__, src, dst);

	GError *err = NULL;
	gchar *chunk_method = NULL;
	GSList *chunks = NULL;

	/* Get the beans */
	void _on_info (void *i UNUSED, enum oio_sds_content_key_e k, const char *v) {
		if (k == OIO_SDS_CONTENT_CHUNKMETHOD)
			chunk_method = g_strdup(v);
	}
	void _on_chunk (void *i UNUSED, struct chunk_s *chunk) {
		chunks = g_slist_prepend (chunks, chunk);
	}

	/* Parse the beans */
	err = _show_content (sds, src->url, NULL, _on_info, _on_chunk, NULL);

	/* download from the beans */
	if (!err) {
		struct _download_ctx_s dl = {
			.sds = sds, .dst = dst, .src = src, .chunk_method = chunk_method,
			.metachunks = NULL, .chunks = chunks,
		};
		int shuffle = _chunk_method_needs_ecd(dl.chunk_method) || sds->no_shuffle;
		err = _organize_chunks(chunks, &dl.metachunks, shuffle, 1);
		if (!err) {
			EXTRA_ASSERT (dl.metachunks != NULL);
			err = _download (&dl);
			_metachunk_cleanv (dl.metachunks);
		}
	}

	/* cleanup and exit */
	g_slist_free_full (chunks, g_free);
	g_free(chunk_method);
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
		err = (struct oio_error_s*) SYSERR("open() error: (%d) %s", errno, strerror(errno));
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
			fclose (out);
			dst->out_size = snk0.out_size;
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
		for (struct oio_sds_dl_range_s **p = src->ranges; *p; ++p)
			total += (*p)->size;
		if (total > dst->data.buffer.length)
			return (struct oio_error_s*) BADREQ(
					"Buffer too small (%"G_GSIZE_FORMAT") "
					"for the specified ranges (%"G_GSIZE_FORMAT")",
					dst->data.buffer.length, total);
	} else {
		/* No range specified: we need more information to fake a range, e.g.
		 * the first 'dst->data.buffer.length' of the content. */
	}

	/* glibc 2.22 without binary mode adds a null-terminator, thus we must
	 * ensure the buffer is large enough. Unfortunately this requires
	 * a data copy operation. */
#if !defined(OIO_USE_OLD_FMEMOPEN) && __GLIBC_PREREQ(2, 22)
	void *bigger_buffer = g_malloc0(dst->data.buffer.length + 1);
	out = fmemopen(bigger_buffer, dst->data.buffer.length + 1, "w");
#else
	out = fmemopen(dst->data.buffer.ptr, dst->data.buffer.length, "wb");
#endif
	if (!out) {
		err = (struct oio_error_s*) SYSERR("fmemopen() error: (%d) %s",
				errno, strerror(errno));
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
		dst->out_size = dst0.out_size;
		fclose (out);
	}

#if !defined(OIO_USE_OLD_FMEMOPEN) && __GLIBC_PREREQ(2, 22)
	memmove(dst->data.buffer.ptr, bigger_buffer, dst->data.buffer.length);
	g_free(bigger_buffer);
#endif
	return err;
}

struct oio_error_s*
oio_sds_download (struct oio_sds_s *sds, struct oio_sds_dl_src_s *dl,
		struct oio_sds_dl_dst_s *snk)
{
	if (!sds || !dl || !snk || !dl->url)
		return (struct oio_error_s*) BADREQ("Missing argument");
	oio_ext_set_reqid (sds->session_id);
	oio_ext_set_admin (sds->admin);

	snk->out_size = 0;

	if (snk->type == OIO_DL_DST_HOOK_SEQUENTIAL)
		return _download_to_hook (sds, dl, snk);
	if (snk->type == OIO_DL_DST_FILE)
		return _download_to_file (sds, dl, snk);
	if (snk->type == OIO_DL_DST_BUFFER)
		return _download_to_buffer (sds, dl, snk);
	return (struct oio_error_s*) SYSERR("Sink type not supported");
}

struct oio_error_s*
oio_sds_download_to_file (struct oio_sds_s *sds, struct oio_url_s *url,
		const char *local)
{
	if (!local)
		return (struct oio_error_s*) BADREQ("Missing local path");
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
	gboolean started;
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
	GPtrArray *sys_props;

	/* set at the first prepare */
	gint64 chunk_size;
	gint64 version;
	gchar *hexid;
	gchar *stgpol;
	gchar *chunk_method;
	gchar *mime_type;

	/* current upload */
	struct metachunk_s *mc;
	struct http_put_s *put;
	GSList *http_dests;
	size_t local_done;
	GChecksum *checksum_metachunk;

	/* erasure coding */
	int ec_handle;
	int ec_k;
	int ec_m;
};

static void
_assert_no_upload (struct oio_sds_ul_s *ul)
{
	g_assert (NULL != ul);
	g_assert (NULL == ul->mc);
	g_assert (NULL == ul->put);
	g_assert (NULL == ul->http_dests);
	g_assert (NULL == ul->checksum_metachunk);
	g_assert (0 == ul->local_done);
}

static void
_sds_upload_reset (struct oio_sds_ul_s *ul)
{
	if (ul->checksum_metachunk)
		g_checksum_free (ul->checksum_metachunk);
	ul->checksum_metachunk = NULL;
	_metachunk_clean (ul->mc);
	ul->mc = NULL;
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
	if (dst->content_id && !oio_str_ishexa1(dst->content_id))
		return NULL;
	if (dst->partial || dst->append) {
		if (!dst->content_id)
			return NULL;
	}

	oio_ext_set_reqid (sds->session_id);
	oio_ext_set_admin (sds->admin);

	struct oio_sds_ul_s *ul = g_malloc0 (sizeof(*ul));
	ul->finished = FALSE;
	ul->ready_for_data = TRUE;
	ul->sds = sds;
	ul->dst = dst;
	ul->checksum_content = g_checksum_new (G_CHECKSUM_MD5);
	ul->checksum_metachunk = NULL;
	ul->buffer_tail = g_queue_new ();
	ul->metachunk_ready = g_queue_new ();
	if (dst->chunk_size > 0)
		ul->chunk_size = dst->chunk_size;
	else
		ul->chunk_size = sds->chunk_size;

	if (dst->content_id) {
		EXTRA_ASSERT(oio_str_ishexa1 (dst->content_id));
		oio_str_replace (&ul->hexid, dst->content_id);
	}
	ul->sys_props = g_ptr_array_new_with_free_func(g_free);
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
	if (ul->metachunk_ready) {
		g_queue_free_full (ul->metachunk_ready, (GDestroyNotify)_metachunk_clean);
		ul->metachunk_ready = NULL;
	}
	if (ul->metachunk_done) {
		g_list_free_full (ul->metachunk_done, (GDestroyNotify)_metachunk_clean);
		ul->metachunk_done = NULL;
	}
	if (ul->sys_props) {
		g_ptr_array_free(ul->sys_props, TRUE);
		ul->sys_props = NULL;
	}

	if (ul->ec_handle > 0) {
		//FIXME: Handle the case where instance destruction is not possible.
		int res = liberasurecode_instance_destroy(ul->ec_handle);
		g_assert(res == 0);
		ul->ec_handle = -1;
	}


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
	EXTRA_ASSERT (ul != NULL);
	if (ul->finished)
		_assert_no_upload (ul);
#endif
	return !ul || ul->finished;
}

int
oio_sds_upload_greedy (struct oio_sds_ul_s *ul)
{
	return NULL != ul && !ul->finished && ul->ready_for_data
		&& g_queue_is_empty(ul->buffer_tail);
}

int
oio_sds_upload_needs_ecd(struct oio_sds_ul_s *ul)
{
	return _chunk_method_needs_ecd(ul->chunk_method);
}

static GError *
oio_sds_upload_ec_init_handle(struct oio_sds_ul_s *ul)
{

	struct oio_sds_ec_s ec_info;
	GError *err = oio_sds_ec_init_handle(ul->chunk_method, &ec_info);
	// Fill the Upload with info.
	ul->ec_k = ec_info.ec_k;
	ul->ec_m = ec_info.ec_m;
	ul->ec_handle = ec_info.ec_handle;
	return err;
}


struct oio_error_s *
oio_sds_upload_prepare (struct oio_sds_ul_s *ul, size_t size)
{
	EXTRA_ASSERT (ul != NULL);

	GError *err = NULL;
	GString *request_body = g_string_sized_new(128);
	GString *reply_body = g_string_sized_new (1024);

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
		CURL_DO(ul->sds, H, err = oio_proxy_call_content_prepare(
					H, ul->dst->url, size, ul->dst->autocreate, &out));

		if (!err && out.header_content && !oio_str_ishexa1 (out.header_content))
			err = SYSERR("returned content-id not hexadecimal");

		if (err)
			g_prefix_error (&err, "Proxy: ");
		else {
			if (out.header_chunk_size && !ul->chunk_size)
				ul->chunk_size = g_ascii_strtoll (out.header_chunk_size, NULL, 10);
			if (out.header_version && !ul->version)
				ul->version = g_ascii_strtoll (out.header_version, NULL, 10);
			if (out.header_content && !ul->hexid)
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

	EXTRA_ASSERT(!ul->hexid || oio_str_ishexa1(ul->hexid));

	GSList *_chunks = NULL;  // GSList<struct chunk_s*>
	/* Parse the output, as a (JSON object with a) JSON array of objects
	 * with fields depicting chunks */
	if (!err) {
		struct json_tokener *tok = json_tokener_new ();
		struct json_object *jbody = json_tokener_parse_ex (tok,
				reply_body->str, reply_body->len);
		if (json_object_is_type(jbody, json_type_object))
			err = _chunks_load_ext(&_chunks, &ul->sys_props, jbody);
		else if (json_object_is_type(jbody, json_type_array))
			err = _chunks_load(&_chunks, jbody);
		else
			err = SYSERR("Invalid JSON received from OIO proxy");
		if (err)
			g_prefix_error (&err, "Parsing: ");
		json_object_put (jbody);
		json_tokener_free (tok);
	}


	/* Verify either we are doing erasure coding or not
	 * and initialize parameters and handles */
	if (!err && oio_sds_upload_needs_ecd(ul)) {
		oio_sds_upload_ec_init_handle(ul);
	}

	/* Organize the set of chunks into metachunks. */
	if (!err) {
		struct metachunk_s **out = NULL;
		// "Shuffling" in this case orders the chunks on a meta.intra basis, which is necessary for EC.
		int shuffle = oio_sds_upload_needs_ecd(ul) || ul->sds->no_shuffle;
		if ((err = _organize_chunks(_chunks, &out, shuffle, ul->ec_k)))
			g_prefix_error (&err, "Logic: ");
		else
			for (struct metachunk_s **p = out; *p; ++p)
				g_queue_push_tail (ul->metachunk_ready, *p);
		if (out)
			g_free(out);
	}
	g_slist_free(_chunks);

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

static void
_upload_feed_bytes (struct oio_sds_ul_s *ul, GBytes *bytes)
{
	g_queue_push_tail (ul->buffer_tail, bytes);
	if (!g_bytes_get_size(bytes))
		ul->ready_for_data = FALSE;
}

struct oio_error_s *
oio_sds_upload_feed (struct oio_sds_ul_s *ul,
		const unsigned char *buf, size_t len)
{
	GRID_TRACE("%s (%p) <- %"G_GSIZE_FORMAT, __FUNCTION__, ul, len);
	EXTRA_ASSERT (ul != NULL);
	g_assert (!ul->finished);
	g_assert (ul->ready_for_data);
	_upload_feed_bytes(ul, g_bytes_new (buf, len));
	return NULL;
}

static void
_finish_metachunk_upload(struct oio_sds_ul_s *ul)
{
	EXTRA_ASSERT(ul != NULL);
	EXTRA_ASSERT(ul->mc != NULL);

	ul->mc->size = ul->local_done;

	for (GSList *l = ul->mc->chunks; l; l = l->next) {
		struct chunk_s *c = l->data;
		EXTRA_ASSERT (c->position.meta == ul->mc->meta);
		c->size = ul->mc->size;
		c->flag_success = 2 == (http_put_get_http_code(ul->put, c) / 100);
	}

	if (ul->checksum_metachunk) {
		const char *h = g_checksum_get_string (ul->checksum_metachunk);
		for (GSList *l = ul->mc->chunks; l; l = l->next) {
			struct chunk_s *c = l->data;
			g_strlcpy (c->hexhash, h, sizeof(c->hexhash));
			oio_str_upper (c->hexhash);
		}
	}
}

static GError *
_sds_upload_finish (struct oio_sds_ul_s *ul)
{
	GRID_TRACE("%s (%p)", __FUNCTION__, ul);
	EXTRA_ASSERT(ul->mc != NULL);
	GError *err = NULL;

	guint failures = http_put_get_failure_number (ul->put);
	guint total = g_slist_length (ul->http_dests);
	GRID_TRACE("%s uploads %u/%u failed", __FUNCTION__, failures, total);

	if (failures >= total) {
		err = ERRPTF("No upload succeeded");
	} else {
		const gboolean is_ec = _chunk_method_is_EC(ul->chunk_method);

		_finish_metachunk_upload(ul);

		/* TODO: in case of EC, we may wanna read response headers */

		/* store the structure in holders for further commit/abort */
		for (GSList *l = ul->mc->chunks; l; l = l->next) {
			struct chunk_s *chunk = l->data;
			if (is_ec || chunk->flag_success) {
				ul->chunks_done = g_slist_prepend (ul->chunks_done, chunk);
			} else {
				ul->chunks_failed = g_slist_prepend (ul->chunks_failed, chunk);
			}
		}

		ul->metachunk_done = g_list_append (ul->metachunk_done, ul->mc);
		GRID_TRACE("%s > metachunks +1 -> %u (%"G_GSIZE_FORMAT")", __FUNCTION__,
				g_list_length(ul->metachunk_done),
				ul->mc->size);
		ul->mc = NULL;
	}

	_sds_upload_reset (ul);
	return err;
}

static void
_sds_upload_add_headers(struct oio_sds_ul_s *ul, struct http_put_dest_s *dest)
{
	http_put_dest_add_header (dest, PROXYD_HEADER_REQID,
			"%s", oio_ext_get_reqid());

	if (oio_ext_is_admin()) {
		/* TODO(jfs): melt these informatiion with the 'mode' (already
		 * containing autocreate, etc */
		http_put_dest_add_header (dest, PROXYD_HEADER_ADMIN, "yes");
	}

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

	struct oio_url_s *url = oio_url_dup(ul->dst->url);
	gchar version[21];
	g_sprintf(version, "%"G_GINT64_FORMAT, ul->version);
	oio_url_set(url, OIOURL_VERSION, version);
	oio_url_set(url, OIOURL_CONTENTID, ul->hexid);
	http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "full-path", "%s",
			oio_url_get(url, OIOURL_FULLPATH));
	oio_url_clean(url);

	http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "oio-version", "%s",
			oio_sds_client_version);

	http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "content-storage-policy",
			"%s", ul->stgpol);
	http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "content-chunk-method",
			"%s", ul->chunk_method);
	http_put_dest_add_header (dest, RAWX_HEADER_PREFIX "content-mime-type",
			"%s", ul->mime_type);
}

static GError *
_sds_upload_renew (struct oio_sds_ul_s *ul)
{
	GRID_TRACE("%s (%p)", __FUNCTION__, ul);

	struct oio_error_s *err = NULL;

	EXTRA_ASSERT (NULL == ul->put);
	EXTRA_ASSERT (NULL == ul->http_dests);
	EXTRA_ASSERT (NULL == ul->checksum_metachunk);

	ul->started = TRUE;

	/* ensure we have a new destination (metachunk) */
	if (!ul->mc) {
		if (g_queue_is_empty (ul->metachunk_ready)) {
			if (NULL != (err = oio_sds_upload_prepare (ul, 1)))
				return (GError*) err;
		}
		ul->mc = g_queue_pop_head (ul->metachunk_ready);
	}
	EXTRA_ASSERT (NULL != ul->mc);

	/* patch the metachunk characteristics (position now known) */
	if (ul->metachunk_done) {
		struct metachunk_s *last = (g_list_last (ul->metachunk_done))->data;
		ul->mc->offset = last->offset + last->size;
		ul->mc->meta = last->meta + 1;
	} else if (BOOL(ul->dst->partial)) {
		ul->mc->offset = ul->dst->offset;
		ul->mc->meta = ul->dst->meta_pos;
	} else {
		ul->mc->offset = 0;
		ul->mc->meta = 0;
	}

	/* then patch each chunk with the same meta-position */
	for (GSList *l = ul->mc->chunks; l; l = l->next) {
		struct chunk_s *c = l->data;
		c->position.meta = ul->mc->meta;
	}

	ul->checksum_metachunk = g_checksum_new (G_CHECKSUM_MD5);

	/* Initiate the PolyPut (c) with all its targets */
	if (oio_sds_upload_needs_ecd(ul)) {
		/*
		 * OH LAWD HERE COMES THE HEADACHE
		 * So ul->chunk_size is actually used BOTH as chunk_size AND as
		 * metachunk_size. (according to Florent). However, the only time I
		 * could see it used as metachunk_size was in tool_roundtrip by
		 * explicitly forcing the ul->chunk_size parameter to be the maximum
		 * expected chunk size. So since that is effectively the only case
		 * where that happens, it's better to add this tiny (read: ugly)
		 * hack so that the tool_roundtrip stuff works.
		 */
		struct chunk_s *c = g_slist_nth_data(ul->mc->chunks, 0);
		gint64 actual_chunk_size =
				((gsize) ul->chunk_size !=
				c->size) ? ul->chunk_size / ul->ec_k : (gint64) c->size;
		ul->put =
				http_put_create_with_ec(-1, actual_chunk_size, ul->ec_handle,
				ul->ec_k, ul->ec_m, ul->checksum_metachunk);
	} else
		ul->put = http_put_create(-1, ul->chunk_size);

	for (GSList * l = ul->mc->chunks; l; l = l->next) {
		struct chunk_s *c = l->data;
		struct http_put_dest_s *dest = http_put_add_dest(ul->put, c->url, c);

		_sds_upload_add_headers(ul, dest);

		http_put_dest_add_header(dest, RAWX_HEADER_PREFIX "chunk-id",
				"%s", strrchr(c->url, '/') + 1);

		gchar strpos[32];
		_chunk_pack_position(c, strpos, sizeof(strpos));
		http_put_dest_add_header(dest, RAWX_HEADER_PREFIX "chunk-pos",
				"%s", strpos);

		ul->http_dests = g_slist_append(ul->http_dests, dest);
	}

	GRID_TRACE("%s (%p) upload ready!", __FUNCTION__, ul);
	return NULL;
}

struct oio_error_s *
oio_sds_upload_step (struct oio_sds_ul_s *ul)
{
	static const char *end = "";
	GRID_TRACE("%s (%p)", __FUNCTION__, ul);
	EXTRA_ASSERT (ul != NULL);

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
				GBytes *empty = g_bytes_new_static (end, 0);
				http_put_feed (ul->put, empty);
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
		EXTRA_ASSERT (NULL == ul->http_dests);
		EXTRA_ASSERT (NULL == ul->checksum_metachunk);
		EXTRA_ASSERT (0 == ul->local_done);

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
		} else {
			/* maybe we received the termination buffer */
			GBytes *buf = g_queue_pop_head (ul->buffer_tail);
			if (0 >= g_bytes_get_size (buf) && ul->started) {
				ul->ready_for_data = FALSE;
				ul->finished = TRUE;
				g_bytes_unref (buf);
			} else {
				/* XXX JFS: if no upload at all has ever been started and we
				 * received a buffer (empty or not), then we have a stream and
				 * we need at least one empty chunk to be able to rebuid the
				 * content. So we re-enqueue the buffer and let the PUT happen. */
				g_queue_push_head (ul->buffer_tail, buf);
				GError *err = _sds_upload_renew (ul);
				if (NULL != err) {
					GRID_TRACE("%s (%p) Failed to renew the upload", __FUNCTION__, ul);
					return (struct oio_error_s*) err;
				}
			}
		}
		return NULL;
	}

	EXTRA_ASSERT (ul->put != NULL);
	EXTRA_ASSERT (0 != http_put_expected_bytes (ul->put));

	/* An upload is really running, maybe feed it */
	if (!g_queue_is_empty (ul->buffer_tail)) {
		GRID_TRACE("%s (%p) Data ready!", __FUNCTION__, ul);
		GBytes *buf = g_queue_pop_head (ul->buffer_tail);

		gsize len = g_bytes_get_size (buf);
		gsize max = http_put_expected_bytes (ul->put);
		EXTRA_ASSERT (max != 0);

		/* the upload still wants more bytes */
		if (!len) {
			GRID_TRACE("%s (%p) tail buffer", __FUNCTION__, ul);
			EXTRA_ASSERT (FALSE == ul->ready_for_data);
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
			if (ul->checksum_metachunk)
				g_checksum_update (ul->checksum_metachunk, b, l);
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
_chunks_remove (GSList *failed, GSList *done)
{
	if (!failed && !done)
		return;

	/* Merge both lists */
	GPtrArray *tmp = g_ptr_array_new();
	for (GSList *l=failed; l ;l=l->next)
		g_ptr_array_add(tmp, ((struct chunk_s*)(l->data))->url);
	for (GSList *l=done; l ;l=l->next)
		g_ptr_array_add(tmp, ((struct chunk_s*)(l->data))->url);
	g_ptr_array_add(tmp, NULL);

	GError *err = http_poly_delete((gchar**)(tmp->pdata));

	g_ptr_array_free(tmp, TRUE);

	if (err) {
		GRID_WARN("Error rolling back some chunks: (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
	}
}

struct oio_error_s *
oio_sds_upload_commit (struct oio_sds_ul_s *ul)
{
	GRID_TRACE("%s (%p) append=%u", __FUNCTION__, ul, ul->dst->append);
	EXTRA_ASSERT (ul != NULL);

	if (ul->put && !http_put_done (ul->put))
		return (struct oio_error_s *) SYSERR("RAWX upload not completed");

	gint64 size = ul->dst->offset;
	for (GList *l = g_list_first(ul->metachunk_done); l; l = g_list_next(l))
		size += ((struct metachunk_s*) l->data)->size;

	GString *request_body = g_string_sized_new(2048);
	GString *reply_body = g_string_sized_new (256);
	_chunks_pack (request_body, ul->chunks_done);

	gchar hash[STRLEN_CHUNKHASH];
	g_strlcpy (hash, g_checksum_get_string (ul->checksum_content), sizeof(hash));
	oio_str_upper (hash);

	/* XXX: this may be unsafe if we allow to retry a failed commit. */
	if (ul->dst->properties) {
		for (int i = 0;
				ul->dst->properties[i] && ul->dst->properties[i+1];
				i += 2) {
			g_ptr_array_add(ul->sys_props, g_strdup(ul->dst->properties[i]));
			g_ptr_array_add(ul->sys_props, g_strdup(ul->dst->properties[i+1]));
		}
	}
	g_ptr_array_add(ul->sys_props, NULL);

	struct oio_proxy_content_create_in_s in = {
		.size = size,
		.version = ul->version,
		.content = ul->hexid,
		.chunks = request_body,
		.hash = hash,
		.stgpol = ul->stgpol,
		.chunk_method = ul->chunk_method,
		.append = BOOL(ul->dst->append),
		.update = BOOL(ul->dst->partial),
		.properties = (const char * const *)ul->sys_props->pdata,
	};

	GRID_TRACE("%s (%p) Saving %s", __FUNCTION__, ul, request_body->str);
	GError *err = NULL;
	CURL_DO(ul->sds, H, err = oio_proxy_call_content_create (H, ul->dst->url, &in, reply_body));

	g_string_free (request_body, TRUE);
	g_string_free (reply_body, TRUE);
	return (struct oio_error_s*) err;
}

struct oio_error_s *
oio_sds_upload_abort (struct oio_sds_ul_s *ul)
{
	EXTRA_ASSERT (ul != NULL);
	_chunks_remove(ul->chunks_failed, ul->chunks_done);
	return NULL;
}

static void
_upload_abort_no_error(struct oio_sds_ul_s *ul)
{
	EXTRA_ASSERT (ul != NULL);
	GRID_WARN("Aborting...");
	struct oio_error_s *e = oio_sds_upload_abort (ul);
	if (e) {
		GRID_WARN("Upload abort failed: (%d) %s",
				oio_error_code (e), oio_error_message (e));
		oio_error_free (e);
	}
}

static void
_ul_debug (const char *caller, struct oio_sds_ul_src_s *src,
		struct oio_sds_ul_dst_s *dst)
{
	if (!GRID_DEBUG_ENABLED())
		return;
	GString *out = g_string_sized_new(128);

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
		return BADREQ("Invalid source, destination or content id");

	struct oio_error_s *err = NULL;

	/* If a size is specified, then prepare enough chunks.
	 * Specifying no size, then preparing no chunks, will require to
	 * call the proxy as soon as a new chunk is necessary, then issuing
	 * several calls to the proxy. */
	if (src->data.hook.size > 0 && src->data.hook.size != (size_t)-1)
		err = oio_sds_upload_prepare(ul, src->data.hook.size);

	size_t sent = 0;

	while (!err && !oio_sds_upload_done (ul)) {
		GRID_TRACE("%s (%p) not done yet", __FUNCTION__, ul);

		/* feed the upload queue */
		if (oio_sds_upload_greedy (ul)) {
			size_t max = 8 * 1024 * 1024;
			if (src->data.hook.size > 0 && src->data.hook.size != (size_t)-1) {
				const size_t remaining = src->data.hook.size - sent;
				max = MIN(remaining, max);
				GRID_TRACE("%s (%p) greedy, expecting %"G_GSIZE_FORMAT" bytes "
						"(%"G_GSIZE_FORMAT" remain among %"G_GSIZE_FORMAT")",
						__FUNCTION__, ul, max, remaining, src->data.hook.size);
			}

			if (0 == max) {
				_upload_feed_bytes (ul, g_bytes_new_static((guint8*)"", 0));
			} else {
				guint8 *b = g_malloc(max);
				size_t l = src->data.hook.cb (src->data.hook.ctx, b, max);
				switch (l) {
					case OIO_SDS_UL__ERROR:
						err = (struct oio_error_s*) SYSERR("data hook error");
						break;
					case OIO_SDS_UL__DONE:
						_upload_feed_bytes (ul, g_bytes_new_static((guint8*)"", 0));
						break;
					case OIO_SDS_UL__NODATA:
						GRID_INFO("%s No data ready from user's hook", __FUNCTION__);
						break;
					default:
						_upload_feed_bytes (ul, g_bytes_new_take(b, l));
						b = NULL;
						sent += l;
						break;
				}
				oio_pfree0(&b, NULL);
			}
		}

		/* do the I/O things */
		if (!err)
			err = oio_sds_upload_step (ul);
	}

	if (!err) {
		err = oio_sds_upload_commit (ul);
		if (err) {
			if (oio_error_code(err) == CODE_CONTENT_EXISTS ||
					oio_error_code(err) == CODE_CONTENT_PRECONDITION) {
				_upload_abort_no_error(ul);
			} else {
				GRID_WARN("Conditons unsafe to abort the upload: (%d) %s",
						oio_error_code(err), oio_error_message(err));
			}
		}
	} else {
		_upload_abort_no_error(ul);
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
	if (dst->content_id && !oio_str_ishexa1 (dst->content_id))
		return (struct oio_error_s*) BADREQ("content_id not hexadecimal");
	if (dst->partial || dst->append) {
		if (!dst->content_id)
			return (struct oio_error_s*) BADREQ("Append/Partial uploads"
					" require a content_id");
	}

	if (src->type == OIO_UL_SRC_HOOK_SEQUENTIAL)
		return (struct oio_error_s*) _upload_sequential (sds, dst, src);

	return (struct oio_error_s*) BADREQ("Invalid argument: %s",
			"source type not managed");
}

static size_t
_read_FILE (void *u, unsigned char *ptr, size_t len)
{
	FILE *in = u;
	GRID_TRACE("Reading at most %"G_GSIZE_FORMAT, len);
	size_t r = fread(ptr, 1, len, in);
	if (0 != r) return r;
	if (ferror(in)) return OIO_SDS_UL__ERROR;
	if (feof(in)) return OIO_SDS_UL__DONE;
	return OIO_SDS_UL__NODATA;
}

struct oio_error_s*
oio_sds_upload_from_file (struct oio_sds_s *sds, struct oio_sds_ul_dst_s *dst,
			  const char *local, size_t off, size_t len)
{
	if (!sds || !dst || !local)
		return (struct oio_error_s*) BADREQ("Invalid argument");
	if (dst->content_id && !oio_str_ishexa1 (dst->content_id))
		return (struct oio_error_s*) BADREQ("content_id not hexadecimal");

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
	if (dst->content_id && !oio_str_ishexa1 (dst->content_id))
		return (struct oio_error_s*) BADREQ("content_id not hexadecimal");

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
	struct json_object *jn, *jh, *jp, *js, *jv;
	struct oio_ext_json_mapping_s m[] = {
		{"name", &jn, json_type_string, 1},
		{"hash", &jh, json_type_string, 1},
		{"size", &js, json_type_int, 1},
		{"version",  &jv, json_type_int, 1},
		{"properties",  &jp, json_type_object, 0},
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

	gchar *_fake_strdup(const gchar *src) {
		return (gchar*)src;
	}
	if (jp) {
		GPtrArray *props = NULL;
		_properties_load(&props, jp, _fake_strdup);
		g_ptr_array_add(props, NULL);
		item.properties = (const char * const *)g_ptr_array_free(props, FALSE);
	} else {
		item.properties = NULL;
	}

	if (listener->on_item)
		listener->on_item (listener->ctx, &item);

	g_free((gpointer)item.properties);
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

	/* Type changed to size_t in json-c 0.13 */
	GRID_TRACE2("Found %zu items, %zu prefixes",
			(size_t)json_object_array_length(jobjects),
			(size_t)json_object_array_length(jprefixes));

	const int count_objects = json_object_array_length(jobjects);
	if (count_objects >= 0)
		*pcount = (size_t) count_objects;
	for (int i = count_objects; i > 0 && !err; i--) {
		struct json_object *it = json_object_array_get_idx (jobjects, i-1);
		err = _notify_list_item (listener, it);
	}

	const int count_prefixes = json_object_array_length(jprefixes);
	for (int i = count_prefixes; i > 0 && !err; i--) {
		struct json_object *it = json_object_array_get_idx(jprefixes, i-1);
		err = _notify_list_prefix(listener, it);
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
	GString *reply_body = g_string_sized_new (2048);

	// Query the proxy
	GError *err = oio_proxy_call_content_list(h, param, reply_body);

	// Unpack the reply
	if (!err) {
		GRID_TRACE("Parsing (%"G_GSIZE_FORMAT") %s", reply_body->len, reply_body->str);
		struct json_tokener *tok = json_tokener_new ();
		struct json_object *jbody = json_tokener_parse_ex (tok,
				reply_body->str, reply_body->len);
		if (!json_object_is_type(jbody, json_type_object)) {
			err = ERRPTF("Invalid JSON from the OIO proxy");
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
		return (struct oio_error_s*) BADREQ("Missing argument");
	if (!oio_url_has_fq_container (param->url))
		return (struct oio_error_s*) BADREQ("Partial URI");
	oio_ext_set_reqid (sds->session_id);
	oio_ext_set_admin (sds->admin);

	GRID_DEBUG("LIST prefix %s marker %s end %s max %"G_GSIZE_FORMAT,
		param->prefix, param->marker, param->end, param->max_items);

	gchar *next = param->marker ? g_strdup (param->marker) : NULL;
	listener->out_truncated = 0;
	listener->out_count = 0;
	GError *err = NULL;

	for (;;) {
		gchar *nextnext = NULL;
		int _hook_bound (void *ctx UNUSED, const char *next_marker) {
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

		CURL_DO(sds, H, err = _single_list (&p0, &l0, H));
		if (NULL != err) {
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
			err = ERRPTF("Truncated list without end marker");
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

/* Quota -------------------------------------------------------------------- */

struct oio_error_s*
oio_sds_get_usage (struct oio_sds_s *sds, struct oio_url_s *url,
		struct oio_sds_usage_s *out)
{
	GString *props_str = NULL;
	GError *err = NULL;
	json_object *root = NULL, *props = NULL, *syst = NULL;
	json_object *usage = NULL, *quota = NULL, *objects = NULL;

	CURL_DO(sds, H, err = oio_proxy_call_container_get_properties(H, url, &props_str));
	if (err)
		goto end;
	root = json_tokener_parse(props_str->str);

	struct oio_ext_json_mapping_s map0[] = {
		{"properties", &props, json_type_object, 0},
		{"system",     &syst,  json_type_object, 1},
		{NULL,NULL,0,0}
	};
	struct oio_ext_json_mapping_s map1[] = {
		{OIO_SDS_CONTAINER_USAGE,   &usage,   json_type_string, 1},
		{OIO_SDS_CONTAINER_QUOTA,   &quota,   json_type_string, 0},
		{OIO_SDS_CONTAINER_OBJECTS, &objects, json_type_string, 0},
		{NULL,NULL,0,0}
	};
	err = oio_ext_extract_json(root, map0);
	if (!err)
		err = oio_ext_extract_json(syst, map1);
	if (err)
		goto end;

	if (usage)
		out->used_bytes = (size_t) json_object_get_int64(usage);

	if (quota)
		out->quota_bytes = (size_t) json_object_get_int64(quota);
	else
		out->quota_bytes = SIZE_MAX;

	if (objects)
		out->used_objects = (int) json_object_get_int64(objects);

end:
	if (root)
		json_object_put(root);
	if (props_str)
		g_string_free(props_str, TRUE);

	return (struct oio_error_s*) err;
}


/* Misc. -------------------------------------------------------------------- */

struct oio_error_s*
oio_sds_truncate (struct oio_sds_s *sds, struct oio_url_s *url, size_t size)
{
	if (!sds || !url)
		return (struct oio_error_s*) BADREQ("Missing argument");
	oio_ext_set_reqid (sds->session_id);

	GError *err;
	CURL_DO(sds, H, err = oio_proxy_call_content_truncate(H, url, size));
	return (struct oio_error_s*) err;
}

struct oio_error_s*
oio_sds_drain(struct oio_sds_s *sds, struct oio_url_s *url)
{
	if (!sds || !url)
		return (struct oio_error_s*) BADREQ("Missing argument");
	oio_ext_set_reqid(sds->session_id);

	GError *err;
	CURL_DO(sds, H, err = oio_proxy_call_content_drain(H, url));
	return (struct oio_error_s*) err;
}

struct oio_error_s*
oio_sds_delete (struct oio_sds_s *sds, struct oio_url_s *url)
{
	if (!sds || !url)
		return (struct oio_error_s*) BADREQ("Missing argument");
	oio_ext_set_reqid (sds->session_id);
	oio_ext_set_admin (sds->admin);

	GError *err;
	CURL_DO(sds,H,err = oio_proxy_call_content_delete (H, url));
	return (struct oio_error_s*) err;
}

struct oio_error_s*
oio_sds_delete_container (struct oio_sds_s *sds, struct oio_url_s *url)
{
	if (!sds || !url)
		return (struct oio_error_s*) BADREQ("Missing argument");
	oio_ext_set_reqid (sds->session_id);
	oio_ext_set_admin (sds->admin);

	GError *err;
	CURL_DO(sds,H,err = oio_proxy_call_container_delete (H, url));
	return (struct oio_error_s*) err;
}

struct oio_error_s*
oio_sds_show_content (struct oio_sds_s *sds, struct oio_url_s *url,
		void *cb_data,
		oio_sds_info_reporter_f cb_info,
		oio_sds_metachunk_reporter_f cb_metachunks,
		oio_sds_property_reporter_f cb_props)
{
	if (!sds || !url)
		return (struct oio_error_s*) BADREQ("Missing argument");
	oio_ext_set_reqid (sds->session_id);
	oio_ext_set_admin (sds->admin);

	GError *err = NULL;
	gsize offset = 0;
	GSList *chunks = NULL;

	void _on_prop (void *i UNUSED, const char *k, const char *v) {
		return cb_props (cb_data, k, v);
	}
	void _on_chunk (void *i UNUSED, struct chunk_s *chunk) {
		chunks = g_slist_prepend (chunks, chunk);
	}
	void _on_info (void *i UNUSED, enum oio_sds_content_key_e k, const char *v) {
		return cb_info (cb_data, k, v);
	}

	err = _show_content (sds, url, NULL,
			cb_info? _on_info : NULL, _on_chunk, cb_props? _on_prop : NULL);
	if (!err) {
		GTree *positions_seen = g_tree_new_full(oio_str_cmp3, NULL, g_free, NULL);
		chunks = g_slist_sort (chunks, (GCompareFunc)_compare_chunks);
		for (GSList *l = chunks; l; l = l->next) {
			const struct chunk_s *chunk = l->data;
			gchar *position = g_strdup_printf("%u", chunk->position.meta);
			if (g_tree_lookup(positions_seen, position)) {
				g_free (position);
			} else {
				if (cb_metachunks)
					cb_metachunks(cb_data, chunk->position.meta, offset, chunk->size);
				offset += chunk->size;
				g_tree_replace (positions_seen, position, GINT_TO_POINTER(1));
			}
		}
		g_tree_destroy (positions_seen);
	}

	g_slist_free_full (chunks, g_free);
	return (struct oio_error_s*) err;
}

struct oio_error_s*
oio_sds_has (struct oio_sds_s *sds, struct oio_url_s *url, int *phas)
{
	if (!sds || !url || !phas)
		return (struct oio_error_s*) BADREQ("Missing argument");
	oio_ext_set_reqid (sds->session_id);
	oio_ext_set_admin (sds->admin);
	GError *err;
	CURL_DO(sds, H, err = oio_proxy_call_content_show (H, url, NULL, NULL));
	*phas = (err == NULL);
	if (err && (CODE_IS_NOTFOUND(err->code) || err->code == CODE_NOT_FOUND))
		g_clear_error(&err);
	return (struct oio_error_s*) err;
}

static struct oio_error_s *
_oio_sds_get_properties(struct oio_sds_s *sds, struct oio_url_s *url,
		on_element_f fct, void *ctx,
		GError* (*call_proxy)(CURL*, struct oio_url_s *, GString **))
{
	if (!sds || !url)
		return (struct oio_error_s*) BADREQ("Missing argument");
	oio_ext_set_reqid (sds->session_id);
	oio_ext_set_admin (sds->admin);

	GString *value = NULL;
	struct oio_error_s *err;

	CURL_DO(sds, H, err = (struct oio_error_s*) call_proxy(H, url, &value));
	if (err)
		return err;

	json_object *json = json_tokener_parse(value->str);
	json_object *props = NULL;
	if (!json_object_object_get_ex(json, "properties", &props)) {
		err = (struct oio_error_s *) SYSERR(
				"Malformed answer received from proxy: no 'properties' key");
	} else {
		json_object_object_foreach(props, key, val) {
			fct(ctx, key, json_object_get_string(val));
		}
	}
	json_object_put(json);
	g_string_free(value, TRUE);
	return err;
}

struct oio_error_s*
oio_sds_get_container_properties(struct oio_sds_s *sds, struct oio_url_s *url,
		on_element_f fct, void *ctx)
{
	return _oio_sds_get_properties(sds, url, fct, ctx,
			oio_proxy_call_container_get_properties);
}

struct oio_error_s*
oio_sds_set_container_properties (struct oio_sds_s *sds, struct oio_url_s *url,
		const char * const *values)
{
	if (!sds || !url || !values)
		return (struct oio_error_s*) BADREQ("Missing argument");
	oio_ext_set_reqid (sds->session_id);
	oio_ext_set_admin (sds->admin);

	GError *err;
	CURL_DO(sds, H, err = oio_proxy_call_container_set_properties(H, url, values));
	return (struct oio_error_s*) err;
}

struct oio_error_s*
oio_sds_get_content_properties(struct oio_sds_s *sds, struct oio_url_s *url,
		on_element_f fct, void *ctx)
{
	return _oio_sds_get_properties(sds, url, fct, ctx,
			oio_proxy_call_content_get_properties);
}

struct oio_error_s*
oio_sds_set_content_properties (struct oio_sds_s *sds, struct oio_url_s *url,
		const char * const *values)
{
	if (!sds || !url || !values)
		return (struct oio_error_s*) BADREQ("Missing argument");
	oio_ext_set_reqid (sds->session_id);
	oio_ext_set_admin (sds->admin);

	GError *err;
	CURL_DO(sds, H, err = oio_proxy_call_content_set_properties(H, url, values););
	return (struct oio_error_s*) err;
}
