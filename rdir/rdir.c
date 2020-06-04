/*
OpenIO SDS rdir
Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include <malloc.h>
#include <unistd.h>

#include <glib.h>
#include <json-c/json.h>
#include <leveldb/c.h>

#include <core/oiostr.h>
#include <core/url_ext.h>
#include <metautils/lib/metautils.h>
#include <server/network_server.h>
#include <server/server_variables.h>
#include <rdir/rdir_variables.h>
#include <metautils/lib/common_variables.h>

#include <proxy/transport_http.h>

#include "routes.h"

static gchar *ns_name = NULL;
static gchar *basedir = NULL;
static gchar *service_id = NULL;
static gboolean config_system = TRUE;
static GSList *config_paths = NULL;
static GSList *config_urlv = NULL;
static struct network_server_s *server = NULL;
static struct grid_task_queue_s *gtq_admin = NULL;
static GThread *th_gtq_admin = NULL;
static GCond cond_bases;
static GMutex lock_bases;
static GTree *tree_bases = NULL;

#define OPT(N) _option(args, (N))

#define CHECK_METHOD(M) do { \
	if (0 != strcmp(args->rq->cmd, (M))) \
		return _reply_method_error(args->rp); \
} while (0)

#define CFG_GROUP "rdir-server"

#define CHUNK_PREFIX "chunk|"
#define ADMIN_PREFIX "admin|"
#define CONTAINER_PREFIX "container|"

#define KEY_LOCK	 ADMIN_PREFIX "lock"
#define KEY_INCIDENT ADMIN_PREFIX "incident_date"

#define STRDUPA(Out, Src, Len) do { \
	if (Src) { \
		(Out) = alloca(1 + (Len)); \
		g_strlcpy((Out), (Src), 1 + (Len)); \
	} else { \
		(Out) = NULL; \
	} \
} while (0)

#define RDIR_LISTING_DEFAULT_LIMIT 1000
#define RDIR_LISTING_MAX_LIMIT 10000
/* ------------------------------------------------------------------------- */

struct req_args_s
{
	struct http_request_s *rq;
	struct http_reply_ctx_s *rp;
	struct oio_requri_s ruri;
};

static const char *
_option(struct req_args_s *args, const char *name)
{
	gsize namelen = strlen(name);
	gchar *needle = g_alloca(namelen+2);
	memcpy(needle, name, namelen);
	needle[namelen] = '=';
	needle[namelen+1] = 0;

	if (args->ruri.query_tokens != NULL) {
		for (gchar **p = args->ruri.query_tokens ; *p ; ++p) {
			if (g_str_has_prefix(*p, needle))
				return (*p) + namelen + 1;
		}
	}
	return NULL;
}

static enum http_rc_e
_reply_bytes(struct http_reply_ctx_s *rp,
		int code, const gchar * msg, GBytes * bytes)
{
	rp->set_status(code, msg);
	if (bytes) {
		if (g_bytes_get_size(bytes) > 0)
			rp->set_content_type("application/json");
		rp->set_body_bytes(bytes);
	} else {
		rp->set_body_bytes(NULL);
	}
	rp->finalize();
	return HTTPRC_DONE;
}

static enum http_rc_e
_reply_json(struct http_reply_ctx_s *rp,
		int code, const gchar * msg, GString * gstr)
{
	return _reply_bytes(rp, code, msg,
			gstr ? g_string_free_to_bytes(gstr) : NULL);
}

static enum http_rc_e
_reply_json_error(struct http_reply_ctx_s *rp,
		int code, const char *msg, GString * gstr)
{
	if (gstr)
		rp->access_tail("e=%.*s", gstr->len, gstr->str);
	return _reply_json(rp, code, msg, gstr);
}

static void
_append_status(GString *out, gint code, const char * msg)
{
	EXTRA_ASSERT(out != NULL);
	oio_str_gstring_append_json_pair_int(out, "status", code);
	g_string_append_c(out, ',');
	oio_str_gstring_append_json_pair(out, "message", msg);
}

static GString *
_create_status(gint code, const gchar * msg)
{
	GString *gstr = g_string_sized_new(256);
	g_string_append_c(gstr, '{');
	_append_status(gstr, code, msg);
	g_string_append_c(gstr, '}');
	return gstr;
}

static GString *
_create_status_error(GError * e)
{
	GString *gstr = _create_status(e->code, e->message);
	g_error_free(e);
	return gstr;
}

static enum http_rc_e
_reply_format_error(struct http_reply_ctx_s *rp, GError * err)
{
	return _reply_json_error(rp, HTTP_CODE_BAD_REQUEST,
			"Bad request", _create_status_error(err));
}

static enum http_rc_e
_reply_method_error(struct http_reply_ctx_s *rp)
{
	return _reply_json_error(rp, HTTP_CODE_METHOD_NOT_ALLOWED,
			"Method not allowed", _create_status_error(BADREQ("Bad method")));
}

static enum http_rc_e
_reply_system_error(struct http_reply_ctx_s *rp, GError *err)
{
	return _reply_json_error(rp, HTTP_CODE_INTERNAL_ERROR,
			"Backend error", _create_status_error(err));
}

static enum http_rc_e
_reply_unavailable(struct http_reply_ctx_s *rp, GError *err)
{
	return _reply_json_error(rp, HTTP_CODE_SRV_UNAVAILABLE,
			"Backend unavailable", _create_status_error(err));
}

static enum http_rc_e
_reply_forbidden(struct http_reply_ctx_s *rp, GError *err)
{
	return _reply_json_error(rp, HTTP_CODE_FORBIDDEN,
			"Forbidden", _create_status_error(err));
}

static enum http_rc_e
_reply_not_found(struct http_reply_ctx_s *rp, GError *err)
{
	return _reply_json_error(rp, HTTP_CODE_NOT_FOUND,
			"Not found", _create_status_error(err));
}

static enum http_rc_e
_reply_common_error(struct http_reply_ctx_s *rp, GError *err)
{
	EXTRA_ASSERT(err != NULL);
	if (CODE_IS_NOTFOUND(err->code))
		return _reply_not_found(rp, err);
	switch (err->code) {
		case CODE_NOT_FOUND:
			return _reply_not_found(rp, err);
		case CODE_NOT_ALLOWED:
			return _reply_forbidden(rp, err);
		case CODE_UNAVAILABLE:
		case CODE_EXCESSIVE_LOAD:
			rp->add_header("Retry-After", g_strdup("1"));
			return _reply_unavailable(rp, err);
		default:
			return _reply_system_error(rp, err);
	}
}

static enum http_rc_e
_reply_created(struct http_reply_ctx_s *rp)
{
	return _reply_json(rp, HTTP_CODE_CREATED, "Created", NULL);
}

static enum http_rc_e
_reply_ok(struct http_reply_ctx_s *rp, GString *body)
{
	if (!body)
		return _reply_json(rp, HTTP_CODE_NO_CONTENT, "No Content", body);
	return _reply_json(rp, HTTP_CODE_OK, "OK", body);
}

static GError *
_map_errno_to_gerror(int code, char *msg)
{
	GError *err = NULL;
	switch (code) {
		case ENOENT:
			err = NEWERROR(CODE_NOT_FOUND, "%s", msg);
			break;
		case EPERM:
		case ENOTDIR:
			err = NEWERROR(CODE_NOT_ALLOWED, "%s", msg);
			break;
		case EINVAL:
			err = BADREQ("%s", msg);
			break;
		default:
			err = SYSERR("(%d) %s", code, msg);
	}

	if (msg)
		free(msg);
	return err;
}

/* ------------------------------------------------------------------------- */

struct rdir_base_s
{
	leveldb_t *base;
	GThread *owner;
};

struct rdir_record_s
{
	gint64 mtime;
	gchar container[STRLEN_CONTAINERID];
	gchar content[LIMIT_LENGTH_CONTENTPATH];
	gchar chunk[LIMIT_LENGTH_CHUNKURL];
};

static void
_base_destroy(struct rdir_base_s *base)
{
	if (!base)
		return;

	if (base->base)
		leveldb_close(base->base);
	base->base = NULL;

	base->owner = NULL;

	g_free(base);
}

static GString *
_record_to_key(struct rdir_record_s *rec)
{
	GString *key = g_string_sized_new(256);
	g_string_printf(key, CHUNK_PREFIX "%s|%s|%s",
			rec->container, rec->content, rec->chunk);
	return key;
}

static void
_record_encode(struct rdir_record_s *rec, GString *value)
{
	g_string_append_c(value, '{');
	oio_str_gstring_append_json_pair(value, "container_id", rec->container);
	g_string_append_c(value, ',');
	oio_str_gstring_append_json_pair(value, "content_id", rec->content);
	g_string_append_c(value, ',');
	oio_str_gstring_append_json_pair(value, "chunk_id", rec->chunk);
	if (rec->mtime > 0) {
		g_string_append_c(value, ',');
		oio_str_gstring_append_json_pair_int(value, "mtime", rec->mtime);
	}
	g_string_append_c(value, '}');
}

static GError *
_record_extract(struct rdir_record_s *rec, struct json_object *jrecord)
{
	struct json_object *jcontainer, *jcontent, *jchunk, *jmtime, *jrtime;
	struct oio_ext_json_mapping_s map[] = {
		{"container_id", &jcontainer, json_type_string, 1},
		{"content_id",   &jcontent,   json_type_string, 1},
		{"chunk_id",     &jchunk,     json_type_string, 1},
		{"mtime",        &jmtime,     json_type_int,    0},
		// FIXME(adu) to delete after deleting all rtime
		{"rtime",        &jrtime,     json_type_int,    0},
		{NULL, NULL, 0, 0}
	};
	GError *err = oio_ext_extract_json(jrecord, map);
	if (!err) {
		g_strlcpy(rec->container, json_object_get_string(jcontainer),
				sizeof(rec->container));
		g_strlcpy(rec->content, json_object_get_string(jcontent),
				sizeof(rec->content));
		g_strlcpy(rec->chunk, json_object_get_string(jchunk),
				sizeof(rec->chunk));
		gint64 mtime = 0;
		gint64 rtime = 0;
		if (jmtime)
			mtime = json_object_get_int64(jmtime);
		if (jrtime)
			rtime = json_object_get_int64(jrtime);
		rec->mtime = MAX(mtime, rtime);
	}
	return err;
}

static GError *
_record_parse(struct rdir_record_s *rec, const char *value, size_t length)
{
	GError *err = NULL;
	struct json_object *jrecord = NULL;

	if (!(err = JSON_parse_buffer((const guint8*)value, length, &jrecord)))
		err = _record_extract(rec, jrecord);

	json_object_put(jrecord);
	return err;
}

static GError *
_db_open(const char *volid, gboolean autocreate, leveldb_t **pdb)
{
	char *errmsg = NULL;
	leveldb_t *db = NULL;
	int errsav = 0;

	gchar *dbname = g_strconcat(basedir, G_DIR_SEPARATOR_S, volid, NULL);

	if (!autocreate && !g_file_test(dbname, G_FILE_TEST_IS_DIR)) {
		g_free(dbname);
		return NEWERROR(CODE_NOT_FOUND, "DB not found");
	}

	leveldb_options_t *options = leveldb_options_create();
	leveldb_options_set_max_open_files(options, rdir_fd_per_base);
	leveldb_options_set_create_if_missing(options, BOOL(autocreate));
	db = leveldb_open(options, dbname, &errmsg);
	leveldb_options_destroy(options);
	g_free(dbname);

	if (!db) {
		errsav = errno;
		if (!errsav)
			errsav = ENOENT;
	}

	*pdb = db;
	return db ? NULL : _map_errno_to_gerror(errsav, errmsg);
}

static GError *
_db_get_generic(GTree *db_tree, GMutex *db_tree_lock, GCond *db_tree_cond,
		const char *volid, gboolean autocreate, struct rdir_base_s **pbase)
{
	GError *err = NULL;
	struct rdir_base_s *b = NULL;
	int errsav = 0;

	g_mutex_lock(db_tree_lock);
retry:
	b = g_tree_lookup(db_tree, volid);
	if (b) {
		/* already handled once */
		if (!b->base) {
			if (!b->owner) {
				/* the previous open failed */
				goto open;
			} else {
				/* being opened */
				g_cond_wait(db_tree_cond, db_tree_lock);
				goto retry;
			}
		}
	} else {
		b = g_malloc0(sizeof(*b));
		g_tree_replace(db_tree, g_strdup(volid), b);
open:
		b->owner = g_thread_self();
		g_mutex_unlock(db_tree_lock);

		leveldb_t *db = NULL;
		err = _db_open(volid, autocreate, &db);
		if (err)
			errsav = errno;

		g_mutex_lock(db_tree_lock);
		if (!db) {
			b = NULL;
			g_tree_remove(db_tree, volid);
		} else {
			b->base = db;
			b->owner = NULL;
		}
	}
	g_cond_signal(db_tree_cond);
	g_mutex_unlock(db_tree_lock);

	errno = errsav;
	*pbase = b;
	return err;
}

static GError *
_db_get(const char *volid, gboolean autocreate, struct rdir_base_s **pbase)
{
	return _db_get_generic(tree_bases, &lock_bases, &cond_bases,
			volid, autocreate, pbase);
}

static GError *
_db_admin_get_incident(const char *volid, gint64 *pincident)
{
	*pincident = 0;

	struct rdir_base_s *base = NULL;
	GError *err = _db_get(volid, FALSE, &base);
	if (err)
		return err;

	leveldb_readoptions_t *options = leveldb_readoptions_create();
	leveldb_readoptions_set_fill_cache(options, 1);
	leveldb_readoptions_set_verify_checksums(options, 0);

	size_t length = 0;
	char *errmsg = NULL;
	char *value = leveldb_get(base->base, options,
			KEY_INCIDENT, sizeof(KEY_INCIDENT)-1, &length, &errmsg);

	leveldb_readoptions_destroy(options);

	if (errmsg)
		return _map_errno_to_gerror(errno, errmsg);

	if (value) {
		if (length > 32) {
			err = SYSERR("Invalid incident date for [%s]", volid);
		} else {
			gchar *v;
			STRDUPA(v, value, length);
			if (!oio_str_is_number(v, pincident))
				err = SYSERR("Invalid incident date for [%s]", volid);
		}
		free(value);
	}
	return err;
}

static GError *
_db_admin_set_incident(const char *volid, gint64 when)
{
	struct rdir_base_s *base = NULL;
	GError *err = NULL;

	if ((err = _db_get(volid, FALSE, &base)))
		return err;

	char *errmsg = NULL;
	gchar buf[64];
	gsize len = g_snprintf(buf, sizeof(buf), "%"G_GINT64_FORMAT, when);

	/* forward to the ... nope, this is too short to be insulated */
	leveldb_writeoptions_t *woptions = leveldb_writeoptions_create();
	leveldb_writeoptions_set_sync(woptions, 1);
	leveldb_put(base->base, woptions,
			KEY_INCIDENT, sizeof(KEY_INCIDENT)-1,
			buf, len, &errmsg);
	int errsav = errno;
	leveldb_writeoptions_destroy(woptions);

	if (!errmsg)
		return NULL;
	return _map_errno_to_gerror(errsav, errmsg);
}

static GError *
_db_insert_generic(struct rdir_base_s *base, GString *key, GString *value)
{
	char *errmsg = NULL;

	leveldb_writeoptions_t *options = leveldb_writeoptions_create();
	leveldb_writeoptions_set_sync(options, 0);
	leveldb_put(base->base, options,
			key->str, key->len, value->str, value->len,
			&errmsg);
	leveldb_writeoptions_destroy(options);

	if (!errmsg)
		return NULL;

	return _map_errno_to_gerror(errno, errmsg);
}

static GError *
_db_vol_push(const char *volid, gboolean autocreate, GString *key,
			 GString *value)
{
	struct rdir_base_s *base = NULL;
	GError *err = _db_get(volid, autocreate, &base);
	if (err)
		return err;

	return _db_insert_generic(base, key, value);
}

struct _listing_req_s {
	const gchar *marker;
	gint64 max;
	const gchar *prefix;
	gboolean rebuild;
};

struct _listing_resp_s {
	gboolean truncated;
	gchar *marker;
	gint64 incident_date;
};

typedef void (*_listing_func) (gint64 incident_date,
		size_t keylen, const gchar *key, struct rdir_record_s *rec);

static void
clean_listing_resp(struct _listing_resp_s *listing_resp)
{
	g_free(listing_resp->marker);
}

static GError *
extract_optional_listing_fields(struct req_args_s *args,
		struct json_object *jbody, struct _listing_req_s *listing_req)
{
	GError *err = NULL;
	struct json_object *jstart = NULL, *jlimit = NULL, *jcid = NULL,
			*jrebuild = NULL;

	if (jbody) {
		// TODO(adu): Delete when it will no longer be used
		if (!json_object_is_type(jbody, json_type_object))
			return BADREQ("null body");
		struct oio_ext_json_mapping_s map[] = {
			{"start_after",  &jstart,   json_type_string,  0},
			{"limit",        &jlimit,   json_type_int,     0},
			{"container_id", &jcid,     json_type_string,  0},
			{"rebuild",      &jrebuild, json_type_boolean, 0},
			{NULL, NULL, 0, 0}
		};
		if ((err = oio_ext_extract_json(jbody, map)))
			return err;
	}

	if (OPT("marker"))
		listing_req->marker = OPT("marker");
	else if (jstart)
		listing_req->marker = json_object_get_string(jstart);
	if (OPT("max"))
		listing_req->max = g_ascii_strtoll(OPT("max"), NULL, 10);
	else if (jlimit)
		listing_req->max = json_object_get_int64(jlimit);
	if (listing_req->max <= 0)
		listing_req->max = RDIR_LISTING_DEFAULT_LIMIT;
	else
		listing_req->max = MIN(RDIR_LISTING_MAX_LIMIT, listing_req->max);
	if (OPT("prefix"))
		listing_req->prefix = OPT("prefix");
	else if (jcid)
		listing_req->prefix = json_object_get_string(jcid);
	if (OPT("rebuild"))
		listing_req->rebuild = oio_str_parse_bool(OPT("rebuild"), FALSE);
	else if (jrebuild)
		listing_req->rebuild = json_object_get_boolean(jrebuild);
	return NULL;
}

static void
load_listing_headers(struct http_reply_ctx_s *rp,
		struct _listing_resp_s *listing_resp)
{
	if (listing_resp->truncated) {
		rp->add_header(PROXYD_HEADER_PREFIX "list-truncated", g_strdup("true"));
		rp->add_header(PROXYD_HEADER_PREFIX "list-marker",
				g_strdup(listing_resp->marker));
	} else {
		rp->add_header(PROXYD_HEADER_PREFIX "list-truncated", g_strdup("false"));
	}
}

static GError *
_db_vol_listing(const char *volid, struct _listing_req_s *listing_req,
		struct _listing_resp_s *listing_resp, _listing_func listing_func)
{
	gint64 nb_chunks = 0;
	gint64 incident_date = 0;
	GError *err = NULL;
	struct rdir_base_s *base = NULL;

	if ((err = _db_admin_get_incident(volid, &incident_date)))
		return err;
	listing_resp->incident_date = incident_date;

	if (listing_req->rebuild && incident_date <= 0) {
		GRID_INFO("Listing the chunks in order to rebuild, but "
				"no incident date set");
		return NULL;
	}

	if ((err = _db_get(volid, FALSE, &base)))
		return err;

	gchar prefix[512], after[512];
	const gsize prefix_len =
		g_snprintf(prefix, sizeof(prefix), CHUNK_PREFIX "%s",
				listing_req->prefix ?: "");
	const gsize after_len =
		g_snprintf(after, sizeof(after), CHUNK_PREFIX "%s",
				listing_req->marker ?: "");

	leveldb_readoptions_t *options = leveldb_readoptions_create();
	leveldb_readoptions_set_fill_cache(options, 0);
	leveldb_readoptions_set_verify_checksums(options, 0);
	leveldb_iterator_t *it = leveldb_create_iterator(base->base, options);
	leveldb_readoptions_destroy(options);

	/* Initially seek at the farthest position */
	const char *key_seek = strcmp(prefix, after) > 0 ? prefix : after;
	leveldb_iter_seek(it, key_seek, strlen(key_seek));

	/* if a 'start_after' has been provided and if the iterator is
	 * exactly on it, let's step one chunk further. */
	if (leveldb_iter_valid(it) && listing_req->marker) {
		size_t keylen = 0;
		const char *key = leveldb_iter_key(it, &keylen);
		if (after_len <= keylen && !memcmp(key, after, after_len))
			leveldb_iter_next(it);
	}

	size_t keylen = 0;
	const char *key = NULL;
	size_t vallen = 0;
	const char *val = NULL;
	for (; leveldb_iter_valid(it); leveldb_iter_next(it)) {
		keylen = 0;
		key = NULL;
		vallen = 0;
		val = NULL;
		struct rdir_record_s rec = {0};

		key = leveldb_iter_key(it, &keylen);

		/* We don't match the prefix anymore, and we won't find the prefix
		 * in further elements, because of the initial seek that jumped
		 * 'at least further than the prefix' */
		if (keylen < prefix_len || 0 != memcmp(key, prefix, prefix_len))
			break;

		val = leveldb_iter_value(it, &vallen);
		err = _record_parse(&rec, val, vallen);
		if (err) {
			GRID_WARN("Malformed record at [%.*s]", (int)keylen, key);
			g_clear_error(&err);
			continue;
		}

		if (listing_req->rebuild && incident_date > 0
				&& rec.mtime > incident_date)
			continue;

		if (listing_req->max > 0 && nb_chunks >= listing_req->max) {
			listing_resp->truncated = TRUE;

			leveldb_iter_prev(it);
			keylen = 0;
			key = NULL;
			key = leveldb_iter_key(it, &keylen);
			listing_resp->marker = g_strndup(key + (sizeof(CHUNK_PREFIX) - 1),
					keylen - (sizeof(CHUNK_PREFIX) - 1));
			break;
		}

		listing_func(incident_date, keylen, key, &rec);

		nb_chunks++;
	}

	leveldb_iter_destroy(it);
	return err;
}

static GError *
_db_vol_fetch(const char *volid, struct _listing_req_s *listing_req,
		struct _listing_resp_s *listing_resp, GString *value)
{
	GError *err = NULL;

	void listing_func(gint64 incident_date UNUSED,
			size_t keylen, const gchar *key, struct rdir_record_s *rec) {
		if (value->len > 1)
			g_string_append_c(value, ',');

		g_string_append_c(value, '[');
		g_string_append_c(value, '"');
		oio_str_gstring_append_json_blob(value,
				key + (sizeof(CHUNK_PREFIX) - 1),
				keylen - (sizeof(CHUNK_PREFIX) - 1));
		g_string_append_c(value, '"');
		g_string_append_c(value, ',');
		g_string_append_c(value, '{');
		oio_str_gstring_append_json_pair_int(value, "mtime", rec->mtime);
		g_string_append_c(value, '}');
		g_string_append_c(value, ']');
	}

	g_string_append_c(value, '[');
	err = _db_vol_listing(volid, listing_req, listing_resp, listing_func);
	g_string_append_c(value, ']');
	return err;
}

static GError *
_db_vol_delete_generic(struct rdir_base_s *base, GString *key)
{
	char *errmsg = NULL;
	leveldb_writeoptions_t *options = leveldb_writeoptions_create();
	leveldb_writeoptions_set_sync(options, 0);
	leveldb_delete(base->base, options, key->str, key->len, &errmsg);
	leveldb_writeoptions_destroy(options);

	if (!errmsg)
		return NULL;
	return _map_errno_to_gerror(errno, errmsg);
}

static GError *
_db_vol_delete(const char *volid, GString *key){
	struct rdir_base_s *base = NULL;
	GError *err = _db_get(volid, FALSE, &base);
	if (err)
		return err;
	return _db_vol_delete_generic(base, key);
}

static void
_dump_vol_status(GString *value, GTree *tree_containers, GTree *tree_to_rebuild)
{
	gboolean first = TRUE;
	gboolean _on_container(gpointer k, gpointer v, gpointer i UNUSED) {
		if (!first)
			g_string_append_c(value, ',');
		first = FALSE;
		oio_str_gstring_append_json_quote(value, k);
		g_string_append_c(value, ':');
		g_string_append_c(value, '{');
		oio_str_gstring_append_json_pair_int(value,
				"total", GPOINTER_TO_INT(v)-1);
		gpointer p = g_tree_lookup(tree_to_rebuild, k);
		if (p) {
			g_string_append_c(value, ',');
			oio_str_gstring_append_json_pair_int(value,
					"to_rebuild", GPOINTER_TO_INT(p)-1);
		}
		g_string_append_c(value, '}');
		return FALSE;
	}
	g_tree_foreach(tree_containers, _on_container, NULL);
}

static GError *
_db_vol_status(const char *volid, struct _listing_req_s *listing_req,
		struct _listing_resp_s *listing_resp, GString *value)
{
	gint64 nb_chunks = 0, nb_to_rebuild = 0;
	GError *err = NULL;

	GTree *tree_containers =
		g_tree_new_full(metautils_strcmp3, NULL, g_free, NULL);
	GTree *tree_to_rebuild =
		g_tree_new_full(metautils_strcmp3, NULL, g_free, NULL);

	void count_chunk(const char *cid) {
		gpointer p = g_tree_lookup(tree_containers, cid);
		gint v = p ? GPOINTER_TO_INT(p) + 1 : 2;
		g_tree_replace(tree_containers, g_strdup(cid), GINT_TO_POINTER(v));
	}
	void count_to_rebuild(const char *cid) {
		gpointer p = g_tree_lookup(tree_to_rebuild, cid);
		gint v = p ? GPOINTER_TO_INT(p) + 1 : 2;
		g_tree_replace(tree_to_rebuild, g_strdup(cid), GINT_TO_POINTER(v));
	}
	void listing_func(gint64 incident_date,
			size_t keylen, const gchar *key, struct rdir_record_s *rec) {
		/* Insulate the name of its container */
		gchar cid[128];
		g_snprintf(cid, sizeof(cid), "%.*s",
				(int)(keylen - (sizeof(CHUNK_PREFIX) - 1)),
				key + (sizeof(CHUNK_PREFIX) - 1));
		char *colon = strchr(cid, '|');
		if (!colon) {
			GRID_WARN("Malformed key at [%.*s]", (int)keylen, key);
			return;
		}
		*colon = 0;

		/* count that chunk */
		nb_chunks++;

		/* count that chunk, for its container */
		count_chunk(cid);

		if (incident_date <= 0 || rec->mtime > incident_date)
			return;

		/* count that chunk to rebuild */
		nb_to_rebuild++;

		/* count that chunk to rebuild, for its container */
		count_to_rebuild(cid);
	}

	err = _db_vol_listing(volid, listing_req, listing_resp, listing_func);
	if (err)
		goto label_end;

	/* pack the answer */
	g_string_append_c(value, '{');
	oio_str_gstring_append_json_quote(value, "chunk");
	g_string_append_c(value, ':');
	g_string_append_c(value, '{');
	oio_str_gstring_append_json_pair_int(value, "total", nb_chunks);
	if (listing_resp->incident_date > 0) {
		g_string_append_c(value, ',');
		oio_str_gstring_append_json_pair_int(value, "to_rebuild",
				nb_to_rebuild);
	}
	g_string_append_c(value, '}');
	g_string_append_c(value, ',');
	oio_str_gstring_append_json_quote(value, "container");
	g_string_append_c(value, ':');
	g_string_append_c(value, '{');
	_dump_vol_status(value, tree_containers, tree_to_rebuild);
	g_string_append_c(value, '}');
	if (listing_resp->incident_date > 0) {
		g_string_append_c(value, ',');
		oio_str_gstring_append_json_quote(value, "rebuild");
		g_string_append_c(value, ':');
		g_string_append_c(value, '{');
		oio_str_gstring_append_json_pair_int(value,
				"incident_date", listing_resp->incident_date);
		g_string_append_c(value, '}');
	}
	g_string_append_c(value, '}');

label_end:
	g_tree_destroy(tree_containers);
	g_tree_destroy(tree_to_rebuild);
	return err;
}

static GError *
_db_admin_show(const char *volid, GString *value)
{
	struct rdir_base_s *base = NULL;
	GError *err = NULL;
	gboolean first = TRUE;

	if ((err = _db_get(volid, FALSE, &base)))
		return err;

	leveldb_readoptions_t *options = leveldb_readoptions_create();
	leveldb_readoptions_set_fill_cache(options, 0);
	leveldb_readoptions_set_verify_checksums(options, 0);
	leveldb_iterator_t *it = leveldb_create_iterator(base->base, options);
	leveldb_readoptions_destroy(options);

	g_string_append_c(value, '{');
	leveldb_iter_seek(it, ADMIN_PREFIX, sizeof(ADMIN_PREFIX)-1);
	for (; leveldb_iter_valid(it) ; leveldb_iter_next(it)) {
		size_t keylen = 0, vallen = 0;
		const char *key = leveldb_iter_key(it, &keylen);

		/* check we still run over an ADMIN key */
		if (*key != ADMIN_PREFIX[0])
			break;
		if (keylen <= sizeof(ADMIN_PREFIX)-1 ||
				0 != memcmp(key, ADMIN_PREFIX, sizeof(ADMIN_PREFIX)-1))
			break;

		/* dump it as a field of the JSON object */
		const char *val = leveldb_iter_value(it, &vallen);
		if (!first)
			g_string_append_c(value, ',');
		first = FALSE;
		g_string_append_c(value, '"');
		oio_str_gstring_append_json_blob(value,
				key+sizeof(ADMIN_PREFIX)-1, keylen-sizeof(ADMIN_PREFIX)+1);
		g_string_append_len(value, "\":\"", 3);
		oio_str_gstring_append_json_blob(value, val, vallen);
		g_string_append_c(value, '"');
	}
	g_string_append_c(value, '}');

	leveldb_iter_destroy(it);
	return NULL;
}

static GError *
_db_admin_lock(const char *volid, const char *who)
{
	struct rdir_base_s *base = NULL;
	GError *err = NULL;

	if ((err = _db_get(volid, FALSE, &base)))
		return err;

	char *errmsg = NULL, *value = NULL;
	int errsav = 0;
	size_t length = 0;

	/* Get the current lock value */
	leveldb_readoptions_t *roptions = leveldb_readoptions_create();
	leveldb_readoptions_set_fill_cache(roptions, 1);
	leveldb_readoptions_set_verify_checksums(roptions, 0);
	value = leveldb_get(base->base, roptions,
			KEY_LOCK, sizeof(KEY_LOCK)-1, &length, &errmsg);
	errsav = errno;
	leveldb_readoptions_destroy(roptions);

	/* check it is held by no-one */
	if (errmsg) {
		err = _map_errno_to_gerror(errno, errmsg);
	} else if (value && (length != strlen(who) ||
				0 != memcmp(who, value, length))) {
		err = NEWERROR(CODE_NOT_ALLOWED, "Already locked by %.*s",
				(int)length, value);
	}
	if (value)
		free(value);

	/* Actually lock the base if not held */
	if (!err) {
		leveldb_writeoptions_t *woptions = leveldb_writeoptions_create();
		leveldb_writeoptions_set_sync(woptions, 0);
		leveldb_put(base->base, woptions, KEY_LOCK, sizeof(KEY_LOCK)-1,
				who, strlen(who), &errmsg);
		errsav = errno;
		leveldb_writeoptions_destroy(woptions);
		if (errmsg)
			err = _map_errno_to_gerror(errsav, errmsg);
	}

	return err;
}

static GError *
_db_admin_unlock(const char *volid)
{
	struct rdir_base_s *base = NULL;
	GError *err = NULL;
	char *errmsg = NULL;
	int errsav = 0;

	if ((err = _db_get(volid, FALSE, &base)))
		return err;

	leveldb_writeoptions_t *options = leveldb_writeoptions_create();
	leveldb_writeoptions_set_sync(options, 0);
	leveldb_delete(base->base, options, KEY_LOCK, sizeof(KEY_LOCK)-1, &errmsg);
	errsav = errno;
	leveldb_writeoptions_destroy(options);

	return errmsg ? _map_errno_to_gerror(errsav, errmsg) : NULL;
}

static GError *
_db_admin_clear(const char *volid, gboolean all, gboolean before_incident,
		gboolean repair, gint64 *p_nb_removed, gint64 *p_nb_repaired,
		gint64 *p_errors)
{
	struct rdir_base_s *base = NULL;
	GError *err = NULL;
	char *errmsg = NULL;
	int errsav = 0;
	gint64 nb_removed = 0;
	gint64 nb_repaired = 0;
	gint64 errors = 0;
	gint64 incident = 0;

	if (before_incident) {
		if ((err = _db_admin_get_incident(volid, &incident)))
			return err;
	}

	if ((err = _db_get(volid, FALSE, &base)))
		return err;

	leveldb_writebatch_t *batch = leveldb_writebatch_create();

	if (all || (before_incident && incident > 0) || repair) {
		leveldb_readoptions_t *roptions = leveldb_readoptions_create();
		leveldb_readoptions_set_fill_cache(roptions, 0);
		leveldb_iterator_t *it = leveldb_create_iterator(base->base, roptions);
		leveldb_readoptions_destroy(roptions);
		leveldb_iter_seek(it, CHUNK_PREFIX, sizeof(CHUNK_PREFIX)-1);
		for (; leveldb_iter_valid(it) ; leveldb_iter_next(it)) {
			size_t keylen = 0;
			const char *key = leveldb_iter_key(it, &keylen);
			if (*key != CHUNK_PREFIX[0])
				break;

			if (all) {
				leveldb_writebatch_delete(batch, key, keylen);
				nb_removed++;
				continue;
			}

			size_t vallen = 0;
			const char *val = leveldb_iter_value(it, &vallen);

			/* TODO(jfs): we parse the whole object, but we just need the rtime
				* so there is maybe a small room for a lean improvement. */
			struct rdir_record_s rec = {0};
			err = _record_parse(&rec, val, vallen);
			if (err) {
				GRID_INFO("Malformed record at [%.*s]", (int)keylen, key);
				g_clear_error(&err);
				errors++;
				continue;
			}

			if (before_incident && incident > 0 && rec.mtime <= incident) {
				leveldb_writebatch_delete(batch, key, keylen);
				nb_removed++;
				continue;
			}

			if (repair) {
				GString *repaired_key = _record_to_key(&rec);
				GString *repaired_val = g_string_sized_new(1024);
				_record_encode(&rec, repaired_val);
				err = _db_vol_push(volid, FALSE, repaired_key, repaired_val);
				g_string_free(repaired_key, TRUE);
				g_string_free(repaired_val, TRUE);
				if (err) {
					GRID_INFO("Push failed at [%.*s]: %s", (int)keylen, key,
							err->message);
					g_clear_error(&err);
					errors++;
					continue;
				}
				nb_repaired++;
			}
		}
		leveldb_iter_destroy(it);
	}

	leveldb_writebatch_delete(batch, KEY_INCIDENT, sizeof(KEY_INCIDENT)-1);

	leveldb_writeoptions_t *woptions = leveldb_writeoptions_create();
	leveldb_write(base->base, woptions, batch, &errmsg);
	errsav = errno;
	leveldb_writeoptions_destroy(woptions);
	leveldb_writebatch_destroy(batch);

	*p_nb_removed = nb_removed;
	*p_nb_repaired = nb_repaired;
	*p_errors = errors;
	return errmsg ? _map_errno_to_gerror(errsav, errmsg) : NULL;
}

/* ------------------------------------------------------------------------- *
 *                            Chunk records                                  *
 * ------------------------------------------------------------------------- */

static GError *
_request_to_key(struct json_object *jbody, GString **pkey)
{
	struct rdir_record_s rec = {0};
	GError *err = _record_extract(&rec, jbody);
	if (err)
		return err;
	*pkey = _record_to_key(&rec);
	return NULL;
}


// RDIR{{
// DELETE /v1/rdir/delete?vol=<volume ip>%3A<volume port>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Unreference a chunk from the volume.
//
// .. code-block:: http
//
//    DELETE /v1/rdir/delete?vol=127.0.0.1%3A6020 HTTP/1.1
//    Host: 127.0.0.1:15
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 135
//    Content-Type: application/x-www-form-urlencoded
//
//
// .. code-block:: json
//
//    {
//      "container_id":"<container id>",
//      "content_id":"<object content id>",
//      "chunk_id":"chunk id"
//    }
//
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 204 OK
//    Connection: Close
//    Content-Length: 0
//
// }}RDIR
static enum http_rc_e
_route_vol_delete(struct req_args_s *args, struct json_object *jbody,
		const char *volid)
{
	/* sanity checks */
	if (!volid)
		return _reply_format_error(args->rp, BADREQ("no volume id"));

	/* extraction of the parameters */
	GError *err = NULL;
	GString *key = NULL;
	if ((err = _request_to_key(jbody, &key)))
		return _reply_format_error(args->rp, err);

	/* Eventually remove the record from the database */
	err = _db_vol_delete(volid, key);
	g_string_free(key, TRUE);

	if (err)
		return _reply_common_error(args->rp, err);
	return _reply_ok(args->rp, NULL);
}


// RDIR{{
// POST /v1/rdir/push?vol=<volume ip>%3A<volume port>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Push the target volume.
//
// .. code-block:: http
//
//    POST /v1/rdir/push?vol=127.0.0.1%3A6020 HTTP/1.1
//    Host: 127.0.0.1:15
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 150
//    Content-Type: application/x-www-form-urlencoded
//
//
// .. code-block:: json
//
//    {
//      "container_id":"<container id>",
//      "content_id":"<object content id>",
//      "chunk_id":"chunk id"
//    }
//
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 204 OK
//    Connection: Close
//    Content-Length: 0
//
// }}RDIR
static enum http_rc_e
_route_vol_push(struct req_args_s *args, struct json_object *jbody,
		const char *volid, const char *str_autocreate)
{
	if (!jbody || !json_object_is_type(jbody, json_type_object))
		return _reply_format_error(args->rp, BADREQ("null body"));
	if (!volid)
		return _reply_format_error(args->rp, BADREQ("no volume id"));

	gboolean autocreate = oio_str_parse_bool(str_autocreate, FALSE);

	/* extract all the record's fields */
	GError *err = NULL;
	struct rdir_record_s rec = {0};
	if ((err = _record_extract(&rec, jbody)))
		return _reply_format_error(args->rp, err);

	GString *key = _record_to_key(&rec);
	GString *value = g_string_sized_new(1024);
	args->rp->access_tail("k=%s", key->str);
	_record_encode(&rec, value);

	/* Eventually push the record in the database */
	err = _db_vol_push(volid, autocreate, key, value);
	g_string_free(key, TRUE);
	g_string_free(value, TRUE);

	if (err)
		return _reply_common_error(args->rp, err);
	return _reply_ok(args->rp, NULL);
}


// RDIR{{
// POST /v1/rdir/fetch?vol=<volume ip>%3A<volume port>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Fetch the target volume.
//
// .. code-block:: http
//
//    POST /v1/rdir/fetch?vol=127.0.0.1%3A6020 HTTP/1.1
//    Host: 127.0.0.1:15
//    User-Agent: curl/7.47.0
//    Accept: */*
//
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Length: 2
//
// }}RDIR
static enum http_rc_e
_route_vol_fetch(struct req_args_s *args, struct json_object *jbody,
		const char *volid)
{
	GError *err = NULL;

	if (!volid)
		return _reply_format_error(args->rp, BADREQ("no volume id"));

	struct _listing_req_s listing_req = {0};
	struct _listing_resp_s listing_resp = {0};
	err = extract_optional_listing_fields(args, jbody, &listing_req);
	if (err)
		return _reply_format_error(args->rp, err);

	GString *value = g_string_sized_new(1024);
	err = _db_vol_fetch(volid, &listing_req, &listing_resp, value);
	if (err)
		g_string_free(value, TRUE);
	else
		load_listing_headers(args->rp, &listing_resp);

	clean_listing_resp(&listing_resp);
	if (err)
		return _reply_common_error(args->rp, err);
	return _reply_ok(args->rp, value);
}


// RDIR{{
// POST /v1/rdir/create?vol=<volume ip>%3A<volume port>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Create the target volume.
//
// .. code-block:: http
//
//    POST /v1/rdir/create?vol=127.0.0.1%3A6020 HTTP/1.1
//    Host: 127.0.0.1:15
//    User-Agent: curl/7.47.0
//    Accept: */*
//
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 201 Created
//    Connection: Close
//    Content-Length: 0
//
// }}RDIR
static enum http_rc_e
_route_vol_create(struct req_args_s *args, const char *volid)
{
	/* sanity checks */
	if (!oio_str_is_set(volid))
		return _reply_format_error(args->rp, BADREQ("no volume id"));

	/* Forward to the ... fuck! this is short enough */
	struct rdir_base_s *base = NULL;
	GError *err = _db_get(volid, TRUE, &base);
	if (err)
		return _reply_common_error(args->rp, err);
	return _reply_created(args->rp);
}


// RDIR{{
// POST /v1/rdir/status?vol=<volume ip>%3A<volume port>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Show the target volume status
//
// .. code-block:: http
//
//    POST /v1/rdir/status?vol=127.0.0.1%3A6020 HTTP/1.1
//    Host: 127.0.0.1:15
//    User-Agent: curl/7.47.0
//    Accept: */*
//
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 36
//
//    {"chunk":{"total":0},"container":{}}
//
// }}RDIR
static enum http_rc_e
_route_vol_status(struct req_args_s *args, const char *volid)
{
	GError *err = NULL;

	if (!volid)
		return _reply_format_error(args->rp, BADREQ("no volume id"));

	struct _listing_req_s listing_req = {0};
	struct _listing_resp_s listing_resp = {0};
	err = extract_optional_listing_fields(args, NULL, &listing_req);
	if (err)
		return _reply_format_error(args->rp, err);
	listing_req.rebuild = FALSE;

	GString *value = g_string_sized_new(1024);
	err = _db_vol_status(volid, &listing_req, &listing_resp, value);
	if (err)
		g_string_free(value, TRUE);
	else
		load_listing_headers(args->rp, &listing_resp);

	clean_listing_resp(&listing_resp);
	if (err)
		return _reply_common_error(args->rp, err);
	return _reply_ok(args->rp, value);
}


// RDIR{{
// POST /v1/rdir/admin/show?vol=<volume ip>%3A<volume port>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Show the target service.
//
// .. code-block:: http
//
//    POST /v1/rdir/admin/show?vol=127.0.0.1%3A6020 HTTP/1.1
//    Host: 127.0.0.1:15
//    User-Agent: curl/7.47.0
//    Accept: */*
//
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 2
//
// }}RDIR
static enum http_rc_e
_route_admin_show(struct req_args_s *args, const char *volid)
{
	/* sanity checks */
	if (!oio_str_is_set(volid))
		return _reply_format_error(args->rp, BADREQ("no volume id"));

	/* forwardd to the backend */
	GError *err = NULL;
	GString *value = g_string_sized_new(1024);
	if ((err = _db_admin_show(volid, value))) {
		g_string_free(value, TRUE);
		return _reply_common_error(args->rp, err);
	}
	return _reply_ok(args->rp, value);
}


// RDIR{{
// POST /v1/rdir/admin/unlock?vol=<volume ip>%3A<volume port>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Unlock the target service.
//
// .. code-block:: http
//
//    POST /v1/rdir/admin/unlock?vol=127.0.0.1%3A6020 HTTP/1.1
//    Host: 127.0.0.1:15
//    User-Agent: curl/7.47.0
//    Accept: */*
//
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 204 OK
//    Connection: Close
//    Content-Length: 0
//
// }}RDIR
static enum http_rc_e
_route_admin_unlock(struct req_args_s *args, const char *volid)
{
	/* sanity checks */
	if (!oio_str_is_set(volid))
		return _reply_format_error(args->rp, BADREQ("no volume id"));

	/* forward to the backend */
	GError *err = NULL;
	if ((err = _db_admin_unlock(volid)))
		return _reply_common_error(args->rp, err);
	return _reply_ok(args->rp, NULL);
}


// RDIR{{
// POST /v1/rdir/admin/lock?vol=<volume ip>%3A<volume port>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Lock the target service with given key.
//
// .. code-block:: http
//
//    POST /v1/rdir/admin/lock?vol=127.0.0.1%3A6020 HTTP/1.1
//    Host: 127.0.0.1:15
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 34
//    Content-Type: application/x-www-form-urlencoded
//
// .. code-block:: json
//
//    {
//      "who": "<volume address>"
//      "key": 0
//    }
//
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 204 OK
//    Connection: Close
//    Content-Length: 0
//
// }}RDIR
static enum http_rc_e
_route_admin_lock(struct req_args_s *args, struct json_object *jbody,
	const char *volid)
{
	GError *err = NULL;

	/* extraction of the parameters */
	struct json_object *jwho;
	struct oio_ext_json_mapping_s map[] = {
		{"who", &jwho, json_type_string, 1},
		{NULL, NULL, 0, 0}
	};
	if ((err = oio_ext_extract_json(jbody, map)))
		return _reply_format_error(args->rp, err);
	const char *who = json_object_get_string(jwho);

	/* sanity checks */
	if (!oio_str_is_set(volid))
		return _reply_format_error(args->rp, BADREQ("no volume id"));
	if (!oio_str_is_set(who))
		return _reply_format_error(args->rp, BADREQ("'who' not set"));

	/* forward to the backend */
	if ((err = _db_admin_lock(volid, who)))
		return _reply_common_error(args->rp, err);
	return _reply_ok(args->rp, NULL);
}


// RDIR{{
// POST /v1/rdir/admin/clear?vol=<volume ip>%3A<volume port>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Clear the target service.
//
// .. code-block:: http
//
//    POST /v1/rdir/admin/clear?vol=127.0.0.1%3A6020 HTTP/1.1
//    Host: 127.0.0.1:15
//    User-Agent: curl/7.47.0
//    Accept: */*
//
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 13
//
//    {"removed":0}
//
// }}RDIR
static enum http_rc_e
_route_admin_clear(struct req_args_s *args, const char *volid, const char *all,
		const char *before_incident, const char *repair)
{
	GError *err = NULL;

	/* sanity checks */
	if (!oio_str_is_set(volid))
		return _reply_format_error(args->rp, BADREQ("no volume id"));

	/* forward to the backend, within a soft lock */
	if ((err = _db_admin_lock(volid, "admin_clear")))
		return _reply_common_error(args->rp, err);

	gint64 nb_removed = 0;
	gint64 nb_repaired = 0;
	gint64 errors = 0;
	err = _db_admin_clear(volid, oio_str_parse_bool(all, FALSE),
			oio_str_parse_bool(before_incident, FALSE),
			oio_str_parse_bool(repair, FALSE), &nb_removed, &nb_repaired,
			&errors);

	GError *_e;
	if ((_e = _db_admin_unlock(volid))) {
		g_clear_error(&_e);
	}

	if (!err) {
		GString *value = g_string_sized_new(64);
		g_string_append_c(value, '{');
		oio_str_gstring_append_json_pair_int(value, "removed", nb_removed);
		g_string_append_c(value, ',');
		oio_str_gstring_append_json_pair_int(value, "repaired", nb_repaired);
		g_string_append_c(value, ',');
		oio_str_gstring_append_json_pair_int(value, "errors", errors);
		g_string_append_c(value, '}');
		return _reply_ok(args->rp, value);
	}
	return _reply_common_error(args->rp, err);
}


// RDIR{{
// GET /v1/rdir/admin/incident?vol=<volume ip>%3A<volume port>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Return target service incident.
//
// .. code-block:: http
//
//    GET /v1/rdir/admin/incident?vol=127.0.0.1%3A6020 HTTP/1.1
//    Host: 127.0.0.1:15
//    User-Agent: curl/7.47.0
//    Accept: */*
//
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 11
//
//    {"date":1533039131}
//
// }}RDIR
static enum http_rc_e
_route_admin_get_incident(struct req_args_s *args, const char *volid)
{
	/* sanity checks */
	if (!oio_str_is_set(volid))
		return _reply_format_error(args->rp, BADREQ("no volume id"));

	GError *err = NULL;
	gint64 incident = 0;
	if ((err = _db_admin_get_incident(volid, &incident)))
		return _reply_common_error(args->rp, err);

	GString *value = g_string_sized_new(64);
	g_string_append_c(value, '{');
	oio_str_gstring_append_json_pair_int(value, "date", incident);
	g_string_append_c(value, '}');
	return _reply_ok(args->rp, value);
}


// RDIR{{
// POST /v1/rdir/admin/incident?vol=<volume ip>%3A<volume port>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Set target service incident.
//
// .. code-block:: http
//
//    POST /v1/rdir/admin/incident?vol=127.0.0.1%3A6020 HTTP/1.1
//    Host: 127.0.0.1:15
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 11
//    Content-Type: application/x-www-form-urlencoded
//
// .. code-block:: json
//
//    {
//      "date": 123456789
//    }
//
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 204 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 0
//
// }}RDIR
static enum http_rc_e
_route_admin_set_incident(struct req_args_s *args, struct json_object *jbody,
		const char *volid)
{
	GError *err = NULL;

	/* extraction of the parameters */
	struct json_object *jwhen;
	struct oio_ext_json_mapping_s map[] = {
		{"date", &jwhen, json_type_int, 1},
		{NULL, NULL, 0, 0}
	};
	if ((err = oio_ext_extract_json(jbody, map)))
		return _reply_format_error(args->rp, err);
	const gint64 when = json_object_get_int64(jwhen);

	/* sanity checks */
	if (!oio_str_is_set(volid))
		return _reply_format_error(args->rp, BADREQ("no volume id"));

	/* forward to the backend */
	err = _db_admin_set_incident(volid, when);

	/* reply to the client */
	if (err)
		return _reply_common_error(args->rp, err);
	return _reply_ok(args->rp, NULL);
}

/* ------------------------------------------------------------------------- *
 *                            Meta2 records                                  *
 * ------------------------------------------------------------------------- *
 *
 * An event is generated every time a meta2 database is created in a meta2 server.
 * We receive an event of that happening and we register it.
 *
 * If an existing base is removed from the meta2 server, then we remove the
 * record citing it in the rdir, and we reference the fact that it used to be
 * on that meta2 server (?)
 *
 * We're reusing the functions used to open/close databases, and trying to
 * replicate to a maximum the way the rdir operated for the chunks.
 */

/*
 * We could technically use the same ones for the chunk logs. However,
 * each time we lock, it's applied to the whole tree for example, so it could
 * potentially make the rdir slower.
 * So we'll keep the same logic used to insert/retrieve/lock database handles
 * but use our own tree/lock/condition. It's probably safer this way, and can
 * be quickly rolled back.
 */
static GMutex meta2_db_lock;
static GTree *meta2_db_tree = NULL;
static GCond meta2_db_cond;

/*
 * This is the structure we're storing. As per the OB-181 ticket, this is what
 * we need to store in the rdir.
 */
struct rdir_meta2_record_s
{
	gint64 mtime;
	gchar *container;
	gchar *container_url;
	gchar *extra_data;
};

/*
 * A structure that packs the parameters for a fetch request.
 */
struct rdir_meta2_record_subset_s
{
	GString *prefix;
	GString *marker;
	gint64 limit;
};


/*
 * Extracts data from a JSON string to initialize an rdir_meta2_record_s
 */
static GError *
_meta2_record_extract(struct rdir_meta2_record_s *rec, struct json_object *jrecord)
{
	struct json_object *jcontainer, *jmtime, *jcontenturl, *jextradata;
	struct oio_ext_json_mapping_s map[] = {
		{"container_id",  &jcontainer,  json_type_string, 1},
		{"container_url", &jcontenturl, json_type_string, 1},
		{"mtime",         &jmtime,      json_type_int,    0},
		{"extra_data",    &jextradata,  json_type_string, 0},
		{NULL, NULL, 0, 0}
	};
	GError *err = oio_ext_extract_json(jrecord, map);
	if (!err) {
		const char *container = json_object_get_string(jcontainer);
		const char *container_url = json_object_get_string(jcontenturl);
		const char *extra = json_object_get_string(jextradata);
		if (container && container_url){
			// FIXME(ABO): Default to current time ?
			rec->mtime = jmtime ? json_object_get_int64(jmtime) : 0;
			rec->container = g_strdup(container);
			rec->container_url = g_strdup(container_url);
			if (extra)
				rec->extra_data = g_strdup(extra);
			else
				rec->extra_data = NULL;
		} else {
			err = NEWERROR(CODE_BAD_REQUEST,
				"[%s] container_id and container_url are mandatory",
				__FUNCTION__);
		}
	}
	return err;
}

/*
 * Computes the key for an rdir_meta2_record_s
 */
static GError *
_meta2_record_to_key(struct rdir_meta2_record_s *rec, GString *key)
{
	GError *err = NULL;
	if (rec->container_url) {
		g_string_printf(key, CONTAINER_PREFIX "%s", rec->container_url);
	} else {
		err = BADREQ("[%s] container_url is mandatory", __FUNCTION__);
	}
	return err;
}

/*
 * Compiles a rdir_meta2_record_s into a JSON object.
 */
static void
_meta2_record_encode(struct rdir_meta2_record_s *rec, GString *value)
{
	g_string_append_c(value, '{');
	oio_str_gstring_append_json_pair(value, "container_id", rec->container);
	g_string_append_c(value, ',');
	oio_str_gstring_append_json_pair(value, "container_url", rec->container_url);
	g_string_append_c(value, ',');
	oio_str_gstring_append_json_pair(value, "extra_data", rec->extra_data);
	g_string_append_c(value, ',');
	oio_str_gstring_append_json_pair_int(value, "mtime", rec->mtime);
	g_string_append_c(value, '}');
}

static void
_meta2_record_free(struct rdir_meta2_record_s *rec)
{
	g_free(rec->container);
	g_free(rec->container_url);
	g_free(rec->extra_data);
}

/*
 * Extracts a description of the desired record subset from the JSON
 * body.
 */
static GError *
_meta2_record_subset_extract(struct rdir_meta2_record_subset_s *subset,
		struct json_object *jrecord)
{
	struct json_object *jprefix, *jmarker, *jlimit;
	struct oio_ext_json_mapping_s map[] = {
		{"prefix", &jprefix, json_type_string, 0},
		{"marker", &jmarker, json_type_string, 0},
		{"limit", &jlimit, json_type_int, 0},
		{NULL, NULL, 0, 0}
	};
	GError *err = oio_ext_extract_json(jrecord, map);
	if (!err) {
		if (jprefix) {
			// TODO(ABO): Sanity checks on the prefix.
			const char *prefix = json_object_get_string(jprefix);
			subset->prefix = g_string_new(prefix);
		} else {
			subset->prefix = NULL;
		}
		if (jmarker) {
			// TODO(ABO): Sanity checks on the prefix.
			const char *marker = json_object_get_string(jmarker);
			subset->marker = g_string_new(marker);
		} else {
			subset->marker = NULL;
		}
		if (jlimit)
			subset->limit = json_object_get_int64(jlimit);
		if (subset->limit <= 0)
			subset->limit = RDIR_LISTING_DEFAULT_LIMIT;
		else
			subset->limit = MIN(RDIR_LISTING_MAX_LIMIT, subset->limit);
	}
	return err;
}


/*
 * Computes the meta2 server RDIR database filename.
 *
 * If the meta2_address is an IP:PORT, the filename is meta2-ip-port, otherwise
 * if the meta2_address is a service ID, then the filename is meta2-service_id.
 */
static GError *
_meta2_db_address_to_filename(const gchar *meta2_address, gchar **filename)
{
	gchar *local_copy = g_strdup(meta2_address);
	gchar *colon_char = strchr(local_copy, ':');
	if (colon_char != NULL) {
		// We have an IP:PORT
		*colon_char = '-';
		*filename = g_strconcat("meta2-", local_copy, NULL);
	} else {
		// We have a service ID
		*filename = g_strconcat("meta2-", local_copy, NULL);
	}
	g_free(local_copy);
	return NULL;
}

/*
 * Given a meta2 server address, we try to fetch a handle on the associated
 * database if it's already available, otherwise we open a new one.
 */
static GError *
_meta2_db_get(const gchar *meta2_address, gboolean autocreate,
		struct rdir_base_s **pbase)
{
	GError *err = NULL;
	gchar *filename = NULL;
	err = _meta2_db_address_to_filename(meta2_address, &filename);
	if (err == NULL) {
		err = _db_get_generic(meta2_db_tree, &meta2_db_lock, &meta2_db_cond,
			filename, autocreate, pbase);
		g_free(filename);
	}
	return err;
}

/*
 * Given an rdir_meta2_record_subset_s, this functions iterates through
 * the LevelDB database to return the wanted subset.
 *
 * If prefix is NULL, then no particular seeking is done before the iteration,
 * and we will return {limit} records starting from and including the
 * first record.
 *
 * If prefix is non-NULL, and there is an limit and marker, what will be
 * returned is (limit) record from and including the first record after
 * we seek the marker. In this case, all the records are guaranteed to have
 * the prefix in the container URL.
 */
static GError *
_meta2_db_fetch(const gchar *meta2_address, struct rdir_meta2_record_subset_s *subset,
				GString *json_reponse, gboolean *truncated)
{
	GError *err = NULL;
	struct rdir_base_s *base = NULL;

	if ((err = _meta2_db_get(meta2_address, FALSE, &base)))
		return err;

	// The prefix/marker is only used here so we can edit it in-place.
	if (subset->prefix)
		subset->prefix = g_string_prepend(subset->prefix, CONTAINER_PREFIX);
	if (subset->marker)
		subset->marker = g_string_prepend(subset->marker, CONTAINER_PREFIX);

	leveldb_readoptions_t *options = leveldb_readoptions_create();
	leveldb_readoptions_set_fill_cache(options, 0);
	leveldb_readoptions_set_verify_checksums(options, 0);
	leveldb_iterator_t *it = leveldb_create_iterator(base->base, options);
	leveldb_readoptions_destroy(options);

	if (subset->marker) {
		// We have a marker.
		leveldb_iter_seek(it, subset->marker->str, subset->marker->len);
		// We shouldn't include the marker in the returned results.
		leveldb_iter_next(it);
	} else if (subset->prefix) {
		// No marker but we still have a prefix
		leveldb_iter_seek(it, subset->prefix->str, subset->prefix->len);
	} else {
		// LevelDB quirk apparently, you have to seek somewhere no matter what
		// before iterating.
		leveldb_iter_seek_to_first(it);
	}

	// Now we're at the first record that has the prefix provided.
	// We start iterating.
	guint nb = 0;
	for (; leveldb_iter_valid(it); leveldb_iter_next(it), nb++) {
		size_t klen = 0, vallen = 0;

		const char *key = leveldb_iter_key(it, &klen);
		if (subset->prefix) {
			// LevelDB's keys are ordered lexicographically, so on the first
			// key that does not have the prefix, we can stop iterating.
			size_t maxlen = MIN(klen, subset->prefix->len);
			if (strncmp(subset->prefix->str, key, maxlen))
				break;
		}

		if (nb > subset->limit) {
			// The current item is valid but we reached the limit during the
			// previous iteration, thus we don't return it.
			*truncated = TRUE;
			break;
		} else if (nb > 0) {
			g_string_append_c(json_reponse, ',');
		}

		const char *val = leveldb_iter_value(it, &vallen);

		// FIXME(ABO): Maybe validate the format as is done in the chunk part
		// of rdir.
		// It would consume a bit more CPU, so wether it's useful or not is
		// debatable especially given that we don't cherry-pick data as in the
		// chunk part of rdir.

		g_string_append_len(json_reponse, val, vallen);
	}

	leveldb_iter_destroy(it);
	return err;
}

/*
 * Add a container to the meta2 server pointed by the meta2_address
 */
static GError*
_meta2_db_push(const char *meta2_address, gboolean autocreate, GString * key,
		GString *val)
{
	struct rdir_base_s *base = NULL;
	GError *err = _meta2_db_get(meta2_address, autocreate, &base);
	if (err)
		return err;
	return _db_insert_generic(base, key, val);
}

/*
 * Remove a record from the database.
 */
static GError *
_meta2_db_delete(const gchar *meta2_address, GString *key)
{
	struct rdir_base_s *base = NULL;
	GError *err = _meta2_db_get(meta2_address, FALSE, &base);
	if (err)
		return err;
	return _db_vol_delete_generic(base, key);
}

// RDIR{{
// POST /v1/rdir/meta2/fetch?vol=<volume ip>%3A<volume port>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Fetch specific meta2 records, or a range of records.
//
// The record are ordered by container_url, so we can seek a specific prefix
// and start iterating from there.
//
// For example, if we want to iterate through the containers that belong to
// account A, we'll seek NS/A and start iterating.
//
// If a prefix is provided, only records whose keys contain this prefix
// will be returned.
//
// We can also seek a specific marker and start iterating from the record
// following the marker.
//
// The marker is never included in the results.
//
// A limit for the number of records to be returned can be specified.
//
// If no limit is specified, the default limit be 4096.
//
// The maximum allowed number of records to be returned is 4096.
//
// If no more records are available for the requested subset, 'truncated'
// will be true, otherwise it will be false.
//
// .. code-block:: http
//
//    POST /v1/rdir/meta2/fetch?vol=127.0.0.1%3A6020 HTTP/1.1
//    Host: 127.0.0.1:15
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: json
//
//    {
//      "prefix":"<container url prefix>",
//      "marker":"<last entry of the previous response>",
//      "limit":"<number of entries to return>"
//    }
//
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Length: 2
//
// }}RDIR
static enum http_rc_e
_route_meta2_fetch(struct req_args_s *args, struct json_object *jbody,
					const char *meta2_address)
{
	if (!jbody || !json_object_is_type(jbody, json_type_object))
		return _reply_format_error(args->rp, BADREQ("null body"));
	if (!meta2_address)
		return _reply_format_error(args->rp, BADREQ("no meta2 id"));

	GError *err = NULL;

	struct rdir_meta2_record_subset_s subset = {0};
	err = _meta2_record_subset_extract(&subset, jbody);
	if (err)
		return _reply_format_error(args->rp, err);

	GString *response_list = g_string_sized_new(1024);
	gboolean truncated = FALSE;
	g_string_append_static(response_list, "{\"records\":[");
	err = _meta2_db_fetch(meta2_address, &subset, response_list, &truncated);
	g_string_append_static(response_list, "], ");
	oio_str_gstring_append_json_pair_boolean(
			response_list, "truncated", truncated);
	g_string_append_c(response_list, '}');

	if (err) {
		g_string_free(response_list, TRUE);
		return _reply_format_error(args->rp, err);
	}

	return _reply_ok(args->rp, response_list);
}

// RDIR{{
// POST /v1/rdir/meta2/create?vol=<volume ip>%3A<volume port>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Create a new meta2 rdir database.
// There is no IP re-use, so the IP addresses of the meta2 servers
// are used to reference them.
//
// .. code-block:: http
//
//    POST /v1/rdir/meta2/create?vol=127.0.0.1%3A6020 HTTP/1.1
//    Host: 127.0.0.1:15
//    User-Agent: curl/7.47.0
//    Accept: */*
//
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 201 Created
//    Connection: Close
//    Content-Length: 0
//
// }}RDIR
static enum http_rc_e
_route_meta2_create(struct req_args_s *args, const char *meta2_address)
{
	if (!oio_str_is_set(meta2_address))
		return _reply_format_error(args->rp, BADREQ("No meta2 ID"));

	// FIXME(ABO): Check for an IP:PORT or service ID format.

	struct rdir_base_s *base = NULL;
	GError *err = _meta2_db_get(meta2_address, TRUE, &base);
	if (err)
		return _reply_common_error(args->rp, err);
	return _reply_created(args->rp);
}

// RDIR{{
// POST /v1/rdir/meta2/push?vol=<volume ip>%3A<volume port>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Add a newly created container to the list of containers handled
// by the meta2 server in question.
//
// .. code-block:: http
//
//    POST /v1/rdir/meta2/push?vol=127.0.0.1%3A6020 HTTP/1.1
//    Host: 127.0.0.1:15
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 150
//    Content-Type: application/x-www-form-urlencoded
//
//
// .. code-block:: json
//
//    {
//      "container_id":"<container id>",
//      "container_url":"<container url>",
//      "mtime":"<last modification timestamp>"
//    }
//
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Length: 0
//
// }}RDIR
static enum http_rc_e
_route_meta2_push(struct req_args_s *args, struct json_object *jbody,
		const char *meta2_address, const char *str_autocreate)
{
	if (!jbody || !json_object_is_type(jbody, json_type_object))
		return _reply_format_error(args->rp, BADREQ("null body"));
	if (!meta2_address)
		return _reply_format_error(args->rp, BADREQ("no meta2 id"));

	gboolean autocreate = oio_str_parse_bool(str_autocreate, TRUE);

	GError *err = NULL;
	struct rdir_meta2_record_s rec = {0};
	if ((err = _meta2_record_extract(&rec, jbody)))
		return _reply_format_error(args->rp, err);

	GString *key = g_string_new("");
	err = _meta2_record_to_key(&rec, key);
	if (err){
		g_string_free(key, TRUE);
		return _reply_format_error(args->rp, err);
	}
	GString *value = g_string_sized_new(1024);
	args->rp->access_tail("k=%s", key->str);
	_meta2_record_encode(&rec, value);


	/* Eventually push the record in the database */
	err = _meta2_db_push(meta2_address, autocreate, key, value);
	g_string_free(key, TRUE);
	g_string_free(value, TRUE);
	_meta2_record_free(&rec);

	if (err)
		return _reply_common_error(args->rp, err);

	return _reply_ok(args->rp, NULL);
}


// RDIR{{
// DELETE /v1/rdir/meta2/delete?vol=<volume ip>%3A<volume port>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Remove a meta2 record from the database.
//
// .. code-block:: http
//
//    DELETE /v1/rdir/meta2/delete?vol=127.0.0.1%3A6020 HTTP/1.1
//    Host: 127.0.0.1:15
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 135
//    Content-Type: application/x-www-form-urlencoded
//
//
// .. code-block:: json
//
//    {
//      "container_id":"<container id>",
//      "container_url":"<container url>",
//    }
//
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}RDIR
static enum http_rc_e
_route_meta2_delete(struct req_args_s *args, struct json_object *jbody,
				  const char *meta2_address)
{
	if (!jbody || !json_object_is_type(jbody, json_type_object))
		return _reply_format_error(args->rp, BADREQ("null body"));
	if (!meta2_address)
		return _reply_format_error(args->rp, BADREQ("no meta2 id"));

	GError *err = NULL;
	struct rdir_meta2_record_s rec = {0};
	if ((err = _meta2_record_extract(&rec, jbody)))
		return _reply_format_error(args->rp, err);

	GString *key = g_string_new("");
	err = _meta2_record_to_key(&rec, key);
	if (err){
		g_string_free(key, TRUE);
		return _reply_format_error(args->rp, err);
	}

	args->rp->access_tail("k=%s", key->str);

	/* Eventually delete the record from the database */
	err = _meta2_db_delete(meta2_address, key);
	g_string_free(key, TRUE);
	_meta2_record_free(&rec);

	if (err)
		return _reply_common_error(args->rp, err);

	return _reply_ok(args->rp, NULL);
}

/* ------------------------------------------------------------------------- *
 *                          General rdir routes                              *
 * ------------------------------------------------------------------------- */

// RDIR{{
// GET /status
// ~~~~~~~~~~~
// Return a brief summary of the usage on the target service.
//
// .. code-block:: http
//
//    GET /status HTTP/1.1
//    Host: 127.0.0.1:6022
//    User-Agent: curl/7.55.1
//    Accept: */*
//
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 21
//
//    {"opened_db_count":6}
//
// }}RDIR
static enum http_rc_e
_route_srv_status(struct req_args_s *args)
{
	g_mutex_lock(&lock_bases);
	guint count = g_tree_nnodes(tree_bases);
	g_mutex_unlock(&lock_bases);

	GString *gstr = g_string_sized_new(128);
	g_string_append_c(gstr, '{');
	oio_str_gstring_append_json_pair_int(gstr, "opened_db_count", count);
	if (service_id) {
		g_string_append_c(gstr, ',');
		oio_str_gstring_append_json_pair(gstr, "service_id", service_id);
	}
	g_string_append_c(gstr, '}');

	return _reply_ok(args->rp, gstr);
}


// RDIR{{
// GET /config
// ~~~~~~~~~~~
//
// Return the live configuration of the target RDIR service.
//
// .. code-block:: http
//
//    GET /config HTTP/1.1
//    Host: 127.0.0.1:6022
//    User-Agent: curl/7.55.1
//    Accept: */*
//
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 2015
//
// .. code-block:: text
//
//    {"core.http.user_agent":"", ...}
//
// }}RDIR
static enum http_rc_e
_route_srv_config(struct req_args_s *args)
{
	return _reply_ok (args->rp, oio_var_list_as_json());
}

/* ------------------------------------------------------------------------- */

static enum http_rc_e
_handler_decode_route(struct req_args_s *args, struct json_object *jbody,
		enum rdir_route_e route)
{
	switch (route) {
		case OIO_ROUTE_STATUS:
			args->rp->no_access();
			CHECK_METHOD("GET");
			return _route_srv_status(args);

		case OIO_ROUTE_CONFIG:
			args->rp->no_access();
			CHECK_METHOD("GET");
			return _route_srv_config(args);

		case OIO_RDIR_STATUS:
			// FALLTHROUGH
		case OIO_RDIR_ADMIN_SHOW:
			args->rp->no_access();
			CHECK_METHOD("GET");
			return _route_admin_show(args, OPT("vol"));

		case OIO_RDIR_ADMIN_UNLOCK:
			CHECK_METHOD("POST");
			return _route_admin_unlock(args, OPT("vol"));

		case OIO_RDIR_ADMIN_LOCK:
			CHECK_METHOD("POST");
			return _route_admin_lock(args, jbody, OPT("vol"));

		case OIO_RDIR_ADMIN_INCIDENT:
			if (!strcmp(args->rq->cmd, "GET"))
				return _route_admin_get_incident(args, OPT("vol"));
			if (!strcmp(args->rq->cmd, "POST"))
				return _route_admin_set_incident(args, jbody, OPT("vol"));
			return _reply_method_error(args->rp);

		case OIO_RDIR_ADMIN_CLEAR:
			CHECK_METHOD("POST");
			return _route_admin_clear(args, OPT("vol"), OPT("all"),
					OPT("before_incident"), OPT("repair"));

		case OIO_RDIR_VOL_CREATE:
			CHECK_METHOD("POST");
			return _route_vol_create(args, OPT("vol"));

		case OIO_RDIR_VOL_PUSH:
			args->rp->no_access();
			CHECK_METHOD("POST");
			return _route_vol_push(args, jbody, OPT("vol"), OPT("create"));

		case OIO_RDIR_VOL_DELETE:
			args->rp->no_access();
			CHECK_METHOD("DELETE");
			return _route_vol_delete(args, jbody, OPT("vol"));

		case OIO_RDIR_VOL_FETCH:
			CHECK_METHOD("POST");
			return _route_vol_fetch(args, jbody, OPT("vol"));

		case OIO_RDIR_VOL_STATUS:
			if (!strcmp(args->rq->cmd, "GET") || !strcmp(args->rq->cmd, "POST"))
				return _route_vol_status(args, OPT("vol"));
			return _reply_method_error(args->rp);

		case OIO_RDIR_META2_CREATE:
			CHECK_METHOD("POST");
			return _route_meta2_create(args, OPT("vol"));

		case OIO_RDIR_META2_PUSH:
			args->rp->no_access();
			CHECK_METHOD("POST");
			return _route_meta2_push(args, jbody, OPT("vol"), OPT("create"));

		case OIO_RDIR_META2_FETCH:
			CHECK_METHOD("POST");
			return _route_meta2_fetch(args, jbody, OPT("vol"));

		case OIO_RDIR_META2_DELETE:
			args->rp->no_access();
			CHECK_METHOD("POST");
			return _route_meta2_delete(args, jbody, OPT("vol"));

		case OIO_RDIR_NOT_MATCHED:
			return _reply_format_error(args->rp, BADREQ("Route not found"));

		default:
			g_assert_not_reached();
			return HTTPRC_ABORT;
	}
}

static enum http_rc_e
handler_action(struct http_request_s *rq, struct http_reply_ctx_s *rp)
{
	enum http_rc_e rc = HTTPRC_ABORT;

	/* Get a request id for the current request */
	const gchar *reqid = g_tree_lookup(rq->tree_headers, PROXYD_HEADER_REQID);
	if (reqid)
		oio_ext_set_reqid(reqid);
	else
		oio_ext_set_prefixed_random_reqid("rdir-");

	/* parse the URLL and forward to the backend if the route matches */
	struct req_args_s args = {0};
	args.rq = rq;
	args.rp = rp;
	oio_requri_parse(rq->req_uri, &args.ruri);

	const enum rdir_route_e route = oio_rdir_parse_route(args.ruri.path);
	if (route == OIO_RDIR_NOT_MATCHED) {
		rc = _reply_not_found(rp, BADREQ("Route not managed"));
	} else {
		struct json_object *jbody = NULL;
		GError *err = JSON_parse_buffer(rq->body->data, rq->body->len, &jbody);
		if (err) {
			rc = _reply_format_error(rp, err);
		} else {
			rc = _handler_decode_route(&args, jbody, route);
			json_object_put(jbody);
		}
	}

	oio_requri_clear(&args.ruri);
	return rc;
}

static void
_main_error(GError * err)
{
	GRID_ERROR("Action failure: (%d) %s", err->code, err->message);
	g_clear_error(&err);
	grid_main_set_status(1);
}

static void
_patch_and_apply_configuration(void)
{
	const guint maxfd = metautils_syscall_count_maxfd();

	/* Enforce arbitrary but acceptable default value */
	if (server_fd_max_passive > 0 && rdir_fd_reserve <= 0) {
		rdir_fd_reserve = maxfd - server_fd_max_passive;
	} else if (server_fd_max_passive <= 0 && rdir_fd_reserve > 0) {
		server_fd_max_passive = maxfd - rdir_fd_reserve;
	} else if (server_fd_max_passive <= 0 && rdir_fd_reserve <= 0) {
		server_fd_max_passive = rdir_fd_reserve = maxfd / 2;
	}

	if (rdir_fd_per_base <= 0) {
		/* rdir are supposed to be deployed alongside the rawx, with a 1:1
		 * ratio as the most common deployment case, and a 8:1 rdir/rawx ratio
		 * in some cases. So assuming a rdir manages 16 bases in most cases
		 * seems decent. */
		rdir_fd_per_base = rdir_fd_reserve / 16;
	}
	if (rdir_fd_per_base <= 8) {
		rdir_fd_per_base = 8;
	}

	if (rdir_fd_reserve + server_fd_max_passive > maxfd) {
		GRID_WARN("Too many FD configured sys[%u] db[%u] passive[%u] %%base[%u]",
				maxfd, rdir_fd_reserve, server_fd_max_passive, rdir_fd_per_base);
	} else {
		GRID_INFO("FD configured sys[%u] db[%u] passive[%u] %%base[%u]",
				maxfd, rdir_fd_reserve, server_fd_max_passive, rdir_fd_per_base);
	}

	network_server_reconfigure(server);
}

static void
_reconfigure_on_SIGHUP(void)
{
	GRID_NOTICE("SIGHUP! Reconfiguring...");
	oio_var_reset_all();
	oio_var_value_with_files(ns_name, config_system, config_paths);
	_patch_and_apply_configuration();
}

static void
grid_main_action(void)
{
	GError *err = NULL;

	if ((err = network_server_open_servers(server))) {
		_main_error(err);
		return;
	}

	if (!(th_gtq_admin = grid_task_queue_run(gtq_admin, &err))) {
		_main_error(err);
		return;
	}

	if ((err = network_server_run(server, _reconfigure_on_SIGHUP))) {
		_main_error(err);
		return;
	}
}

static struct grid_main_option_s *
grid_main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{"Bind", OT_LIST, {.lst = &config_urlv},
			"An additional URL to bind to (might be used several time).\n"
			"\t\tAccepts UNIX and INET sockets." },

		{"SysConfig", OT_BOOL, {.b = &config_system},
			"Load the system configuration and overload the central variables"},

		{"Config", OT_LIST, {.lst = &config_paths},
			"Load the given file and overload the central variables"},

		{NULL, 0, {.i = 0}, NULL}
	};

	return options;
}

static void
grid_main_set_defaults(void)
{
}

static void
grid_main_specific_fini(void)
{
	if (th_gtq_admin) {
		grid_task_queue_stop(gtq_admin);
		g_thread_join(th_gtq_admin);
		th_gtq_admin = NULL;
	}
	if (gtq_admin) {
		grid_task_queue_destroy(gtq_admin);
		gtq_admin = NULL;
	}

	if (server) {
		network_server_close_servers(server);
		network_server_stop(server);
		network_server_clean(server);
		server = NULL;
	}

	g_slist_free_full(config_urlv, g_free);
	config_urlv = NULL;

	g_tree_destroy(tree_bases);
	tree_bases = NULL;
	g_cond_clear(&cond_bases);
	g_mutex_clear(&lock_bases);

	g_tree_destroy(meta2_db_tree);
	tree_bases = NULL;
	g_cond_clear(&meta2_db_cond);
	g_mutex_clear(&meta2_db_lock);

	oio_str_clean(&basedir);
	oio_str_clean(&service_id);
}

static void
_task_malloc_trim(gpointer p UNUSED)
{
	VARIABLE_PERIOD_DECLARE();
	if (VARIABLE_PERIOD_SKIP(sqlx_periodic_malloctrim_period))
		return;

	malloc_trim (sqlx_periodic_malloctrim_size);
}

#define CFG(K) g_key_file_get_string(gkf, CFG_GROUP, (K), &err)

#define DUAL_ERROR(FMT,...) do { \
	g_printerr("\n*** " FMT " ***\n\n", ##__VA_ARGS__); \
	GRID_ERROR(FMT, ##__VA_ARGS__); \
} while (0)

static gboolean
_config_error(const char *where, GError *err)
{
	DUAL_ERROR("Configuration error: %s: (%d) %s",
			where, err->code, err->message);
	g_clear_error(&err);
	return FALSE;
}

static gboolean
grid_main_configure(int argc, char **argv)
{
	if (argc != 1) {
		GRID_ERROR("Invalid parameter, expected PATH_CONFIG");
		return FALSE;
	}

	const char *cfg_path = argv[0];

	GError *err = NULL;
	GKeyFile *gkf = g_key_file_new();
	EXTRA_ASSERT(gkf != NULL);

	if (!g_key_file_load_from_file(gkf, cfg_path, G_KEY_FILE_NONE, &err)) {
		g_key_file_free(gkf);
		return _config_error("File error", err);
	}

	if (!g_key_file_has_group(gkf, CFG_GROUP)) {
		g_key_file_free(gkf);
		return _config_error("File error", SYSERR("No [%s] section", CFG_GROUP));
	}

	ns_name = CFG("namespace");
	if (!ns_name) {
		g_key_file_free(gkf);
		return _config_error("NS name", err);
	}

	basedir = CFG("db_path");
	if (!basedir) {
		g_key_file_free(gkf);
		return _config_error("DB path", err);
	}

	service_id = CFG("service_id");
	if (err)
		g_clear_error(&err);

	gchar *cfg_ip = CFG("bind_addr");
	STRING_STACKIFY(cfg_ip);
	if (!cfg_ip) {
		g_key_file_free(gkf);
		return _config_error("Bind address", err);
	}

	gchar *cfg_port = CFG("bind_port");
	STRING_STACKIFY(cfg_port);
	if (!cfg_port) {
		g_key_file_free(gkf);
		return _config_error("Bind port", err);
	}

	gchar *cfg_syslog = CFG("syslog_prefix");
	if (err)
		g_clear_error(&err);
	STRING_STACKIFY(cfg_syslog);

	g_key_file_free(gkf);
	gkf = NULL;

	/* supersedes the default logging */
	if (cfg_syslog) {
		const gsize len0 = g_strlcpy(syslog_id, cfg_syslog, sizeof(syslog_id));
		if (len0 >= sizeof(syslog_id))
			return _config_error("Syslog prefix",
					NEWERROR(EINVAL, "Prefix too long (64B max)"));
		logger_syslog_open();
	}

	/* Check the basedir exists and we have the required permissions on it */
	if (0 != g_access(basedir, R_OK|W_OK|X_OK)) {
		DUAL_ERROR("Basedir error [%s]: (%d) %s", basedir, errno, strerror(errno));
		return FALSE;
	}
	if (!g_file_test(basedir, G_FILE_TEST_IS_DIR)) {
		DUAL_ERROR("Basedir error [%s]: not a directory", basedir);
		return FALSE;
	}

	/* Load the central configuration facility, it will tell us our
	 * NS is locally known. */
	if (!oio_var_value_with_files(ns_name, config_system, config_paths)) {
		DUAL_ERROR("NS [%s] unknown in the configuration", ns_name);
		return FALSE;
	}

	_patch_and_apply_configuration();

	gchar *cfg_main_url = g_strconcat(cfg_ip, ":", cfg_port, NULL);
	STRING_STACKIFY(cfg_main_url);

	/* Validate the volume was never used for another rdir */
	err = volume_service_lock(basedir, NAME_SRVTYPE_RDIR,
				  cfg_main_url, ns_name, oio_volume_lock_lazy);
	if (err != NULL)
		return _config_error("Volume lock error", err);

	/* Prepare the network side of the application */
	server = network_server_init();

	network_server_bind_host(server, cfg_main_url, handler_action,
			(network_transport_factory) transport_http_factory0);

	for (GSList *lu=config_urlv ; lu ; lu=lu->next)
		network_server_bind_host(server, lu->data, handler_action,
				(network_transport_factory) transport_http_factory0);

	g_cond_init(&cond_bases);
	g_mutex_init(&lock_bases);
	tree_bases = g_tree_new_full(metautils_strcmp3, NULL,
			g_free, (GDestroyNotify)_base_destroy);

	g_cond_init(&meta2_db_cond);
	g_mutex_init(&meta2_db_lock);
	meta2_db_tree = g_tree_new_full(metautils_strcmp3, NULL,
			g_free, (GDestroyNotify)_base_destroy);

	/* Ask for a periodic release of the memory slices kept by the process */
	gtq_admin = grid_task_queue_create("admin");
	grid_task_queue_register(gtq_admin, 1, _task_malloc_trim, NULL, NULL);
	return TRUE;
}

static const char *
grid_main_get_usage(void)
{
	return "PATH_CONFIG";
}

static void
grid_main_specific_stop(void)
{
	if (server)
		network_server_stop(server);
}

static struct grid_main_callbacks main_callbacks =
{
	.options = grid_main_get_options,
	.action = grid_main_action,
	.set_defaults = grid_main_set_defaults,
	.specific_fini = grid_main_specific_fini,
	.configure = grid_main_configure,
	.usage = grid_main_get_usage,
	.specific_stop = grid_main_specific_stop,
};

int
main(int argc, char **argv)
{
	return grid_main(argc, argv, &main_callbacks);
}
