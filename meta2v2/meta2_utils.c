/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS

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

#include <string.h>

#include <glib.h>

#include <core/oiolog.h>
#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/meta2_utils.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_variables.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <meta2v2/meta2_utils_json.h>
#include <meta2v2/meta2_utils_lb.h>

static GError*
_get_container_policy(struct sqlx_sqlite3_s *sq3, struct namespace_info_s *nsinfo,
		struct storage_policy_s **result);

static GError*
_purge_exceeding_aliases(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		const gchar *url, m2_onbean_cb cb, gpointer u0);

static gint
_tree_compare_int(gconstpointer a, gconstpointer b)
{
	return CMP(GPOINTER_TO_INT(a), GPOINTER_TO_INT(b));
}

#define FORMAT_ERROR(v,s,e) (!(v) && errno == EINVAL)
#define RANGE_ERROR(v) ((v) == G_MININT64 || (v) == G_MAXINT64)
#define STRTOLL_ERROR(v,s,e) (FORMAT_ERROR(v,s,e) || RANGE_ERROR(v))

/* Tell if a bean represents a property and has a NULL or empty value. */
static gboolean
_is_empty_prop(gpointer bean)
{
	if (DESCR(bean) != &descr_struct_PROPERTIES)
		return FALSE;
	GByteArray *val = PROPERTIES_get_value((struct bean_PROPERTIES_s *)bean);
	return !val || !val->len || !val->data;
}

void
m2v2_position_encode (GString *out, struct m2v2_position_s *p)
{
	EXTRA_ASSERT(out != NULL);
	EXTRA_ASSERT(p != NULL);
	if (p->flag_rain) {
		g_string_printf(out, "%d.%d%s", p->meta, p->intra, p->flag_parity ? "p" : "");
	} else {
		g_string_printf(out, "%d", p->meta);
	}
}

struct m2v2_position_s
m2v2_position_decode (const char *s)
{
	struct m2v2_position_s out = {0, 0, 0, 0, 0};
	gchar *end = NULL;
	gboolean parity = FALSE;
	gint64 p64, s64;

	if (!s)
		return out;

	p64 = g_ascii_strtoll(s, &end, 10);
	if (STRTOLL_ERROR(p64, s, end))
		return out;
	if (!*end) {
		out.meta = p64;
		out.flag_ok = 1;
		return out;
	}

	if (*end != '.')
		return out;
	s = end + 1;
	if (!*s) // Trailing dot not accepted
		return out;

	if (*s == 'p') {
		parity = 1;
		++ s;
	}

	end = NULL;
	s64 = g_ascii_strtoll(s, &end, 10);
	if (STRTOLL_ERROR(s64, s, end))
		return out;
	if (*end) // Trailing extra chars not accepted
		return out;

	out.meta = p64;
	out.intra = s64;
	out.flag_parity = BOOL(parity);
	out.flag_rain = 1;
	out.flag_ok = 1;
	return out;
}

void
m2db_get_container_size_and_obj_count(sqlite3 *db, gboolean check_alias,
		guint64 *size_out, gint64 *obj_count_out)
{
	guint64 size = 0;
	gint64 obj_count = 0;
	gchar tmp[512];
	g_snprintf(tmp, sizeof(tmp), "%s%s", "SELECT SUM(size),COUNT(id) FROM contents",
			!check_alias ? "" :
			" WHERE EXISTS (SELECT content FROM aliases WHERE content = id)");
	const gchar *sql = tmp;
	int rc, grc = SQLITE_OK;
	const gchar *next;
	sqlite3_stmt *stmt = NULL;

	while ((grc == SQLITE_OK) && sql && *sql) {
		next = NULL;
		sqlite3_prepare_debug(rc, db, sql, -1, &stmt, &next);
		sql = next;
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			grc = rc;
		else if (stmt) {
			while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
				size = sqlite3_column_int64(stmt, 0);
				obj_count = sqlite3_column_int64(stmt, 1);
			}
			if (rc != SQLITE_OK && rc != SQLITE_DONE) {
				grc = rc;
			}
			rc = sqlite3_finalize(stmt);
		}

		stmt = NULL;
	}
	if (size_out)
		*size_out = size;
	if (obj_count_out)
		*obj_count_out = obj_count;
}

gint64
m2db_get_max_versions(struct sqlx_sqlite3_s *sq3, gint64 def)
{
	if (oio_ext_has_simulate_versioning())
		return -1;
	return sqlx_admin_get_i64(sq3, M2V2_ADMIN_VERSIONING_POLICY, def);
}

void
m2db_set_max_versions(struct sqlx_sqlite3_s *sq3, gint64 max)
{
	sqlx_admin_set_i64(sq3, M2V2_ADMIN_VERSIONING_POLICY, max);
}

gint64
m2db_get_ctime(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_admin_get_i64(sq3, M2V2_ADMIN_CTIME, 0);
}

void
m2db_set_ctime(struct sqlx_sqlite3_s *sq3, gint64 now)
{
	sqlx_admin_set_i64(sq3, M2V2_ADMIN_CTIME, now);
}

gint64
m2db_get_keep_deleted_delay(struct sqlx_sqlite3_s *sq3, gint64 def)
{
	return sqlx_admin_get_i64(sq3, M2V2_ADMIN_KEEP_DELETED_DELAY, def);
}

gint64
m2db_get_flag_delete_exceeding_versions(struct sqlx_sqlite3_s *sq3, gint64 def)
{
	return sqlx_admin_get_i64(sq3, M2V2_ADMIN_DELETE_EXCEEDING_VERSIONS, def);
}

gint64
m2db_get_version(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_admin_get_i64(sq3, M2V2_ADMIN_VERSION, 1);
}

void
m2db_increment_version(struct sqlx_sqlite3_s *sq3)
{
	sqlx_admin_inc_i64(sq3, M2V2_ADMIN_VERSION, 1);
}

gint64
m2db_get_size(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_admin_get_i64(sq3, M2V2_ADMIN_SIZE, 0);
}

void
m2db_set_size(struct sqlx_sqlite3_s *sq3, gint64 size)
{
	sqlx_admin_set_i64(sq3, M2V2_ADMIN_SIZE, size);
}

gint64
m2db_get_quota(struct sqlx_sqlite3_s *sq3, gint64 def)
{
	return sqlx_admin_get_i64(sq3, M2V2_ADMIN_QUOTA, def);
}

gint64
m2db_get_obj_count(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_admin_get_i64(sq3, M2V2_ADMIN_OBJ_COUNT, 0);
}

void
m2db_set_obj_count(struct sqlx_sqlite3_s *sq3, gint64 count)
{
	sqlx_admin_set_i64(sq3, M2V2_ADMIN_OBJ_COUNT, count);
}

gint64
m2db_get_damaged_objects(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_admin_get_i64(sq3, M2V2_ADMIN_DAMAGED_OBJECTS, 0);
}

void
m2db_set_damaged_objects(struct sqlx_sqlite3_s *sq3, gint64 damaged)
{
	if (damaged < 0)
		damaged = 0;
	sqlx_admin_set_i64(sq3, M2V2_ADMIN_DAMAGED_OBJECTS, damaged);
}

gint64
m2db_get_missing_chunks(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_admin_get_i64(sq3, M2V2_ADMIN_MISSING_CHUNKS, 0);
}

void
m2db_set_missing_chunks(struct sqlx_sqlite3_s *sq3, gint64 missing)
{
	if (missing < 0)
		missing = 0;
	sqlx_admin_set_i64(sq3, M2V2_ADMIN_MISSING_CHUNKS, missing);
}

/* GET ---------------------------------------------------------------------- */

static void
_load_chunk_quality(GHashTable *qualities, struct bean_PROPERTIES_s *prop)
{
	GError *err = NULL;
	GByteArray *val = PROPERTIES_get_value(prop);
	json_tokener *parser = json_tokener_new();
	json_object *jbody = json_tokener_parse_ex(
			parser, (const char*)val->data, val->len);
	if (json_tokener_get_error(parser) != json_tokener_success) {
		err = NEWERROR(0, "%s",
				json_tokener_error_desc(json_tokener_get_error(parser)));
	} else {
		struct oio_lb_selected_item_s *item = g_malloc0(sizeof *item);
		err = meta2_json_fill_item_quality(jbody, item);
		if (!err) {
			GString *key = PROPERTIES_get_key(prop);
			EXTRA_ASSERT(g_str_has_prefix(key->str, OIO_CHUNK_SYSMETA_PREFIX));
			g_hash_table_insert(qualities,
					g_strdup(key->str + strlen(OIO_CHUNK_SYSMETA_PREFIX)), item);
		} else {
			oio_lb_selected_item_free(item);
		}
	}

	if (jbody)
		json_object_put(jbody);
	json_tokener_free(parser);
	if (err)
		GRID_WARN("Failed to parse chunk quality: %s", err->message);
	g_clear_error(&err);
}

static void
_load_chunk_qualities(GHashTable *qualities, GSList *properties)
{
	for (GSList *l = properties; l != NULL; l = l->	next)
		_load_chunk_quality(qualities, l->data);
}

static void
_sort_content_cb(gpointer sorted_content, gpointer bean)
{
	struct m2v2_sorted_content_s *content = sorted_content;
	if (DESCR(bean) == &descr_struct_CHUNKS) {
		gint64 pos = g_ascii_strtoll(
				CHUNKS_get_position(bean)->str, NULL, 10);
		GSList *mc = g_tree_lookup(content->metachunks, GINT_TO_POINTER(pos));
		mc = g_slist_prepend(mc, bean);
		g_tree_insert(content->metachunks, GINT_TO_POINTER(pos), mc);
		content->n_chunks++;
	} else if (DESCR(bean) == &descr_struct_ALIASES) {
		content->aliases = g_slist_prepend(content->aliases, bean);
	} else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
		content->header = bean;
	} else if (DESCR(bean) == &descr_struct_PROPERTIES) {
		content->properties = g_slist_prepend(content->properties, bean);
	} else {
		g_assert_not_reached();
	}
}

static gboolean
_foreach_free_list(gpointer key UNUSED, gpointer value, gpointer data UNUSED)
{
	if (value)
		g_slist_free((GSList *)value);
	return FALSE;
}

void
m2v2_sorted_content_free(struct m2v2_sorted_content_s *content)
{
	g_slist_free(content->aliases);
	g_slist_free(content->properties);
	g_tree_foreach(content->metachunks, _foreach_free_list, NULL);
	g_tree_destroy(content->metachunks);
	g_free(content);
}

void
m2v2_sort_content(GSList *beans, struct m2v2_sorted_content_s **content)
{
	EXTRA_ASSERT(content != NULL);
	EXTRA_ASSERT(*content == NULL);
	*content = g_malloc0(sizeof(struct m2v2_sorted_content_s));
	/* Do not set value free func, we will insert linked lists
	 * containing the previous values. */
	(*content)->metachunks = g_tree_new(_tree_compare_int);
	for (GSList *l = beans; l; l = l->next) {
		gpointer bean = l->data;
		_sort_content_cb(*content, bean);
	}
}

static GError*
_manage_header(sqlite3 *db, struct bean_CONTENTS_HEADERS_s *bean,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;

	GPtrArray *tmp = g_ptr_array_new();
	err = _db_get_FK_by_name_buffered(bean, "chunks", db, tmp);
	if (!err) {
		while (tmp->len > 0) {
			struct bean_CHUNKS_s *chunk = tmp->pdata[0];
			g_ptr_array_remove_index_fast(tmp, 0);
			if (chunk)
				cb(u0, chunk);
		}
	}

	_bean_cleanv2(tmp); /* cleans unset beans */

	cb(u0, bean);
	return err;
}

static GError*
_manage_alias(sqlite3 *db, struct bean_ALIASES_s *bean,
		gboolean deeper, m2_onbean_cb cb, gpointer u0)
{
	GPtrArray *tmp = g_ptr_array_new();
	GError *err = _db_get_FK_by_name_buffered(bean, "image", db, tmp);
	if (!err) {
		while (tmp->len > 0) {
			struct bean_CONTENTS_HEADERS_s *header = tmp->pdata[0];
			g_ptr_array_remove_index_fast(tmp, 0);
			if (!header)
				continue;
			if (deeper)
				_manage_header(db, header, cb, u0);
			else
				cb(u0, header);
		}
	}

	_bean_cleanv2(tmp); /* cleans unset beans */
	return err;
}

static GError*
_alias_fetch_info(struct sqlx_sqlite3_s *sq3, guint32 flags, GPtrArray *beans,
		m2_onbean_cb cb, gpointer u0) {
	GError *err = NULL;

	if (beans->len <= 0) {
		err = NEWERROR(CODE_CONTENT_NOTFOUND, "Alias not found");
	} else if (beans->len == 1 && ALIASES_get_deleted(beans->pdata[0]) &&
			(flags & M2V2_FLAG_NODELETED)) {
		err = NEWERROR(CODE_CONTENT_NOTFOUND, "Alias deleted");
	}

	/* recurse on headers if allowed */
	if (!err && cb && ((flags & M2V2_FLAG_HEADERS) ||
			!(flags & M2V2_FLAG_NORECURSION))) {
		for (guint i = 0; !err && i < beans->len; i++) {
			struct bean_ALIASES_s *alias = beans->pdata[i];
			if (!alias)
				continue;
			if ((flags & M2V2_FLAG_NODELETED) && ALIASES_get_deleted(alias))
				continue;
			_manage_alias(sq3->db, alias, !(flags & M2V2_FLAG_NORECURSION), cb, u0);
		}
	}

	/* recurse on properties if allowed */
	if (!err && cb && !(flags & M2V2_FLAG_NOPROPS)) {
		for (guint i = 0; !err && i < beans->len; i++) {
			struct bean_ALIASES_s *alias = beans->pdata[i];
			if (!alias)
				continue;
			GPtrArray *props = g_ptr_array_new();
			err = _db_get_FK_by_name_buffered(alias, "properties", sq3->db, props);
			if (!err) {
				for (guint j = 0; j < props->len; ++j) {
					cb(u0, props->pdata[j]);
					props->pdata[j] = NULL;
				}
			}
			_bean_cleanv2 (props);
		}
	}

	/* eventually manage the aliases */
	if (!err && cb) {
		for (guint i = 0; i < beans->len; i++) {
			struct bean_ALIASES_s *alias = beans->pdata[i];
			if (!alias)
				continue;
			if ((flags & M2V2_FLAG_NODELETED) && ALIASES_get_deleted(alias))
				_bean_clean(alias);
			else
				cb(u0, alias);
			beans->pdata[i] = NULL;
		}
	}

	return err;
}

GError*
m2db_get_alias(struct sqlx_sqlite3_s *sq3, struct oio_url_s *u,
		guint32 flags, m2_onbean_cb cb, gpointer u0)
{
	/* sanity checks */
	if (!oio_url_has(u, OIOURL_PATH) && !oio_url_has(u, OIOURL_CONTENTID))
		return BADREQ("Missing path and content");

	/* query */
	GError *err = NULL;
	const gchar *sql = NULL;
	GVariant *params[3] = {NULL, NULL, NULL};

	if (oio_url_has(u, OIOURL_PATH)) {
		params[0] = g_variant_new_string(oio_url_get(u, OIOURL_PATH));
		if (flags & M2V2_FLAG_LATEST) {
			sql = "alias = ? ORDER BY version DESC LIMIT 1";
		} else if (flags & M2V2_FLAG_ALLVERSION) {
			sql = "alias = ? ORDER BY version DESC";
		} else {
			if (oio_url_has(u, OIOURL_VERSION)) {
				sql = "alias = ? AND version = ? LIMIT 1";
				gint64 version =
					g_ascii_strtoll(oio_url_get(u, OIOURL_VERSION), NULL, 10);
				params[1] = g_variant_new_int64(version);
			} else {
				sql = "alias = ? ORDER BY version DESC LIMIT 1";
			}
		}
	} else {

		do { /* get the content-id in its binary form */
			/* TODO factorize this */
			const char *h = oio_url_get(u, OIOURL_CONTENTID);
			gsize hl = strlen(h);
			guint8 b[hl/2];
			if (!oio_str_hex2bin (h, b, hl/2))
				err = BADREQ("The content ID is not hexa");
			else {
				params[0] = _bytes_to_gvariant(b, hl/2);
			}
		} while (0);

		if (flags & M2V2_FLAG_LATEST) {
			sql = "content = ? ORDER BY version DESC LIMIT 1";
		} else if (flags & M2V2_FLAG_ALLVERSION) {
			sql = "content = ? ORDER BY version DESC";
		} else {
			if (oio_url_has(u, OIOURL_VERSION)) {
				sql = "content = ? AND version = ? LIMIT 1";
				gint64 version =
					g_ascii_strtoll(oio_url_get(u, OIOURL_VERSION), NULL, 10);
				params[1] = g_variant_new_int64(version);
			} else {
				sql = "content = ? ORDER BY version DESC LIMIT 1";
			}
		}
	}

	GPtrArray *tmp = g_ptr_array_new();
	if (!err)
		err = ALIASES_load(sq3->db, sql, params, _bean_buffer_cb, tmp);
	metautils_gvariant_unrefv(params);

	if (!err) {
		if (tmp->len <= 0) {
			err = NEWERROR(CODE_CONTENT_NOTFOUND, "Alias not found");
		} else if (tmp->len == 1 && ALIASES_get_deleted(tmp->pdata[0]) &&
				(flags & M2V2_FLAG_NODELETED)) {
			err = NEWERROR(CODE_CONTENT_NOTFOUND, "Alias deleted");
		}
	}

	if (!err) {
		err = _alias_fetch_info(sq3, flags, tmp, cb, u0);
	}

	_bean_cleanv2(tmp);
	return err;
}

GError*
m2db_get_alias1(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		guint32 flags, struct bean_ALIASES_s **out)
{
	EXTRA_ASSERT (out != NULL);

	// get only the alias
	flags &= ~M2V2_FLAG_HEADERS;
	flags |=  (M2V2_FLAG_NOPROPS|M2V2_FLAG_NORECURSION);

	GPtrArray *tmp = g_ptr_array_new ();
	GError *err = m2db_get_alias(sq3, url, flags, _bean_buffer_cb, tmp);
	if (!err) {
		*out = tmp->pdata[0];
		tmp->pdata[0] = NULL;
	}
	_bean_cleanv2 (tmp);
	return err;
}

GError*
m2db_get_alias_version(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		gint64 *out)
{
	GError *err = NULL;
	struct bean_ALIASES_s *latest = NULL;

	if (NULL != (err = m2db_latest_alias(sq3, url, &latest))) {
		g_prefix_error(&err, "Latest error: ");
		return err;
	}

	if (!latest)
		return NEWERROR(CODE_CONTENT_NOTFOUND, "Alias not found");

	*out = ALIASES_get_version(latest);
	_bean_clean(latest);
	return NULL;
}

GError*
m2db_latest_alias(struct sqlx_sqlite3_s *sq3,  struct oio_url_s *url,
		struct bean_ALIASES_s **alias)
{
	return m2db_get_alias1(sq3, url, M2V2_FLAG_LATEST, alias);
}

GError*
m2db_get_versioned_alias(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		struct bean_ALIASES_s **alias)
{
	return m2db_get_alias1 (sq3, url, 0, alias);
}

static void
_cb_has_not(gpointer udata, gpointer bean)
{
	if (!bean)
		return;
	*((gboolean*)udata) = FALSE;
	_bean_clean(bean);
}

GError*
check_alias_doesnt_exist(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url)
{
	gboolean no_bean = TRUE;
	GError *err = m2db_get_alias(sq3, url,
			M2V2_FLAG_NORECURSION|M2V2_FLAG_NOPROPS, _cb_has_not, &no_bean);
	if (NULL != err) {
		if (err->code == CODE_CONTENT_NOTFOUND) {
			g_clear_error(&err);
		} else {
			g_prefix_error(&err, "Could not check the ALIAS is present"
					" (multiple versions not allowed): ");
		}
	}
	else if (!no_bean)
		err = NEWERROR(CODE_CONTENT_EXISTS, "Alias already present");
	return err;
}

GError*
check_alias_doesnt_exist2(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url)
{
	GError *err = NULL;
	if (oio_url_has(url, OIOURL_PATH) && oio_url_has(url, OIOURL_CONTENTID)) {
		struct oio_url_s *u = oio_url_dup(url);
		oio_url_unset(u, OIOURL_CONTENTID);
		err = check_alias_doesnt_exist(sq3, u);
		if (err) {
			oio_url_clean(u);
			return err;
		}
		oio_url_unset(u, OIOURL_PATH);
		oio_url_set(u, OIOURL_CONTENTID, oio_url_get(url, OIOURL_CONTENTID));
		err = check_alias_doesnt_exist(sq3, u);
		oio_url_clean(u);
	} else {
		err = check_alias_doesnt_exist(sq3, url);
	}
	return err;
}

/* LIST --------------------------------------------------------------------- */

static GVariant **
_list_params_to_sql_clause(struct list_params_s *lp, GString *clause,
		GSList *headers)
{
	void lazy_and () {
		if (clause->len > 0) g_string_append_static(clause, " AND");
	}
	GPtrArray *params = g_ptr_array_new ();

	if (lp->marker_start) {
		lazy_and();
		g_string_append_static (clause, " alias > ?");
		g_ptr_array_add (params, g_variant_new_string (lp->marker_start));
	} else if (lp->prefix) {
		lazy_and();
		g_string_append_static (clause, " alias >= ?");
		g_ptr_array_add (params, g_variant_new_string (lp->prefix));
	}

	if (lp->marker_end) {
		lazy_and();
		g_string_append_static (clause, " alias < ?");
		g_ptr_array_add (params, g_variant_new_string (lp->marker_end));
	}

	if (headers) {
		lazy_and();
		if (headers->next) {
			g_string_append_static (clause, " content IN (");
			for (GSList *l = headers; l; l = l->next) {
				if (l != headers)
					g_string_append_c (clause, ',');
				g_string_append_c (clause, '?');
				GByteArray *gba = CONTENTS_HEADERS_get_id (l->data);
				g_ptr_array_add (params, _gba_to_gvariant (gba));
			}
			g_string_append_c (clause, ')');
		} else {
			g_string_append_static (clause, " content = ?");
			GByteArray *gba = CONTENTS_HEADERS_get_id (headers->data);
			g_ptr_array_add (params, _gba_to_gvariant (gba));
		}
	}

	if (clause->len == 0)
		clause = g_string_append_static (clause, " 1");

	g_string_append_static(clause, " ORDER BY alias ASC, version DESC");

	if (lp->maxkeys > 0)
		g_string_append_printf(clause, " LIMIT %"G_GINT64_FORMAT, lp->maxkeys);

	g_ptr_array_add (params, NULL);
	return (GVariant**) g_ptr_array_free (params, FALSE);
}

static void
_load_fk_by_name(struct sqlx_sqlite3_s *sq3, struct bean_ALIASES_s *alias,
		const gchar *fk_name, m2_onbean_cb cb, gpointer udata)
{
	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(alias != NULL);
	EXTRA_ASSERT(fk_name != NULL);
	EXTRA_ASSERT(cb != NULL);

	GPtrArray *t0 = g_ptr_array_new();
	GError *err = _db_get_FK_by_name_buffered(alias, fk_name, sq3->db, t0);
	if (err) {
		GRID_WARN("Failed to load FK '%s' for alias [%s]: (%d) %s", fk_name,
				ALIASES_get_alias(alias)->str, err->code, err->message);
		g_clear_error(&err);
	} else {
		for (guint i = 0; i < t0->len; i++)
			cb(udata, t0->pdata[i]);
	}
	g_ptr_array_free(t0, TRUE);
}

GError*
m2db_list_aliases(struct sqlx_sqlite3_s *sq3, struct list_params_s *lp0,
		GSList *headers, m2_onbean_cb cb, gpointer u)
{
	GError *err = NULL;
	gint64 count_aliases = 0;
	// Last encountered alias, for pagination
	gchar *last_alias_name = NULL;
	struct list_params_s lp = *lp0;
	gboolean done = FALSE;
	GPtrArray *cur_aliases = NULL;

	void _load_header_and_send(struct bean_ALIASES_s *alias) {
		if (lp.flag_headers)
			_load_fk_by_name(sq3, alias, "image", cb, u);
		if (lp.flag_properties)
			_load_fk_by_name(sq3, alias, "properties", cb, u);
		cb(u, alias);
	}
	void cleanup (void) {
		if (cur_aliases) {
			g_ptr_array_set_free_func(cur_aliases, _bean_clean);
			g_ptr_array_free(cur_aliases, TRUE);
			cur_aliases = NULL;
		}
	}

	while (!done) {
		cur_aliases = g_ptr_array_new();

		if (lp.maxkeys > 0)
			lp.maxkeys -= count_aliases;
		count_aliases = 0;
		if (last_alias_name)
			lp.marker_start = last_alias_name;

		// List the next items
		GString *clause = g_string_sized_new(128);
		GVariant **params = _list_params_to_sql_clause (&lp, clause, headers);
		err = ALIASES_load(sq3->db, clause->str, params,
				_bean_buffer_cb, cur_aliases);
		metautils_gvariant_unrefv(params);
		g_free(params), params = NULL;
		g_string_free(clause, TRUE);
		if (err || !cur_aliases->len)
			break;
		done = lp.maxkeys <= 0 || cur_aliases->len < lp.maxkeys;

		metautils_gpa_reverse(cur_aliases);

		if (lp.flag_allversion) {
			g_free(last_alias_name);
			last_alias_name = g_strdup(
				ALIASES_get_alias(cur_aliases->pdata[0])->str);
		}
		for (guint i = cur_aliases->len; i > 0; i--) {
			struct bean_ALIASES_s *alias = cur_aliases->pdata[i-1];
			const gchar *name = ALIASES_get_alias(alias)->str;

			if (lp.prefix && !g_str_has_prefix(name, lp.prefix))
				goto label_end;

			g_ptr_array_remove_index_fast(cur_aliases, i-1);

			if (lp.flag_allversion) {
				_load_header_and_send(alias);
				count_aliases++;
				if (lp.maxkeys > 0 && count_aliases >= lp.maxkeys) {
					goto label_end;
				}
			} else {
				if (last_alias_name && !strcmp(last_alias_name, name)) {
					_bean_clean(alias);
				} else {
					g_free(last_alias_name);
					last_alias_name = g_strdup(name);
					if (!lp.flag_nodeleted || !ALIASES_get_deleted(alias)) {
						_load_header_and_send(alias);
						count_aliases++;
						if (lp.maxkeys > 0 && count_aliases >= lp.maxkeys) {
							goto label_end;
						}
					} else {
						_bean_clean(alias);
					}
				}
			}
		}

		cleanup();
	}

label_end:
	cleanup();
	g_free(last_alias_name);
	return err;
}

/* PROPERTIES --------------------------------------------------------------- */

GError*
m2db_get_properties(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		m2_onbean_cb cb, gpointer u0)
{
	GPtrArray *tmp = g_ptr_array_new ();

	GError *err = m2db_get_alias(sq3, url, M2V2_FLAG_HEADERS|M2V2_FLAG_NORECURSION, _bean_buffer_cb, tmp);
	if (err)
		_bean_cleanv2(tmp);
	else {
		for (guint i = 0; i < tmp->len; ++i)
			cb(u0, tmp->pdata[i]);
		g_ptr_array_free(tmp, TRUE);
	}
	return err;
}

GError*
m2db_set_properties(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		gboolean flush, GSList *beans, GSList **out)
{
	EXTRA_ASSERT(out != NULL);

	struct bean_ALIASES_s *alias = NULL;
	GError *err = m2db_get_alias1(sq3, url, M2V2_FLAG_NOPROPS
			|M2V2_FLAG_NORECURSION, &alias);
	if (err)
		return err;
	if (!alias)
		return NEWERROR(CODE_CONTENT_NOTFOUND, "Alias not found");

	GString *name = ALIASES_get_alias(alias);
	gint64 version = ALIASES_get_version(alias);
	// Used to remove duplicate modified properties
	GHashTable *modified = g_hash_table_new_full(
			g_str_hash, g_str_equal, NULL, _bean_clean);

	if (flush) {
		GSList *deleted = NULL;
		gchar *namev = NULL;
		err = m2db_del_properties(sq3, url, &namev, &deleted);
		for (GSList *l = deleted; !err && l; l = l->next) {
			if (DESCR(l->data) == &descr_struct_PROPERTIES) {
				struct bean_PROPERTIES_s *prop = l->data;
				g_hash_table_replace(
						modified, PROPERTIES_get_key(prop)->str, prop);
			} else {
				// We already have a pointer to the alias
				_bean_clean(l->data);
			}
		}
		// Do not free values, they are in the hash table, or already freed
		g_slist_free(deleted);
	}

	for (; !err && beans; beans = beans->next) {
		struct bean_PROPERTIES_s *prop = beans->data;
		if (DESCR(prop) != &descr_struct_PROPERTIES)
			continue;
		PROPERTIES_set_alias(prop, name);
		PROPERTIES_set_version(prop, version);
		if (_is_empty_prop(prop)) {
			err = _db_delete_bean(sq3->db, prop);
			// In case it is empty but not NULL
			PROPERTIES_set_value(prop, NULL);
		} else {
			err = _db_save_bean(sq3->db, prop);
		}
		g_hash_table_replace(
				modified, PROPERTIES_get_key(prop)->str, _bean_dup(prop));
	}

	if (err) {
		_bean_clean(alias);
	} else {
		gboolean _forward_bean(gpointer key UNUSED,
				gpointer bean, gpointer udata UNUSED) {
			*out = g_slist_prepend(*out, bean);
			return TRUE;
		}
		g_hash_table_foreach_steal(modified, _forward_bean, NULL);
		*out = g_slist_prepend(*out, alias);
	}
	g_hash_table_destroy(modified);
	return err;
}

GError*
m2db_del_properties(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		gchar **namev, GSList **out)
{
	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(namev != NULL);
	EXTRA_ASSERT(out != NULL);
	EXTRA_ASSERT(*out == NULL);

	GSList *deleted = NULL;
	struct bean_ALIASES_s *alias = NULL;
	GPtrArray *tmp = g_ptr_array_new();
	GError *err = m2db_get_properties(sq3, url, _bean_buffer_cb, tmp);
	if (!err) {
		for (guint i = 0; i < tmp->len; ++i) {
			struct bean_PROPERTIES_s *bean = tmp->pdata[i];
			if (DESCR(bean) != &descr_struct_PROPERTIES) {
				if (alias == NULL && DESCR(bean) == &descr_struct_ALIASES) {
					alias = _bean_dup(bean);
				}
				continue;
			}
			if (namev && *namev) {
				/* explicit properties to be deleted */
				for (gchar **p = namev; *p; ++p) {
					if (!strcmp(*p, PROPERTIES_get_key(bean)->str)) {
						_db_delete_bean(sq3->db, bean);
						tmp->pdata[i] = NULL;  // Prevent double free
						PROPERTIES_set_value(bean, NULL);  // Signal deletion
						deleted = g_slist_prepend(deleted, bean);
						break;
					}
				}
			} else {
				/* all properties to be deleted */
				_db_delete_bean(sq3->db, bean);
				tmp->pdata[i] = NULL;  // Prevent double free
				PROPERTIES_set_value(bean, NULL);  // Signal deletion
				deleted = g_slist_prepend(deleted, bean);
			}
		}
		*out = g_slist_prepend(deleted, alias);
	}

	_bean_cleanv2(tmp);
	return err;
}

/* DELETE ------------------------------------------------------------------- */

static GError *
m2db_purge_alias_being_deleted(struct sqlx_sqlite3_s *sq3, GSList *beans,
		GSList **pdeleted)
{
	GError *err = NULL;

	gboolean check_FK(gpointer bean, const gchar *fk) {
		gint64 count = 0;
		err = _db_count_FK_by_name(bean, fk, sq3->db, &count);
		return (NULL == err) && (1 >= count);
	}

	GSList *deleted = NULL;

	// First, mark the ALIAS for deletion, and check each header
	gboolean header_deleted = FALSE;
	for (GSList *l = beans; !err && l; l = l->next) {
		gpointer bean = l->data;
		if (&descr_struct_ALIASES == DESCR(bean))
			deleted = g_slist_prepend(deleted, bean);
		else if (&descr_struct_CONTENTS_HEADERS == DESCR(bean)) {
			if (check_FK(bean, "aliases")) {
				header_deleted = TRUE;
				deleted = g_slist_prepend(deleted, bean);
			}
		}
	}

	// Then, only if the HEADER is deleted, we can remove all the CHUNKS
	if (header_deleted) {
		for (GSList *l = beans; !err && l; l = l->next) {
			gpointer bean = l->data;
			if (&descr_struct_CHUNKS == DESCR(bean))
				deleted = g_slist_prepend(deleted, bean);
		}
	}

	if (err || !pdeleted)
		g_slist_free(deleted);
	else
		*pdeleted = metautils_gslist_precat (*pdeleted, deleted);
	return err;
}

static GError*
_real_delete(struct sqlx_sqlite3_s *sq3, GSList *beans, GSList **deleted_beans)
{
	// call the purge to know which beans must be really deleted
	GSList *deleted = NULL;
	GError *err = m2db_purge_alias_being_deleted(sq3, beans, &deleted);
	if (err) {
		_bean_cleanl2 (deleted);
		g_prefix_error(&err, "Purge error: ");
		return err;
	}

	_bean_debugl2 ("PURGE", deleted);

	// Now really delete the beans, and notify them.
	// But do not notify ALIAS already marked deleted (they have already been notified)
	for (GSList *l = deleted; l; l = l->next) {
		if (DESCR(l->data) != &descr_struct_ALIASES || !ALIASES_get_deleted(l->data))
			*deleted_beans = g_slist_prepend (*deleted_beans, l->data);
		GError *e = _db_delete_bean(sq3->db, l->data);
		if (e != NULL) {
			GRID_WARN("Bean delete failed: (%d) %s", e->code, e->message);
			g_clear_error(&e);
		}
	}

	// recompute container size and object count
	gint64 obj_count = m2db_get_obj_count(sq3);
	for (GSList *l = deleted; l; l = l->next) {
		if (&descr_struct_CONTENTS_HEADERS == DESCR(l->data)) {
			gint64 decrement = CONTENTS_HEADERS_get_size(l->data);
			gint64 size = m2db_get_size(sq3) - decrement;
			m2db_set_size(sq3, size);
			GRID_DEBUG("CONTAINER size = %"G_GINT64_FORMAT
					" (lost %"G_GINT64_FORMAT")", size, decrement);
			obj_count--;
		}
	}
	m2db_set_obj_count(sq3, obj_count);

	g_slist_free(deleted);
	deleted = NULL;
	return NULL;
}

GError *
m2db_drain_content(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	err = m2db_get_alias(sq3, url, M2V2_FLAG_NOPROPS|M2V2_FLAG_HEADERS, cb, u0);
	for (GSList *l = *(GSList **)u0; l; l = l->next) {
		if (DESCR(l->data) == &descr_struct_CHUNKS) {
			_db_delete_bean(sq3->db, l->data);
		} else if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS) {
			CONTENTS_HEADERS_set2_chunk_method(l->data, CHUNK_METHOD_DRAINED);
			_db_save_bean(sq3->db, l->data);
		}
	}
	return err;
}

static GError*
_real_delete_and_save_deleted_beans(struct sqlx_sqlite3_s *sq3, GSList *beans,
		struct bean_ALIASES_s *alias, struct bean_CONTENTS_HEADERS_s *header,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	GSList *deleted_beans = NULL;

	err = _real_delete(sq3, beans, &deleted_beans);
	if (!err && cb) {
		gboolean header_encountered = FALSE;
		/* Client asked to remove no-more referenced beans,
		 * we tell him which */
		for (GSList *bean = deleted_beans; bean; bean = bean->next) {
			if (bean->data == header)
				header_encountered = TRUE;
			cb(u0, _bean_dup(bean->data));
		}
		/* Header hasn't been deleted but contains useful information */
		/* The delete marker doesn't have a header */
		if (!header_encountered && header)
			cb(u0, _bean_dup(header));
	}
	// deleted_beans contains direct pointers to the original beans
	g_slist_free(deleted_beans);

	// sqliterepo might disable foreign keys management, so that we have
	// to manage this by ourselves.
	if (!err && alias)
		err = _db_del_FK_by_name (alias, "properties", sq3->db);

	return err;
}

static GError*
_real_delete_aliases(struct sqlx_sqlite3_s *sq3, GPtrArray *aliases,
		m2_onbean_cb cb, gpointer u0) {
	if (aliases->len == 0)
		return NULL;

	GError *err = NULL;
	GPtrArray *tmp = g_ptr_array_new();
	g_ptr_array_add(tmp, NULL);
	struct bean_ALIASES_s *alias = NULL;
	struct bean_CONTENTS_HEADERS_s *header = NULL;
	GSList *beans = NULL;
	GSList *deleted_beans = NULL;

	void _search_alias_and_header(gpointer plist, gpointer bean) {
		if (DESCR(bean) == &descr_struct_ALIASES)
			alias = _bean_dup(bean);
		else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS)
			header = bean;
		*((GSList**)plist) = g_slist_prepend (*((GSList**)plist), bean);
	}

	for (guint i = 0; !err && i < aliases->len; i++) {
		tmp->pdata[0] = aliases->pdata[i];
		alias = NULL;
		header = NULL;
		beans = NULL;

		err = _alias_fetch_info(sq3, 0, tmp, _search_alias_and_header, &beans);
		if (!err) {
			if (cb) {
				deleted_beans = NULL;
				err = _real_delete_and_save_deleted_beans(sq3, beans, alias,
						header, _bean_list_cb, &deleted_beans);
				if (deleted_beans != NULL) {
					cb(u0, deleted_beans);
				}
			} else {
				err = _real_delete_and_save_deleted_beans(sq3, beans, alias,
						header, NULL, NULL);
			}
		}

		_bean_clean(alias);
		_bean_cleanl2(beans);
		aliases->pdata[i] = NULL;
	}
	tmp->pdata[0] = NULL;
	_bean_cleanv2(tmp);

	return err;
}

GError*
m2db_delete_alias(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		gboolean delete_marker, struct oio_url_s *url,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err;
	struct bean_ALIASES_s *alias = NULL;
	struct bean_CONTENTS_HEADERS_s *header = NULL;
	GSList *beans = NULL;

	void _search_alias_and_size(gpointer ignored, gpointer bean) {
		(void) ignored;
		if (DESCR(bean) == &descr_struct_ALIASES)
			alias = _bean_dup(bean);
		else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS)
			header = bean;
		beans = g_slist_prepend(beans, bean);
	}

	if (VERSIONS_DISABLED(max_versions) && oio_url_has(url, OIOURL_VERSION)
			&& 0!=g_ascii_strtoll(oio_url_get(url, OIOURL_VERSION), NULL, 10))
		return NEWERROR(CODE_BAD_REQUEST,
				"Versioning not supported and version specified");

	err = m2db_get_alias(sq3, url, M2V2_FLAG_NOPROPS|M2V2_FLAG_HEADERS,
			_search_alias_and_size, NULL);

	if (NULL != err) {
		_bean_cleanl2(beans);
		return err;
	}
	if (!alias || !beans) {
		_bean_cleanl2(beans);
		return NEWERROR(CODE_CONTENT_NOTFOUND, "No content to delete");
	}

	GRID_TRACE("CONTENT %s beans=%u maxvers=%"G_GINT64_FORMAT
			" deleted=%d ver=%u/%s",
			oio_url_get(url, OIOURL_WHOLE), g_slist_length(beans),
			max_versions, ALIASES_get_deleted(alias),
			oio_url_has(url, OIOURL_VERSION), oio_url_get(url, OIOURL_VERSION));

	gboolean add_delete_marker = FALSE;
	if (VERSIONS_DISABLED(max_versions) || VERSIONS_SUSPENDED(max_versions) ||
			oio_url_has(url, OIOURL_VERSION) || ALIASES_get_deleted(alias)) {
		if (delete_marker) {
			if (VERSIONS_DISABLED(max_versions) ||
					VERSIONS_SUSPENDED(max_versions)) {
				err = BADREQ("Versioning not enabled and delete marker specified");
			} else if (ALIASES_get_deleted(alias)) {
				err = BADREQ("Alias is a delete marker and delete marker specified");
			} else {
				add_delete_marker = TRUE;
			}
		} else {
			err = _real_delete_and_save_deleted_beans(sq3, beans,
					alias, header, cb, u0);
		}
	} else {
		add_delete_marker = TRUE;
	}
	if (!err && add_delete_marker) {
		/* Check if delete marker already exists */
		struct oio_url_s *delete_marker_url = oio_url_dup(url);
		oio_url_set(delete_marker_url, OIOURL_PATH,
				ALIASES_get_alias(alias)->str);
		gint64 delete_marker_version = ALIASES_get_version(alias) + 1;
		gchar *str_delete_marker_version = g_strdup_printf(
				"%"G_GINT64_FORMAT, delete_marker_version);
		oio_url_set(delete_marker_url, OIOURL_VERSION,
				str_delete_marker_version);
		g_free(str_delete_marker_version);
		oio_url_unset(delete_marker_url, OIOURL_CONTENTID);
		err = check_alias_doesnt_exist(sq3, delete_marker_url);
		if (err)
			g_prefix_error(&err, "Delete marker error: ");
		oio_url_clean(delete_marker_url);

		if (!err) {
			gint64 now = oio_ext_real_seconds();
			/* Create a new version marked as deleted */
			struct bean_ALIASES_s *new_alias = _bean_create(
					&descr_struct_ALIASES);
			ALIASES_set_deleted(new_alias, TRUE);
			ALIASES_set_alias(new_alias, ALIASES_get_alias(alias));
			ALIASES_set_version(new_alias, 1 + ALIASES_get_version(alias));
			GByteArray *content = g_byte_array_new_take(
					(guint8 *) "DELETED", 7);
			ALIASES_set_content(new_alias, content);
			g_byte_array_free(content, FALSE);
			ALIASES_set_ctime(new_alias, now);
			ALIASES_set_mtime(new_alias, now);
			err = _db_save_bean(sq3->db, new_alias);
			if (cb)
				cb(u0, new_alias);
			else
				_bean_clean(new_alias);
			new_alias = NULL;
		}
	}

	_bean_clean(alias);
	_bean_cleanl2(beans);
	return err;
}

static struct oio_url_s *
_dup_content_id_url(struct oio_url_s *url)
{
	struct oio_url_s *local_url = NULL;
	if (!oio_url_has(url, OIOURL_CONTENTID)) {
		GRID_WARN("Updating content by path (%s), other paths "
				"linked to the same content id won't be notified!",
				oio_url_get(url, OIOURL_WHOLE));
		local_url = oio_url_dup(url);
	} else {
		local_url = oio_url_empty();
		oio_url_set(local_url, OIOURL_NS, oio_url_get(url, OIOURL_NS));
		oio_url_set(local_url, OIOURL_HEXID, oio_url_get(url, OIOURL_HEXID));
		oio_url_set(local_url, OIOURL_CONTENTID,
				oio_url_get(url, OIOURL_CONTENTID));
	}
	return local_url;
}

GError*
m2db_truncate_content(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		gint64 truncate_size, GSList **out_deleted, GSList **out_added)
{
	GError *err = NULL;
	struct m2v2_sorted_content_s content = {
		.header = NULL,
		.aliases = NULL,
		.properties = NULL,
		.metachunks = g_tree_new(_tree_compare_int),
	};
	GSList *discarded = NULL, *kept = NULL;
	struct oio_url_s *local_url = _dup_content_id_url(url);

	if ((err = m2db_get_alias(sq3, local_url, M2V2_FLAG_NOPROPS|M2V2_FLAG_HEADERS,
			_sort_content_cb, &content)))
		goto cleanup;
	EXTRA_ASSERT(content.properties == NULL);

	if (!strcmp(CONTENTS_HEADERS_get_chunk_method(content.header)->str,
			CHUNK_METHOD_DRAINED)){
		err = NEWERROR(CODE_CONTENT_DRAINED, "The content is drained");
		goto cleanup;
	}

	if (truncate_size > CONTENTS_HEADERS_get_size(content.header)) {
		err = BADREQ("truncate operation cannot grow contents");
		goto cleanup;
	}

	gint64 offset = 0, kept_size = 0;
	gboolean chunk_boundary_found = FALSE;
	gboolean _discard_extra_chunks(gpointer key, gpointer value,
			gpointer data UNUSED) {
		gint64 pos = GPOINTER_TO_INT(key);
		GSList *mc = value;
		gint64 current_size = CHUNKS_get_size(mc->data);
		/* We should never discard position 0: when content size is 0,
		 * we keep a chunk to be able to reconstruct the content if
		 * the directory has been lost. */
		if (offset >= truncate_size && pos > 0) {
			chunk_boundary_found |= (offset == truncate_size);
			discarded = metautils_gslist_precat(mc, discarded);
		} else {
			kept = metautils_gslist_precat(mc, kept);
			kept_size += current_size;
		}
		offset += current_size;
		return FALSE;
	}
	g_tree_foreach(content.metachunks, _discard_extra_chunks, NULL);

	if (!chunk_boundary_found && kept_size != truncate_size) {
		err = BADREQ("Cannot truncate %s at %"G_GINT64_FORMAT" bytes, "
				"nearest metachunk boundary is at %"G_GINT64_FORMAT" bytes.",
				oio_url_get(url, OIOURL_WHOLE), truncate_size, kept_size);
		goto cleanup;
	}

	for (GSList *l = discarded; l && !err; l = l->next)
		err = _db_delete_bean(sq3->db, l->data);
	if (err)
		goto cleanup;

	/* Update size and mtime in header */
	const gint64 now = oio_ext_real_time() / G_TIME_SPAN_SECOND;
	gint64 sz_gap = CONTENTS_HEADERS_get_size(content.header) - truncate_size;
	CONTENTS_HEADERS_set_size(content.header, truncate_size);
	CONTENTS_HEADERS_set2_hash(content.header, (guint8*)"", 0);
	CONTENTS_HEADERS_set_mtime(content.header, now);
	kept = g_slist_prepend(kept, content.header);
	content.header = NULL;

	/* Update mtime in aliases */
	for (GSList *l = content.aliases; l; l = l->next) {
		struct bean_ALIASES_s *alias = l->data;
		ALIASES_set_mtime(alias, now);
		kept = g_slist_prepend(kept, alias);
	}
	g_slist_free(content.aliases);
	content.aliases = NULL;
	err = _db_save_beans_list(sq3->db, kept);

	if (!err) {
		m2db_set_size(sq3, m2db_get_size(sq3) - sz_gap);
		*out_added = kept;
		*out_deleted = discarded;
		// prevent cleanup
		kept = NULL;
		discarded = NULL;
	}

cleanup:
	_bean_clean(content.header);
	_bean_cleanl2(content.aliases);
	// Don't free values, they are in kept, discarded, out_added or out_deleted
	g_tree_destroy(content.metachunks);
	_bean_cleanl2(kept);
	_bean_cleanl2(discarded);
	oio_url_clean(local_url);
	return err;
}

/* PUT commons -------------------------------------------------------------- */

static void _patch_beans_with_version (GSList *beans, gint64 version) {
	for (GSList *l = beans; l; l = l->next) {
		gpointer bean = l->data;
		if (DESCR(bean) == &descr_struct_ALIASES) {
			ALIASES_set_version(bean, version);
		} else if (DESCR(bean) == &descr_struct_PROPERTIES) {
			PROPERTIES_set_version (bean, version);
		}
	}
}

static void
_patch_beans_with_contentid(GSList *beans, const guint8 *uid, gsize len)
{
	for (GSList *l = beans; l; l = l->next) {
		gpointer bean = l->data;
		if (DESCR(bean) == &descr_struct_ALIASES) {
			ALIASES_set2_content(bean, uid, len);
		} else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
			CONTENTS_HEADERS_set2_id(bean, uid, len);
		} else if (DESCR(bean) == &descr_struct_CHUNKS) {
			CHUNKS_set2_content(bean, uid, len);
		}
	}
}

static void _patch_beans_with_time (GSList *beans,
		struct bean_ALIASES_s *latest) {
	gint64 now = oio_ext_real_seconds();
	gint64 ctime = now;
	if (latest) {
		/* Keep the same ctime if the object already exists */
		ctime = ALIASES_get_ctime(latest);
	}
	for (GSList *l = beans; l; l = l->next) {
		gpointer bean = l->data;
		if (DESCR(bean) == &descr_struct_ALIASES) {
			ALIASES_set_ctime(bean, ctime);
			ALIASES_set_mtime(bean, now);
		} else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
			CONTENTS_HEADERS_set_ctime(bean, now);
			CONTENTS_HEADERS_set_mtime(bean, now);
		} else if (DESCR(bean) == &descr_struct_CHUNKS) {
			CHUNKS_set_ctime(bean, now);
		}
	}
}

static void _patch_beans_defaults (GSList *beans) {
#define lazy_set_str(T,B,F,V) do { \
	GString *gs = T##_get_##F(B); \
	if (!gs || !gs->str || !gs->len) T##_set2_##F(B,V); \
} while (0)
for (GSList *l = beans; l; l = l->next) {
	gpointer bean = l->data;
	if (!l->data)
		continue;
	if (DESCR(bean) == &descr_struct_ALIASES) {
		ALIASES_set_deleted(bean, FALSE);
	} else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
		lazy_set_str(CONTENTS_HEADERS, bean, chunk_method, OIO_DEFAULT_CHUNKMETHOD);
		lazy_set_str(CONTENTS_HEADERS, bean, mime_type, OIO_DEFAULT_MIMETYPE);
		lazy_set_str(CONTENTS_HEADERS, bean, policy, OIO_DEFAULT_STGPOL);
	}
}
}

gint64 find_alias_version (GSList *beans) {
	for (GSList *l = beans; l; l = l->next) {
		gpointer bean = l->data;
		if (DESCR(bean) == &descr_struct_ALIASES)
			return ALIASES_get_version(bean);
	}
	return -1;
}

static gint64 _fetch_content_size (GSList *beans) {
	for (GSList *l = beans; l; l = l->next) {
		gpointer bean = l->data;
		if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS)
			return CONTENTS_HEADERS_get_size(bean);
	}
	return 0;
}

static void _extract_chunks_sizes_positions(GSList *beans,
		GSList **chunks, gint64 *size, GTree *positions) {
	for (GSList *l = beans; l; l = l->next) {
		gpointer bean = l->data;
		if (bean && &descr_struct_CHUNKS == DESCR(bean)) {
			struct bean_CHUNKS_s *chunk = _bean_dup(bean);
			*chunks = g_slist_prepend(*chunks, chunk);
			gint64 pos = g_ascii_strtoll(
					CHUNKS_get_position(chunk)->str, NULL, 10);
			if (!g_tree_lookup(positions, GINT_TO_POINTER(pos))) {
				*size += CHUNKS_get_size(chunk);
				g_tree_insert(positions, GINT_TO_POINTER(pos), GINT_TO_POINTER(1));
			}
		}
	}
}

/* PUT ---------------------------------------------------------------------- */

static GError* m2db_purge_exceeding_versions(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url, gint64 max_versions,
		m2_onbean_cb cb, gpointer u0) {
	GError *err = NULL;

	if (m2db_get_flag_delete_exceeding_versions(sq3,
			meta2_flag_delete_exceeding_versions)) {
		GPtrArray *aliases = g_ptr_array_new();
		if ((err = _purge_exceeding_aliases(sq3, max_versions,
				oio_url_get(url, OIOURL_PATH), _bean_buffer_cb, aliases))) {
			GRID_WARN("Failed to purge ALIASES: (code=%d) %s",
					err->code, err->message);
			_bean_cleanv2(aliases);
			return err;
		}

		err = _real_delete_aliases(sq3, aliases, cb, u0);

		_bean_cleanv2(aliases);
	}
	return err;
}

static GError* m2db_real_put_alias(struct sqlx_sqlite3_s *sq3, GSList *beans,
		m2_onbean_cb cb, gpointer cb_data) {
	GError *err = NULL;
	for (GSList *l = beans; !err && l; l = l->next) {
		/* FIXME(FVE): we could accept empty properties (but not NULL ones). */
		if (_is_empty_prop(l->data))
			PROPERTIES_set_value(l->data, NULL);
		else
			err = _db_save_bean(sq3->db, l->data);
	}
	if (!err && cb) {
		for (GSList *l = beans; l; l = l->next)
			cb(cb_data, _bean_dup(l->data));
	}
	return err;
}

/* Returns NULL if the content is absent, an explicit error indicating it is
 * present or the error that occured while checking (if any) */
static GError* m2db_check_content_absent(struct sqlx_sqlite3_s *sq3,
		const guint8 *uid, const gsize len) {
	GPtrArray *tmp = g_ptr_array_new ();
	GVariant *params[2] = {NULL, NULL};
	params[0] = _bytes_to_gvariant(uid, len);
	GError *err = CONTENTS_HEADERS_load (sq3->db, " id = ? LIMIT 1", params,
			_bean_buffer_cb, tmp);
	metautils_gvariant_unrefv(params);
	guint count = tmp->len;
	_bean_cleanv2 (tmp);
	if (err)
		return err;
	if (count)
		return NEWERROR(CODE_CONTENT_EXISTS, "A content exists with this ID");
	return NULL;
}

/* TODO(jfs): return the beans added/deleted */
GError* m2db_force_alias(struct m2db_put_args_s *args, GSList *beans,
		m2_onbean_cb cb_deleted UNUSED, gpointer u0_deleted UNUSED,
		m2_onbean_cb cb_added, gpointer u0_added)
{
	EXTRA_ASSERT(args != NULL);
	EXTRA_ASSERT(args->sq3 != NULL);
	EXTRA_ASSERT(args->url != NULL);
	if (!oio_url_has_fq_path(args->url))
		return NEWERROR(CODE_BAD_REQUEST, "Missing path");

	GError *err = NULL;

	struct bean_ALIASES_s *latest = NULL;
	if (oio_url_has(args->url, OIOURL_VERSION))
		err = m2db_get_versioned_alias(args->sq3, args->url, &latest);
	else
		err = m2db_latest_alias(args->sq3, args->url, &latest);

	if (err) {
		if (err->code != CODE_CONTENT_NOTFOUND) {
			g_prefix_error(&err, "Version error: ");
			return err;
		}
		g_clear_error(&err);
	}

	if (latest && args->worm_mode) {
		err = NEWERROR(CODE_CONTENT_EXISTS, "NS wormed! Cannot overwrite.");
		goto cleanup;
	}

	_patch_beans_defaults(beans);
	_patch_beans_with_time(beans, latest);

	gint64 added_size = 0;
	gint64 obj_count = m2db_get_obj_count(args->sq3);

	if (!latest) {
		/* put everything (and patch everything */
		RANDOM_UID(uid, uid_size);
		_patch_beans_with_contentid(beans, (guint8*)&uid, uid_size);
		_patch_beans_with_version(beans, find_alias_version(beans));
		err = m2db_real_put_alias(args->sq3, beans, cb_added, u0_added);
		if (!err) {
			added_size = _fetch_content_size(beans);
			obj_count++;
		}
	} else {
		/* We found an ALIAS with the same name and version. Just add the chunks
		 * to the CONTENT and the properties to the ALIAS. */
		GByteArray *gba = ALIASES_get_content (latest);
		_patch_beans_with_version(beans, ALIASES_get_version(latest));
		_patch_beans_with_contentid(beans, gba->data, gba->len);
		for (GSList *l = beans; l; l = l->next) {
			gpointer bean = l->data;
			if (DESCR(bean) != &descr_struct_CHUNKS &&
				DESCR(bean) != &descr_struct_PROPERTIES)
				continue;
			if (!(err = _db_insert_bean(args->sq3->db, bean))) {
				if (cb_added)
					cb_added(u0_added, _bean_dup(bean));
			}
		}
		/* TODO need to recompute the container's size */
	}

	if (!err) {
		m2db_set_size(args->sq3, m2db_get_size(args->sq3) + added_size);
		m2db_set_obj_count(args->sq3, obj_count);
	}

cleanup:
	if (latest)
		_bean_clean(latest);

	return err;
}

GError* m2db_update_content(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url, GSList *beans,
		m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added) {
	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(oio_url_has(url, OIOURL_PATH) ||
			oio_url_has(url, OIOURL_CONTENTID));

	GSList *aliases = NULL, *old_beans = NULL, *new_beans = NULL;

	/* Compute the size of the metachunks we are adding. Build and use a tree
	 * to avoid counting several times the same metachunk, and later to
	 * find which beans we must remove from the database. */
	GTree *positions_seen = g_tree_new(_tree_compare_int);
	gint64 added_size = 0;
	_extract_chunks_sizes_positions(beans,
			&new_beans, &added_size, positions_seen);

	/* Make sure we load the beans by content id */
	struct oio_url_s *local_url = _dup_content_id_url(url);

	/* Find which beans we must remove from the database */
	GTree *old_positions_seen = g_tree_new(_tree_compare_int);
	struct bean_CONTENTS_HEADERS_s *header = NULL;
	void _keep_or_free(gpointer udata, gpointer bean) {
		(void)udata;
		if (DESCR(bean) == &descr_struct_CHUNKS) {
			struct bean_CHUNKS_s *chunk = bean;
			gint64 pos = g_ascii_strtoll(
					CHUNKS_get_position(chunk)->str, NULL, 10);
			if (g_tree_lookup(positions_seen, GINT_TO_POINTER(pos))) {
				old_beans = g_slist_prepend(old_beans, chunk);
				if (!g_tree_lookup(old_positions_seen, GINT_TO_POINTER(pos))) {
					g_tree_insert(old_positions_seen,
							GINT_TO_POINTER(pos), GINT_TO_POINTER(1));
					added_size -= CHUNKS_get_size(chunk);
				}
			} else {
				_bean_clean(bean);
			}
		} else if (DESCR(bean) == &descr_struct_ALIASES) {
			aliases = g_slist_prepend(aliases, bean);
		} else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
			header = bean;
		} else {
			g_assert_not_reached();
			_bean_clean(bean);
		}
	}
	GError *err = m2db_get_alias(sq3, local_url,
			M2V2_FLAG_HEADERS|M2V2_FLAG_NOPROPS, _keep_or_free, NULL);
	if (err)
		goto cleanup;

	if (!strcmp(CONTENTS_HEADERS_get_chunk_method(header)->str,
			CHUNK_METHOD_DRAINED)){
		err = NEWERROR(CODE_CONTENT_DRAINED, "The content is drained");
		goto cleanup;
	}

	/* Update size (in header) and mtime (in alias and header) */
	const gint64 now = oio_ext_real_time() / G_TIME_SPAN_SECOND;
	struct bean_CONTENTS_HEADERS_s *new_header = _bean_dup(header);
	CONTENTS_HEADERS_set_size(new_header,
			CONTENTS_HEADERS_get_size(header) + added_size);
	CONTENTS_HEADERS_set2_hash(new_header, (guint8*)"", 0);
	CONTENTS_HEADERS_set_mtime(new_header, now);
	new_beans = g_slist_prepend(new_beans, new_header);
	for (GSList *l = aliases; l; l = l->next) {
		struct bean_ALIASES_s *alias = _bean_dup(l->data);
		ALIASES_set_mtime(alias, now);
		new_beans = g_slist_prepend(new_beans, alias);
	}
	err = _db_save_beans_list(sq3->db, new_beans);

	/* Remove old chunks from the database */
	for (GSList *l = old_beans; l && !err; l = l->next) {
		err = _db_delete_bean(sq3->db, l->data);
	}
	if (err)
		goto cleanup;

	/* Update the size of the container and notify the caller with new beans */
	m2db_set_size(sq3, m2db_get_size(sq3) + added_size);
	if (cb_deleted) {
		cb_deleted(u0_deleted, g_slist_prepend(old_beans, header));
		header = NULL;
		old_beans = NULL;
	}
	if (cb_added) {
		for (GSList *l = new_beans; l; l = l->next)
			cb_added(u0_added, _bean_dup(l->data));
	}

cleanup:
	_bean_clean(header);
	_bean_cleanl2(aliases);
	_bean_cleanl2(new_beans);
	_bean_cleanl2(old_beans);
	g_tree_destroy(old_positions_seen);
	g_tree_destroy(positions_seen);
	oio_url_clean(local_url);
	return err;
}

GError* m2db_put_alias(struct m2db_put_args_s *args, GSList *beans,
		m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added)
{
	struct bean_ALIASES_s *latest = NULL;
	GError *err = NULL;
	gboolean purge_latest = FALSE;

	EXTRA_ASSERT(args != NULL);
	EXTRA_ASSERT(args->sq3 != NULL);
	EXTRA_ASSERT(args->url != NULL);
	if (!oio_url_has_fq_path(args->url))
		return NEWERROR(CODE_BAD_REQUEST, "Missing fully qualified path");

	gint64 version = find_alias_version(beans);
	if (version <= 0) {
		return BADREQ("Missing or invalid alias bean (no version found)");
	}
	if (oio_url_has(args->url, OIOURL_VERSION)) {
		/* If there is a version in the URL,
		 * ensure it is the same as in the beans. */
		gchar *endptr = NULL;
		const gchar *sversion = oio_url_get(args->url, OIOURL_VERSION);
		gint64 uversion = g_ascii_strtoll(sversion, &endptr, 10);
		if (endptr != sversion && uversion != version)
			return NEWERROR(CODE_BAD_REQUEST, "URL version is present (%s)",
					oio_url_get(args->url, OIOURL_VERSION));
	}

	/* Needed later several times, we extract now the content-id */
	const char *content_hexid = oio_url_get (args->url, OIOURL_CONTENTID);
	if (!content_hexid) {
		return BADREQ("Invalid URL (missing content ID)");
	}
	gsize content_idlen = strlen(content_hexid) / 2;
	guint8 *content_id = g_alloca(1 + strlen(content_hexid));
	if (!oio_str_hex2bin(content_hexid, content_id, content_idlen))
		return BADREQ("Invalid content ID (not hexa)");

	/* The content-id has been specified, we MUST check it will be UNIQUE */
	err = m2db_check_content_absent(args->sq3, content_id, content_idlen);
	if (NULL != err)
		return err;

	/* Ensure the beans are all linked to the content (with their content-id) */
	_patch_beans_with_contentid(beans, content_id, content_idlen);

	/* needed for later: the latest content in place. Fetch it once for all */
	if (NULL != (err = m2db_latest_alias(args->sq3, args->url, &latest))) {
		if (err->code != CODE_CONTENT_NOTFOUND) {
			g_prefix_error(&err, "Version error: ");
			return err;
		}
		GRID_TRACE("Alias not yet present (1)");
		g_clear_error(&err);
	}

	gint64 max_versions = m2db_get_max_versions(
			args->sq3, args->ns_max_versions);

	/* Manage the potential conflict with the latest alias in place. */
	const gint64 latest_version = latest? ALIASES_get_version(latest) : 0;
	/* version explicitely specified */
	if (version == latest_version) {
		err = NEWERROR(CODE_CONTENT_EXISTS, "Alias already saved");
	} else if (version < latest_version) {
		if (VERSIONS_ENABLED(max_versions)) {
			/* Check if alias already exists */
			struct oio_url_s *url2 = oio_url_dup(args->url);
			if (!oio_url_has(url2, OIOURL_VERSION)) {
				gchar *str_version = g_strdup_printf(
						"%"G_GINT64_FORMAT, version);
				oio_url_set(url2, OIOURL_VERSION, str_version);
				g_free(str_version);
			}
			oio_url_unset(url2, OIOURL_CONTENTID);
			err = check_alias_doesnt_exist(args->sq3, url2);
			oio_url_clean(url2);
		} else {
			err = NEWERROR(CODE_CONTENT_PRECONDITION,
					"New object version is older than latest version");
		}
	}

	/* Check the operation respects the rules of versioning for the container */
	if (!err && latest) {
		if (VERSIONS_DISABLED(max_versions)) {
			if (ALIASES_get_deleted(latest) || ALIASES_get_version(latest) > 0) {
				GRID_DEBUG("Versioning DISABLED but clues of SUSPENDED");
				goto suspended;
			} else {
				err = NEWERROR(CODE_CONTENT_EXISTS, "versioning disabled + content present");
			}
		}
		else if (VERSIONS_SUSPENDED(max_versions)) {
suspended:
			if (args->worm_mode) {
				err = NEWERROR(CODE_CONTENT_EXISTS,
						"NS wormed! Cannot overwrite.");
			}

			// JFS: do not alter the size to manage the alias being removed,
			// this will be done by the real purge of the latest.
			purge_latest = TRUE;
		}
		else {
			purge_latest = FALSE;
		}
	}

	/* Perform the insertion now and patch the URL with the version */
	if (!err) {
		/* Patch the beans, before inserting */
		_patch_beans_defaults(beans);
		_patch_beans_with_time(beans, latest);
		_patch_beans_with_version(beans, version);

		err = m2db_real_put_alias(args->sq3, beans, cb_added, u0_added);
	}
	if (!err) {
		m2db_set_size(args->sq3,
				m2db_get_size(args->sq3) + _fetch_content_size(beans));
		m2db_set_obj_count(args->sq3, m2db_get_obj_count(args->sq3) + 1);
	}

	/* Purge the latest alias if the condition was met */
	if (!err && purge_latest && latest) {
		GRID_TRACE("Need to purge the previous LATEST");
		GSList *inplace = g_slist_prepend (NULL, _bean_dup(latest));
		err = _manage_alias (args->sq3->db, latest, TRUE, _bean_list_cb, &inplace);
		if (!err) { /* remove the alias, header, content, chunk */
			GSList *deleted = NULL;
			err = _real_delete (args->sq3, inplace, &deleted);
			if (cb_deleted) {
				GSList *deleted_beans = NULL;
				for (GSList *l = deleted; l; l = l->next)
					deleted_beans = g_slist_prepend(deleted_beans,
							_bean_dup(l->data));
				cb_deleted(u0_deleted, deleted_beans);
			}
			/* <deleted> beans are direct pointer to <inplace> beans */
			g_slist_free (deleted);
		}
		_bean_cleanl2 (inplace);
		if (!err) /* remove the properties */
			err = _db_del_FK_by_name (latest, "properties", args->sq3->db);
	}

	/* Purge the exceeding aliases */
	if (!err && !purge_latest && latest && VERSIONS_LIMITED(max_versions))
		m2db_purge_exceeding_versions(args->sq3, args->url, max_versions,
				cb_deleted, u0_deleted);

	if (latest)
		_bean_clean(latest);
	return err;
}

GError*
m2db_change_alias_policy(struct m2db_put_args_s *args, GSList *new_beans,
		m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added)
{
	GError *err;
	struct bean_ALIASES_s *current_alias = NULL;
	struct bean_CONTENTS_HEADERS_s *current_header = NULL;
	struct bean_ALIASES_s *new_alias = NULL;
	struct bean_CONTENTS_HEADERS_s *new_header = NULL;
	GSList *beans_to_delete = NULL;
	GSList *deleted_beans = NULL;
	guint8 *content_id = NULL;

	for (GSList *l = new_beans; l; l = l->next) {
		if (DESCR(l->data) == &descr_struct_ALIASES) {
			new_alias = l->data;
		} else if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS) {
			new_header = l->data;
		}
	}

	/* Search the specific version */
	gint64 version = ALIASES_get_version(new_alias);
	if (version <= 0) {
		return BADREQ("Invalid alias version");
	}
	void _search_alias_and_size(gpointer ignored, gpointer bean) {
		(void) ignored;
		if (DESCR(bean) == &descr_struct_ALIASES) {
			current_alias = bean;
		} else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
			current_header = bean;
			beans_to_delete = g_slist_prepend(beans_to_delete, bean);
		} else if (DESCR(bean) == &descr_struct_CHUNKS) {
			beans_to_delete = g_slist_prepend(beans_to_delete, bean);
		}
	}
	struct oio_url_s *url_with_version = oio_url_dup(args->url);
	gchar *version_str = g_strdup_printf("%"G_GINT64_FORMAT, version);
	oio_url_set(url_with_version, OIOURL_VERSION, version_str);
	g_free(version_str);
	err = m2db_get_alias(args->sq3, url_with_version,
			M2V2_FLAG_NOPROPS|M2V2_FLAG_HEADERS, _search_alias_and_size, NULL);
	oio_url_clean(url_with_version);
	if (err) {
		goto label_end;
	}

	if (ALIASES_get_deleted(current_alias)) {
		err = BADREQ("The specified object version is a delete marker");
		goto label_end;
	}

	if (CONTENTS_HEADERS_get_size(current_header) !=
			CONTENTS_HEADERS_get_size(new_header) ||
			!metautils_gba_equal(CONTENTS_HEADERS_get_hash(current_header),
				CONTENTS_HEADERS_get_hash(new_header))) {
		GString *current_hash = metautils_gba_to_hexgstr(
				NULL, CONTENTS_HEADERS_get_hash(current_header));
		GString *new_hash = metautils_gba_to_hexgstr(
				NULL, CONTENTS_HEADERS_get_hash(new_header));
		err = BADREQ("Different content "
				"(current: size=%ld, hash=%s ; new: size=%ld, hash=%s)",
				CONTENTS_HEADERS_get_size(current_header),
				current_hash->str,
				CONTENTS_HEADERS_get_size(new_header),
				new_hash->str);
		g_string_free(current_hash, TRUE);
		g_string_free(new_hash, TRUE);
		goto label_end;
	}

	/* Needed later several times, we extract now the content-id */
	const char *content_hexid = oio_url_get(args->url, OIOURL_CONTENTID);
	if (!content_hexid) {
		err = BADREQ("Invalid URL (missing content ID)");
		goto label_end;
	}
	gsize content_idlen = strlen(content_hexid) / 2;
	content_id = g_alloca(1 + strlen(content_hexid));
	if (!oio_str_hex2bin(content_hexid, content_id, content_idlen)) {
		err = BADREQ("Invalid content ID (not hexa)");
		goto label_end;
	}

	/* The content-id has been specified, we MUST check it will be UNIQUE */
	err = m2db_check_content_absent(args->sq3, content_id, content_idlen);
	if (err) {
		goto label_end;
	}

	if (args->worm_mode) {
		err = NEWERROR(CODE_CONTENT_EXISTS, "NS wormed! Cannot overwrite.");
		goto label_end;
	}

	err = _real_delete_and_save_deleted_beans(args->sq3,
			beans_to_delete, NULL, current_header,
			_bean_list_cb, &deleted_beans);
	if (err) {
		goto label_end;
	}

	/* Patch the beans, before inserting */
	_patch_beans_defaults(new_beans);
	_patch_beans_with_time(new_beans, current_alias);
	/* Ensure the beans are all linked to the content (with their content-id) */
	_patch_beans_with_contentid(new_beans, content_id, content_idlen);
	/* Keep the same mtime */
	ALIASES_set_mtime(new_alias, ALIASES_get_mtime(current_alias));

	err = m2db_real_put_alias(args->sq3, new_beans, cb_added, u0_added);
	if (!err) {
		m2db_set_size(args->sq3,
				m2db_get_size(args->sq3) +
				CONTENTS_HEADERS_get_size(new_header));
		m2db_set_obj_count(args->sq3, m2db_get_obj_count(args->sq3) + 1);
	}

label_end:
	_bean_clean(current_alias);
	_bean_cleanl2(beans_to_delete);

	if (!err && cb_deleted && deleted_beans)
		cb_deleted(u0_deleted, deleted_beans);
	else
		_bean_cleanl2(deleted_beans);

	return err;
}

GError* m2db_append_to_alias(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		GSList *beans, m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	GSList *newchunks = NULL;

	// Sanity checks
	GRID_TRACE("M2 APPEND(%s)", oio_url_get(url, OIOURL_WHOLE));
	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(url != NULL);
	if (!oio_url_has(url, OIOURL_PATH))
		return NEWERROR(CODE_BAD_REQUEST, "Missing path");

	GPtrArray *tmp = g_ptr_array_new ();
	if (oio_url_has(url, OIOURL_VERSION))
		err = m2db_get_alias(sq3, url, M2V2_FLAG_LATEST|M2V2_FLAG_NOPROPS,
							 _bean_buffer_cb, tmp);
	else
		err = m2db_get_alias(sq3, url, M2V2_FLAG_NOPROPS,
							 _bean_buffer_cb, tmp);

	/* Content does not exist or is deleted -> the append is a PUT */
	if (err) {
		if (err->code != CODE_CONTENT_NOTFOUND)
			goto out;
		g_clear_error(&err);
	}
	if (tmp->len <= 0) {
		_bean_cleanv2(tmp);

		struct m2db_put_args_s args = {0};
		args.sq3 = sq3;
		args.url = url;
		/* whatever, the content is not present, we won't reach a limit */
		args.ns_max_versions = -1;
		return m2db_put_alias(&args, beans, NULL, NULL, NULL, NULL);
	}

	/* a content is present, let's append the chunks. Let's start by filtering
	 * the chunks. */
	gint64 added_size = 0;
	GTree *positions_seen = g_tree_new(_tree_compare_int);
	_extract_chunks_sizes_positions(beans,
			&newchunks, &added_size, positions_seen);
	g_tree_destroy(positions_seen);

	/* For the beans in place, get the position of the last chunk (meta), and
	 * the current content ID */
	gint64 last_position = -1;
	GBytes *content_id = NULL;
	struct bean_CONTENTS_HEADERS_s *header = NULL;
	const gint64 now = oio_ext_real_time() / G_TIME_SPAN_SECOND;
	for (guint i = 0; i < tmp->len; ++i) {
		gpointer bean = tmp->pdata[i];
		if (&descr_struct_CONTENTS_HEADERS == DESCR(bean)) {
			header = bean;
			if(!strcmp(CONTENTS_HEADERS_get_chunk_method(bean)->str,
						CHUNK_METHOD_DRAINED)) {
				err= NEWERROR(CODE_CONTENT_DRAINED, "The content is drained");
				goto out;
			}
			GByteArray *gba = CONTENTS_HEADERS_get_id (header);
			if (gba) {
				if (content_id)
					g_bytes_unref (content_id);
				content_id = g_bytes_new (gba->data, gba->len);
			}
			gint64 size = CONTENTS_HEADERS_get_size(header) + added_size;
			CONTENTS_HEADERS_set_size(header, size);
			CONTENTS_HEADERS_set2_hash(header, (guint8*)"", 0);
			CONTENTS_HEADERS_set_mtime(header, now);
		}
		else if (&descr_struct_CHUNKS == DESCR(bean)) {
			struct bean_CHUNKS_s *chunk = bean;
			GString *gs = CHUNKS_get_position (chunk);
			if (gs) {
				gint64 p = g_ascii_strtoll (gs->str, NULL, 10);
				last_position = MAX(last_position, p);
			}
		}
	}
	g_assert (last_position >= 0);
	g_assert (content_id != NULL);

	/* update the position in each new chunk, and link it to the content
	 * in place */
	GByteArray *cid_gba = g_bytes_unref_to_array(content_id);
	for (GSList *l = newchunks; l; l = l->next) {
		struct bean_CHUNKS_s *chunk = l->data;
		GString *gs = CHUNKS_get_position (chunk);
		struct m2v2_position_s position = m2v2_position_decode (gs->str);
		position.meta += last_position + 1;
		m2v2_position_encode  (gs, &position);
		CHUNKS_set_content(chunk, cid_gba);
	}
	g_byte_array_free(cid_gba, TRUE);

	/* Save the modified content header */
	if ((err = _db_save_bean(sq3->db, header)))
		goto out;

	/* Now insert each chunk bean */
	if (!(err = _db_insert_beans_list (sq3->db, newchunks))) {
		if (cb) {
			for (GSList *l = newchunks; l; l = l->next) {
				cb (u0, l->data);
				l->data = NULL;  // prevent double free
			}
			cb(u0, _bean_dup(header));
		}
	}
	if (!err)
		m2db_set_size(sq3, m2db_get_size(sq3) + added_size);

out:
	_bean_cleanl2(newchunks);
	_bean_cleanv2(tmp);
	return err;
}

/* GENERATOR ---------------------------------------------------------------- */


GError*
m2_generate_beans(struct oio_url_s *url, gint64 size, gint64 chunk_size,
		struct storage_policy_s *pol, struct oio_lb_s *lb,
		m2_onbean_cb cb, gpointer cb_data)
{
	GSList *beans = NULL;
	GError *err = oio_generate_beans(url, size, chunk_size, pol, lb, &beans);
	if (err)
		return err;
	if (cb) {
		for (GSList *l=beans; l; l=l->next)
			cb(cb_data, l->data);
		g_slist_free(beans);
	} else {
		_bean_cleanl2(beans);
	}
	return NULL;
}

enum _content_broken_state_e
{
	NONE,
	REPARABLE,
	IRREPARABLE
};

struct checked_content_s
{
	gboolean partial;
	guint nb_copy;
	guint k;
	guint m;
	gint expected_metapos;
	gint64 size;
	GSList *present_chunks;
	GSList *missing_pos;
	enum _content_broken_state_e broken_state;
};

static struct checked_content_s *
_checked_content_new(gboolean partial, guint nb_copy, guint k, guint m)
{
	struct checked_content_s *checked_content = g_malloc0(
			sizeof(struct checked_content_s));
	checked_content->partial = partial;
	checked_content->nb_copy = nb_copy;
	checked_content->k = k;
	checked_content->m = m;
	return checked_content;
}

void
checked_content_free(struct checked_content_s *checked_content)
{
	g_slist_free_full(checked_content->missing_pos, g_free);
	g_slist_free(checked_content->present_chunks);
	g_free(checked_content);
}

void
checked_content_append_json_string(struct checked_content_s *checked_content,
		GString *message)
{
	g_string_append(message, "\"present_chunks\":[");
	meta2_json_chunks_only(message, checked_content->present_chunks, FALSE);

	g_string_append(message, "], \"missing_chunks\":[");
	gboolean first_missing_pos = TRUE;
	for (GSList *missing_pos = checked_content->missing_pos; missing_pos;
			missing_pos = missing_pos->next) {
		if (first_missing_pos) {
			first_missing_pos = FALSE;
		} else {
			g_string_append_c(message, ',');
		}
		g_string_append_c(message, '"');
		oio_str_gstring_append_json_string(message, missing_pos->data);
		g_string_append_c(message, '"');
	}
	g_string_append_c(message, ']');
}

guint
checked_content_get_missing_chunks(struct checked_content_s *checked_content)
{
	return g_slist_length(checked_content->missing_pos);
}

static gboolean
_check_metachunk_plain_content(GSList *chunks, struct checked_content_s *plain)
{
	guint nb_chunks = 0;
	gint64 chunk_size = CHUNKS_get_size(chunks->data);

	for (GSList *l = chunks; l; l = l->next) {
		gpointer chunk = l->data;

		plain->present_chunks = g_slist_prepend(plain->present_chunks, chunk);
		nb_chunks++;

		if (CHUNKS_get_size(chunk) != chunk_size) {
			plain->broken_state = IRREPARABLE;
			return FALSE;
		}
	}

	if (plain->nb_copy > nb_chunks) {
		gchar *pos = CHUNKS_get_position(chunks->data)->str;
		for (guint i = nb_chunks; i < plain->nb_copy; i++) {
			plain->missing_pos = g_slist_prepend(plain->missing_pos,
				g_strdup(pos));
		}
		plain->broken_state = REPARABLE;
	}

	plain->size += plain->nb_copy * chunk_size;
	return TRUE;
}

static gboolean
_check_metachunk_ec_content(GSList *chunks, struct checked_content_s *ec)
{
	guint expected_nb_chunk = ec->k + ec->m;
	guint nb_chunks = 0;
	gint64 chunk_size = CHUNKS_get_size(chunks->data);
	guint8 present_subpos[expected_nb_chunk];
	for (guint i=0; i < expected_nb_chunk; i++) {
		present_subpos[i] = 0;
	}

	for (GSList *l = chunks; l; l = l->next) {
		gpointer chunk = l->data;

		gchar *pos = CHUNKS_get_position(chunk)->str;
		char *subpos_str = g_strrstr(pos, ".");
		if (subpos_str == NULL) {
			ec->broken_state = IRREPARABLE;
			return FALSE;
		}
		gint64 subpos = g_ascii_strtoll(++subpos_str, NULL, 10);
		if (subpos < 0 || subpos >= expected_nb_chunk) {
			ec->broken_state = IRREPARABLE;
			return FALSE;
		}

		if (present_subpos[subpos]) {
			ec->broken_state = IRREPARABLE;
			return FALSE;
		}
		present_subpos[subpos] = 1;

		ec->present_chunks = g_slist_prepend(ec->present_chunks, chunk);
		nb_chunks++;

		if (CHUNKS_get_size(chunk) != chunk_size) {
			ec->broken_state = IRREPARABLE;
			return FALSE;
		}
	}

	ec->size += expected_nb_chunk * chunk_size;
	if (nb_chunks == expected_nb_chunk) {
		return TRUE;
	}
	if (nb_chunks < ec->k) {
		ec->broken_state = IRREPARABLE;
		return FALSE;
	}

	for (guint subpos=0; subpos < expected_nb_chunk; subpos++) {
		if (present_subpos[subpos]) {
			continue;
		}

		ec->missing_pos = g_slist_prepend(ec->missing_pos,
			g_strdup_printf("%d.%d", ec->expected_metapos, subpos));
	}
	ec->broken_state = REPARABLE;
	return TRUE;
}

static gboolean
_foreach_check_plain_content(gpointer key, gpointer value, gpointer data)
{
	struct checked_content_s *checked_content = data;
	gint metapos = GPOINTER_TO_INT(key);
	if (checked_content->expected_metapos != metapos &&
			!checked_content->partial) {
		// There is a hole in the sequence of metachunks
		checked_content->broken_state = IRREPARABLE;
		return TRUE;
	}

	gboolean res = _check_metachunk_plain_content(value, checked_content);
	checked_content->expected_metapos++;
	return !res;
}

static gboolean
_foreach_check_ec_content(gpointer key, gpointer value, gpointer data)
{
	struct checked_content_s *checked_content = data;
	gint metapos = GPOINTER_TO_INT(key);
	if (checked_content->expected_metapos != metapos &&
			!checked_content->partial) {
		// There is a hole in the sequence of metachunks
		checked_content->broken_state = IRREPARABLE;
		return TRUE;
	}

	gboolean res = _check_metachunk_ec_content(value, checked_content);
	checked_content->expected_metapos++;
	return !res;
}

static enum _content_broken_state_e
_check_plain_content(struct m2v2_sorted_content_s *content,
		const struct data_security_s *dsec,
		struct checked_content_s **checked_content_p, gboolean partial)
{
	EXTRA_ASSERT(checked_content_p != NULL);
	EXTRA_ASSERT(*checked_content_p == NULL);

	gint nb_copy = data_security_get_int64_param(dsec, DS_KEY_COPY_COUNT, 1);
	if (!content->header)
		return IRREPARABLE;

	gint64 size = CONTENTS_HEADERS_get_size(content->header);
	struct checked_content_s *checked_content = _checked_content_new(
			partial, nb_copy, 0, 0);

	g_tree_foreach(content->metachunks, _foreach_check_plain_content,
			checked_content);

	if (checked_content->broken_state == IRREPARABLE) {
		checked_content_free(checked_content);
		return IRREPARABLE;
	}
	/* Check if the last metachunks are present
	 * or check if the chunk sizes match the content size */
	if (!checked_content->partial
			&& checked_content->size < size * checked_content->nb_copy) {
		checked_content_free(checked_content);
		return IRREPARABLE;
	}

	*checked_content_p = checked_content;
	return checked_content->broken_state;
}

static enum _content_broken_state_e
_check_ec_content(struct m2v2_sorted_content_s *content,
		struct storage_policy_s *pol,
		struct checked_content_s **checked_content_p, gboolean partial)
{
	EXTRA_ASSERT(checked_content_p != NULL);
	EXTRA_ASSERT(*checked_content_p == NULL);

	if (!content->header)
		return IRREPARABLE;

	gint64 size = CONTENTS_HEADERS_get_size(content->header);
	struct checked_content_s *checked_content = _checked_content_new(
			partial, 0, storage_policy_parameter(pol, DS_KEY_K, 6),
			storage_policy_parameter(pol, DS_KEY_M, 3));

	g_tree_foreach(content->metachunks, _foreach_check_ec_content,
			checked_content);

	if (checked_content->broken_state == IRREPARABLE) {
		checked_content_free(checked_content);
		return IRREPARABLE;
	}
	/* Check if the last metachunks are present
	 * or check if the chunk sizes match the content size */
	if (!checked_content->partial
			&& checked_content->size < size * (checked_content->k + checked_content->m) / checked_content->k) {
		checked_content_free(checked_content);
		return IRREPARABLE;
	}

	*checked_content_p = checked_content;
	return checked_content->broken_state;
}

static GError *
_m2db_check_content_validity(struct m2v2_sorted_content_s *sorted_content,
		struct storage_policy_s *pol,
		struct checked_content_s **checked_content_p, gboolean partial)
{
	GError *err = NULL;
	enum _content_broken_state_e cbroken = NONE;
	const struct data_security_s *dsec = storage_policy_get_data_security(pol);
	switch (data_security_get_type(dsec)) {
		case STGPOL_DS_BACKBLAZE:
		case STGPOL_DS_PLAIN:
			cbroken = _check_plain_content(sorted_content, dsec,
					checked_content_p, partial);
			break;
		case STGPOL_DS_EC:
			cbroken = _check_ec_content(sorted_content, pol,
					checked_content_p, partial);
			break;
		default:
			err = NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid policy type");
	}

	switch (cbroken) {
		case NONE:
			break;
		case REPARABLE:
			err = NEWERROR(CODE_CONTENT_UNCOMPLETE, "Content broken but reparable");
			break;
		case IRREPARABLE:
			err = NEWERROR(CODE_CONTENT_CORRUPTED, "Content broken and irreparable");
			break;
	}
	return err;
}

static GError *
_m2db_get_content_missing_chunks(struct m2v2_sorted_content_s *sorted_content,
		struct storage_policy_s *pol, gint64 *missing_chunks)
{
	gint64 expected_chunks = 0;
	const struct data_security_s *dsec = storage_policy_get_data_security(pol);
	switch (data_security_get_type(dsec)) {
		case STGPOL_DS_BACKBLAZE:
		case STGPOL_DS_PLAIN:
			expected_chunks = data_security_get_int64_param(
					dsec, DS_KEY_COPY_COUNT, 1);
			break;
		case STGPOL_DS_EC:
			expected_chunks = data_security_get_int64_param(
					dsec, DS_KEY_K, 1);
			expected_chunks += data_security_get_int64_param(
					dsec, DS_KEY_M, 1);
			break;
		default:
			return NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid policy type");
	}
	*missing_chunks = (expected_chunks * g_tree_nnodes(
			sorted_content->metachunks)) - sorted_content->n_chunks;
	return NULL;
}

void
m2db_check_content_quality(struct m2v2_sorted_content_s *sorted_content,
		GSList *chunk_meta, GSList **to_be_improved)
{
	EXTRA_ASSERT(to_be_improved != NULL);
	/* keys are chunk URLs,
	 * values are <struct oio_lb_selected_item_s *> */
	GHashTable *chunk_items = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, (GDestroyNotify) oio_lb_selected_item_free);
	_load_chunk_qualities(chunk_items, chunk_meta);

	gboolean _on_metachunk(gpointer ppos, GSList *chunks, gpointer udata UNUSED) {
		gint mc_pos = GPOINTER_TO_INT(ppos);
		GString *out = g_string_sized_new(1024);
		g_string_append_c(out, '{');
		oio_str_gstring_append_json_pair_int(out, "pos", mc_pos);
		g_string_append_c(out, ',');
		oio_str_gstring_append_json_quote(out, "chunks");
		g_string_append(out, ":[");
		gboolean must_send_event = FALSE;
		for (GSList *cur = chunks; cur; cur = cur->next) {
			GString *chunk_id = CHUNKS_get_id(cur->data);
			struct oio_lb_selected_item_s *item = g_hash_table_lookup(
					chunk_items, chunk_id->str);
			if (item) {
				if (cur != chunks)
					g_string_append_c(out, ',');
				g_string_append_c(out, '{');
				meta2_json_encode_bean(out, cur->data);
				g_string_append_c(out, ',');
				oio_str_gstring_append_json_quote(out, "quality");
				g_string_append_c(out, ':');
				oio_selected_item_quality_to_json(out, item);
				if (item->final_dist <= item->warn_dist ||
						strcmp(item->final_slot, item->expected_slot)) {
					must_send_event = TRUE;
				}
				g_string_append_c(out, '}');
			} else {
				GRID_DEBUG("%s: no quality description for chunk %s",
						__FUNCTION__, chunk_id->str);
			}
		}
		g_string_append(out, "]}");
		if (must_send_event) {
			*to_be_improved = g_slist_prepend(*to_be_improved,
					g_string_free(out, FALSE));
		} else {
			GRID_DEBUG("Event avoided (sufficient quality): %s", out->str);
			g_string_free(out, TRUE);
		}
		return FALSE;
	}

	g_tree_foreach(sorted_content->metachunks,
			(GTraverseFunc)_on_metachunk, NULL);
	g_hash_table_destroy(chunk_items);
}

GError *
m2db_check_content(struct m2v2_sorted_content_s *sorted_content,
		struct namespace_info_s *nsinfo,
		struct checked_content_s **checked_content_p, gboolean partial)
{
	GError *err = NULL;

	struct storage_policy_s *pol = NULL;
	GString *polname = NULL;

	if (sorted_content->header != NULL)
		polname = CONTENTS_HEADERS_get_policy(sorted_content->header);
	if (polname && polname->str && polname->len)
		pol = storage_policy_init(nsinfo, polname->str);
	if (!pol)
		err = NEWERROR(CODE_POLICY_NOT_SUPPORTED,
				"Invalid policy: %s", polname ? polname->str : "not found");

	if (!err)
		err = _m2db_check_content_validity(sorted_content, pol,
				checked_content_p, partial);

	if (pol)
		storage_policy_clean(pol);

	return err;
}

GError *
m2db_get_content_missing_chunks(struct m2v2_sorted_content_s *sorted_content,
		struct namespace_info_s *nsinfo, gint64 *missing_chunks)
{
	GError *err = NULL;

	struct storage_policy_s *pol = NULL;
	GString *polname = NULL;

	if (sorted_content->header != NULL)
		polname = CONTENTS_HEADERS_get_policy(sorted_content->header);
	if (polname && polname->str && polname->len)
		pol = storage_policy_init(nsinfo, polname->str);
	if (!pol)
		err = NEWERROR(CODE_POLICY_NOT_SUPPORTED,
				"Invalid policy: %s", polname ? polname->str : "not found");

	if (!err)
		err = _m2db_get_content_missing_chunks(sorted_content, pol,
				missing_chunks);

	if (pol)
		storage_policy_clean(pol);

	return err;
}

/* Storage Policy ----------------------------------------------------------- */

static GError*
_get_content_policy(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		struct namespace_info_s *nsinfo, struct storage_policy_s **result)
{
	GError *err = NULL;
	GPtrArray *tmp = NULL;
	struct bean_ALIASES_s *latest = NULL;
	struct storage_policy_s *policy = NULL;

	tmp = g_ptr_array_new();

	if (!(err = m2db_latest_alias(sq3, url, &latest))) {
		if (latest != NULL) {
			err = _db_get_FK_by_name(latest, "image", sq3->db, _bean_buffer_cb, tmp);
			if (!err && tmp->len > 0) {
				struct bean_CONTENTS_HEADERS_s *header = tmp->pdata[0];
				GString *polname = CONTENTS_HEADERS_get_policy(header);
				if (polname && polname->str && polname->len) {
					policy = storage_policy_init(nsinfo, polname->str);
				}
			}
		}
	}

	_bean_cleanv2(tmp);
	if (!err)
		*result = policy;
	return err;
}

static GError*
_get_container_policy(struct sqlx_sqlite3_s *sq3, struct namespace_info_s *nsinfo,
		struct storage_policy_s **result)
{
	gchar *pname;
	EXTRA_ASSERT(result != NULL);

	*result = NULL;
	pname = sqlx_admin_get_str(sq3, M2V2_ADMIN_STORAGE_POLICY);
	if (pname) {
		*result = storage_policy_init(nsinfo, pname);
		g_free(pname);
	}

	return NULL;
}

GError*
m2db_get_storage_policy(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		struct namespace_info_s *nsinfo, gboolean from_previous,
		struct storage_policy_s **result)
{
	GError *err = NULL;
	struct storage_policy_s *policy = NULL;

	GRID_TRACE2("%s(%s)", __FUNCTION__, oio_url_get(url, OIOURL_WHOLE));
	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(nsinfo != NULL);
	EXTRA_ASSERT(result != NULL);

	if (from_previous)
		err = _get_content_policy(sq3, url, nsinfo, &policy);

	if (!err && !policy)
		err = _get_container_policy(sq3, nsinfo, &policy);

	if (!err)
		*result = policy;
	return err;
}

GError*
m2db_set_storage_policy(struct sqlx_sqlite3_s *sq3, const gchar *polname, int replace)
{
	const gchar *k = M2V2_ADMIN_STORAGE_POLICY;

	if (!replace) {
		gchar *s = sqlx_admin_get_str(sq3, k);
		if (s) {
			g_free(s);
			return NULL;
		}
	}

	sqlx_admin_set_str(sq3, k, polname);
	return NULL;
}

void
m2db_set_container_name(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url)
{
	sqlx_admin_init_str(sq3, M2V2_ADMIN_VERSION, "0");

	struct map_s { const char *f; int k; } map[] = {
		{SQLX_ADMIN_NAMESPACE, OIOURL_NS},
		{SQLX_ADMIN_ACCOUNT, OIOURL_ACCOUNT},
		{SQLX_ADMIN_USERNAME, OIOURL_USER},
		{NULL,0},
	};
	for (struct map_s *p = map; p->f; ++p) {
		const gchar *v = oio_url_get(url, p->k);
		if (v != NULL)
			sqlx_admin_init_str(sq3, p->f, v);
	}
}

/* ------------------------------------------------------------------------- */

static GError*
_purge_exceeding_aliases(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		const gchar *alias, m2_onbean_cb cb, gpointer u0)
{
	struct elt_s {
		gchar *alias;
		gint64 count;
	};

	GRID_TRACE("%s, max_versions = %"G_GINT64_FORMAT, __FUNCTION__, max_versions);

	const gchar *sql_lookup;
	if (alias) {
		sql_lookup = "SELECT alias, count(*)"
			"FROM aliases "
			"WHERE NOT deleted " // Do not count last extra deleted version
			"and alias = ? "
			"GROUP BY alias "
			"HAVING COUNT(*) > ?";
	} else {
		sql_lookup = "SELECT alias, count(*)"
			"FROM aliases "
			"WHERE NOT deleted " // Do not count last extra deleted version
			"GROUP BY alias "
			"HAVING COUNT(*) > ?";
	}
	const gchar *sql_delete = " rowid IN "
		"(SELECT rowid FROM aliases WHERE NOT deleted AND alias = ? "
		" ORDER BY version ASC LIMIT ? ) ";

	int rc = SQLITE_OK;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	GSList *to_be_deleted = NULL;

	if (VERSIONS_UNLIMITED(max_versions))
		return NULL;
	if (!VERSIONS_ENABLED(max_versions))
		max_versions = 1;

	sqlite3_prepare_debug(rc, sq3->db, sql_lookup, -1, &stmt, NULL);
	sqlite3_clear_bindings(stmt);
	sqlite3_reset(stmt);
	if (alias) {
		sqlite3_bind_text(stmt, 1, alias, -1, NULL);
		sqlite3_bind_int64(stmt, 2, max_versions);
	} else {
		sqlite3_bind_int64(stmt, 1, max_versions);
	}
	while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
		struct elt_s *elt = g_malloc0(sizeof(*elt));
		elt->alias = g_strdup((gchar*)sqlite3_column_text(stmt, 0));
		elt->count = sqlite3_column_int64(stmt, 1);
		to_be_deleted = g_slist_prepend(to_be_deleted, elt);
	}
	(void) sqlite3_finalize(stmt);

	GRID_DEBUG("Nb alias to drop: %d", g_slist_length(to_be_deleted));

	// Delete the alias bean and send it to callback
	void _delete_cb(gpointer udata, struct bean_ALIASES_s *alias_to_delete)
	{
		GError *local_err = _db_delete_bean(sq3->db, alias_to_delete);
		if (!local_err) {
			cb(udata, alias_to_delete); // alias is cleaned by callback
		} else {
			GRID_WARN("Failed to drop %s (v%"G_GINT64_FORMAT"): %s",
					ALIASES_get_alias(alias_to_delete)->str,
					ALIASES_get_version(alias_to_delete),
					local_err->message);
			_bean_clean(alias_to_delete);
			g_clear_error(&local_err);
		}
	}

	for (GSList *l = to_be_deleted; l; l = l->next) {
		GError *err2 = NULL;
		GVariant *params[] = {NULL, NULL, NULL};
		struct elt_s *elt = l->data;
		params[0] = g_variant_new_string(elt->alias);
		params[1] = g_variant_new_int64(elt->count - max_versions);
		err2 = ALIASES_load(sq3->db, sql_delete, params,
				(m2_onbean_cb)_delete_cb, u0);
		if (err2) {
			GRID_WARN("Failed to drop exceeding copies of %s: %s",
					elt->alias, err2->message);
			if (!err)
				err = err2;
			else
				g_clear_error(&err2);
		}
		metautils_gvariant_unrefv(params);
	}

	for (GSList *l = to_be_deleted; l; l = l->next) {
		struct elt_s *elt = l->data;
		g_free(elt->alias);
		g_free(elt);
		l->data = NULL;
	}
	g_slist_free(to_be_deleted);
	to_be_deleted = NULL;
	return err;
}

static GError*
_purge_deleted_aliases(struct sqlx_sqlite3_s *sq3, gint64 delay,
		const gchar *alias, m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	gchar *sql;
	GVariant *params[] = {NULL, NULL, NULL};
	gint64 now = oio_ext_real_time () / G_TIME_SPAN_SECOND;
	gint64 time_limit = 0;

	// All aliases which have one version deleted (the last) older than time_limit
	if (alias) {
		sql = (" alias IN "
				"(SELECT alias FROM "
				"  (SELECT alias,ctime,deleted FROM aliases WHERE alias = ? "
				"   GROUP BY alias) "
				" WHERE deleted AND ctime < ?) ");
	} else {
		sql = (" alias IN "
				"(SELECT alias FROM "
				"  (SELECT alias,ctime,deleted FROM aliases GROUP BY alias) "
				" WHERE deleted AND ctime < ?) ");
	}

	if (now < 0) {
		err = g_error_new(GQ(), CODE_INTERNAL_ERROR,
				"Cannot get current time: %s", g_strerror(errno));
		return err;
	}

	if (delay >= 0 && delay < now) {
		time_limit = now - delay;
	}

	// Delete the alias bean and send it to callback
	void _delete_cb(gpointer udata, struct bean_ALIASES_s *alias_to_delete)
	{
		GError *local_err = _db_delete_bean(sq3->db, alias_to_delete);
		if (!local_err) {
			cb(udata, alias_to_delete); // alias is cleaned by callback
		} else {
			GRID_WARN("Failed to drop %s (v%"G_GINT64_FORMAT"): %s",
					ALIASES_get_alias(alias_to_delete)->str,
					ALIASES_get_version(alias_to_delete),
					local_err->message);
			_bean_clean(alias_to_delete);
			g_clear_error(&local_err);
		}
	}

	// Do the purge.
	GRID_DEBUG("Purging deleted aliases older than %"G_GINT64_FORMAT" seconds (timestamp < %"G_GINT64_FORMAT")",
			delay, time_limit);
	if (alias) {
		params[0] = g_variant_new_string(alias);
		params[1] = g_variant_new_int64(time_limit);
	} else {
		params[0] = g_variant_new_int64(time_limit);
	}
	err = ALIASES_load(sq3->db, sql, params, (m2_onbean_cb)_delete_cb, u0);
	metautils_gvariant_unrefv(params);

	return err;
}

GError*
m2db_purge(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		gint64 retention_delay, const gchar *alias,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err;

	GPtrArray *aliases = g_ptr_array_new();
	if ((err = _purge_exceeding_aliases(sq3, max_versions, alias,
			_bean_buffer_cb, aliases))) {
		GRID_WARN("Failed to purge ALIASES: (code=%d) %s",
				err->code, err->message);
		_bean_cleanv2(aliases);
		return err;
	}

	if (retention_delay >= 0) {
		if ((err = _purge_deleted_aliases(sq3, retention_delay, alias,
				_bean_buffer_cb, aliases))) {
			GRID_WARN("Failed to purge deleted ALIASES: (code=%d) %s",
					err->code, err->message);
			_bean_cleanv2(aliases);
			return err;
		}
	}

	if (!err)
		err = _real_delete_aliases(sq3, aliases, cb, u0);

	_bean_cleanv2(aliases);
	return err;
}

GError*
m2db_flush_container(struct sqlx_sqlite3_s *sq3, m2_onbean_cb cb, gpointer u0,
		gboolean *truncated)
{
	GError *err = NULL;
	gint64 limit = meta2_flush_limit + 1;

	GPtrArray *aliases = g_ptr_array_new();
	GVariant *params[3] = {NULL};
	gchar sql[32];
	g_snprintf(sql, 32, "1 LIMIT %"G_GINT64_FORMAT, limit);
	err = ALIASES_load(sq3->db, sql, params, _bean_buffer_cb, aliases);
	metautils_gvariant_unrefv(params);

	guint nb_aliases = aliases->len;
	if (nb_aliases == limit) {
		_bean_clean(aliases->pdata[limit-1]);
		aliases->pdata[limit-1] = NULL;
		g_ptr_array_remove_index_fast(aliases, limit-1);
		*truncated = TRUE;
	}

	if (!err)
		err = _real_delete_aliases(sq3, aliases, cb, u0);
	_bean_cleanv2(aliases);

	if (!err && !(*truncated)) {
		int rc = sqlx_exec(sq3->db,
				"DELETE FROM aliases;"
				"DELETE FROM contents;"
				"DELETE FROM chunks;"
				"DELETE FROM properties");
		if (rc != SQLITE_OK)
			return SQLITE_GERROR(sq3->db, rc);
		// reset container size and object count
		m2db_set_size(sq3, 0);
		m2db_set_obj_count(sq3, 0);
	}

	return err;
}
