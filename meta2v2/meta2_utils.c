/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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
#include <meta2v2/meta2_dedup_utils.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <meta2v2/meta2_utils_json.h>

#define RANDOM_UID(uid,uid_size) \
	struct { guint64 now; guint32 r; guint16 pid; guint16 th; } uid; \
	uid.now = oio_ext_real_time (); \
	uid.r = oio_ext_rand_int(); \
	uid.pid = getpid(); \
	uid.th = oio_log_current_thread_id(); \
	gsize uid_size = sizeof(uid);

static GError*
_get_container_policy(struct sqlx_sqlite3_s *sq3, struct namespace_info_s *nsinfo,
		struct storage_policy_s **result);

static gint64
_m2db_count_alias_versions(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url)
{
	int rc;
	gint64 v;
	sqlite3_stmt *stmt = NULL;

	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(url != NULL);

	v = 0;
	sqlite3_prepare_debug(rc, sq3->db,
			"SELECT COUNT(version) FROM aliases WHERE alias = ?", -1, &stmt, NULL);
	if (rc == SQLITE_OK) {
		sqlite3_bind_text(stmt, 1, oio_url_get(url, OIOURL_PATH), -1, NULL);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			v = sqlite3_column_int64(stmt, 0);
		}
		rc = sqlite3_finalize(stmt);
	}

	return v;
}

static gint
_tree_compare_int(gconstpointer a, gconstpointer b)
{
	return CMP(GPOINTER_TO_INT(a), GPOINTER_TO_INT(b));
}

#define FORMAT_ERROR(v,s,e) (!(v) && errno == EINVAL)
#define RANGE_ERROR(v) ((v) == G_MININT64 || (v) == G_MAXINT64)
#define STRTOLL_ERROR(v,s,e) (FORMAT_ERROR(v,s,e) || RANGE_ERROR(v))

gchar*
m2v2_build_chunk_url (const char *srv, const char *id)
{
	return g_strconcat("http://", srv, "/", id, NULL);
}

static gchar*
m2v2_build_chunk_url_storage (const struct storage_policy_s *pol,
		const gchar *str_id)
{
	switch(data_security_get_type(storage_policy_get_data_security(pol))) {
	case STGPOL_DS_BACKBLAZE:
		return g_strconcat("b2/", str_id, NULL);
	default:
		return NULL;
	}
	return NULL;
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


/* GET ---------------------------------------------------------------------- */

struct _sorted_content_s {
	struct bean_CONTENTS_HEADERS_s *header;
	GSList *aliases;    // GSList<struct bean_ALIASES_s*>
	GSList *properties; // GSList<struct bean_PROPERTIES_s*>
	GTree *metachunks;  // GTree<gint,GSList<struct bean_CHUNKS_s*>>
};

static void
_sort_content_cb(gpointer sorted_content, gpointer bean)
{
	struct _sorted_content_s *content = sorted_content;
	if (DESCR(bean) == &descr_struct_CHUNKS) {
		gint64 pos = g_ascii_strtoll(
				CHUNKS_get_position(bean)->str, NULL, 10);
		GSList *mc = g_tree_lookup(content->metachunks, GINT_TO_POINTER(pos));
		mc = g_slist_prepend(mc, bean);
		g_tree_insert(content->metachunks, GINT_TO_POINTER(pos), mc);
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
				GBytes *gb = g_bytes_new_static (b, hl/2);
				params[0] = _gb_to_gvariant(gb);
				g_bytes_unref (gb);
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
		err = ALIASES_load_buffered(sq3->db, sql, params, tmp);
	metautils_gvariant_unrefv(params);

	if (!err) {
		if (tmp->len <= 0) {
			err = NEWERROR(CODE_CONTENT_NOTFOUND, "Alias not found");
		} else if (tmp->len == 1 && ALIASES_get_deleted(tmp->pdata[0]) &&
				(flags & M2V2_FLAG_NODELETED)) {
			err = NEWERROR(CODE_CONTENT_NOTFOUND, "Alias deleted");
		}
	}

	/* recurse on headers if allowed */
	if (!err && cb && ((flags & M2V2_FLAG_HEADERS) ||
			!(flags & M2V2_FLAG_NORECURSION))) {
		for (guint i = 0; !err && i < tmp->len; i++) {
			struct bean_ALIASES_s *alias = tmp->pdata[i];
			if (!alias)
				continue;
			if ((flags & M2V2_FLAG_NODELETED) && ALIASES_get_deleted(alias))
				continue;
			_manage_alias(sq3->db, alias, !(flags & M2V2_FLAG_NORECURSION), cb, u0);
		}
	}

	/* recurse on properties if allowed */
	if (!err && cb && !(flags & M2V2_FLAG_NOPROPS)) {
		for (guint i = 0; !err && i < tmp->len; i++) {
			struct bean_ALIASES_s *alias = tmp->pdata[i];
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
		for (guint i = 0; i < tmp->len; i++) {
			struct bean_ALIASES_s *alias = tmp->pdata[i];
			if (!alias)
				continue;
			if ((flags & M2V2_FLAG_NODELETED) && ALIASES_get_deleted(alias))
				_bean_clean(alias);
			else
				cb(u0, alias);
			tmp->pdata[i] = NULL;
		}
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

	if (!lp->flag_allversion || lp->maxkeys>0 || lp->marker_start || lp->marker_end)
		g_string_append_static(clause, " ORDER BY alias ASC, version ASC");

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
	GSList *aliases = NULL;
	guint count_aliases = 0;
	struct list_params_s lp = *lp0;
	gboolean done = FALSE;

	while (!done && (lp.maxkeys <= 0 || count_aliases < lp.maxkeys)) {
		GPtrArray *tmp = g_ptr_array_new();
		void cleanup (void) {
			g_ptr_array_set_free_func (tmp, _bean_clean);
			g_ptr_array_free (tmp, TRUE);
			tmp = NULL;
		}

		if (aliases)
			lp.marker_start = ALIASES_get_alias(aliases->data)->str;
		if (lp.maxkeys > 0)
			lp.maxkeys -= count_aliases;

		// List the next items
		GString *clause = g_string_sized_new(128);
		GVariant **params = _list_params_to_sql_clause (&lp, clause, headers);
		err = ALIASES_load(sq3->db, clause->str, params, _bean_buffer_cb, tmp);
		metautils_gvariant_unrefv (params);
		g_free (params), params = NULL;
		g_string_free (clause, TRUE);
		if (err) { cleanup (); goto label_error; }
		if (!tmp->len) { cleanup (); goto label_ok; }

		metautils_gpa_reverse (tmp);

		for (guint i = tmp->len; i > 0; i--) {
			struct bean_ALIASES_s *alias = tmp->pdata[i-1];
			const gchar *name = ALIASES_get_alias(alias)->str;

			if ((lp.prefix && !g_str_has_prefix(name, lp.prefix)) ||
					(lp.maxkeys > 0 && count_aliases > lp.maxkeys)) {
				cleanup (); goto label_ok;
			}

			g_ptr_array_remove_index_fast (tmp, i-1);

			if (!aliases || lp.flag_allversion) {
				aliases = g_slist_prepend(aliases, alias);
				++ count_aliases;
			} else {
				const gchar *last_name = ALIASES_get_alias(aliases->data)->str;
				if (!strcmp(last_name, name)) {
					_bean_clean (aliases->data);
					aliases->data = alias;
				} else {
					aliases = g_slist_prepend(aliases, alias);
					++ count_aliases;
				}
			}
		}

		done = (lp.maxkeys <= 0) || (lp.maxkeys > tmp->len);
		cleanup();
	}

label_ok:
	aliases = g_slist_reverse(aliases);
	for (GSList *l = aliases; l; l = l->next) {
		struct bean_ALIASES_s *alias = l->data;
		if (!lp.flag_nodeleted || !ALIASES_get_deleted(alias) || lp.flag_allversion){
			if (lp.flag_headers)
				_load_fk_by_name(sq3, alias, "image", cb, u);
			if (lp.flag_properties)
				_load_fk_by_name(sq3, alias, "properties", cb, u);
			cb(u, alias);
			l->data = NULL;
		}
	}

label_error:
	g_slist_free_full (aliases, _bean_clean);
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
		gboolean flush, GSList *beans, m2_onbean_cb cb, gpointer u0)
{
	struct bean_ALIASES_s *alias = NULL;
	GError *err = m2db_get_alias1(sq3, url, M2V2_FLAG_NOPROPS
			|M2V2_FLAG_NORECURSION, &alias);
	if (err)
		return err;
	if (!alias)
		return NEWERROR(CODE_CONTENT_NOTFOUND, "Alias not found");

	const char *name = ALIASES_get_alias(alias)->str;
	gint64 version = ALIASES_get_version(alias);

	if (flush) {
		const char *sql = "alias = ? AND version = ?";
		GVariant *params[3] = {NULL, NULL, NULL};
		params[0] = g_variant_new_string (name);
		params[1] = g_variant_new_int64 (ALIASES_get_version(alias));
		err = _db_delete (&descr_struct_PROPERTIES, sq3->db, sql, params);
		metautils_gvariant_unrefv (params);
	}

	for (; !err && beans; beans = beans->next) {
		struct bean_PROPERTIES_s *prop = beans->data;
		if (DESCR(prop) != &descr_struct_PROPERTIES)
			continue;
		PROPERTIES_set2_alias(prop, name);
		PROPERTIES_set_version(prop, version);
		GByteArray *v = PROPERTIES_get_value(prop);
		if (!v || !v->len || !v->data) {
			err = _db_delete_bean (sq3->db, prop);
		} else {
			err = _db_save_bean (sq3->db, prop);
			if (!err && cb)
				cb(u0, _bean_dup(prop));
		}
	}

	_bean_clean(alias);
	return err;
}

GError*
m2db_del_properties(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url, gchar **namev)
{
	GError *err;
	GPtrArray *tmp;

	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(namev != NULL);

	tmp = g_ptr_array_new();
	err = m2db_get_properties(sq3, url, _bean_buffer_cb, tmp);
	if (!err) {
		for (guint i = 0; !err && i < tmp->len; ++i) {
			struct bean_PROPERTIES_s *bean = tmp->pdata[i];
			if (DESCR(bean) != &descr_struct_PROPERTIES)
				continue;
			if (namev && *namev) {
				/* explicit properties to be deleted */
				for (gchar **p = namev; *p; ++p) {
					if (!strcmp(*p, PROPERTIES_get_key(bean)->str))
						_db_delete_bean (sq3->db, bean);
				}
			} else {
				/* all properties to be deleted */
				_db_delete_bean (sq3->db, bean);
			}
		}
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

GError*
m2db_delete_alias(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		struct oio_url_s *url, m2_onbean_cb cb, gpointer u0)
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

	if (VERSIONS_DISABLED(max_versions) || VERSIONS_SUSPENDED(max_versions) ||
			oio_url_has(url, OIOURL_VERSION) || ALIASES_get_deleted(alias)) {

		GSList *deleted_beans = NULL;
		err = _real_delete(sq3, beans, &deleted_beans);
		if (cb) {
			gboolean header_encountered = FALSE;
			/* Client asked to remove no-more referenced beans,
			 * we tell him which */
			for (GSList *bean = deleted_beans; bean; bean = bean->next) {
				if (bean->data == header)
					header_encountered = TRUE;
				cb(u0, _bean_dup(bean->data));
			}
			/* Header hasn't been deleted but contains useful information */
			if (!header_encountered)
				cb(u0, _bean_dup(header));
		}
		// deleted_beans contains direct pointers to the original beans
		g_slist_free(deleted_beans);

		// sqliterepo might disable foreign keys management, so that we have
		// to manage this by ourselves.
		if (!err)
			err = _db_del_FK_by_name (alias, "properties", sq3->db);

	} else {
		gint64 now = oio_ext_real_time () / G_TIME_SPAN_SECOND;
		/* Create a new version marked as deleted */
		struct bean_ALIASES_s *new_alias = _bean_dup(alias);
		ALIASES_set_deleted(new_alias, TRUE);
		ALIASES_set_version(new_alias, 1 + ALIASES_get_version(alias));
		ALIASES_set_ctime(new_alias, now);
		ALIASES_set_mtime(new_alias, now);
		err = _db_save_bean(sq3->db, new_alias);
		if (cb)
			cb(u0, new_alias);
		else
			_bean_clean(new_alias);
		new_alias = NULL;
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
	struct _sorted_content_s content = {
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

#if 0
static void _patch_beans_with_stgpol(GSList *beans, const char *stgpol) {
	for (GSList *l = beans; l; l = l->next) {
		gpointer bean = l->data;
		if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
			CONTENTS_HEADERS_set2_policy(bean, stgpol);
		}
	}
}

static gchar* _fetch_content_policy (GSList *beans) {
	for (GSList *l = beans; l; l = l->next) {
		gpointer bean = l->data;
		if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
			GString *gs = CONTENTS_HEADERS_get_policy(bean);
			return (gs && gs->len && gs->str) ? g_strdup(gs->str) : NULL;
		}
	}
	return NULL;
}
#endif

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

static void _patch_beans_with_contentid (GSList *beans,
		const guint8 *uid, gsize len) {
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

static void _patch_beans_with_time (GSList *beans, gint64 now) {
	for (GSList *l = beans; l; l = l->next) {
		gpointer bean = l->data;
		if (DESCR(bean) == &descr_struct_ALIASES) {
			ALIASES_set_ctime(bean, now);
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

static gint64 _fetch_alias_version (GSList *beans) {
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

static void m2db_purge_exceeding_versions(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url, gint64 maxver) {
	gint64 count = _m2db_count_alias_versions(sq3, url);
	if (maxver <= count) {
		/** TODO purge the oldest alias */
		GRID_WARN("GLOBAL PURGE necessary");
	}
}

static GError* m2db_real_put_alias(struct sqlx_sqlite3_s *sq3, GSList *beans,
		m2_onbean_cb cb, gpointer cb_data) {
	GError *err = NULL;
	for (GSList *l = beans; !err && l; l = l->next)
		err = _db_save_bean(sq3->db, l->data);
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
	GBytes *id = g_bytes_new (uid, len);
	params[0] = _gb_to_gvariant (id);
	GError *err = CONTENTS_HEADERS_load (sq3->db, " id = ? LIMIT 1", params,
			_bean_buffer_cb, tmp);
	metautils_gvariant_unrefv(params);
	guint count = tmp->len;
	_bean_cleanv2 (tmp);
	g_bytes_unref (id);
	if (err)
		return err;
	if (count)
		return NEWERROR(CODE_CONTENT_EXISTS, "A content exists with this ID");
	return NULL;
}

/* TODO(jfs): return the beans added/deleted */
GError* m2db_force_alias(struct m2db_put_args_s *args, GSList *beans,
		GSList **out_deleted UNUSED, GSList **out_added)
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

	if (NULL != err) {
		if (err->code != CODE_CONTENT_NOTFOUND) {
			g_prefix_error(&err, "Version error: ");
			return err;
		}
		g_clear_error(&err);
	}

	_patch_beans_defaults(beans);
	_patch_beans_with_time(beans, oio_ext_real_seconds());

	gint64 added_size = 0;
	gint64 obj_count = m2db_get_obj_count(args->sq3);

	if (!latest) {
		/* put everything (and patch everything */
		RANDOM_UID(uid, uid_size);
		_patch_beans_with_contentid(beans, (guint8*)&uid, uid_size);
		_patch_beans_with_version(beans, _fetch_alias_version(beans));
		err = m2db_real_put_alias(args->sq3, beans,
				out_added ? _bean_list_cb : NULL, out_added);
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
				if (out_added)
					*out_added = g_slist_prepend(*out_added, _bean_dup(bean));
			}
		}
		/* TODO need to recompute the container's size */
	}

	if (!err) {
		m2db_set_size(args->sq3, m2db_get_size(args->sq3) + added_size);
		m2db_set_obj_count(args->sq3, obj_count);
	}

	if (latest)
		_bean_clean(latest);

	return err;
}

GError* m2db_update_content(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url, GSList *beans,
		GSList **out_deleted, GSList **out_added) {
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
	if (out_deleted) {
		*out_deleted = g_slist_prepend(old_beans, header);
		header = NULL;
		old_beans = NULL;
	}
	if (out_added) {
		*out_added = new_beans;
		new_beans = NULL;
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
		GSList **out_deleted, GSList **out_added)
{
	struct bean_ALIASES_s *latest = NULL;
	GError *err = NULL;
	gboolean purge_latest = FALSE;

	EXTRA_ASSERT(args != NULL);
	EXTRA_ASSERT(args->sq3 != NULL);
	EXTRA_ASSERT(args->url != NULL);
	if (!oio_url_has_fq_path(args->url))
		return NEWERROR(CODE_BAD_REQUEST, "Missing fully qualified path");
	if (oio_url_has(args->url, OIOURL_VERSION))
		return NEWERROR(CODE_BAD_REQUEST, "URL version is present");

	/* Needed later several times, we extract now the content-id if specified */
	gint64 version = _fetch_alias_version(beans);
	const char *content_hexid = oio_url_get (args->url, OIOURL_CONTENTID);
	gsize content_idlen = 0;
	guint8 *content_id = NULL;
	if (content_hexid) {
		content_idlen = strlen(content_hexid) / 2;
		content_id = g_alloca(1 + strlen(content_hexid));
		if (!oio_str_hex2bin(content_hexid, content_id, content_idlen))
			return BADREQ("Invalid content ID (not hexa)");
	}

	/* The content-id has been specified, we MUST check it will be UNIQUE */
	if (content_id) {
		err = m2db_check_content_absent(args->sq3, content_id, content_idlen);
		if (NULL != err)
			return err;
	}

	/* Ensure the beans are all linked to the content (with their content-id) */
	if (content_id) {
		_patch_beans_with_contentid(beans, content_id, content_idlen);
	} else {
		RANDOM_UID(uid, uid_size);
		_patch_beans_with_contentid(beans, (guint8*)&uid, uid_size);
	}

	/* needed for later: the latest content in place. Fetch it once for all */
	if (NULL != (err = m2db_latest_alias(args->sq3, args->url, &latest))) {
		if (err->code != CODE_CONTENT_NOTFOUND) {
			g_prefix_error(&err, "Version error: ");
			return err;
		}
		GRID_TRACE("Alias not yet present (1)");
		g_clear_error(&err);
	}

	/* Manage the potential conflict with the latest alias in place. */
	if (version > 0) {
		/* version explicitely specified */
		if (latest && version == ALIASES_get_version(latest)) {
			/* TODO decide if it is better to alter the version to insert though */
			err = NEWERROR(CODE_CONTENT_EXISTS, "Alias already saved");
		} else {
			/* TODO check the PUT doesn't override an alias in place that is not the latest */
		}
	} else {
		/* version unset, let's deduce it from the alias in place */
		version = oio_ext_real_seconds();
		if (latest && ALIASES_get_version(latest) == version)
			version ++;
	}

	gint64 max_versions = m2db_get_max_versions(args->sq3,
												args->ns_max_versions);

	/* Check the operation respects the rules of versioning for the container */
	if (latest) {
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
		_patch_beans_with_time(beans, oio_ext_real_seconds());
		_patch_beans_with_version(beans, version);

		err = m2db_real_put_alias(args->sq3, beans,
				out_added ? _bean_list_cb : NULL, out_added);
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
			if (out_deleted) {
				GSList *o = NULL;
				for (GSList *l = deleted; l; l = l->next)
					o = g_slist_prepend(o, _bean_dup(l->data));
				*out_deleted = o;
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
		m2db_purge_exceeding_versions(args->sq3, args->url, max_versions);

	if (latest)
		_bean_clean(latest);
	return err;
}

GError* m2db_copy_alias(struct m2db_put_args_s *args, const char *src_path)
{
	struct bean_ALIASES_s *orig = NULL, *target = NULL, *latest = NULL;
	struct oio_url_s *url_orig = NULL, *url_target = NULL;
	GError *err = NULL;

	EXTRA_ASSERT(args != NULL);
	EXTRA_ASSERT(args->sq3 != NULL);
	EXTRA_ASSERT(args->url != NULL);
	EXTRA_ASSERT(src_path != NULL);

	if (!oio_url_has_fq_path(args->url))
		return NEWERROR(CODE_BAD_REQUEST, "Missing path");

	url_target = oio_url_dup(args->url);
	url_orig = oio_url_dup(args->url);
	oio_url_set(url_orig, OIOURL_PATH, src_path);

	/* Load the source bean, not found is an error */
	if (oio_url_has(url_orig, OIOURL_VERSION))
		err = m2db_get_versioned_alias(args->sq3, url_orig, &orig);
	else
		err = m2db_latest_alias(args->sq3, url_orig, &orig);
	if (!err && !orig)
		err = NEWERROR(CODE_CONTENT_NOTFOUND,
					   "Cannot copy content, source doesn't exist");

	gint64 maxver = m2db_get_max_versions(args->sq3, args->ns_max_versions);
	if (!err) {
		gint64 now = oio_ext_real_seconds();
		target = _bean_dup(orig);
		ALIASES_set2_alias(target, oio_url_get(url_target, OIOURL_PATH));
		ALIASES_set_ctime(target, now);
		ALIASES_set_mtime(target, now);
		ALIASES_set_version(target, oio_ext_real_time());
		ALIASES_set_deleted(target, FALSE);
	}

	/* source ok but special management for specific versioning modes */
	if (!err && (VERSIONS_DISABLED(maxver) || VERSIONS_SUSPENDED(maxver))) {
		err = m2db_latest_alias(args->sq3, url_target, &latest);
		if (err && CODE_IS_NOTFOUND(err->code))
			g_clear_error(&err);
		else if (!err && latest)
			err = NEWERROR(CODE_CONTENT_EXISTS, "Destination already exists "
					"(and versioning disabled)");
	}

	/* time to save now! */
	if (!err) {
		GString *tmp = _bean_debug(NULL, target);
		GRID_DEBUG("COPY %s :: %s", oio_url_get(url_orig, OIOURL_WHOLE),
				   tmp->str);
		g_string_free(tmp, TRUE);
		err = _db_save_bean(args->sq3->db, target);
	}

	if (!err && latest && VERSIONS_LIMITED(maxver))
		m2db_purge_exceeding_versions(args->sq3, url_target, maxver);

	oio_url_clean(url_orig);
	oio_url_clean(url_target);
	_bean_clean(target);
	_bean_clean(orig);
	_bean_clean(latest);

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
		return m2db_put_alias(&args, beans, NULL, NULL);
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
	for (GSList *l = newchunks; l; l = l->next) {
		struct bean_CHUNKS_s *chunk = l->data;
		GString *gs = CHUNKS_get_position (chunk);
		struct m2v2_position_s position = m2v2_position_decode (gs->str);
		position.meta += last_position + 1;
		m2v2_position_encode  (gs, &position);
		CHUNKS_set2_content (chunk, g_bytes_get_data(content_id, NULL),
				g_bytes_get_size(content_id));
	}

	g_bytes_unref (content_id);

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

/* Link -------------------------------------------------------------------- */

static GError*
_load_content(struct sqlx_sqlite3_s *sq3, GBytes *content_id,
		struct bean_CONTENTS_HEADERS_s **header)
{
	GPtrArray *tmp = g_ptr_array_new();
	GVariant *params[2] = {NULL, NULL};
	params[0] = _gb_to_gvariant(content_id);
	GError *err = CONTENTS_HEADERS_load(sq3->db, " id = ? LIMIT 1",
			params, _bean_buffer_cb, tmp);
	metautils_gvariant_unrefv(params);
	if (!err) {
		if (tmp->len == 1) {
			if (header)
				*header = g_ptr_array_index(tmp, 0);
			else
				_bean_clean(g_ptr_array_index(tmp, 0));
		} else {
			g_assert(tmp->len == 0);
			err = NEWERROR(CODE_CONTENT_NOTFOUND,
					"no content with such an ID");
		}
	}
	g_ptr_array_free(tmp, TRUE);
	return err;
}

GError*
m2db_link_content(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		GBytes *content_id)
{
	/* check the content exists */
	GError *err = _load_content(sq3, content_id, NULL);
	if (err) {
		g_prefix_error (&err, "Check failed: ");
		goto out;
	}

	/* get the latest alias */
	gint64 version = -1;
	err = m2db_get_alias_version (sq3, url, &version);
	if (err) {
		if (err->code != CODE_CONTENT_NOTFOUND)
			goto out;
		g_clear_error (&err);
	}

	/* TODO manage the case of disabled versioning */

	/* make a new link */
	gint64 now = oio_ext_real_time () / G_TIME_SPAN_SECOND;
	struct bean_ALIASES_s *a = _bean_create (&descr_struct_ALIASES);
	ALIASES_set2_alias (a, oio_url_get(url, OIOURL_PATH));
	size_t len = 0;
	const void *bin = g_bytes_get_data (content_id, &len);
	ALIASES_set2_content (a, bin, len);
	ALIASES_set_version (a, version + 1);
	ALIASES_set_ctime (a, now);
	ALIASES_set_mtime (a, now);
	ALIASES_set_deleted (a, FALSE);
	err = _db_save_bean (sq3->db, a);
	_bean_clean (a);
	if (err)
		g_prefix_error (&err, "Save failed: ");
out:
	return err;
}

/* GENERATOR ---------------------------------------------------------------- */

struct gen_ctx_s
{
	struct oio_url_s *url;
	const struct storage_policy_s *pol;
	struct oio_lb_s *lb;
	guint8 *uid;
	gsize uid_size;
	guint8 h[16];
	gint64 size;
	gint64 chunk_size;
	m2_onbean_cb cb;
	gpointer cb_data;
};

static guint
_policy_parameter(struct storage_policy_s *pol, const gchar *key, guint def)
{
	const char *s;
	if (!pol || !key)
		return def;
	s = data_security_get_param(storage_policy_get_data_security(pol), key);
	if (!s)
		return def;
	return (guint) atoi(s);
}

static void
_m2_generate_alias_header(struct gen_ctx_s *ctx)
{
	const gchar *p;
	p = ctx->pol ? storage_policy_get_name(ctx->pol) : "none";

	GRID_TRACE2("%s(%s)", __FUNCTION__, oio_url_get(ctx->url, OIOURL_WHOLE));
	const gint64 now = oio_ext_real_time ();

	struct bean_ALIASES_s *alias = _bean_create(&descr_struct_ALIASES);
	ALIASES_set2_alias(alias, oio_url_get(ctx->url, OIOURL_PATH));
	ALIASES_set_version(alias, now);
	ALIASES_set_ctime(alias, now / G_TIME_SPAN_SECOND);
	ALIASES_set_mtime(alias, now / G_TIME_SPAN_SECOND);
	ALIASES_set_deleted(alias, FALSE);
	ALIASES_set2_content(alias, ctx->uid, ctx->uid_size);
	ctx->cb(ctx->cb_data, alias);

	struct bean_CONTENTS_HEADERS_s *header;
	header = _bean_create(&descr_struct_CONTENTS_HEADERS);
	CONTENTS_HEADERS_set_size(header, ctx->size);
	CONTENTS_HEADERS_set2_id(header, ctx->uid, ctx->uid_size);
	CONTENTS_HEADERS_set2_policy(header, p);
	CONTENTS_HEADERS_nullify_hash(header);
	CONTENTS_HEADERS_set_ctime(header, now / G_TIME_SPAN_SECOND);
	CONTENTS_HEADERS_set_mtime(header, now / G_TIME_SPAN_SECOND);
	CONTENTS_HEADERS_set2_mime_type(header, OIO_DEFAULT_MIMETYPE);

	GString *chunk_method = storage_policy_to_chunk_method(ctx->pol);
	CONTENTS_HEADERS_set_chunk_method(header, chunk_method);
	g_string_free(chunk_method, TRUE);
	ctx->cb(ctx->cb_data, header);
}

static int
is_stgpol_backblaze(const struct storage_policy_s *pol)
{
	switch(data_security_get_type(storage_policy_get_data_security(pol))) {
		case STGPOL_DS_BACKBLAZE:
			return TRUE;
		default:
			return FALSE;
	}
	return FALSE;
}

static void
_gen_chunk(struct gen_ctx_s *ctx, gchar *straddr,
		gint64 cs, guint pos, gint subpos)
{
	guint8 binid[32];
	gchar *chunkid, strpos[24], strid[65];

	GRID_TRACE2("%s(%s)", __FUNCTION__, oio_url_get(ctx->url, OIOURL_WHOLE));

	oio_buf_randomize (binid, sizeof(binid));
	oio_str_bin2hex (binid, sizeof(binid), strid, sizeof(strid));

	if (subpos < 0)
		g_snprintf(strpos, sizeof(strpos), "%u", pos);
	else
		g_snprintf(strpos, sizeof(strpos), "%u.%d", pos, subpos);

	if (straddr)
		chunkid = m2v2_build_chunk_url (straddr, strid);
	else
		chunkid = m2v2_build_chunk_url_storage (ctx->pol, strid);

	struct bean_CHUNKS_s *chunk = _bean_create(&descr_struct_CHUNKS);
	CHUNKS_set2_id(chunk, chunkid);
	CHUNKS_set2_content(chunk, ctx->uid, ctx->uid_size);
	CHUNKS_set_ctime(chunk, oio_ext_real_time() / G_TIME_SPAN_SECOND);
	CHUNKS_set2_hash(chunk, ctx->h, sizeof(ctx->h));
	CHUNKS_set_size(chunk, cs);
	CHUNKS_set2_position(chunk, strpos);
	ctx->cb(ctx->cb_data, chunk);

	g_free(chunkid);
}

static GError*
_m2_generate_chunks(struct gen_ctx_s *ctx,
		gint64 mcs /* actual metachunk size */,
		gboolean subpos)
{
	GError *err = NULL;

	GRID_TRACE2("%s(%s)", __FUNCTION__, oio_url_get(ctx->url, OIOURL_WHOLE));

	_m2_generate_alias_header(ctx);

	guint pos = 0;
	gint64 esize = MAX(ctx->size, 1);
	for (gint64 s = 0; s < esize && !err; s += mcs, ++pos) {
		GPtrArray *ids = g_ptr_array_new_with_free_func(g_free);
		void _on_id(oio_location_t loc, const char *id)
		{
			(void)loc;
			char *shifted = g_strdup(id);
			meta1_url_shift_addr(shifted);
			g_ptr_array_add(ids, shifted);
		}
		const char *pool = storage_policy_get_service_pool(ctx->pol);
		// FIXME(FVE): set last argument
		if ((err = oio_lb__poll_pool(ctx->lb, pool, NULL, _on_id, NULL))) {
			g_prefix_error(&err, "at position %u: "
					"found only %u services matching the criteria (pool=%s): ",
					pos, ids->len, pool);
		} else {
			if (is_stgpol_backblaze(ctx->pol)) {
				// Shortcut for backblaze
				_gen_chunk(ctx, NULL, ctx->chunk_size, pos, -1);
			} else {
				for (int i = 0; i < (int)ids->len; i++)
					_gen_chunk(ctx, g_ptr_array_index(ids, i),
							ctx->chunk_size, pos, subpos? i : -1);
			}
		}
		g_ptr_array_free(ids, TRUE);
	}

	return err;
}

GError*
m2_generate_beans(struct oio_url_s *url, gint64 size, gint64 chunk_size,
		struct storage_policy_s *pol, struct oio_lb_s *lb,
		m2_onbean_cb cb, gpointer cb_data)
{
	GRID_TRACE2("%s(%s)", __FUNCTION__, oio_url_get(url, OIOURL_WHOLE));
	EXTRA_ASSERT(url != NULL);

	if (!oio_url_has(url, OIOURL_PATH))
		return NEWERROR(CODE_BAD_REQUEST, "Missing path");
	if (size < 0)
		return NEWERROR(CODE_BAD_REQUEST, "Invalid size");
	if (chunk_size <= 0)
		return NEWERROR(CODE_BAD_REQUEST, "Invalid chunk size");

	RANDOM_UID(uid, uid_size);
	struct gen_ctx_s ctx;
	memset(&ctx, 0, sizeof(ctx));

	ctx.url = url;
	ctx.pol = pol;
	ctx.uid = (guint8*) &uid;
	ctx.uid_size = uid_size;
	ctx.size = size;
	ctx.chunk_size = chunk_size;
	ctx.cb = cb;
	ctx.cb_data = cb_data;
	ctx.lb = lb;

	if (!pol)
		return _m2_generate_chunks(&ctx, chunk_size, 0);

	gint64 k;
	switch (data_security_get_type(storage_policy_get_data_security(pol))) {
		case STGPOL_DS_BACKBLAZE:
		case STGPOL_DS_PLAIN:
			return _m2_generate_chunks(&ctx, chunk_size, 0);
		case STGPOL_DS_EC:
			k = _policy_parameter(pol, DS_KEY_K, 6);
			return _m2_generate_chunks(&ctx, k*chunk_size, TRUE);
		default:
			return NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid policy type");
	}
}

enum _content_broken_state_e
{
	NONE,
	REPARABLE,
	IRREPARABLE
};

struct _check_content_s
{
	gint64 size;
	gint last_pos;
	GString *present_chunks;
	GString *missing_pos;
	guint nb_copy;
	gint k;
	gint m;
	enum _content_broken_state_e ecb;
	gboolean partial;
};

static void
_prepare_message(struct _check_content_s *content, GString *message)
{
	g_string_append(message, "\"present_chunks\":[");
	g_string_append(message, content->present_chunks->str);
	g_string_append(message, "], \"missing_chunks\":[");
	g_string_append(message, content->missing_pos->str);
	g_string_append_c(message, ']');
	g_string_free(content->missing_pos, TRUE);
	g_string_free(content->present_chunks, TRUE);
}

static gboolean
_check_metachunk_number(GSList *beans, struct _check_content_s *ec)
{

	gint last_pos = 0;
	gint i = 0;
	meta2_json_chunks_only(ec->present_chunks, beans, FALSE);

	for (GSList *l = beans; l; l = l->next) {
		i++;
		gpointer bean = l->data;
		if (DESCR(bean) != &descr_struct_CHUNKS) {
			ec->ecb = IRREPARABLE;
			return TRUE;
		}

		GString *gs = CHUNKS_get_position(bean);
		char *subpos = g_strrstr(gs->str, ".");
		if (subpos != NULL) {
			subpos++;
		} else {
			ec->ecb = IRREPARABLE;
			return TRUE;
		}

		gint64 p = g_ascii_strtoll(subpos, NULL, 10);
		for (; last_pos < p - 1; last_pos++) {
			oio_str_gstring_append_json_string(ec->missing_pos,
					CHUNKS_get_position(bean)->str);
		}

		last_pos++;
		ec->size += CHUNKS_get_size(bean);
	}

	if (i < ec->k || i > ec->k + ec->m) {
		ec->ecb = IRREPARABLE;
		return TRUE;
	} else if (i >= ec->k && i < ec->k + ec->m) {
		ec->ecb = REPARABLE;
	}

	return FALSE;
}

static gboolean
_foreach_check_plain_content(gpointer key, gpointer value, gpointer data)
{
	struct _check_content_s *content = data;
	if (content->last_pos != GPOINTER_TO_INT(key) - 1 && content->last_pos != -1
			&& !content->partial) {
		content->ecb = IRREPARABLE;
		return TRUE;
	}

	content->last_pos = GPOINTER_TO_INT(key);
	guint nb_chunks = 0;
	meta2_json_chunks_only (content->present_chunks, value, FALSE);
	for (GSList *l = value; l; l = l->next) {
		content->size += CHUNKS_get_size(l->data);
		nb_chunks++;
	}

	if (content->nb_copy > nb_chunks) {
		for (guint i = nb_chunks; i < content->nb_copy; i++) {
			if (content->missing_pos->len)
				g_string_append(content->missing_pos, ",");
			oio_str_gstring_append_json_string(content->missing_pos,
					CHUNKS_get_position(((GSList *)value)->data)->str);
		}
		content->ecb = REPARABLE;
	}

	return FALSE;
}

static gboolean
_foreach_check_ec_content(gpointer key, gpointer value, gpointer data)
{
	struct _check_content_s *content = data;
	if (content->last_pos != GPOINTER_TO_INT(key) - 1 && content->last_pos != -1
		&& !content->partial) {
		content->ecb = IRREPARABLE;
		return TRUE;
	}

	content->last_pos = GPOINTER_TO_INT(key);
	return _check_metachunk_number(value, content);
}

static enum _content_broken_state_e
_check_plain_content(struct _sorted_content_s *content,
		const struct data_security_s *dsec, GString *message, gboolean partial)
{
	gint nb_copy = data_security_get_int64_param(dsec, DS_KEY_COPY_COUNT, 1);
	if (!content->header)
		return IRREPARABLE;

	gint64 size =  CONTENTS_HEADERS_get_size(content->header);
	struct _check_content_s cp = {
		.size = 0,
		.last_pos = -1,
		.missing_pos = g_string_new(""),
		.present_chunks = g_string_new(""),
		.nb_copy = nb_copy,
		.partial = partial,
	};

	g_tree_foreach(content->metachunks, _foreach_check_plain_content, &cp);
	_prepare_message(&cp, message);
	/*If the size of all the chunks is inferior to the size indicate in the header
	 *it means that some missing chunks could not be detected and so irreparable */
	if (cp.size < size * nb_copy && cp.ecb == NONE && !cp.partial)
		cp.ecb = IRREPARABLE;

	return cp.ecb;
}

static enum _content_broken_state_e
_check_ec_content(struct _sorted_content_s *content,
		struct storage_policy_s *pol, GString *message, gboolean partial)
{
	if (!content->header)
		return IRREPARABLE;

	gint size = CONTENTS_HEADERS_get_size(content->header);
	struct _check_content_s cec = {
		.size = 0,
		.last_pos = -1,
		.present_chunks = g_string_new(""),
		.missing_pos = g_string_new(""),
		.k = _policy_parameter(pol, DS_KEY_K, 6),
		.m = _policy_parameter(pol, DS_KEY_M, 3),
		.partial = partial,
	};

	g_tree_foreach(content->metachunks, _foreach_check_ec_content, &cec);
	_prepare_message(&cec, message);
	/* Check if the size is at least superior to the minimum necessary to
	 * size needed by the storage policy*/
	if (cec.size < size * (cec.k + cec.m) / cec.k && cec.ecb == NONE
			&& !cec.partial)
		return IRREPARABLE;

	return cec.ecb;
}

static gboolean
_foreach_free_list(gpointer key, gpointer value, gpointer data){
	(void) data;
	(void) key;
	if (value)
		g_slist_free((GSList *)value);
	return FALSE;
}

GError *m2db_check_content(GSList *beans, struct namespace_info_s *nsinfo,
		GString *message, gboolean partial)
{
	GError *err = NULL;
	struct _sorted_content_s sorted_content = {
		.header = NULL,
		.aliases = NULL,
		.properties = NULL,
		.metachunks = g_tree_new(_tree_compare_int),
	};

	struct storage_policy_s *pol = NULL;
	GString *polname = NULL;
	for (GSList *l = beans; l; l = l->next) {
		gpointer bean = l->data;
		_sort_content_cb(&sorted_content, bean);
		if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
			polname = CONTENTS_HEADERS_get_policy(bean);
		}
	}

	if (polname && polname->str && polname->len)
		pol = storage_policy_init(nsinfo, polname->str);

	enum _content_broken_state_e  cbroken = NONE;
	const struct data_security_s *dsec = storage_policy_get_data_security(pol);
	switch (data_security_get_type(dsec)) {
		case STGPOL_DS_BACKBLAZE:
		case STGPOL_DS_PLAIN:
			cbroken = _check_plain_content(&sorted_content, dsec, message, partial);
			break;
		case STGPOL_DS_EC:
			cbroken = _check_ec_content(&sorted_content, pol, message, partial);
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

	if (sorted_content.aliases)
		g_slist_free(sorted_content.aliases);
	if (sorted_content.properties)
		g_slist_free(sorted_content.properties);

	g_tree_foreach(sorted_content.metachunks, _foreach_free_list, NULL);
	g_tree_destroy(sorted_content.metachunks);
	if(pol)
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
		{SQLX_ADMIN_USERTYPE, OIOURL_TYPE},
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
		m2_onbean_cb cb, gpointer u0)
{
	struct elt_s {
		gchar *alias;
		gint64 count;
	};

	GRID_TRACE("%s, max_versions = %"G_GINT64_FORMAT, __FUNCTION__, max_versions);

	const gchar *sql_lookup = "SELECT alias, count(*)"
		"FROM aliases "
		"WHERE NOT deleted " // Do not count last extra deleted version
		"GROUP BY alias "
		"HAVING COUNT(*) > ?";
	const gchar *sql_delete = " rowid IN "
		"(SELECT rowid FROM aliases WHERE alias = ? "
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
	sqlite3_bind_int64(stmt, 1, max_versions);
	while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
		struct elt_s *elt = g_malloc0(sizeof(*elt));
		elt->alias = g_strdup((gchar*)sqlite3_column_text(stmt, 0));
		elt->count = sqlite3_column_int64(stmt, 1);
		to_be_deleted = g_slist_prepend(to_be_deleted, elt);
	}
	(void) sqlite3_finalize(stmt);

	GRID_DEBUG("Nb alias to drop: %d", g_slist_length(to_be_deleted));

	// Delete the alias bean and send it to callback
	void _delete_cb(gpointer udata, struct bean_ALIASES_s *alias)
	{
		GError *local_err = _db_delete_bean(sq3->db, alias);
		if (!local_err) {
			cb(udata, alias); // alias is cleaned by callback
		} else {
			GRID_WARN("Failed to drop %s (v%"G_GINT64_FORMAT"): %s",
					ALIASES_get_alias(alias)->str,
					ALIASES_get_version(alias),
					local_err->message);
			_bean_clean(alias);
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

static void m2v2_dup_alias(struct dup_alias_params_s *params, gpointer bean);

static GError*
_purge_deleted_aliases(struct sqlx_sqlite3_s *sq3, gint64 delay,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	gchar *sql, *sql2;
	GSList *old_deleted = NULL;
	GVariant *params[] = {NULL, NULL};
	gint64 now = oio_ext_real_time () / G_TIME_SPAN_SECOND;
	gint64 time_limit = 0;
	struct dup_alias_params_s dup_params;

	// All aliases which have one version deleted (the last) older than time_limit
	sql = (" alias IN "
			"(SELECT alias FROM "
			"  (SELECT alias,ctime,deleted FROM aliases GROUP BY alias) "
			" WHERE deleted AND ctime < ?) ");

	// Last snapshoted aliases part of deleted contents.
	// (take some paracetamol)
	sql2 = (" rowid IN (SELECT a1.rowid FROM aliases AS a1"
			" INNER JOIN "
			"(SELECT alias,max(deleted) as mdel FROM aliases GROUP BY alias) AS a2 "
			"ON a1.alias = a2.alias "
			"WHERE mdel "
			"GROUP BY a1.alias HAVING max(version)) ");

	if (now < 0) {
		err = g_error_new(GQ(), CODE_INTERNAL_ERROR,
				"Cannot get current time: %s", g_strerror(errno));
		return err;
	}

	if (delay >= 0 && delay < now) {
		time_limit = now - delay;
	}

	// We need to copy/delete snapshoted aliases that used to appear deleted
	// thanks to a more recent alias which will be erased soon.
	// Build the list.
	void _load_old_deleted(gpointer u, gpointer bean) {
		(void) u;
		old_deleted = g_slist_prepend(old_deleted, bean);
	}
	ALIASES_load(sq3->db, sql2, params, _load_old_deleted, NULL);

	// Delete the alias bean and send it to callback
	void _delete_cb(gpointer udata, struct bean_ALIASES_s *alias)
	{
		GError *local_err = _db_delete_bean(sq3->db, alias);
		if (!local_err) {
			cb(udata, alias); // alias is cleaned by callback
		} else {
			GRID_WARN("Failed to drop %s (v%"G_GINT64_FORMAT"): %s",
					ALIASES_get_alias(alias)->str,
					ALIASES_get_version(alias),
					local_err->message);
			_bean_clean(alias);
			g_clear_error(&local_err);
		}
	}

	// Do the purge.
	GRID_DEBUG("Purging deleted aliases older than %"G_GINT64_FORMAT" seconds (timestamp < %"G_GINT64_FORMAT")",
			delay, time_limit);
	params[0] = g_variant_new_int64(time_limit);
	err = ALIASES_load(sq3->db, sql, params, (m2_onbean_cb)_delete_cb, u0);
	metautils_gvariant_unrefv(params);

	// Re-delete what needs to.
	memset(&dup_params, 0, sizeof(struct dup_alias_params_s));
	dup_params.sq3 = sq3;
	dup_params.set_deleted = TRUE;
	dup_params.c_version = m2db_get_version(sq3);
	for (GSList *l = old_deleted; l != NULL; l = l->next) {
		if (!ALIASES_get_deleted(l->data)) {
			if (GRID_TRACE_ENABLED()) {
				GRID_TRACE("Copy/delete %s version %"G_GINT64_FORMAT,
					ALIASES_get_alias(l->data)->str,
					ALIASES_get_version(l->data));
			}
			m2v2_dup_alias(&dup_params, l->data); // also cleans l->data
		} else {
			_bean_clean(l->data);
		}
	}
	g_slist_free(old_deleted);
	if (dup_params.errors != NULL) {
		if (err == NULL) {
			err = NEWERROR(0,
				"Got at least one error while purging aliases, see meta2 logs");
		}
		for (GSList *l = dup_params.errors; l; l = l->next) {
			GRID_WARN("Alias purge error: %s", ((GError*)l->data)->message);
			g_clear_error((GError**)&l->data);
		}
		g_slist_free(dup_params.errors);
	}

	return err;
}

GError*
m2db_purge(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		gint64 retention_delay)
{
	GPtrArray *tmp = g_ptr_array_new ();

	GError *err;
	if ((err = _purge_exceeding_aliases(sq3, max_versions, _bean_buffer_cb, tmp))) {
		GRID_WARN("Failed to purge ALIASES: (code=%d) %s",
				err->code, err->message);
		g_clear_error(&err);
	}

	if (retention_delay >= 0) {
		if ((err = _purge_deleted_aliases(sq3, retention_delay, _bean_buffer_cb, tmp))) {
			GRID_WARN("Failed to purge deleted ALIASES: (code=%d) %s",
					err->code, err->message);
			g_clear_error(&err);
		}
	}

	/* purge unreferenced properties */
	sqlx_exec(sq3->db, "DELETE FROM properties WHERE NOT EXISTS "
			"(SELECT alias FROM aliases "
			" WHERE aliases.alias = properties.alias)");

	/* purge unreferenced content_headers, cascading to contents */
	sqlx_exec(sq3->db, "DELETE FROM chunks WHERE NOT EXISTS "
			"(SELECT content FROM aliases WHERE aliases.content = chunks.content)");

	guint64 size = 0u;
	gint64 obj_count = 0;
	m2db_get_container_size_and_obj_count(sq3->db, FALSE, &size, &obj_count);
	m2db_set_size(sq3, (gint64)size);
	m2db_set_obj_count(sq3, obj_count);

	/* TODO(jfs): send the beans to the event-agent */
	_bean_cleanv2 (tmp);
	return NULL;
}

GError*
m2db_deduplicate_contents(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url)
{
	GError *err = NULL;
	GSList *impacted_aliases = NULL;
	guint64 size_before = 0u;
	m2db_get_container_size_and_obj_count(sq3->db, TRUE, &size_before, NULL);
	guint64 saved_space = dedup_aliases(sq3->db, url, &impacted_aliases, &err);
	guint64 size_after = 0u;
	m2db_get_container_size_and_obj_count(sq3->db, TRUE, &size_after, NULL);

	GRID_INFO("DEDUP [%s]"
			"%"G_GUINT64_FORMAT" bytes saved "
			"by deduplication of %u contents "
			"(%"G_GUINT64_FORMAT" -> %"G_GUINT64_FORMAT" bytes)",
			oio_url_get (url, OIOURL_WHOLE),
			saved_space, g_slist_length(impacted_aliases),
			size_before, size_after);

	g_slist_free_full(impacted_aliases, g_free);
	return err;
}

GError*
m2db_flush_container(sqlite3 *db)
{
	int rc = sqlx_exec(db, "DELETE FROM aliases");
	if (SQLITE_OK == rc) return NULL;
	return SQLITE_GERROR(db, rc);
}

static void
m2v2_dup_alias(struct dup_alias_params_s *params, gpointer bean)
{
	GError *local_err = NULL;
	if (DESCR(bean) == &descr_struct_ALIASES) {
		struct bean_ALIASES_s *new_alias = _bean_dup(bean);
		gint64 latest_version = ALIASES_get_version(bean);
		/* If source container version specified, we may not be duplicating
		 * latest version of each alias, so we must find it. */
		if (params->src_c_version >= 1) {
			struct oio_url_s *url = oio_url_empty();
			oio_url_set(url, OIOURL_PATH, ALIASES_get_alias(new_alias)->str);
			local_err = m2db_get_alias_version(params->sq3, url, &latest_version);
			if (local_err != NULL) {
				GRID_WARN("Failed to get latest alias version for '%s'",
						ALIASES_get_alias(new_alias)->str);
				g_clear_error(&local_err);
				_bean_clean(new_alias);
				new_alias = NULL;
			}
			oio_url_clean(url);
		}
		if (local_err == NULL) {
			ALIASES_set_version(new_alias,
					(!params->overwrite_latest) + latest_version);
			if (params->set_deleted) {
				ALIASES_set_deleted(new_alias, TRUE);
			}
			local_err = ALIASES_save(params->sq3->db, new_alias);
		}
		_bean_clean(new_alias);
	}
	_bean_clean(bean); // TODO: add parameter to disable cleaning
	if (local_err != NULL) {
		params->errors = g_slist_prepend(params->errors, local_err);
	}
}

