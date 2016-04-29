/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/meta2_dedup_utils.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>

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

#define FORMAT_ERROR(v,s,e) (!(v) && errno == EINVAL)
#define RANGE_ERROR(v) ((v) == G_MININT64 || (v) == G_MAXINT64)
#define STRTOLL_ERROR(v,s,e) (FORMAT_ERROR(v,s,e) || RANGE_ERROR(v))

gchar*
m2v2_build_chunk_url (const char *srv, const char *id)
{
	return g_strconcat("http://", srv, "/", id, NULL);
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

guint64
m2db_get_container_size(sqlite3 *db, gboolean check_alias)
{
	guint64 size = 0;
	gchar tmp[512];
	g_snprintf(tmp, sizeof(tmp), "%s%s", "SELECT SUM(size) FROM contents",
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
			}
			if (rc != SQLITE_OK && rc != SQLITE_DONE) {
				grc = rc;
			}
			rc = sqlite3_finalize(stmt);
		}

		stmt = NULL;
	}
	return size;
}

/**
 * @return The namespace name defined in the admin table. Must be freed.
 */
gchar *
m2db_get_namespace(struct sqlx_sqlite3_s *sq3, const gchar *def)
{
	gchar *ns = sqlx_admin_get_str(sq3, SQLX_ADMIN_NAMESPACE);
	if (!ns)
		return def? g_strdup(def) : NULL;
	return ns;
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

void
m2db_set_keep_deleted_delay(struct sqlx_sqlite3_s *sq3, gint64 delay)
{
	sqlx_admin_set_i64(sq3, M2V2_ADMIN_KEEP_DELETED_DELAY, delay);
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

void
m2db_set_quota(struct sqlx_sqlite3_s *sq3, gint64 quota)
{
	sqlx_admin_set_i64(sq3, M2V2_ADMIN_QUOTA, quota);
}

/* GET ---------------------------------------------------------------------- */

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
		return NEWERROR(CODE_BAD_REQUEST, "Missing path and content");

	GRID_TRACE("GET(%s)", oio_url_get(u, OIOURL_WHOLE));

	/* query, and nevermind the snapshot */
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
				params[1] = g_variant_new_int64(atoi(oio_url_get(u, OIOURL_VERSION)));
			} else {
				sql = "alias = ? ORDER BY version DESC LIMIT 1";
			}
		}
	} else {

		do { /* get the content-id in its binary form */
			/* XXX TODO this code is multiplicated, there is room for factorisation */
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
				params[1] = g_variant_new_int64(atoi(oio_url_get(u, OIOURL_VERSION)));
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
	if (!err && cb && ((flags & M2V2_FLAG_HEADERS) || !(flags & M2V2_FLAG_NORECURSION))) {
		for (guint i=0; !err && i<tmp->len ;i++) {
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
		for (guint i=0; !err && i<tmp->len ;i++) {
			struct bean_ALIASES_s *alias = tmp->pdata[i];
			if (!alias)
				continue;
			GPtrArray *props = g_ptr_array_new();
			err = _db_get_FK_by_name_buffered(alias, "properties", sq3->db, props);
			if (!err) {
				for (guint j=0; j<props->len ;++j) {
					cb(u0, props->pdata[j]);
					props->pdata[j] = NULL;
				}
			}
			_bean_cleanv2 (props);
		}
	}

	/* eventually manage the aliases */
	if (!err && cb) {
		for (guint i=0; i<tmp->len ;i++) {
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

	flags &= ~(M2V2_FLAG_HEADERS|M2V2_FLAG_NOFORMATCHECK); // meaningless
	flags |=  (M2V2_FLAG_NOPROPS|M2V2_FLAG_NORECURSION);   // only alias

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
		if (clause->len > 0) g_string_append(clause, " AND");
	}
	GPtrArray *params = g_ptr_array_new ();

	if (lp->marker_start) {
		lazy_and();
		g_string_append (clause, " alias > ?");
		g_ptr_array_add (params, g_variant_new_string (lp->marker_start));
	} else if (lp->prefix) {
		lazy_and();
		g_string_append (clause, " alias >= ?");
		g_ptr_array_add (params, g_variant_new_string (lp->prefix));
	}

	if (lp->marker_end) {
		lazy_and();
		g_string_append (clause, " alias < ?");
		g_ptr_array_add (params, g_variant_new_string (lp->marker_end));
	}

	if (headers) {
		lazy_and();
		if (headers->next) {
			g_string_append (clause, " content_id IN (");
			for (GSList *l=headers; l ;l=l->next) {
				if (l != headers)
					g_string_append_c (clause, ',');
				g_string_append_c (clause, '?');
				GByteArray *gba = CONTENTS_HEADERS_get_id (l->data);
				g_ptr_array_add (params, _gba_to_gvariant (gba));
			}
			g_string_append (clause, ")");
		} else {
			g_string_append (clause, " content_id = ?");
			GByteArray *gba = CONTENTS_HEADERS_get_id (headers->data);
			g_ptr_array_add (params, _gba_to_gvariant (gba));
		}
	}

	if (clause->len == 0)
		clause = g_string_append(clause, " 1");

	if (!lp->flag_allversion || lp->maxkeys>0 || lp->marker_start || lp->marker_end)
		g_string_append(clause, " ORDER BY alias ASC, version ASC");

	if (lp->maxkeys > 0)
		g_string_append_printf(clause, " LIMIT %"G_GINT64_FORMAT, lp->maxkeys);

	g_ptr_array_add (params, NULL);
	return (GVariant**) g_ptr_array_free (params, FALSE);
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
		GString *clause = g_string_new("");
		GVariant **params = _list_params_to_sql_clause (&lp, clause, headers);
		err = ALIASES_load(sq3->db, clause->str, params, _bean_buffer_cb, tmp);
		metautils_gvariant_unrefv (params);
		g_free (params), params = NULL;
		g_string_free (clause, TRUE);
		if (err) { cleanup (); goto label_error; }
		if (!tmp->len) { cleanup (); goto label_ok; }

		metautils_gpa_reverse (tmp);

		for (guint i=tmp->len; i>0 ;i--) {
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
	aliases = g_slist_reverse (aliases);
	for (GSList *l=aliases; l ;l=l->next) {
		struct bean_ALIASES_s *alias = l->data;
		if (lp.flag_headers) {
			GPtrArray *t0 = g_ptr_array_new();
			GError *e = _db_get_FK_by_name_buffered(alias, "image", sq3->db, t0);
			if (e) {
				GRID_DEBUG("No header for [%s] : (%d) %s",
						ALIASES_get_alias(alias)->str,
						err->code, err->message);
				g_clear_error (&e);
			}
			for (guint i=0; i<t0->len ;i++)
				cb(u, t0->pdata[i]);
			g_ptr_array_free (t0, TRUE);
		}
		cb(u, alias);
		l->data = NULL;
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
		for (guint i=0; i<tmp->len; ++i)
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

	for (; !err && beans ;beans=beans->next) {
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
		for (guint i=0; !err && i<tmp->len ;++i) {
			struct bean_PROPERTIES_s *bean = tmp->pdata[i];
			if (DESCR(bean) != &descr_struct_PROPERTIES)
				continue;
			if (namev && *namev) {
				/* explicit properties to be deleted */
				for (gchar **p=namev; *p ;++p) {
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
	for (GSList *l = beans; !err && l ;l=l->next) {
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
		for (GSList *l = beans; !err && l ;l=l->next) {
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
	for (GSList *l = deleted; l ;l=l->next) {
		if (DESCR(l->data) != &descr_struct_ALIASES || !ALIASES_get_deleted(l->data))
			*deleted_beans = g_slist_prepend (*deleted_beans, l->data);
		GError *e = _db_delete_bean(sq3->db, l->data);
		if (e != NULL) {
			GRID_WARN("Bean delete failed: (%d) %s", e->code, e->message);
			g_clear_error(&e);
		}
	}

	// recompute container size
	for (GSList *l = deleted; l ;l=l->next) {
		if (&descr_struct_CONTENTS_HEADERS == DESCR(l->data)) {
			gint64 decrement = CONTENTS_HEADERS_get_size(l->data);
			gint64 size = m2db_get_size(sq3) - decrement;
			m2db_set_size(sq3, size);
			GRID_DEBUG("CONTAINER size = %"G_GINT64_FORMAT
					" (lost %"G_GINT64_FORMAT")", size, decrement);
		}
	}

	g_slist_free(deleted);
	deleted = NULL;
	return NULL;
}

GError*
m2db_delete_alias(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		struct oio_url_s *url, m2_onbean_cb cb, gpointer u0)
{
	GError *err;
	struct bean_ALIASES_s *alias = NULL;
	GSList *beans = NULL;

	void _search_alias_and_size(gpointer ignored, gpointer bean) {
		(void) ignored;
		if (DESCR(bean) == &descr_struct_ALIASES)
			alias = _bean_dup(bean);
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

		GRID_TRACE("deleting now");

		GSList *deleted_beans = NULL;
		err = _real_delete(sq3, beans, &deleted_beans);
		/* Client asked to remove no-more referenced beans, we tell him which */
		for (GSList *bean = deleted_beans; bean; bean = bean->next) {
			if (cb)
				cb(u0, _bean_dup(bean->data));
		}
		// XXX deleted_beans's contents are direct pointers to the original beans.
		g_slist_free(deleted_beans);

		// sqliterepo might disable foreign keys management, so that we have
		// to manage this by ourselves.
		if (!err)
			err = _db_del_FK_by_name (alias, "properties", sq3->db);

	} else if (oio_url_has(url, OIOURL_VERSION)) {
		/* Alias is in a snapshot but user explicitly asked for its deletion */
		err = NEWERROR(CODE_NOT_ALLOWED,
				"Cannot delete a content belonging to a snapshot");
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

/* PUT commons -------------------------------------------------------------- */

struct put_args_s
{
	struct m2db_put_args_s *put_args;

	guint8 *uid;
	gsize uid_size;

	gint64 version;
	gint64 count_version;

	m2_onbean_cb cb;
	gpointer cb_data;

	GSList *beans;
	gboolean merge_only;
};

#define lazy_set_str(T,B,F,V) do { \
	GString *gs = T##_get_##F(B); \
	if (!gs || !gs->str || !gs->len) T##_set2_##F(B,V); \
} while (0)

static GError*
m2db_real_put_alias(struct sqlx_sqlite3_s *sq3, struct put_args_s *args)
{
	gint64 now = oio_ext_real_time() / G_TIME_SPAN_SECOND;

	/* patch the beans */
	for (GSList *l=args->beans; l ;l=l->next) {
		gpointer bean = l->data;
		if (!l->data)
			continue;

		if (DESCR(bean) == &descr_struct_ALIASES) {
			if (args->merge_only)
				continue;
			if (0 >= ALIASES_get_version (bean))
				ALIASES_set_version(bean, args->version+1);
			ALIASES_set2_content(bean, args->uid, args->uid_size);
			ALIASES_set_deleted(bean, FALSE);
			ALIASES_set_ctime(bean, now);
			ALIASES_set_mtime(bean, now);
		}
		else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
			if (args->merge_only)
				continue;
			CONTENTS_HEADERS_set2_id(bean, args->uid, args->uid_size);
			CONTENTS_HEADERS_set_ctime(bean, now);
			CONTENTS_HEADERS_set_mtime(bean, now);
			lazy_set_str (CONTENTS_HEADERS, bean, chunk_method, OIO_DEFAULT_CHUNKMETHOD);
			lazy_set_str (CONTENTS_HEADERS, bean, mime_type, OIO_DEFAULT_MIMETYPE);
			lazy_set_str (CONTENTS_HEADERS, bean, policy, OIO_DEFAULT_STGPOL);
		}
		else if (DESCR(bean) == &descr_struct_CHUNKS) {
			CHUNKS_set2_content(bean, args->uid, args->uid_size);
			CHUNKS_set_ctime(bean, now);
		}
		else if (DESCR(bean) == &descr_struct_PROPERTIES) {
			PROPERTIES_set_version (bean, args->version+1);
		}
	}

	/* now save them */
	GError *err = NULL;
	for (GSList *l=args->beans; !err && l ;l=l->next)
		err = _db_save_bean(sq3->db, l->data);
	if (!err && args->cb) {
		for (GSList *l=args->beans; l ;l=l->next)
			args->cb(args->cb_data, _bean_dup(l->data));
	}
	return err;
}

/* PUT ---------------------------------------------------------------------- */

static gint64
_patch_content_stgpol (struct m2db_put_args_s *args, GSList *beans)
{
	gchar policy[256];
	gint64 size = 0;

	EXTRA_ASSERT(args != NULL);

	/* ensure a storage policy and store the result */
	for (GSList *l=beans; l ;l=l->next) {
		gpointer bean;
		if (!(bean = l->data))
			continue;
		if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
			size = CONTENTS_HEADERS_get_size(bean);
			GString *spol = CONTENTS_HEADERS_get_policy(bean);
			if (!spol || spol->len <= 0) {
				struct storage_policy_s *pol = NULL;
				GError *err;

				/* force the policy to the default policy of the container
				 * or namespace */
				err = _get_container_policy(args->sq3, args->nsinfo, &pol);
				CONTENTS_HEADERS_set2_policy(bean,
						(!err && pol) ? storage_policy_get_name(pol) : "none");
				if (pol)
					storage_policy_clean(pol);
				if (err)
					g_clear_error(&err);
			}

			g_strlcpy(policy, CONTENTS_HEADERS_get_policy(bean)->str,
					sizeof(policy));
		}
	}

	return size;
}

GError*
m2db_force_alias(struct m2db_put_args_s *args, GSList *beans,
		GSList **out_deleted, GSList **out_added)
{
	struct put_args_s args2;
	struct bean_ALIASES_s *latest = NULL;
	GError *err = NULL;

	EXTRA_ASSERT(args != NULL);
	EXTRA_ASSERT(args->sq3 != NULL);
	EXTRA_ASSERT(args->url != NULL);
	if (!oio_url_has(args->url, OIOURL_PATH))
		return NEWERROR(CODE_BAD_REQUEST, "Missing path");

	/* TODO(jfs): return the beans added/deleted */
	(void) out_deleted, (void) out_added;

	memset(&args2, 0, sizeof(args2));
	args2.beans = beans;

	gint64 size = _patch_content_stgpol (args, beans);

	if (oio_url_has(args->url, OIOURL_VERSION)) {
		const char *tmp = oio_url_get(args->url, OIOURL_VERSION);
		args2.version = g_ascii_strtoll(tmp, NULL, 10);
		err = m2db_get_versioned_alias(args->sq3, args->url, &latest);
	} else {
		err = m2db_latest_alias(args->sq3, args->url, &latest);
	}

	if (NULL != err) {
		if (err->code != CODE_CONTENT_NOTFOUND)
			g_prefix_error(&err, "Version error: ");
		else {
			g_clear_error(&err);
			RANDOM_UID(uid, uid_size);
			args2.uid = (guint8*) &uid;
			args2.uid_size = uid_size;
			err = m2db_real_put_alias(args->sq3, &args2);
		}
	}
	else {
		if (latest) {
			GByteArray *gba = ALIASES_get_content (latest);
			args2.merge_only = TRUE;
			args2.uid = gba->data;
			args2.uid_size = gba->len;
		} else {
			RANDOM_UID(uid, uid_size);
			args2.uid = (guint8*) &uid;
			args2.uid_size = uid_size;
		}
		err = m2db_real_put_alias(args->sq3, &args2);
	}

	if(!err)
       m2db_set_size(args->sq3, m2db_get_size(args->sq3) + size);

	if (latest)
		_bean_clean(latest);

	return err;
}

GError*
m2db_put_alias(struct m2db_put_args_s *args, GSList *beans,
		GSList **out_deleted, GSList **out_added)
{
	struct bean_ALIASES_s *latest = NULL;
	GError *err = NULL;
	gboolean purge_latest = FALSE;

	EXTRA_ASSERT(args != NULL);
	EXTRA_ASSERT(args->sq3 != NULL);
	EXTRA_ASSERT(args->url != NULL);
	if (!oio_url_has(args->url, OIOURL_PATH))
		return NEWERROR(CODE_BAD_REQUEST, "Missing path");

	RANDOM_UID(uid, uid_size);
	struct put_args_s args2;

	memset(&args2, 0, sizeof(args2));
	args2.put_args = args;
	if (oio_url_has (args->url, OIOURL_CONTENTID)) {
		const char *h = oio_url_get (args->url, OIOURL_CONTENTID);
		gsize hl = strlen(h);
		guint8 *b = g_alloca (hl/2);
		if (oio_str_hex2bin(h, b, hl/02)) {
			args2.uid = b;
			args2.uid_size = hl/2;
		} else {
			return BADREQ("Invalid content ID (not hexa)");
		}
	} else {
		args2.uid = (guint8*) &uid;
		args2.uid_size = uid_size;
	}
	args2.cb = out_added ? _bean_list_cb : NULL;
	args2.cb_data = out_added;
	args2.beans = beans;
	args2.version = -1;

	/* a specific content ID has been provided. We DO NOT allow overriding
	 * a content with the same ID. So let's check the content is not present,
	 * yet */
	if (oio_url_has(args->url, OIOURL_CONTENTID)) {
		GPtrArray *tmp = g_ptr_array_new ();
		GVariant *params[2] = {NULL, NULL};
		GBytes *id = g_bytes_new (args2.uid, args2.uid_size);
		params[0] = _gb_to_gvariant (id);
		err = CONTENTS_HEADERS_load (args->sq3->db, " id = ? LIMIT 1", params,
				_bean_buffer_cb, tmp);
		metautils_gvariant_unrefv(params);
		guint count = tmp->len;
		_bean_cleanv2 (tmp);
		g_bytes_unref (id);
		if (err)
			return err;
		if (count)
			return NEWERROR(CODE_CONTENT_EXISTS, "A content exists with this ID");
	}

	if (NULL != (err = m2db_latest_alias(args->sq3, args->url, &latest))) {
		if (err->code == CODE_CONTENT_NOTFOUND) {
			GRID_TRACE("Alias not yet present (1)");
			g_clear_error(&err);
		} else {
			g_prefix_error(&err, "Version error: ");
		}
	}
	else if (!latest) {
		GRID_TRACE("Alias not yet present (2)");
	}
	else {
		/* create a new version, and do not override */
		args2.version = ALIASES_get_version(latest);

		if (VERSIONS_DISABLED(args->max_versions)) {
			if (ALIASES_get_deleted(latest) || ALIASES_get_version(latest) > 0) {
				GRID_DEBUG("Versioning DISABLED but clues of SUSPENDED");
				goto suspended;
			} else {
				err = NEWERROR(CODE_CONTENT_EXISTS, "versioning disabled + content present");
			}
		}
		else if (VERSIONS_SUSPENDED(args->max_versions)) {
suspended:
			// JFS: do not alter the size to manage the alias being removed,
			// this will be done by the real purge of the latest.
			purge_latest = TRUE;
		}
		else {
			purge_latest = FALSE;
		}
	}

	gint64 size = _patch_content_stgpol (args, beans);

	/** Perform the insertion now and patch the URL with the version */
	if (!err) {
		err = m2db_real_put_alias(args->sq3, &args2);
		if (!err)
			m2db_set_size(args->sq3, m2db_get_size(args->sq3) + size);
	}

	/** Purge the latest alias if the condition was met */
	if (!err && purge_latest && latest) {
		GRID_TRACE("Need to purge the previous LATEST");
		GSList *inplace = g_slist_prepend (NULL, _bean_dup(latest));
		err = _manage_alias (args->sq3->db, latest, TRUE, _bean_list_cb, &inplace);
		if (!err) { /* remove the alias, header, conbte,t chunk */
			GSList *deleted = NULL;
			err = _real_delete (args->sq3, inplace, &deleted);
			if (out_deleted) for (GSList *l=deleted; l ;l=l->next)
				*out_deleted = g_slist_prepend (*out_deleted, _bean_dup (l->data));
			// XXX <deleted> beans are direct pointer to <inplace> beans
			g_slist_free (deleted);
		}
		_bean_cleanl2 (inplace);
		if (!err) /* remove the properties */
			err = _db_del_FK_by_name (latest, "properties", args->sq3->db);
	}

	/** Purge the exceeding aliases */
	if (VERSIONS_LIMITED(args->max_versions)) {
		gint64 count_versions = _m2db_count_alias_versions(args->sq3, args->url);
		if (args->max_versions <= count_versions) {
			/** XXX purge the oldest alias */
			GRID_WARN("GLOBAL PURGE necessary");
		}
	}

	if (latest)
		_bean_clean(latest);
	return err;
}

GError*
m2db_copy_alias(struct m2db_put_args_s *args, const char *source)
{
	struct bean_ALIASES_s *latest = NULL;
	struct bean_ALIASES_s *dst_latest = NULL;
	struct oio_url_s *orig = NULL;
	GError *err = NULL;

	GRID_TRACE("M2 COPY(%s FROM %s)", oio_url_get(args->url, OIOURL_WHOLE), source);
	EXTRA_ASSERT(args != NULL);
	EXTRA_ASSERT(args->sq3 != NULL);
	EXTRA_ASSERT(args->url != NULL);
	EXTRA_ASSERT(source != NULL);

	if (!oio_url_has(args->url, OIOURL_PATH))
		return NEWERROR(CODE_BAD_REQUEST, "Missing path");

	// Try to use source as an URL
	orig = oio_url_init(source);
	if (!orig || !oio_url_has(orig, OIOURL_PATH)) {
		// Source is just the name of the content to copy
		orig = oio_url_init(oio_url_get(args->url, OIOURL_WHOLE));
		oio_url_set(orig, OIOURL_PATH, source);
	}

	if (oio_url_has(orig, OIOURL_VERSION)) {
		err = m2db_get_versioned_alias(args->sq3, orig, &latest);
	} else {
		err = m2db_latest_alias(args->sq3, orig, &latest);
	}

	if (!err) {
		if (latest == NULL) {
			/* source ko */
			err = NEWERROR(CODE_CONTENT_NOTFOUND,
					"Cannot copy content, source doesn't exist");
		} else if (ALIASES_get_deleted(latest)) {
			err = NEWERROR(CODE_CONTENT_NOTFOUND,
					"Cannot copy content, source is deleted");
		} else {
			ALIASES_set2_alias(latest, oio_url_get(args->url, OIOURL_PATH));
			if (VERSIONS_DISABLED(args->max_versions) ||
					VERSIONS_SUSPENDED(args->max_versions)) {
				ALIASES_set_version(latest, 0);
			} else {
				// Will be overwritten a few lines below if content already exists
				ALIASES_set_version(latest, 1);
			}
			/* source ok */
			if (!(err = m2db_latest_alias(args->sq3, args->url, &dst_latest))) {
				if (dst_latest) {
					if (VERSIONS_DISABLED(args->max_versions)) {
						err = NEWERROR(CODE_CONTENT_EXISTS, "Cannot copy content,"
								"destination already exists (and versioning disabled)");
					} else if (VERSIONS_ENABLED(args->max_versions)) {
						ALIASES_set_version(latest, ALIASES_get_version(dst_latest) + 1);
					} // else -> VERSIONS_SUSPENDED -> version always 0
					_bean_clean(dst_latest);
				}
			} else {
				g_clear_error(&err);
			}
			if (!err) {
				GString *tmp = _bean_debug(NULL, latest);
				GRID_INFO("Saving new ALIAS %s", tmp->str);
				g_string_free(tmp, TRUE);
				err = _db_save_bean(args->sq3->db, latest);
			}
			_bean_clean(latest);
		}
	}

	oio_url_clean(orig);

	return err;
}

/* APPEND ------------------------------------------------------------------- */

GError*
m2db_append_to_alias(struct sqlx_sqlite3_s *sq3, namespace_info_t *ni,
		gint64 max_versions, struct oio_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;

	// Sanity checks
	GRID_TRACE("M2 APPEND(%s)", oio_url_get(url, OIOURL_WHOLE));
	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(url != NULL);
	if (!oio_url_has(url, OIOURL_PATH))
		return NEWERROR(CODE_BAD_REQUEST, "Missing path");

	GPtrArray *tmp = g_ptr_array_new ();
	err = m2db_get_alias(sq3, url, M2V2_FLAG_LATEST|M2V2_FLAG_NOPROPS,
			_bean_buffer_cb, tmp);

	/* Content does not exist or is deleted */
	if (err) {
		if (err->code != CODE_CONTENT_NOTFOUND)
			goto out;
		g_clear_error(&err);
	}
	if (tmp->len <= 0) {
		_bean_cleanv2(tmp);

		struct m2db_put_args_s args;
		memset(&args, 0, sizeof(args));
		args.sq3 = sq3;
		args.url = url;
		args.max_versions = max_versions;
		args.nsinfo = ni;
		return m2db_put_alias(&args, beans, NULL, NULL); /** XXX TODO FIXME */
	}

	/* a content is present, let's append the chunks. Let's start by filtering
	 * the chunks. */
	GSList *newchunks = NULL;
	for (GSList *l=beans; l ;l=l->next) {
		gpointer bean = l->data;
		if (bean && &descr_struct_CHUNKS == DESCR(bean))
			newchunks = g_slist_prepend (newchunks, _bean_dup (bean));
	}

	/* For the beans in place, get the position of the last chunk (meta), and
	 * the current content ID */
	gint64 last_position = -1;
	GBytes *content_id = NULL;
	for (guint i=0; i<tmp->len ;++i) {
		gpointer bean = tmp->pdata[i];
		if (&descr_struct_CONTENTS_HEADERS == DESCR(bean)) {
			struct bean_CONTENTS_HEADERS_s *header = bean;
			GByteArray *gba = CONTENTS_HEADERS_get_id (header);
			if (gba) {
				if (content_id)
					g_bytes_unref (content_id);
				content_id = g_bytes_new (gba->data, gba->len);
			}
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
	for (GSList *l=newchunks; l ;l=l->next) {
		struct bean_CHUNKS_s *chunk = l->data;
		GString *gs = CHUNKS_get_position (chunk);
		struct m2v2_position_s position = m2v2_position_decode (gs->str);
		position.meta += last_position + 1;
		m2v2_position_encode  (gs, &position);
		CHUNKS_set2_content (chunk, g_bytes_get_data(content_id, NULL),
				g_bytes_get_size(content_id));
	}

	g_bytes_unref (content_id);
	content_id = NULL;

	/* Now insert each chunk bean */
	if (!(err = _db_insert_beans_list (sq3->db, newchunks))) {
		if (cb) {
			for (GSList *l=newchunks; l ;l=l->next) {
				cb (u0, l->data);
				l->data = NULL;
			}
		}
	}
	_bean_cleanl2 (newchunks);

out:
	_bean_cleanv2(tmp);
	return err;
}

/* Link -------------------------------------------------------------------- */

GError*
m2db_link_content(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		GBytes *content_id)
{
	GError *err = NULL;

	size_t len = 0;
	const void *bin = g_bytes_get_data (content_id, &len);

	/* check the content exists */
	GPtrArray *tmp = g_ptr_array_new ();
	GVariant *params[2] = {NULL, NULL};
	params[0] = _gb_to_gvariant(content_id);
	err = CONTENTS_HEADERS_load (sq3->db, " id = ? LIMIT 1",
			params, _bean_buffer_cb, tmp);
	metautils_gvariant_unrefv(params);
	if (err) {
		g_prefix_error (&err, "Check failed: ");
		goto out;
	}
	if (tmp->len <= 0) {
		err = NEWERROR (CODE_CONTENT_NOTFOUND, "no content with such an ID");
		goto out;
	}
	g_assert (tmp->len == 1);

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
	_bean_cleanv2 (tmp);
	return err;
}

/* GENERATOR ---------------------------------------------------------------- */

struct gen_ctx_s
{
	struct oio_url_s *url;
	struct storage_policy_s *pol;
	struct grid_lb_iterator_s *iter;
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
	GString *chunk_method;
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
	chunk_method = storage_policy_to_chunk_method(ctx->pol);
	CONTENTS_HEADERS_set_chunk_method(header, chunk_method);
	g_string_free(chunk_method, TRUE);
	ctx->cb(ctx->cb_data, header);
}

static void
_m2_generate_content_chunk(struct gen_ctx_s *ctx, struct service_info_s *si,
		guint pos, gint64 cs, gint subpos, gboolean parity)
{
	guint8 binid[32];
	gchar *chunkid, strpos[24], strid[65], straddr[STRLEN_ADDRINFO];

	GRID_TRACE2("%s(%s)", __FUNCTION__, oio_url_get(ctx->url, OIOURL_WHOLE));

	oio_str_randomize (binid, sizeof(binid));
	oio_str_bin2hex (binid, sizeof(binid), strid, sizeof(strid));
	grid_addrinfo_to_string(&(si->addr), straddr, sizeof(straddr));

	if (subpos >= 0)
		g_snprintf(strpos, sizeof(strpos), (parity ? "%u.p%d" : "%u.%d"), pos, subpos);
	else
		g_snprintf(strpos, sizeof(strpos), "%u", pos);

	chunkid = m2v2_build_chunk_url (straddr, strid);

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
_m2_generate_RAIN(struct gen_ctx_s *ctx)
{
	GError *err = NULL;
	/* Storage policy storage class */
	const struct storage_class_s *stgclass;
	gint distance, k, m;

	GRID_TRACE2("%s(%s)", __FUNCTION__, oio_url_get(ctx->url, OIOURL_WHOLE));
	distance = _policy_parameter(ctx->pol, DS_KEY_DISTANCE, 1);
	k = _policy_parameter(ctx->pol, DS_KEY_K, 3);
	m = _policy_parameter(ctx->pol, DS_KEY_M, 2);
	stgclass = storage_policy_get_storage_class(ctx->pol);
	_m2_generate_alias_header(ctx);

	(void) distance;

	guint pos = 0;
	for (gint64 s=0; s < MAX(ctx->size,1) ;) {
		struct service_info_s **siv = NULL;

		struct lb_next_opt_s opt;
		memset(&opt, 0, sizeof(opt));
		opt.req.duplicates = (distance <= 0);
		opt.req.max = k + m;
		opt.req.distance = distance;
		opt.req.stgclass = stgclass;
		opt.req.strict_stgclass = FALSE; // Accept ersatzes

		if (!grid_lb_iterator_next_set(ctx->iter, &siv, &opt, &err)) {
			g_prefix_error(&err, "at position %u: ", pos);
			break;
		}

		for (gint i=0; siv[i] ;++i) {
			gboolean parity = (i >= k);
			_m2_generate_content_chunk(ctx, siv[i], pos, ctx->chunk_size,
					(parity ? i-k : i), parity);
		}

		service_info_cleanv(siv, FALSE);
		++ pos;
		s += ctx->chunk_size;
	}

	return err;
}

static GError*
_m2_generate_DUPLI(struct gen_ctx_s *ctx)
{
	GError *err = NULL;
	/* Storage policy storage class */
	const struct storage_class_s *stgclass;
	gint distance, copies;

	GRID_TRACE2("%s(%s)", __FUNCTION__, oio_url_get(ctx->url, OIOURL_WHOLE));
	distance = _policy_parameter(ctx->pol, DS_KEY_DISTANCE, 1);
	copies = _policy_parameter(ctx->pol, DS_KEY_COPY_COUNT, 1);
	stgclass = storage_policy_get_storage_class(ctx->pol);
	_m2_generate_alias_header(ctx);

	(void) distance;

	guint pos = 0;
	for (gint64 s=0; s < MAX(ctx->size,1) ; s += ctx->chunk_size) {
		struct service_info_s **psi, **siv = NULL;

		struct lb_next_opt_s opt;
		memset(&opt, 0, sizeof(opt));
		// suppose that duplicates have distance=0 between them
		opt.req.duplicates = (distance <= 0);
		opt.req.max = copies;
		opt.req.distance = distance;
		opt.req.stgclass = stgclass;
		opt.req.strict_stgclass = FALSE; // Accept ersatzes

		if (!grid_lb_iterator_next_set(ctx->iter, &siv, &opt, &err)) {
			g_prefix_error(&err, "at position %u: ", pos);
			break;
		}

		for (psi=siv; *psi ;++psi)
			_m2_generate_content_chunk(ctx, *psi, pos, ctx->chunk_size, -1, FALSE);

		service_info_cleanv(siv, FALSE);
		++ pos;
	}

	return err;
}

GError*
m2_generate_beans(struct oio_url_s *url, gint64 size, gint64 chunk_size,
		struct storage_policy_s *pol, struct grid_lb_iterator_s *iter,
		m2_onbean_cb cb, gpointer cb_data)
{
	GRID_TRACE2("%s(%s)", __FUNCTION__, oio_url_get(url, OIOURL_WHOLE));
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(iter != NULL);

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
	ctx.iter = iter;
	ctx.uid = (guint8*) &uid;
	ctx.uid_size = uid_size;
	ctx.size = size;
	ctx.chunk_size = chunk_size;
	ctx.cb = cb;
	ctx.cb_data = cb_data;

	if (!pol)
		return _m2_generate_DUPLI(&ctx);

	switch (data_security_get_type(storage_policy_get_data_security(pol))) {
		case RAIN:
			return _m2_generate_RAIN(&ctx);
		case DS_NONE:
		case DUPLI:
			return _m2_generate_DUPLI(&ctx);
		default:
			return NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid policy type");
	}
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
	for (struct map_s *p = map; p->f ; ++p) {
		const gchar *v = oio_url_get(url, p->k);
		if (v != NULL)
			sqlx_admin_init_str(sq3, p->f, v);
	}
}

GError*
m2db_get_container_status(struct sqlx_sqlite3_s *sq3, guint32 *status)
{
	*status = sqlx_admin_get_i64(sq3, SQLX_ADMIN_STATUS, (gint64)CONTAINER_STATUS_ENABLED);
	return NULL;
}

GError*
m2db_set_container_status(struct sqlx_sqlite3_s *sq3, guint32 repl)
{
	sqlx_admin_set_i64(sq3, SQLX_ADMIN_STATUS, (gint64)repl);
	return NULL;
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

	for (GSList *l=to_be_deleted; l ; l=l->next) {
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

	for (GSList *l=to_be_deleted; l ;l=l->next) {
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

	guint64 size = m2db_get_container_size(sq3->db, FALSE);
	m2db_set_size(sq3, (gint64)size);

	/* TODO(jfs): send the beans to the event-agent */
	_bean_cleanv2 (tmp);
	return NULL;
}

GError*
m2db_deduplicate_contents(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url)
{
	GError *err = NULL;
	GSList *impacted_aliases = NULL;
	guint64 size_before = m2db_get_container_size(sq3->db, TRUE);
	guint64 saved_space = dedup_aliases(sq3->db, url, &impacted_aliases, &err);
	guint64 size_after = m2db_get_container_size(sq3->db, TRUE);

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

/* Duplicate an alias bean */
void
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

GError*
m2db_dup_all_aliases(struct sqlx_sqlite3_s *sq3, gint64 src_c_version,
		gboolean set_deleted, gboolean overwrite_latest)
{
	GError *err = NULL;
	gchar *clause = NULL;
	GVariant *params[] = {NULL, NULL};
	struct dup_alias_params_s cb_params;
	cb_params.sq3 = sq3;
	cb_params.c_version = m2db_get_version(sq3);
	cb_params.src_c_version = src_c_version;
	cb_params.overwrite_latest = overwrite_latest;
	cb_params.set_deleted = set_deleted;
	cb_params.errors = NULL;

	if (src_c_version < 1) {
		// Duplicate current (latest) version
		clause = " 1 GROUP BY alias HAVING version = max(version) ";
	} else {
		// Duplicate possibly old version (e.g. in case of restoration)
		clause = " GROUP BY alias "; // FIXME: group by needed ?
		params[0] = g_variant_new_int64(src_c_version);
	}

	err = ALIASES_load(sq3->db, clause, params,
			(m2_onbean_cb)m2v2_dup_alias, &cb_params);
	if (err != NULL) {
		g_prefix_error(&err, "Failed to load aliases to duplicate: ");
	}

	if (cb_params.errors != NULL) {
		if (err == NULL) {
			err = NEWERROR(0,
				"Got at least one error while duplicating aliases, see meta2 logs");
		}
		for (GSList *l = cb_params.errors; l; l = l->next) {
			GRID_WARN("Dup alias error: %s", ((GError*)l->data)->message);
			g_clear_error((GError**)&l->data);
		}
		g_slist_free(cb_params.errors);
	}

	if (params[0] != NULL)
		g_variant_unref(params[0]);
	return err;
}

