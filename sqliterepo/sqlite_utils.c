/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#include <string.h>

#include "sqliterepo.h"

int
sqlx_exec(sqlite3 *handle, const gchar *sql)
{
	int rc, grc = SQLITE_OK;
	const gchar *next;
	sqlite3_stmt *stmt = NULL;

	while ((grc == SQLITE_OK) && sql && *sql) {
		next = NULL;
		sqlite3_prepare_debug(rc, handle, sql, -1, &stmt, &next);
		sql = next;
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			grc = rc;
		else if (stmt) {
			sqlite3_step_debug_until_end(rc, stmt);
			if (rc != SQLITE_OK && rc != SQLITE_DONE)
				grc = rc;
			rc = sqlite3_finalize(stmt);
		}

		stmt = NULL;
	}

	return grc;
}

void
sqlx_admin_set_gba_and_clean(struct sqlx_sqlite3_s *sq3, const gchar *k,
		GByteArray *gba)
{
	// Avoid replacing the value if the same is already present
	GByteArray *prev = g_tree_lookup(sq3->admin, k);
	if (prev && gba->len == prev->len) {
		if (!memcmp(gba->data, prev->data, prev->len)) {
			g_byte_array_free(gba, TRUE);
			return;
		}
	}

	g_tree_replace(sq3->admin, g_strdup(k), gba);
	sq3->admin_dirty = 1;
}

void
sqlx_admin_set_str(struct sqlx_sqlite3_s *sq3, const gchar *k, const gchar *v)
{
	sqlx_admin_set_gba_and_clean(sq3, k, metautils_gba_from_string(v));
}

gboolean
sqlx_admin_init_str(struct sqlx_sqlite3_s *sq3, const gchar *k, const gchar *v)
{
	if (g_tree_lookup(sq3->admin, k))
		return FALSE;
	sqlx_admin_set_str(sq3, k, v);
	return TRUE;
}

void
sqlx_admin_del(struct sqlx_sqlite3_s *sq3, const gchar *k)
{
	sqlx_admin_set_str (sq3, k, NULL);
}

void
sqlx_admin_del_all_user(struct sqlx_sqlite3_s *sq3)
{
	gchar **k = gtree_string_keys(sq3->admin);
	if (!k)
		return;
	for (gchar **p=k; *p ;p++) {
		if (g_str_has_prefix(*p, SQLX_ADMIN_PREFIX_USER))
			sqlx_admin_del (sq3, *p);
	}
	g_free (k);
}

int
sqlx_admin_has(struct sqlx_sqlite3_s *sq3, const gchar *k)
{
	return NULL != g_tree_lookup(sq3->admin, k);
}

gchar*
sqlx_admin_get_str(struct sqlx_sqlite3_s *sq3, const gchar *k)
{
	GByteArray *v = g_tree_lookup(sq3->admin, k);
	return v ? g_strndup((gchar*)v->data, v->len) : NULL;
}

GByteArray*
sqlx_admin_get_gba(struct sqlx_sqlite3_s *sq3, const gchar *k)
{
	GByteArray *v = g_tree_lookup(sq3->admin, k);
	return v ? metautils_gba_dup(v) : NULL;
}

gint64
sqlx_admin_get_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 def)
{
	gchar *s = sqlx_admin_get_str(sq3, k);
	if (!s)
		return def;
	gint64 i64 = g_ascii_strtoll(s, NULL, 10);
	g_free(s);
	return i64;
}

void
sqlx_admin_set_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 v)
{
	gchar buf[64];
	g_snprintf(buf, 64, "%"G_GINT64_FORMAT, v);
	sqlx_admin_set_str(sq3, k, buf);
}

gboolean
sqlx_admin_init_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 v)
{
	if (g_tree_lookup(sq3->admin, k))
		return FALSE;
	sqlx_admin_set_i64(sq3, k, v);
	return TRUE;
}

void
sqlx_admin_inc_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 delta)
{
	gchar *s = sqlx_admin_get_str(sq3, k);
	if (!s)
		sqlx_admin_set_i64(sq3, k, delta);
	else {
		sqlx_admin_set_i64(sq3, k, delta + g_ascii_strtoll(s, NULL, 10));
		g_free(s);
	}
}

void
sqlx_admin_inc_version(struct sqlx_sqlite3_s *sq3, const gchar *k, const int delta)
{
	gchar buf[128], *p, *prev;

	if (!(prev = sqlx_admin_get_str(sq3, k)))
		return;
	if (!(p = strchr(prev, ':')))
		return;

	*(p++) = '\0';
	g_snprintf(buf, sizeof(buf), "%"G_GINT64_FORMAT":%"G_GINT64_FORMAT,
			g_ascii_strtoll(prev, NULL, 10) + delta,
			g_ascii_strtoll(p, NULL, 10));
	g_free(prev);
	sqlx_admin_set_str(sq3, k, buf);
}

gboolean
sqlx_admin_ensure_versions (struct sqlx_sqlite3_s *sq3)
{
	int rc, any_added = FALSE;
	sqlite3_stmt *stmt = NULL;
	sqlite3_prepare_debug(rc, sq3->db, "SELECT name FROM sqlite_master"
			" WHERE type = 'table'", -1, &stmt, NULL);
	if (rc == SQLITE_OK) {
		EXTRA_ASSERT(stmt != NULL);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			const gchar *name = (const gchar*)sqlite3_column_text(stmt, 0);
			gchar *k = g_strdup_printf("version:main.%s", name);
			any_added |= sqlx_admin_init_str (sq3, k, "1:0");
			g_free(k);
		}
		sqlite3_finalize(stmt);
	}
	return BOOL(any_added);
}

void
sqlx_admin_inc_all_versions(struct sqlx_sqlite3_s *sq3, const int delta)
{
	gboolean runner(gchar *k0, GByteArray *v, gpointer ignored) {
		(void) ignored;
		if (!g_str_has_prefix(k0, "version:"))
			return FALSE;

		gchar *prev = g_alloca(v->len+8);
		memset(prev, 0, v->len+8);
		memcpy(prev, v->data, v->len);

		/* Build the new version string */
		gchar *p = strchr(prev, ':');
		if (!p)
			return FALSE;
		*(p++) = '\0';
		gint64 v0 = g_ascii_strtoll(prev, NULL, 10) + delta;
		gint64 v1 = g_ascii_strtoll(p, NULL, 10);
		g_snprintf(prev, v->len+8, "%"G_GINT64_FORMAT":%"G_GINT64_FORMAT, v0, v1);

		/* Change in place and mark for a later save in the DB */
		g_byte_array_set_size(v, 0);
		g_byte_array_append(v, (guint8*)prev, strlen(prev));
		sq3->admin_dirty = 1;
		return FALSE;
	}

	g_tree_foreach(sq3->admin, (GTraverseFunc)runner, NULL);
}

void
sqlx_admin_set_status(struct sqlx_sqlite3_s *sq3, gint64 status)
{
	sqlx_admin_set_i64(sq3, SQLX_ADMIN_STATUS, status);
}

gint64
sqlx_admin_get_status(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_admin_get_i64(sq3, SQLX_ADMIN_STATUS,
			(gint64)ADMIN_STATUS_ENABLED);
}

gchar**
sqlx_admin_get_keys(struct sqlx_sqlite3_s *sq3)
{
	gboolean runner(gchar *k, GByteArray *v, GPtrArray *tmp) {
		(void) v;
		g_ptr_array_add (tmp, g_strdup(k));
		return FALSE;
	}

	GPtrArray *tmp = g_ptr_array_new ();
	g_tree_foreach (sq3->admin, (GTraverseFunc) runner, tmp);
	return (gchar**) metautils_gpa_to_array (tmp, TRUE);
}

gchar**
sqlx_admin_get_keyvalues (struct sqlx_sqlite3_s *sq3)
{
	gboolean runner(gchar *k, GByteArray *v, GPtrArray *tmp) {
		(void) v;
		g_ptr_array_add (tmp, g_strdup(k));
		if (!v->len || !v->data)
			g_ptr_array_add (tmp, g_strdup(""));
		else
			g_ptr_array_add (tmp, g_strndup((gchar*)v->data, v->len));
		return FALSE;
	}

	GPtrArray *tmp = g_ptr_array_new ();
	g_tree_foreach (sq3->admin, (GTraverseFunc) runner, tmp);
	return (gchar**) metautils_gpa_to_array (tmp, TRUE);
}

guint
sqlx_admin_save (struct sqlx_sqlite3_s *sq3)
{
	int rc;
	guint count = 0;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	gboolean run_to_delete = FALSE;

	EXTRA_ASSERT(sq3 != NULL);

	sqlite3_prepare_debug(rc, sq3->db,
			"INSERT OR REPLACE INTO admin (k,v) VALUES (?,?)", -1, &stmt, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		err = SYSERR("DB error: (%d) %s", rc, sqlite3_errmsg(sq3->db));
	else {
		gboolean _save (gchar *k, GByteArray *v, gpointer i) {
			if (!v || !v->len || !v->data) {
				run_to_delete = TRUE;
				return FALSE;
			}
			(void) i;
			sqlite3_reset (stmt);
			sqlite3_clear_bindings (stmt);
			sqlite3_bind_text (stmt, 1, k, -1, NULL);
			sqlite3_bind_blob (stmt, 2, v->data, v->len, NULL);
			sqlite3_step_debug_until_end (rc, stmt);
			if (rc != SQLITE_OK && rc != SQLITE_DONE)
				err = SYSERR("DB error: (%d) %s", rc, sqlite3_errmsg(sq3->db));
			count ++;
			return err != NULL;
		}
		g_tree_foreach (sq3->admin, (GTraverseFunc)_save, NULL);
		(void) sqlite3_finalize(stmt);
	}


	if (run_to_delete && !err) {
		sqlite3_prepare_debug(rc, sq3->db, "DELETE FROM admin WHERE k = ?", -1, &stmt, NULL);
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			err = SYSERR("DB error: (%d) %s", rc, sqlite3_errmsg(sq3->db));
		else {
			GSList *deleted = NULL;
			gboolean _delete (gchar *k, GByteArray *v, gpointer i) {
				if (v && v->len)
					return FALSE;
				(void) i;
				sqlite3_reset (stmt);
				sqlite3_clear_bindings (stmt);
				sqlite3_bind_text (stmt, 1, k, -1, NULL);
				sqlite3_step_debug_until_end (rc, stmt);
				if (rc != SQLITE_OK && rc != SQLITE_DONE)
					err = SYSERR("DB error: (%d) %s", rc, sqlite3_errmsg(sq3->db));
				else
					deleted = g_slist_prepend(deleted, k);
				count ++;
				return err != NULL;
			}
			g_tree_foreach (sq3->admin, (GTraverseFunc)_delete, NULL);
			(void) sqlite3_finalize(stmt);
			for (GSList *l = deleted; !err && l; l = l->next)
				g_tree_remove(sq3->admin, l->data);
			g_slist_free(deleted);  // values were freed by g_tree_remove
		}
	}

	if (err) {
		GRID_WARN("DB error: failed to save the admin table: (%d) %s",
				err->code, err->message);
		g_clear_error (&err);
		count = 0;
	}
	return count;
}

guint
sqlx_admin_save_lazy (struct sqlx_sqlite3_s *sq3)
{
	if (!sq3 || !sq3->admin_dirty) return 0;
	guint rc = sqlx_admin_save (sq3);
	sq3->admin_dirty = 0;
	return rc;
}

guint
sqlx_admin_save_lazy_tnx (struct sqlx_sqlite3_s *sq3)
{
	if (!sq3 || !sq3->admin_dirty) return 0;
	sqlx_exec (sq3->db, "BEGIN");
	guint rc = sqlx_admin_save (sq3);
	sqlx_exec (sq3->db, "COMMIT");
	sq3->admin_dirty = 0;
	return rc;
}

void
sqlx_admin_load(struct sqlx_sqlite3_s *sq3)
{
	sqlite3_stmt *stmt = NULL;
	int rc;

	sqlite3_prepare_debug(rc, sq3->db, "SELECT k,v FROM admin", -1, &stmt, NULL);
	if (rc == SQLITE_OK) {
		EXTRA_ASSERT(stmt != NULL);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			const gchar *k = (const gchar*)sqlite3_column_text(stmt, 0);
			GByteArray *v = g_byte_array_append(
					g_byte_array_sized_new(sqlite3_column_bytes(stmt, 1)),
					sqlite3_column_blob(stmt, 1),
					sqlite3_column_bytes(stmt, 1));
			g_tree_replace(sq3->admin, g_strdup(k), v);
		}
		sqlite3_finalize(stmt);
	}
}

void
sqlx_alert_dirty_base(struct sqlx_sqlite3_s *sq3, const char *msg)
{
	GRID_ERROR ("BUG: Base [%s][%s] %s", sq3->name.base, sq3->name.type, msg);
	g_assert (!sq3->admin_dirty);
}

struct oio_url_s*
sqlx_admin_get_url (struct sqlx_sqlite3_s *sq3)
{
	EXTRA_ASSERT(sq3 != NULL);
	struct oio_url_s *u = oio_url_empty ();
	void _set (int which, const char *k) {
		gchar *s = sqlx_admin_get_str(sq3, k);
		if (s) {
			oio_url_set (u, which, s);
			g_free (s);
		}
	}
	_set (OIOURL_NS, SQLX_ADMIN_NAMESPACE);
	_set (OIOURL_ACCOUNT, SQLX_ADMIN_ACCOUNT);
	_set (OIOURL_USER, SQLX_ADMIN_USERNAME);
	oio_url_set (u, OIOURL_TYPE, sq3->name.type);
	return u;
}
