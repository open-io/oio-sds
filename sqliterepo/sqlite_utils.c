/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2025 OVH SAS

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
#include "version.h"

/** Prepared SQL statements to change sqlite's journal_mode.
 * The variable oio_sqliterepo_journal_mode selects one of them.
 * Keep them in this order! */
static const gchar *sqlx_journal_mode_sql[] = {
	"PRAGMA journal_mode = DELETE",
	"PRAGMA journal_mode = TRUNCATE",
	"PRAGMA journal_mode = PERSIST",
	"PRAGMA journal_mode = MEMORY",
	"PRAGMA journal_mode = WAL",
//	"PRAGMA journal_mode = OFF",  // Dangerous
	NULL,
};

/** @private */
struct _cache_entry_s {
	/* the size of the value, without the trailing 0 */
	guint32 len;
	guint8 flag_deleted : 1;
	guint8 flag_changed : 1;
	gchar buffer[];
};

static inline gsize _buffer_length(const gsize len) { return MAX(len,32) + 1; }

static inline gsize
_cache_entry_length(struct _cache_entry_s *e)
{
	return _buffer_length(e->len);
}

static struct _cache_entry_s *
_make_cache_entry(const gchar *buf, gsize len)
{
	/* By allocating 32 bytes for the value, we know it will ever be enough
	 * for the value that represent the version of a table in the database.
	 * Those entries are changed in place, later, because this is done really
	 * often and it saves memory allocations. */
	struct _cache_entry_s *e = g_malloc0(
			sizeof(struct _cache_entry_s) + _buffer_length(len));
	e->len = len;
	if (buf && len > 0)
		memcpy(e->buffer, buf, len);
	if (!buf)
		e->flag_deleted = 1;
	return e;
}

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

int
sqlx_set_journal_mode(sqlite3 *handle, guint journal_mode)
{
	return sqlx_exec(
			handle, sqlx_journal_mode_sql[journal_mode]);
}

int
sqlx_set_page_size(sqlite3 *handle, guint page_size)
{
	gchar line[128] = {0};
	snprintf(line, sizeof(line), "PRAGMA page_size = %u;", page_size);
	int rc = sqlx_exec(handle, line);
	if (rc != SQLITE_OK) {
		GRID_WARN("Failed to set page_size=%u: %s (reqid=%s)",
				page_size, sqlite_strerror(rc), oio_ext_get_reqid());
	}
	return rc;
}

int
sqlx_sqlite3_finalize(struct sqlx_sqlite3_s *sq3, sqlite3_stmt *stmt,
		GError *err)
{
	EXTRA_ASSERT(sq3 != NULL);

	if (err || !sq3->save_update_queries
			|| sqlite3_stmt_readonly(stmt))
		goto end;

	gchar *expanded_sql = sqlite3_expanded_sql(stmt);
	if (sq3->transaction) {
		sq3->transaction_update_queries = g_list_append(
				sq3->transaction_update_queries, g_strdup(expanded_sql));
	} else {
		sq3->update_queries = g_list_append(sq3->update_queries,
				g_strdup(expanded_sql));
	}
	sqlite3_free(expanded_sql);

end:
	return sqlite3_finalize(stmt);
}

#ifdef HAVE_EXTRA_DEBUG
#define _dump_entry(tag,k,v) \
	GRID_TRACE2("%s: %s <- {del:%d, changed:%d, %s}", tag, \
			k, v->flag_deleted, v->flag_changed, v->buffer)
#else
#define _dump_entry(tag,k,v)
#endif

gboolean
sqlx_admin_set_str_all_keys_with_prefix(struct sqlx_sqlite3_s *sq3,
		const gchar *prefix, const gchar *value)
{
	gboolean runner(gchar *k, struct _cache_entry_s *v, gpointer i UNUSED) {
		if (v->flag_deleted)
			return FALSE;
		if (g_str_has_prefix(k, prefix)) {
			return sqlx_admin_set_str(sq3, k, value);
		}
		return FALSE;
	}
	g_tree_foreach(sq3->admin, (GTraverseFunc)runner, NULL);
	return TRUE;
}

gboolean
sqlx_admin_set_str(struct sqlx_sqlite3_s *sq3, const gchar *k, const gchar *v)
{
	v = v ?: "";
	const gsize len = strlen(v);

	/* Avoid replacing the value if the same is already present */
	struct _cache_entry_s *prev = g_tree_lookup(sq3->admin, k);
	if (prev && !prev->flag_deleted && len == prev->len
			&& (!len || !memcmp(v, prev->buffer, len))) {
		return FALSE;
	}

	/* If the new value is not longer than the previous, we can even reuse
	 * the same buffer */
	if (prev && len < _cache_entry_length(prev)) {
		prev->len = g_strlcpy(prev->buffer, v, _cache_entry_length(prev));
		prev->flag_deleted = 0;
	} else {
		prev = _make_cache_entry(v, len);
		g_tree_replace(sq3->admin, g_strdup(k), prev);
	}

	prev->flag_changed = 1;
	sq3->admin_dirty = 1;
	_dump_entry("change", k, prev);
	return TRUE;
}

gboolean
sqlx_admin_init_str(struct sqlx_sqlite3_s *sq3, const gchar *k, const gchar *v)
{
	if (g_tree_lookup(sq3->admin, k))
		return FALSE;
	return sqlx_admin_set_str(sq3, k, v);
}

void
sqlx_admin_del(struct sqlx_sqlite3_s *sq3, const gchar *k)
{
	struct _cache_entry_s *v = g_tree_lookup(sq3->admin, k);
	if (v && !v->flag_deleted) {
		v->flag_deleted = 1;
		v->flag_changed = 1;
		sq3->admin_dirty = 1;
		_dump_entry("change", k, v);
	}
}

void
sqlx_admin_del_all_keys_with_prefix(struct sqlx_sqlite3_s *sq3,
		const gchar *prefix, GTraverseFunc func, gpointer data)
{
	gboolean runner(gchar *k, struct _cache_entry_s *v, gpointer i UNUSED) {
		if (v->flag_deleted)
			return FALSE;
		if (g_str_has_prefix(k, prefix)) {
			v->flag_deleted = 1;
			v->flag_changed = 1;
			_dump_entry("change", k, v);
			if (func) {
				func(k, NULL, data);
			}
		}
		return FALSE;
	}
	g_tree_foreach(sq3->admin, (GTraverseFunc)runner, NULL);
	sq3->admin_dirty = TRUE;
}

void
sqlx_admin_del_all_user(struct sqlx_sqlite3_s *sq3, GTraverseFunc func,
		gpointer data)
{
	return sqlx_admin_del_all_keys_with_prefix(sq3, SQLX_ADMIN_PREFIX_USER,
			func, data);
}

int
sqlx_admin_has(struct sqlx_sqlite3_s *sq3, const gchar *k)
{
	struct _cache_entry_s *v = g_tree_lookup(sq3->admin, k);
	return v != NULL && !v->flag_deleted;
}

gchar*
sqlx_admin_get_str(struct sqlx_sqlite3_s *sq3, const gchar *k)
{
	struct _cache_entry_s *v = g_tree_lookup(sq3->admin, k);
	if (!v || v->flag_deleted)
		return NULL;
	return g_strndup(v->buffer, v->len);
}

gint64
sqlx_admin_get_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 def)
{
	struct _cache_entry_s *v = g_tree_lookup(sq3->admin, k);
	if (!v || v->flag_deleted)
		return def;
	return g_ascii_strtoll(v->buffer, NULL, 10);
}

void
sqlx_admin_set_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 v)
{
	gchar buf[32];
	g_snprintf(buf, 32, "%"G_GINT64_FORMAT, v);
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
	struct _cache_entry_s *v = g_tree_lookup(sq3->admin, k);
	if (!v)
		return sqlx_admin_set_i64(sq3, k, delta);

	/* the buffer is large enough for a single gint64, let's have no worry
	 * about the buffer length */
	v->len = g_snprintf(v->buffer, _cache_entry_length(v), "%"G_GINT64_FORMAT,
			delta + (v->flag_deleted ? 0 : g_ascii_strtoll(v->buffer, NULL, 10)));

	v->flag_changed = 1;
	v->flag_deleted = 0;
	sq3->admin_dirty = 1;
	_dump_entry("change", k, v);
}

static void
_cache_entry_increment_version(struct _cache_entry_s *entry, const gint64 delta)
{
	/* Build the new version string in place, as explained the buffer
	 * is large enough for the longest version string possible. So we can
	 * use the strlcpy() return size as the actual length of the buffer. */
	if (entry->flag_deleted) {
		entry->len = g_strlcpy(entry->buffer, "1:0", _cache_entry_length(entry));
	} else {
		gchar *p = strchr(entry->buffer, ':');
		if (!p) {
			entry->len = g_strlcpy(entry->buffer, "1:0", _cache_entry_length(entry));
		} else {
			const gint64 v0 = g_ascii_strtoll(entry->buffer, NULL, 10);
			const gint64 v1 = g_ascii_strtoll(p+1, NULL, 10);
			entry->len = g_snprintf(entry->buffer, _cache_entry_length(entry),
					"%"G_GINT64_FORMAT":%"G_GINT64_FORMAT, v0 + delta, v1);
		}
	}

	entry->flag_changed = 1;
	entry->flag_deleted = 0;
}

void
sqlx_admin_inc_version(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 delta)
{
	struct _cache_entry_s *prev = g_tree_lookup(sq3->admin, k);
	if (prev) {
		_cache_entry_increment_version(prev, delta);
		sq3->admin_dirty = 1;
		_dump_entry("change", k, prev);
	}
}

void
sqlx_admin_ensure_versions (struct sqlx_sqlite3_s *sq3)
{
	int rc;
	sqlite3_stmt *stmt = NULL;
	sqlite3_prepare_debug(rc, sq3->db, "SELECT name FROM sqlite_master"
			" WHERE type = 'table'", -1, &stmt, NULL);
	if (rc == SQLITE_OK) {
		EXTRA_ASSERT(stmt != NULL);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			gchar k[512];
			g_snprintf(k, sizeof(k), "version:main.%s",
					sqlite3_column_text(stmt, 0));
			sqlx_admin_init_str (sq3, k, "1:0");
		}
		sqlite3_finalize(stmt);
	}
}

gboolean
sqlx_admin_ensure_peers(struct sqlx_sqlite3_s *sq3, gchar **peers)
{
	EXTRA_ASSERT(peers != NULL);
	gboolean modified = FALSE;
	if (!sqlx_admin_has(sq3, SQLX_ADMIN_PEERS)) {
		gchar *packed_peers = g_strjoinv(",", peers);
		modified = sqlx_admin_set_str(sq3, SQLX_ADMIN_PEERS, packed_peers);
		g_free(packed_peers);
	}
	return modified;
}

void
sqlx_admin_inc_all_versions(struct sqlx_sqlite3_s *sq3, const gint64 delta)
{
	gboolean runner(gchar *k0, struct _cache_entry_s *v, gpointer i UNUSED) {
		if (!g_str_has_prefix(k0, "version:"))
			return FALSE;
		_cache_entry_increment_version(v, delta);
		return FALSE;
	}

	g_tree_foreach(sq3->admin, (GTraverseFunc)runner, NULL);
	sq3->admin_dirty = TRUE;
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

const gchar*
sqlx_admin_status2str(gint64 status)
{
	switch (status) {
		case ADMIN_STATUS_FROZEN:
			return "frozen";
		case ADMIN_STATUS_DISABLED:
			return "disabled";
		case ADMIN_STATUS_ENABLED:
			return "enabled";
		default:
			return "unknown";
	}
}

gchar**
sqlx_admin_get_keys(struct sqlx_sqlite3_s *sq3)
{
	gboolean runner(gchar *k, struct _cache_entry_s *v, GPtrArray *tmp) {
		if (v->flag_deleted)
			return FALSE;
		g_ptr_array_add (tmp, g_strdup(k));
		return FALSE;
	}

	GPtrArray *tmp = g_ptr_array_new ();
	g_tree_foreach (sq3->admin, (GTraverseFunc) runner, tmp);
	return (gchar**) metautils_gpa_to_array (tmp, TRUE);
}

gchar**
sqlx_admin_get_keyvalues(struct sqlx_sqlite3_s *sq3,
		gboolean (*filter)(const gchar *k))
{
	gboolean runner(gchar *k, struct _cache_entry_s *v, GPtrArray *tmp) {
		if (v->flag_deleted)
			return FALSE;
		if (filter && !filter(k))
			return FALSE;
		g_ptr_array_add(tmp, g_strdup(k));
		if (!v->len)
			g_ptr_array_add(tmp, g_strdup(""));
		else
			g_ptr_array_add(tmp, g_strndup((gchar*)v->buffer, v->len));
		return FALSE;
	}

	GPtrArray *tmp = g_ptr_array_new();
	g_tree_foreach(sq3->admin, (GTraverseFunc) runner, tmp);
	return (gchar**) metautils_gpa_to_array(tmp, TRUE);
}

static guint
sqlx_admin_save (struct sqlx_sqlite3_s *sq3)
{
	int rc;
	guint count = 0;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;

	EXTRA_ASSERT(sq3 != NULL);

	sqlite3_prepare_debug(rc, sq3->db,
			"INSERT OR REPLACE INTO admin (k,v) VALUES (?,?)", -1, &stmt, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		err = SYSERR("DB error: (%d) %s", rc, sqlite3_errmsg(sq3->db));
	else {
		gboolean _save (gchar *k, struct _cache_entry_s *v, gpointer i UNUSED) {
			_dump_entry("save", k, v);
			if (!v->flag_changed)
				return FALSE;

			sqlite3_reset (stmt);
			sqlite3_clear_bindings (stmt);
			sqlite3_bind_text (stmt, 1, k, -1, NULL);

			if (v->flag_deleted) {
				sqlite3_bind_null (stmt, 2);
			} else if (!v->len) {
				sqlite3_bind_text (stmt, 2, "", 0, NULL);
			} else {
				sqlite3_bind_blob (stmt, 2, (guint8*)v->buffer, v->len, NULL);
			}
			sqlite3_step_debug_until_end (rc, stmt);
			if (rc != SQLITE_OK && rc != SQLITE_DONE)
				err = SYSERR("DB error: (%d) %s", rc, sqlite3_errmsg(sq3->db));
			count ++;
			return err != NULL;
		}
		g_tree_foreach (sq3->admin, (GTraverseFunc)_save, NULL);
		(void) sqlite3_finalize(stmt);
	}

	if (err) {
		GRID_WARN("Failed to save the admin table: (%d) %s",
				err->code, err->message);
		if (rc == SQLITE_NOTADB || rc == SQLITE_CORRUPT)
			sq3->corrupted = TRUE;
		g_clear_error(&err);
		count = 0;
	}
	return count;
}

guint
sqlx_admin_save_lazy (struct sqlx_sqlite3_s *sq3)
{
	if (!sq3 || !sq3->admin_dirty)
		return 0;
	guint rc = sqlx_admin_save (sq3);
	sq3->admin_dirty = 0;
	return rc;
}

guint
sqlx_admin_save_lazy_tnx (struct sqlx_sqlite3_s *sq3)
{
	if (!sq3 || !sq3->admin_dirty)
		return 0;
	sqlx_exec (sq3->db, "BEGIN");
	guint rc = sqlx_admin_save (sq3);
	sqlx_exec (sq3->db, "COMMIT");
	sq3->admin_dirty = 0;
	return rc;
}

void
sqlx_admin_load(struct sqlx_sqlite3_s *sq3)
{
	gboolean invalid_entry = FALSE;
	sqlite3_stmt *stmt = NULL;
	int rc;

	sqlite3_prepare_debug(rc, sq3->db, "SELECT k,v FROM admin", -1, &stmt, NULL);
	if (rc == SQLITE_OK) {
		EXTRA_ASSERT(stmt != NULL);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			const gchar *k = (const gchar*)sqlite3_column_text(stmt, 0);
			struct _cache_entry_s *v = NULL;
			if (unlikely(sqlite3_column_type(stmt, 0) == SQLITE_NULL)) {
				if (!invalid_entry) {
					GRID_ERROR(
							"BUG: Base [%s][%s] has null keys in admin table",
							sq3->name.base, sq3->name.type);
					invalid_entry = TRUE;
				}
				continue;
			}
			if (sqlite3_column_type(stmt, 1) == SQLITE_NULL)
				v = _make_cache_entry(NULL, 0);
			else
				v = _make_cache_entry(
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

#define _set(which,k) do { \
		gchar *s = sqlx_admin_get_str(sq3, k); \
		if (s) { \
			oio_url_set (u, which, s); \
			g_free (s); \
		} \
	} while (0)

struct oio_url_s*
sqlx_admin_get_url (struct sqlx_sqlite3_s *sq3)
{
	EXTRA_ASSERT(sq3 != NULL);
	struct oio_url_s *u = oio_url_empty ();
	_set (OIOURL_NS, SQLX_ADMIN_NAMESPACE);
	_set (OIOURL_ACCOUNT, SQLX_ADMIN_ACCOUNT);
	_set (OIOURL_USER, SQLX_ADMIN_USERNAME);
	return u;
}

static gboolean
hook_extract(gchar *k, struct _cache_entry_s *v, GTree *version)
{
	if (!g_str_has_prefix(k, "version:"))
		return FALSE;

	gchar *p;
	if (!(p = strchr(v->buffer, ':')))
		return FALSE;

	struct object_version_s ov;
	ov.version = atoll(v->buffer);
	ov.when = atoll(p + 1);
	g_tree_insert(version,
			hashstr_create(k + sizeof("version:") - 1),
			oio_memdup(&ov, sizeof(ov)));
	return FALSE;
}

GTree*
version_empty(void)
{
	return g_tree_new_full(hashstr_quick_cmpdata, NULL, g_free, g_free);
}

GTree*
version_extract_from_admin_tree(GTree *t)
{
	GTree *v = version_empty();
	g_tree_foreach(t, (GTraverseFunc)hook_extract, v);
	return v;
}

struct db_properties_s
{
	GTree *system;
	GTree *user;
};

struct db_properties_s *
db_properties_new(void)
{
	struct db_properties_s *db_properties = g_malloc0(
		sizeof(struct db_properties_s));
	db_properties->system = g_tree_new((GCompareFunc)g_strcmp0);
	db_properties->user = g_tree_new((GCompareFunc)g_strcmp0);
	return db_properties;
}

void
db_properties_free(struct db_properties_s *db_properties)
{
	g_tree_destroy(db_properties->system);
	g_tree_destroy(db_properties->user);
	g_free(db_properties);
}

void
db_properties_add(struct db_properties_s *db_properties,
		gchar *key, gchar *value)
{
	if (!db_properties)
		return;

	if (g_str_has_prefix(key, SQLX_ADMIN_PREFIX_SYS)) {
		g_tree_insert(db_properties->system, key, value);
	} else if (g_str_has_prefix(key, SQLX_ADMIN_PREFIX_USER)) {
		g_tree_insert(db_properties->user,
				key + strlen(SQLX_ADMIN_PREFIX_USER), value);
	}
}

GString *
db_properties_to_json(
		struct db_properties_s *db_properties, GString *json)
{
	if (!db_properties)
		return NULL;

	gboolean first = TRUE;
	gboolean _property_to_json(gpointer key, gpointer value,
			gpointer data UNUSED) {
		if (first)
			first = FALSE;
		else
			g_string_append_c(json, ',');

		oio_str_gstring_append_json_pair(json, key, value);
		return FALSE;
	}

	g_string_append_static(json, "\"system\":{");
	g_tree_foreach(db_properties->system, _property_to_json, NULL);
	first = TRUE;
	g_string_append_static(json, "},\"properties\":{");
	g_tree_foreach(db_properties->user, _property_to_json, NULL);
	g_string_append_static(json, "}");
	return json;
}

GPtrArray *
db_properties_system_to_gpa(struct db_properties_s *db_properties, GPtrArray *gpa)
{
	if (!db_properties || !gpa) {
		return NULL;
	}

	gboolean _add_property_to_gpa(gpointer key, gpointer value, gpointer data UNUSED) {
		g_ptr_array_add(gpa, g_strdup((gchar *) key));
		g_ptr_array_add(gpa, g_strdup((gchar *) value));
		return FALSE;
	}
	g_tree_foreach(db_properties->system, _add_property_to_gpa, NULL);

	return gpa;
}

gboolean
db_properties_has_system_property(struct db_properties_s *db_properties,
		gchar **properties)
{
	if (!db_properties || !db_properties->system) {
		return FALSE;
	}

	gboolean has_property = FALSE;
	gboolean _is_property(gpointer key, gpointer value UNUSED,
			gpointer data UNUSED) {
		for (gchar **property=properties; *property; property+=1) {
			if (g_strcmp0(key, *property) == 0) {
				has_property = TRUE;
				return TRUE;
			}
		}
		return FALSE;
	}
	g_tree_foreach(db_properties->system, _is_property, NULL);
	return has_property;
}

static gint64 _sqlx_get_number(struct sqlx_sqlite3_s *sq3, const gchar *req) {
	gint64 result = -1;
	gint rc;
	sqlite3_stmt *stmt = NULL;

	sqlite3_prepare_debug(rc, sq3->db, req, -1, &stmt, NULL);
	if (rc == SQLITE_OK) {
		EXTRA_ASSERT(stmt != NULL);
		if (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			result = sqlite3_column_int64(stmt, 0);
		}
	}
	sqlite3_finalize(stmt);
	return result;
}

GPtrArray* sqlx_admin_get_usage(struct sqlx_sqlite3_s *sq3) {
	GPtrArray *result = g_ptr_array_new();

	g_ptr_array_add(result, g_strdup("stats.page_count"));
	g_ptr_array_add(result, g_strdup_printf("%"G_GINT64_FORMAT,
		_sqlx_get_number(sq3, "PRAGMA main.page_count")));


	g_ptr_array_add(result, g_strdup("stats.freelist_count"));
	g_ptr_array_add(result, g_strdup_printf("%"G_GINT64_FORMAT,
		_sqlx_get_number(sq3, "PRAGMA main.freelist_count")));

	g_ptr_array_add(result, g_strdup("stats.page_size"));
	g_ptr_array_add(result, g_strdup_printf("%"G_GINT64_FORMAT,
		_sqlx_get_number(sq3, "PRAGMA main.page_size")));

	return result;
}

GPtrArray* sqlx_admin_get_extra_counters(struct sqlx_sqlite3_s *sq3) {
	GPtrArray *result = g_ptr_array_new();

	/* Specific meta2 counters */
	if (g_strcmp0("meta2", sq3->name.type) == 0) {
		g_ptr_array_add(result, g_strdup("extra_counter.drained"));
		g_ptr_array_add(result, g_strdup_printf("%"G_GINT64_FORMAT,
			_sqlx_get_number(
				sq3, "SELECT COUNT(*) FROM contents WHERE chunk_method = 'drained'"
			)
		));
	}

	return result;
}
