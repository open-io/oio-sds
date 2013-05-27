/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "./meta2_backend_internals.h"

#include <meta2_utils.h>
#include <storage_policy.h>
#include <resolv.h>

#include <meta2_macros.h>
#include <meta2v2_remote.h>
#include <meta2_dedup_utils.h>
#include <generic.h>
#include <autogen.h>
#include <metatypes.h>

#include "../sqliterepo/sqlite_utils.h"

static GError*
_get_container_policy(sqlite3 *db, struct namespace_info_s *nsinfo,
		struct storage_policy_s **result);

static void
gvariant_unrefv(GVariant **v)
{
	if (!v)
		return;
	for (; *v ;v++) {
		g_variant_unref(*v);
		*v = NULL;
	}
}

static gchar*
m2v2_flags(guint32 flags, gchar *d, gsize ds)
{
	memset(d, 0, ds);
	g_snprintf(d, ds, "%08X", flags);
	if (flags & M2V2_FLAG_NOPROPS)
		g_strlcat(d, "|NOPROP", ds);
	if (flags & M2V2_FLAG_NODELETED)
		g_strlcat(d, "|NODEL", ds);
	if (flags & M2V2_FLAG_ALLVERSION)
		g_strlcat(d, "|ALLVER", ds);
	return d;
}

/**
 * @param db
 * @param url
 * @return
 */
static gint64
_m2db_count_alias_versions(sqlite3 *db, struct hc_url_s *url)
{
	int rc;
	gint64 v;
	sqlite3_stmt *stmt = NULL;

	g_assert(db != NULL);
	g_assert(url != NULL);

	v = 0;
	sqlite3_prepare_debug(rc, db,
			"SELECT COUNT(version) FROM aliases WHERE name = ?", -1, &stmt, NULL);
	if (rc == SQLITE_OK) {
		sqlite3_bind_text(stmt, 1, hc_url_get(url, HCURL_PATH), -1, NULL);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			v = sqlite3_column_int64(stmt, 0);
		}
		rc = sqlite3_finalize(stmt);
	}

	return v;
}


gint64
m2db_get_max_versions(sqlite3 *db, gint64 def)
{
	return sqlx_get_int64_admin_value(db, M2V2_PROP_PREFIX_SYS
			M2V2_KEY_VERSIONING_POLICY, def);
}

void
m2db_set_max_versions(sqlite3 *db, gint64 max)
{
	sqlx_set_int64_admin_value(db, M2V2_PROP_PREFIX_SYS
			M2V2_KEY_VERSIONING_POLICY, max);
}

gint64
m2db_get_version(sqlite3 *db)
{
	return sqlx_get_int64_admin_value(db, M2V2_PROP_PREFIX_SYS M2V2_KEY_VERSION, 1);
}


void
m2db_increment_version(sqlite3 *db)
{
	sqlx_increment_admin_int64(db, M2V2_PROP_PREFIX_SYS M2V2_KEY_VERSION);
}

gint64
m2db_get_size(sqlite3 *db)
{
	return sqlx_get_int64_admin_value(db, M2V2_PROP_PREFIX_SYS M2V2_KEY_SIZE, 0);
}

void
m2db_set_size(sqlite3 *db, gint64 size)
{
	return sqlx_set_int64_admin_value(db, M2V2_PROP_PREFIX_SYS
			M2V2_KEY_SIZE, size);
}

gint64
m2db_get_quota(sqlite3 *db, gint64 def)
{
	return sqlx_get_int64_admin_value(db, M2V2_PROP_PREFIX_SYS M2V2_KEY_QUOTA, def);
}

void
m2db_set_quota(sqlite3 *db, gint64 quota)
{
	return sqlx_set_int64_admin_value(db, M2V2_PROP_PREFIX_SYS
			M2V2_KEY_QUOTA, quota);
}

GError*
m2db_save_beans_list(sqlite3 *db, GSList *list)
{
	GError *err = NULL;

	g_assert(db != NULL);
	for (; !err && list ;list=list->next) {
		if (!list->data)
			continue;
		if (GRID_TRACE2_ENABLED()) {
			GString *s = _bean_debug(NULL, list->data);
			GRID_TRACE("M2 saving  %s", s->str);
			g_string_free(s, TRUE);
		}
		err = _db_save_bean(db, list->data);
	}
	return err;
}

/**
 * @param db
 * @param tmp
 * @return
 */
GError*
m2db_save_beans_array(sqlite3 *src, GPtrArray *tmp)
{
	GError *err = NULL;

	g_assert(src != NULL);
	g_assert(tmp != NULL);
	for (guint i=0; !err && i<tmp->len; i++) {
		if (GRID_TRACE_ENABLED()) {
			GString *s = _bean_debug(NULL, tmp->pdata[i]);
			GRID_TRACE("M2 saving  %s", s->str);
			g_string_free(s, TRUE);
		}
		err = _db_save_bean(src, tmp->pdata[i]);
	}
	return err;
}

/* GET ---------------------------------------------------------------------- */

static GError*
_manage_content(sqlite3 *db, struct bean_CONTENTS_HEADERS_s *bean,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err;
	err = _db_get_FK_by_name(bean, "chunk", db, cb, u0);
	cb(u0, bean);
	return err;
}

static GError*
_manage_header(sqlite3 *db, struct bean_CONTENTS_HEADERS_s *bean,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;

	/* Get the contents */
	GPtrArray *tmp = g_ptr_array_new();
	err = _db_get_FK_by_name_buffered(bean, "content", db, tmp);
	if (!err) {
		while (tmp->len > 0) {
			struct bean_CONTENTS_HEADERS_s *header = tmp->pdata[0];
			g_ptr_array_remove_index_fast(tmp, 0);
			if (header)
				_manage_content(db, header, cb, u0);
		}
	}

	_bean_cleanv2(tmp); /* cleans unset beans */

	cb(u0, bean); /* send the content */
	return err;
}

static GError*
_manage_alias(sqlite3 *db, struct bean_ALIASES_s *bean,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;

	/* Get the headers */
	GPtrArray *tmp = g_ptr_array_new();
	err = _db_get_FK_by_name_buffered(bean, "image", db, tmp);
	if (!err) {
		while (tmp->len > 0) {
			struct bean_CONTENTS_HEADERS_s *header = tmp->pdata[0];
			g_ptr_array_remove_index_fast(tmp, 0);
			if (header)
				_manage_header(db, header, cb, u0);
		}
	}

	_bean_cleanv2(tmp); /* cleans unset beans */

	cb(u0, bean); /* send the alias */

	return err;
}

GError*
m2db_get_alias(sqlite3 *db, struct hc_url_s *u, guint32 flags,
		m2_onbean_cb cb, gpointer u0)
{
	gchar d0[64], d1[64];
	static guint32 allowed_mask = M2V2_FLAG_NOPROPS|M2V2_FLAG_NODELETED
			|M2V2_FLAG_ALLVERSION;
	GError *err = NULL;
	GVariant *params[3] = {NULL,NULL,NULL};
	GPtrArray *tmp = g_ptr_array_new();

	/* sanity checks */
	if (!hc_url_has(u, HCURL_PATH))
		return NEWERROR(400, "Missing path");

	GRID_TRACE("GET(%s) Flags got[%s], allowed[%s]", hc_url_get(u, HCURL_WHOLE),
			m2v2_flags(flags, d0, sizeof(d0)),
			m2v2_flags(allowed_mask, d1, sizeof(d1)));

	/* now manage the aliases and recurse on the other types */
	params[0] = g_variant_new_string(hc_url_get(u, HCURL_PATH));
	const gchar *sql = NULL;
	if (flags & M2V2_FLAG_ALLVERSION) {
		sql = "alias = ?";
	}
	else {
		if (hc_url_has(u, HCURL_VERSION)) {
			gchar *s;
			gint64 i64;

			errno = 0;
			s = NULL;
			i64 = g_ascii_strtoll(hc_url_get(u, HCURL_VERSION), &s, 10);
			if (s == hc_url_get(u, HCURL_VERSION) || errno != 0 || i64 <= 0) {
				err = NEWERROR(400, "Invalid version");
			}
			else {
				sql = "alias = ? AND version = ? LIMIT 1";
				params[1] = g_variant_new_int64(i64);
			}
		}
		else {
			sql = "alias = ? ORDER BY version DESC LIMIT 1";
		}
	}

	if (!err) {
		err = ALIASES_load_buffered(db, sql, params, tmp);
	}

	gvariant_unrefv(params);

	if (!err && tmp->len <= 0) {
		err = NEWERROR(CODE_CONTENT_NOTFOUND, "Alias not found");
	}

	if (!err) {
		while (tmp->len > 0) {
			struct bean_ALIASES_s *alias = tmp->pdata[0];
			g_ptr_array_remove_index_fast(tmp, 0);
			if (alias) {
				if ((flags & M2V2_FLAG_NODELETED) && ALIASES_get_deleted(alias))
					_bean_clean(alias);
				else
					_manage_alias(db, alias, cb, u0);
			}
		}
	}

	if (!err && !(flags & M2V2_FLAG_NOPROPS)) {
		/* collect the properties */
		if (NULL != (err = m2db_get_properties(db, u, flags, cb, u0))) {
			g_prefix_error(&err, "Properties error: ");
			return err;
		}
	}

	_bean_cleanv2(tmp); /* cleans unset beans */
	return err;
}

GError*
m2db_list_aliases(sqlite3 *db, guint32 flags, m2_onbean_cb cb, gpointer u)
{
	static guint32 allowed_mask = M2V2_FLAG_NODELETED|M2V2_FLAG_ALLVERSION|M2V2_FLAG_HEADERS;
	const gchar *sql;
	gchar d0[64], d1[64];
	GVariant *params[1] = {NULL};
	GError *err = NULL;

	auto void wrapper(gpointer u0, gpointer bean);
	auto gboolean runner(gpointer k, gpointer v, gpointer u0);

	g_assert(db != NULL);

	GRID_TRACE("LIST Flags got[%s], allowed[%s]",
			m2v2_flags(flags, d0, sizeof(d0)),
			m2v2_flags(allowed_mask, d1, sizeof(d1)));

	sql = (flags & M2V2_FLAG_NODELETED) ? "NOT deleted" : "1";

	if (flags & M2V2_FLAG_HEADERS) {
		GRID_DEBUG("Loading HEADERS");
		if(NULL != (err = CONTENTS_HEADERS_load(db, "1", params, cb, u))) {
			GRID_INFO("Error while loading HEADERS :%s", err->message);
			return err;
		}
	}

	if (flags & M2V2_FLAG_ALLVERSION)
		return ALIASES_load(db, sql, params, cb, u);

	// Store all the aliases in a structure, but only keep the lastest
	// version met. At the end, we just run the tree and forward each
	// element to the caller.

	void wrapper(gpointer u0, gpointer bean) {
		GTree *atree = u0;
		struct bean_ALIASES_s *alias, *found;
		alias = bean;
		found = g_tree_lookup(atree, ALIASES_get_alias(alias)->str);
		if (!found || ALIASES_get_version(alias) > ALIASES_get_version(found)) {
			g_tree_replace(atree, g_strdup(ALIASES_get_alias(alias)->str), alias);
			if (found)
				_bean_clean(found);
		}
		else {
			_bean_clean(alias);
		}
	}
	gboolean runner(gpointer k, gpointer v, gpointer u0) {
		(void) k;
		cb(u0, v);
		return FALSE;
	}

	GTree *atree = g_tree_new_full(metautils_strcmp3, NULL, g_free, NULL);
	err = ALIASES_load(db, sql, params, wrapper, atree);
	if (!err)
		g_tree_foreach(atree, runner, u);
	g_tree_destroy(atree);
	return err;
}

GError*
m2db_get_alias_version(sqlite3 *db, struct hc_url_s *url, guint32 flags,
		gint64 *version)
{
	GError *err = NULL;
	struct bean_ALIASES_s *latest = NULL;

	(void) flags;
	if (NULL != (err = m2db_latest_alias(db, url, (gpointer*)(&latest)))) {
		g_prefix_error(&err, "Latest error: ");
		return err;
	}

	if (!latest)
		return NEWERROR(CODE_CONTENT_NOTFOUND, "Alias not found");

	*version = ALIASES_get_version(latest);
	_bean_clean(latest);
	return NULL;
}

GError*
m2db_get_versioned_alias(sqlite3 *db, struct hc_url_s *url, gpointer *result)
{
	GError *err;
	GPtrArray *tmp;
	GVariant *params[3] = { NULL, NULL, NULL };

	g_assert(db != NULL);
	g_assert(url != NULL);
	g_assert(result != NULL);

	if (!hc_url_has(url, HCURL_PATH))
		return NEWERROR(400, "Missing path");
	if (!hc_url_has(url, HCURL_VERSION))
		return NEWERROR(400, "Missing version");

	tmp = g_ptr_array_new();
	params[0] = g_variant_new_string(hc_url_get(url, HCURL_PATH));
	params[1] = g_variant_new_string(hc_url_get(url, HCURL_VERSION));
	err = _db_get_bean(&descr_struct_ALIASES, db,
			"alias=? AND version=? LIMIT 1",
			params, _bean_buffer_cb, tmp);
	gvariant_unrefv(params);

	if (!tmp->len)
		*result = NULL;
	else {
		*result = tmp->pdata[0];
		g_ptr_array_remove_index_fast(tmp, 0);
	}

	_bean_cleanv2(tmp);
	return err;
}

GError*
m2db_latest_alias(sqlite3 *db,  struct hc_url_s *url, gpointer *result)
{
	GError *err;
	GPtrArray *tmp;
	GVariant *params[2] = { NULL, NULL };

	g_assert(db != NULL);
	g_assert(url != NULL);
	g_assert(result != NULL);

	if (!hc_url_has(url, HCURL_PATH))
		return NEWERROR(400, "Missing path");

	tmp = g_ptr_array_new();
	params[0] = g_variant_new_string(hc_url_get(url, HCURL_PATH));
	err = _db_get_bean(&descr_struct_ALIASES, db,
			"alias=? ORDER BY version DESC LIMIT 1",
			params, _bean_buffer_cb, tmp);
	g_variant_unref(params[0]);

	if (!tmp->len)
		*result = NULL;
	else {
		*result = tmp->pdata[0];
		g_ptr_array_remove_index_fast(tmp, 0);
	}

	_bean_cleanv2(tmp);
	return err;
}

GError*
m2db_delete_content(sqlite3 *db, gpointer content)
{
	GError *e = NULL;
	sqlite3_stmt *stmt = NULL;
	int rc;

	sqlite3_prepare_debug(rc, db, "DELETE FROM content_v2 WHERE chunk_id = ? AND content_id = ?", -1, &stmt, NULL);

	sqlite3_clear_bindings(stmt);
	sqlite3_reset(stmt);
	sqlite3_bind_text(stmt, 1, CONTENTS_get_chunk_id(content)->str,
			CONTENTS_get_chunk_id(content)->len, NULL);
	sqlite3_bind_blob(stmt, 2, CONTENTS_get_content_id(content)->data,
			CONTENTS_get_content_id(content)->len, NULL);
	while (SQLITE_ROW == (rc = sqlite3_step(stmt))) { 
		if (rc != SQLITE_OK && rc != SQLITE_DONE) {
			e = NEWERROR(500, "SQLite error: (%d) %s", rc, sqlite3_errmsg(db));
		}
	}

	(void) sqlite3_finalize(stmt);

	return e;
}



/* PROPERTIES --------------------------------------------------------------- */

struct prop_ctx_s
{
	GTree *done;
	m2_onbean_cb cb;
	gpointer cb_data;
	guint32 flags;
};

static void
_filter_properties(gpointer u, gpointer bean)
{
	struct prop_ctx_s *ctx = u;
	struct bean_PROPERTIES_s *found;

	found = g_tree_lookup(ctx->done, PROPERTIES_get_key(bean)->str);
	if (!found) {
		g_tree_replace(ctx->done, g_strdup(PROPERTIES_get_key(bean)->str), bean);
		return;
	}

	gint64 vprop = PROPERTIES_get_alias_version(bean);
	gint64 vfound = PROPERTIES_get_alias_version(found);
	if (vprop > vfound) {
		g_tree_replace(ctx->done, g_strdup(PROPERTIES_get_key(bean)->str), bean);
		_bean_clean(found);
	}
	else {
		_bean_clean(bean);
	}
}

static gboolean
_forward_properties(gpointer k, gpointer v, gpointer u)
{
	struct prop_ctx_s *ctx = u;

	(void) k;
	if (!(ctx->flags & M2V2_FLAG_NODELETED) || !PROPERTIES_get_deleted(v)) {
		ctx->cb(ctx->cb_data, v);
	}
	else {
		_bean_clean(v);
	}

	return FALSE;
}

GError*
m2db_get_property(sqlite3 *db, struct hc_url_s *url, const gchar *prop_name, guint32 flags,
		m2_onbean_cb cb, gpointer u0)
{
	gint64 version = -1;
	GError *err = NULL;

	do { // Ensure the ALIAS exists
		struct bean_ALIASES_s *latest = NULL;
		if (NULL != (err = m2db_latest_alias(db, url, (gpointer*)&latest)))
			return err;
		if (!latest)
			return NEWERROR(CODE_CONTENT_NOTFOUND, "Alias not found");
		if (ALIASES_get_deleted(latest)) {
			_bean_clean(latest);
			return NULL;
		}
		_bean_clean(latest);
	} while (0);

	if (hc_url_has(url, HCURL_VERSION)) {
		version = g_ascii_strtoll(hc_url_get(url, HCURL_VERSION), NULL, 10);
	}

	// Generate a SQL query matching the URL and the FLAGS
	GVariant *params[4] = {NULL,NULL,NULL,NULL};
	guint param_count = 0;
	const gchar *cl_alias = "alias = ?";
	const gchar *cl_version = "";
	const gchar *cl_propname = "";
	const gchar *cl_del ="";

	params[param_count++] = g_variant_new_string(hc_url_get(url, HCURL_PATH));

	if (version > 0) {
		cl_version = " AND alias_version <= ?";
		params[param_count++] = g_variant_new_int64(version);
	}

	if (prop_name && *prop_name) {
		cl_propname = " AND key = ?";
		params[param_count++] = g_variant_new_string(prop_name);
	}

	gchar *clause = g_strconcat(cl_alias, cl_version, cl_propname, cl_del, NULL);

	// Now perform the SELECT
	if (!err) {
		if (flags & M2V2_FLAG_ALLVERSION) {
			err = _db_get_bean(&descr_struct_PROPERTIES, db, clause, params,
					cb, u0);
		}
		else {
			// Filter the properties ourself, SQLite is not able to do it.
			// So we wrap the original callback
			struct prop_ctx_s ctx;
			ctx.done = g_tree_new_full(metautils_strcmp3, NULL, g_free, NULL);
			ctx.cb = cb;
			ctx.cb_data = u0;
			ctx.flags = flags & M2V2_FLAG_NODELETED;
			err = _db_get_bean(&descr_struct_PROPERTIES, db, clause, params,
					_filter_properties, &ctx);
			if (!err)
				g_tree_foreach(ctx.done, _forward_properties, &ctx);
			g_tree_destroy(ctx.done);
		}
	}

	g_free(clause);
	gvariant_unrefv(params);
	return err;
}

GError*
m2db_get_properties(sqlite3 *db, struct hc_url_s *url, guint32 flags,
		m2_onbean_cb cb, gpointer u0)
{
	return m2db_get_property(db, url, NULL, flags, cb, u0);
}

GError*
m2db_set_properties(sqlite3 *db, gint64 max_versions, struct hc_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err;
	struct bean_ALIASES_s *latest = NULL;

	if (!beans)
		return NEWERROR(400, "No properties");
	if (NULL != (err = m2db_latest_alias(db, url, (gpointer*)(&latest))))
		return err;
	if (!latest)
		return NEWERROR(CODE_CONTENT_NOTFOUND, "Alias not found");

	if (ALIASES_get_deleted(latest))
		err = NEWERROR(CODE_CONTENT_NOTFOUND, "Alias deleted");

	if (!err) {
		gint64 base_version = m2db_get_version(db);
		gint64 version = ALIASES_get_version(latest);
		if (VERSIONS_ENABLED(max_versions)) {
			/* Make a new alias revision */
			base_version++;
			version++;

			ALIASES_set_container_version(latest, base_version);
			ALIASES_set_version(latest, version);

			if (!(err = _db_save_bean(db, latest))) {
				if (cb) {
					cb(u0, latest);
					latest = NULL;
				}
			}
		}

		/* Save each property bean */
		for (; !err && beans ;beans=beans->next) {

			struct bean_PROPERTIES_s *prop = beans->data;

			if (DESCR(prop) != &descr_struct_PROPERTIES) {
				/* We discard any non-property bean */
				continue;
			}

			prop = _bean_dup(prop);
			PROPERTIES_set2_alias(prop, hc_url_get(url, HCURL_PATH));
			PROPERTIES_set_alias_version(prop, version);
			err = _db_save_bean(db, prop);
			if (err || !cb)
				_bean_clean(prop);
			else
				cb(u0, prop);
		}
	}

	_bean_clean(latest);
	return err;
}

GError*
m2db_get_container_properties(sqlite3 *db, guint32 flags, gpointer cb_data,
		m2_onprop_cb cb)
{
	int rc;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;

	g_assert(db != NULL);

	sqlite3_prepare_debug(rc, db, "SELECT k, v FROM admin", -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		err = M2_SQLITE_GERROR(db, rc);
	}
	else {
		while (SQLITE_ROW == sqlite3_step(stmt)) {
			if (!cb)
				continue;
			const gchar *k = (gchar*)sqlite3_column_text(stmt, 0);
			if (!(flags & M2V2_FLAG_ALLPROPS)) {
				if (!g_str_has_prefix(k, M2V2_PROP_PREFIX_SYS)
						&& !g_str_has_prefix(k, M2V2_PROP_PREFIX_USER))
					continue;
			}
			if (!cb(cb_data, k,
						(guint8*)sqlite3_column_blob(stmt, 1),
						sqlite3_column_bytes(stmt, 1)))
				break;
		}
		(void) sqlite3_finalize(stmt);
	}
	return err;
}

GError*
m2db_set_container_properties(sqlite3 *db, guint32 flags, GSList *props)
{
	int rc, delete = 0;
	GError *err = NULL;
	GSList *l = NULL;
	sqlite3_stmt *stmt = NULL;

	g_assert(db != NULL);

	/* Properties to be inserted/updated */
	sqlite3_prepare_debug(rc, db, "REPLACE INTO admin(k,v) VALUES (?,?)", -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		err = M2_SQLITE_GERROR(db, rc);
	}
	else {
		for (l = props; !err && l;l=l->next) {
			struct meta2_property_s *m2p = NULL;

			if (!(m2p = l->data) || !m2p->name || !m2p->value) {
				delete = delete || (m2p->value == NULL);
				continue;
			}

			if (!(flags && M2V2_FLAG_NOFORMATCHECK)) {
				if (!g_str_has_prefix(m2p->name, M2V2_PROP_PREFIX_USER)
						&& !g_str_has_prefix(m2p->name, M2V2_PROP_PREFIX_SYS))
					continue;
			}

			sqlite3_clear_bindings(stmt);
			sqlite3_reset(stmt);
			sqlite3_bind_text(stmt, 1, m2p->name, -1, NULL);
			sqlite3_bind_blob(stmt, 2, m2p->value->data, m2p->value->len, NULL);

			while (SQLITE_ROW == (rc = sqlite3_step(stmt))) { }
			if (rc != SQLITE_OK && rc != SQLITE_DONE) {
				err = NEWERROR(500, "SQLite error: (%d) %s", rc, sqlite3_errmsg(db));
			}
		}
		(void) sqlite3_finalize(stmt);
	}

	/* Properties to be deleted */
	if (!err && delete) {
		sqlite3_prepare_debug(rc, db, "DELETE FROM admin WHERE k = ?", -1, &stmt, NULL);
		for (l = props; !err && l ;l=l->next) {
			struct meta2_property_s *m2p = NULL;

			if (!(m2p = l->data) || !m2p->name || NULL != m2p->value)
				continue;

			if (!g_str_has_prefix(m2p->name, M2V2_PROP_PREFIX_USER)
					&& !g_str_has_prefix(m2p->name, M2V2_PROP_PREFIX_SYS))
				continue;

			sqlite3_clear_bindings(stmt);
			sqlite3_reset(stmt);
			sqlite3_bind_text(stmt, 1, m2p->name, strlen(m2p->name), NULL);

			while (SQLITE_ROW == (rc = sqlite3_step(stmt))) { }
			if (rc != SQLITE_OK && rc != SQLITE_DONE) {
				err = NEWERROR(500, "SQLite error: (%d) %s", rc, sqlite3_errmsg(db));
			}
		}
		(void) sqlite3_finalize(stmt);
	}

	return err;
}

GError*
m2db_get_all_properties(sqlite3 *db, const gchar *k, guint32 flags,
		m2_onbean_cb cb, gpointer u0)
{
	GVariant *params[2] = {NULL,NULL};
	GError *err;

	(void) flags;

	params[0] = g_variant_new_string(k);
	err = PROPERTIES_load(db, "key = ?", params, cb, u0);
	g_variant_unref(params[0]);
	return err;
}

GError*
m2db_del_property(sqlite3 *db, struct hc_url_s *url, const gchar *k)
{
	guint i;
	GError *err;
	GPtrArray *tmp;

	g_assert(db != NULL);
	g_assert(url != NULL);
	g_assert(k != NULL);

	tmp = g_ptr_array_new();
	err = m2db_get_property(db, url, k, M2V2_FLAG_NODELETED, _bean_buffer_cb, tmp);
	if (!err) {
		for (i=0; !err && i<tmp->len ;++i) {
			gpointer bean = tmp->pdata[i];
			PROPERTIES_set_deleted(bean, TRUE);
			err = _db_save_bean(db, bean);
		}
	}

	_bean_cleanv2(tmp);
	return err;
}

GError*
m2db_flush_property(sqlite3 *db, const gchar *k)
{
	GVariant *params[] = { NULL, NULL };
	GError *err;

	params[0] = g_variant_new_string(k);
	err = PROPERTIES_delete(db, "key = ?", params);
	g_variant_unref(params[0]);

	GRID_DEBUG("%i services deleted", sqlite3_changes(db));
	return err;
}


/* VIEWS -------------------------------------------------------------------- */

GError*
m2db_filter_alias(sqlite3 *src, sqlite3 *dst, struct hc_url_s *url,
		guint32 flags)
{
	auto void cb(gpointer u, gpointer bean);

	void cb(gpointer u, gpointer bean) {
		_db_save_bean((sqlite3*)u, bean);
	}
	return m2db_get_alias(src, url, flags, cb, dst);
}

GError*
m2db_check_alias_view(sqlite3 *db, struct hc_url_s *url)
{
	gchar *sql;
	int rc, count_expected;

	auto int cb_count(void *u, int nbcols, char **cols, char **names);

	int cb_count(void *u, int nbcols, char **cols, char **names) {
		(void) names;
		g_assert(nbcols == 1);
		return !(atoi(cols[0]) >= *((int*)u));
	}
	(void) url;

	if (!hc_url_has(url, HCURL_PATH))
		return NEWERROR(400, "Missing path");

	/* Check the alias exist */
	sql = g_strdup_printf("SELECT COUNT(*) FROM %s", descr_struct_ALIASES.sql_name);
	count_expected = 1;
	rc = sqlite3_exec(db, sql, cb_count, &count_expected, NULL);
	g_free(sql);

	switch (rc) {
		case SQLITE_ABORT:
			return NEWERROR(CODE_CONTENT_NOTFOUND, "Alias not found");
		case 0:
			break;
		default:
			return NEWERROR(500, "SQLite error: %s", sqlite3_errmsg(db));
	}

	/* Check it has a content_header*/
	sql = g_strdup_printf("SELECT COUNT(*) FROM %s",
			descr_struct_CONTENTS_HEADERS.sql_name);
	count_expected = 1;
	rc = sqlite3_exec(db, sql, cb_count, &count_expected, NULL);
	g_free(sql);

	switch (rc) {
		case SQLITE_ABORT:
			return NEWERROR(CODE_CONTENT_NOTFOUND, "ContentHeader not found");
		case 0:
			break;
		default:
			return NEWERROR(500, "SQLite error: %s", sqlite3_errmsg(db));
	}

	/* Check it has a content */
	sql = g_strdup_printf("SELECT COUNT(*) FROM %s", descr_struct_CONTENTS.sql_name);
	count_expected = 1;
	rc = sqlite3_exec(db, sql, cb_count, &count_expected, NULL);
	g_free(sql);

	switch (rc) {
		case SQLITE_ABORT:
			return NEWERROR(CODE_CONTENT_NOTFOUND, "Content not found");
		case 0:
			break;
		default:
			return NEWERROR(500, "SQLite error: %s", sqlite3_errmsg(db));
	}

	/* Check it has the chunks */

	return NULL;
}

GError*
m2db_get_alias_view(sqlite3 *src, sqlite3 **dst, struct hc_url_s *url,
		guint32 flags)
{
	sqlite3 *view = NULL;
	GError *err;

	if (!hc_url_has(url, HCURL_PATH))
		return NEWERROR(400, "Missing path");

	if (!(err = m2db_create_view(&view))) {
		if (!(err = m2db_filter_alias(src, view, url, flags))) {
			*dst = view;
			return NULL;
		}
		sqlite3_close(view);
	}

	return err;
}

GError*
m2db_create_view(sqlite3 **res)
{
	sqlite3 *view = NULL;

	sqlite3_open(":memory:", &view);
	sqlite3_exec(view, schema, NULL, NULL, NULL);
	*res = view;

	return NULL;
}


/* CHECK -------------------------------------------------------------------- */

GError*
m2db_check_alias(sqlite3 *db, struct hc_url_s *url)
{
	GError *err;
	sqlite3 *view = NULL;

	if (!hc_url_has(url, HCURL_PATH))
		return NEWERROR(400, "Missing path");

	err = m2db_get_alias_view(db, &view, url, M2V2_FLAG_NODELETED);
	if (!err)
		err = m2db_check_alias_view(view, url);
	sqlite3_close(view);

	return err;
}

GError*
m2db_check_alias_beans_list(struct hc_url_s *url, GSList *beans)
{
	GError *err;
	sqlite3 *view = NULL;

	if (!beans)
		return NEWERROR(400, "no bean");
	if (!hc_url_has(url, HCURL_PATH))
		return NEWERROR(400, "Missing path");

	err = m2db_create_view(&view);
	if (!err) {
		if (!(err = m2db_save_beans_list(view, beans))) {
			GRID_TRACE("Beans saved, checking view");
			err = m2db_check_alias_view(view, url);
		} else {
			GRID_TRACE("Error while saving beans list");
		}
		sqlite3_close(view);
	}

	return err;
}



/* DELETE ------------------------------------------------------------------- */

static GError*
_real_delete(sqlite3 *db, gint64 max_versions, struct bean_ALIASES_s *alias)
{
	char tmp[512];
	memset(tmp, '\0', 512);
	g_snprintf(tmp, 512, "DELETE from alias_v2 WHERE alias = \"%s\" "
			"and version = \"%"G_GINT64_FORMAT"\"", ALIASES_get_alias(alias)->str,
			ALIASES_get_version(alias)); 
	sqlx_exec(db, tmp);
	/* delete other part (last params NULL, chunk will not be deleted) */
	return m2db_purge(db, max_versions, NULL);
}

GError*
m2db_delete_alias(sqlite3 *db, gint64 max_versions, struct hc_url_s *url,
	m2_onbean_cb cb, gpointer u0)
{
	auto void _search_alias_and_size(gpointer ignored, gpointer bean);

	GError *err;
	struct bean_ALIASES_s *alias = NULL;
	gint64 size = 0;

	void _search_alias_and_size(gpointer ignored, gpointer bean)
	{
		(void) ignored;
		if(DESCR(bean) == &descr_struct_ALIASES) {
			alias = bean;
		} else if(DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
			size = CONTENTS_HEADERS_get_size(bean);
			_bean_clean(bean);
		} else {
			_bean_clean(bean);
		}
	}

	if (VERSIONS_DISABLED(max_versions) && hc_url_has(url, HCURL_VERSION)) {
		return NEWERROR(400, "Versioning not supported and version specified");
	}

	if (hc_url_has(url, HCURL_VERSION)) {
		if (NULL != (err = m2db_get_versioned_alias(db, url, (gpointer*)(&alias))))
			return err;
	}
	else {
		if (NULL != (err = m2db_get_alias(db, url, M2V2_FLAG_NOPROPS|M2V2_FLAG_NODELETED,
				_search_alias_and_size, NULL)))
			return err;
	}

	if (!alias) {
		return NEWERROR(CODE_CONTENT_NOTFOUND, "No content to delete");
	}

	gint64 alias_version;
	struct bean_ALIASES_s *deleted;

	// Mark the alias itself as DELETED
	alias_version = ALIASES_get_version(alias);

	if(VERSIONS_DISABLED(max_versions)) {
		/* delete alias */
		err = _real_delete(db, max_versions, alias);
	} else {
		deleted = _bean_dup(alias);
		ALIASES_set_deleted(deleted, TRUE);
		ALIASES_set_container_version(deleted, 1+m2db_get_version(db));
		if (!(err = _db_save_bean(db, deleted))) {
			if (cb) {
				cb(u0, deleted);
			}
			else {
				_bean_clean(deleted);
			}
		}

		// Now ensure that properties for this alias have a DELETED version for
		// the current version.
		if (!err) {
			GPtrArray *tmp = g_ptr_array_new();
			err = m2db_get_properties(db, url, 0, _bean_buffer_cb, tmp);
			for (guint i=0; !err && i<tmp->len ;i++) {
				struct bean_PROPERTIES_s *prop = tmp->pdata[i];
				PROPERTIES_set_alias_version(prop, alias_version);
				PROPERTIES_set_deleted(prop, TRUE);
				err = _db_save_bean(db, prop);
			}
			_bean_cleanv2(tmp);
		}

	}

	m2db_set_size(db, m2db_get_size(db) - size);

	_bean_clean(alias);
	return err;
}

/* PUT commons -------------------------------------------------------------- */

struct put_args_s
{
	struct m2db_put_args_s *pargs;
	guint8 *uid;
	gsize uid_size;

	gint64 version;
	gint64 count_version;

	m2_onbean_cb cb;
	gpointer cb_data;

	GSList *beans;
	gboolean merge_only;
};

static GError*
m2db_real_put_alias(sqlite3 *db, struct put_args_s *args)
{
	gint64 container_version;
	GError *err = NULL;
	GSList *l;

	container_version = 1 + m2db_get_version(db);

	for (l=args->beans; !err && l ;l=l->next) {
		gpointer bean = l->data;

		if (!l->data)
			continue;

		if (DESCR(bean) == &descr_struct_ALIASES) {
			if (args->merge_only)
				continue;
			/* reset the alias version and remap the header'is */
			ALIASES_set_version(bean, args->version+1);
			ALIASES_set2_content_id(bean, args->uid, args->uid_size);
			ALIASES_set_container_version(bean, container_version);
			ALIASES_set_deleted(bean, FALSE);
			ALIASES_set_ctime(bean, time(0));
			/* ensures mandatory fields are present on the metadata */
			GHashTable *ht;
			GString *gstr = ALIASES_get_mdsys(bean);
			ht = gstr ? metadata_unpack_string(gstr->str, NULL)
				: metadata_create_empty();
			metadata_add_time(ht, "creation-date", NULL);
			if (!g_hash_table_lookup(ht,"chunk-method"))
				metadata_add_printf(ht,"chunk-method","chunk-size");
			if (!g_hash_table_lookup(ht,"mime-type"))
				metadata_add_printf(ht,"mime-type","octet/stream");
			GByteArray *gba = metadata_pack(ht, NULL);
			g_byte_array_append(gba, (guint8*)"", 1);
			ALIASES_set2_mdsys(bean, (gchar*) gba->data);
			g_byte_array_unref(gba);
			g_hash_table_destroy(ht);
		}
		else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
			if (args->merge_only)
				continue;
			/* remap the header's id */
			CONTENTS_HEADERS_set2_id(bean, args->uid, args->uid_size);
		}
		else if (DESCR(bean) == &descr_struct_CONTENTS) {
			/* remap the contant_header id to a unique value */
			CONTENTS_set2_content_id(bean, args->uid, args->uid_size);
		}

		err = _db_save_bean(db, bean);
	}

	if (!err && args->cb) {
		for (l=args->beans; l ;l=l->next)
			args->cb(args->cb_data, _bean_dup(l->data));
	}

	return err;
}

static GError*
m2db_merge_alias(sqlite3 *db, struct bean_ALIASES_s *latest,
		struct put_args_s *args)
{
	auto void cb(gpointer u0, gpointer bean);

	void cb(gpointer u0, gpointer bean) {
		GByteArray **pgba = u0;
		if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
			GByteArray *gba = CONTENTS_HEADERS_get_id(bean);
			if (!*pgba)
				*pgba = g_byte_array_new();
			else
				g_byte_array_set_size(*pgba, 0);
			g_byte_array_append(*pgba, gba->data, gba->len);
		}
		_bean_clean(bean);
	}

	GError *err = NULL;;
	GByteArray *gba = NULL;

	/* Extract the CONTENT_HEADER id in place */
	g_assert(latest != NULL);
	if (NULL != (err = _db_get_FK_by_name(latest, "image", db, cb, &gba)))
		g_prefix_error(&err, "DB error: ");
	else {
		if (gba == NULL)
			err = NEWERROR(500, "HEADER not found");
		else {
			args->merge_only = TRUE;
			args->uid = gba->data;
			args->uid_size = gba->len;
			err = m2db_real_put_alias(db, args);
		}
	}

	if (gba)
		g_byte_array_free(gba, TRUE);
	return err;
}


/* PUT ---------------------------------------------------------------------- */

static gint64
m2db_patch_alias_beans_list(struct m2db_put_args_s *args,
		GSList *beans)
{
	gchar policy[256];
	GSList *l;
	gint64 size = 0;

	g_assert(args != NULL);

	/* ensure a storage policy and store the result */
	for (l=beans; l ;l=l->next) {
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
				err = _get_container_policy(args->db, &(args->nsinfo), &pol);
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

	/* write the storage policy in the system metadata */
	/*for (l=beans; l ;l=l->next) {
		gpointer bean;
		if (!(bean = l->data))
			continue;
		if (DESCR(bean) == &descr_struct_ALIASES) {
			GHashTable *md;

			do {
				GString *gstr = ALIASES_get_mdsys(bean);
				if (!gstr || gstr->len <= 0)
					md = metadata_create_empty();
				else
					md = metadata_unpack_string(gstr->str, NULL);
			} while (0);

			g_hash_table_replace(md, g_strdup("storage-policy"), g_strdup(policy));

			GByteArray *packed = metadata_pack(md, NULL);
			g_byte_array_append(packed, (guint8*)"", 1);
			ALIASES_set2_mdsys(bean, (gchar*)packed->data);
			g_hash_table_destroy(md);
			g_byte_array_free(packed, TRUE);
		}
	}*/
	return size;
}

GError*
m2db_force_alias(sqlite3 *db, struct hc_url_s *url, GSList *beans)
{
	guint8 uid[33];
	struct put_args_s args;
	struct bean_ALIASES_s *latest = NULL;
	GError *err = NULL;

	g_assert(db != NULL);
	g_assert(url != NULL);
	if (!hc_url_has(url, HCURL_PATH))
		return NEWERROR(400, "Missing path");

	memset(&args, 0, sizeof(args));
	args.beans = beans;

	if (NULL != (err = m2db_latest_alias(db, url, (gpointer*)&latest))) {
		if (err->code != CODE_CONTENT_NOTFOUND)
			g_prefix_error(&err, "Version error: ");
		else {
			g_clear_error(&err);
			SHA256_randomized_buffer(uid, sizeof(uid));
			args.uid = uid;
			args.uid_size = sizeof(uid);
			err = m2db_real_put_alias(db, &args);
		}
	}
	else {
		if (latest)
			err = m2db_merge_alias(db, latest, &args);
		else {
			SHA256_randomized_buffer(uid, sizeof(uid));
			args.uid = uid;
			args.uid_size = sizeof(uid);
			err = m2db_real_put_alias(db, &args);
		}
	}

	return err;
}

GError*
m2db_put_alias(struct m2db_put_args_s *args, GSList *beans,
		m2_onbean_cb cb, gpointer u0)
{
	struct put_args_s args2;
	struct bean_ALIASES_s *latest = NULL;
	guint8 uid[32];
	GError *err = NULL;

	memset(&args2, 0, sizeof(args2));
	memset(uid, 0, sizeof(uid));

	GRID_TRACE("M2 PUT(%s)", hc_url_get(args->url, HCURL_WHOLE));
	g_assert(args != NULL);
	g_assert(args->db != NULL);
	g_assert(args->url != NULL);
	if (!hc_url_has(args->url, HCURL_PATH))
		return NEWERROR(400, "Missing path");

	gint64 size = m2db_patch_alias_beans_list(args, beans);

	if (NULL != (err = m2db_check_alias_beans_list(args->url, beans))) {
		g_prefix_error(&err, "Invalid beans: ");
		err->code = 400;
		return err;
	}

	SHA256_randomized_buffer(uid, sizeof(uid));
	args2.pargs = args;
	args2.uid = uid;
	args2.uid_size = sizeof(uid);
	args2.cb = cb;
	args2.cb_data = u0;
	args2.beans = beans;

	if (NULL != (err = m2db_latest_alias(args->db, args->url, (gpointer*)&latest))) {
		if (err->code == CODE_CONTENT_NOTFOUND)
			g_clear_error(&err);
		else
			g_prefix_error(&err, "Version error: ");
	}
	else if (latest) { /* alias present  */
		gint64 count_versions = _m2db_count_alias_versions(args->db, args->url);
		args2.version = ALIASES_get_version(latest);

		if (args->max_versions < 0) { /* versioning disabled */
			if (!ALIASES_get_deleted(latest)) { /* content online */
				err = NEWERROR(CODE_CONTENT_EXISTS,
						"Versioning disabled and content already available");
			}
		}
		else { /* versioning enabled */
			if (args->max_versions <= count_versions + 1) {
				GRID_DEBUG("About to exceed the maximum of version for [%s]",
						hc_url_get(args->url, HCURL_WHOLE));
				/** @todo TODO trigger a purge on this URL */
			}
		}
	}

	if (!err) {
		err = m2db_real_put_alias(args->db, &args2);
		if(!err)
			m2db_set_size(args->db, m2db_get_size(args->db) + size);
	}

	if (latest)
		_bean_clean(latest);
	return err;
}


/* APPEND ------------------------------------------------------------------- */

struct append_context_s
{
	GPtrArray *tmp;
	guint8 uid[32];
	GString *md;
	GString *policy;
	gint64 container_version;
	gint64 old_version;
	gint64 old_count;
	gint64 old_size;
	gboolean fresh;
	gboolean versioning;
};

static void
_increment_position(GString *encoded_position, gint64 inc)
{
	gchar tail[128];
	gchar *end = NULL;
	gint64 pos;

	memset(tail, 0, sizeof(tail));
	pos = g_ascii_strtoll(encoded_position->str, &end, 10);
	g_strlcpy(tail, end, sizeof(tail));

	g_string_printf(encoded_position, "%"G_GINT64_FORMAT"%s", pos+inc, tail);
}

static void
_keep_old_bean(gpointer u, gpointer bean)
{
	struct append_context_s *ctx = u;
	GString *gs;
	gint64 i64;

	if (DESCR(bean) == &descr_struct_CONTENTS) {
		CONTENTS_set2_content_id(bean, ctx->uid, sizeof(ctx->uid));
		if (NULL != (gs = CONTENTS_get_position(bean))) {
			i64 = g_ascii_strtoll(gs->str, NULL, 10);
			if (ctx->old_count < i64)
				ctx->old_count = i64;
		}
		g_ptr_array_add(ctx->tmp, bean);
	}
	else {
		if (DESCR(bean) == &descr_struct_ALIASES) {
			/* get the most up-to-date version */
			i64 = ALIASES_get_version(bean);
			if (ctx->old_version < i64) {
				ctx->old_version = i64;
				/* get the most up-to-date metadata */
				if (NULL != (gs = ALIASES_get_mdsys(bean))) {
					g_string_assign(ctx->md, gs->str);
				}
			}
		}
		else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
			ctx->old_size = CONTENTS_HEADERS_get_size(bean);
			if (NULL != (gs = CONTENTS_HEADERS_get_policy(bean))) {
				g_string_assign(ctx->policy, gs->str);
			}
		}
		_bean_clean(bean);
	}
}

static gboolean
_mangle_new_bean(struct append_context_s *ctx, gpointer bean)
{
	if (DESCR(bean) == &descr_struct_ALIASES) {
		bean = _bean_dup(bean);
		ALIASES_set_container_version(bean, ctx->container_version);
		ALIASES_set_version(bean, ((ctx->versioning) ? ctx->old_version + 1 : ctx->old_version));
		ALIASES_set2_content_id(bean, ctx->uid, sizeof(ctx->uid));
		ALIASES_set_mdsys(bean, ctx->md);
		g_ptr_array_add(ctx->tmp, bean);
		return FALSE;
	}

	if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
		bean = _bean_dup(bean);
		CONTENTS_HEADERS_set_size(bean, CONTENTS_HEADERS_get_size(bean) + ctx->old_size);
		CONTENTS_HEADERS_set2_id(bean, ctx->uid, sizeof(ctx->uid));
		CONTENTS_HEADERS_set2_policy(bean, ctx->policy->str);
		CONTENTS_HEADERS_nullify_hash(bean);
		g_ptr_array_add(ctx->tmp, bean);
		return TRUE;
	}

	if (DESCR(bean) == &descr_struct_CONTENTS) {
		bean = _bean_dup(bean);
		_increment_position(CONTENTS_get_position(bean), ctx->old_count);
		CONTENTS_set2_content_id(bean, ctx->uid, sizeof(ctx->uid));
		g_ptr_array_add(ctx->tmp, bean);
		return FALSE;
	}

	if (DESCR(bean) == &descr_struct_CHUNKS) {
		bean = _bean_dup(bean);
		g_ptr_array_add(ctx->tmp, bean);
		return FALSE;
	}

	/* other bean types are ignored and discarded */
	return FALSE;
}

GError*
m2db_append_to_alias(sqlite3 *db, gint64 max_versions,
		struct hc_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0)
{
	struct append_context_s ctx;
	GError *err = NULL;

	// Sanity checks
	GRID_TRACE("M2 APPEND(%s)", hc_url_get(url, HCURL_WHOLE));
	g_assert(db != NULL);
	g_assert(url != NULL);
	if (!hc_url_has(url, HCURL_PATH))
		return NEWERROR(400, "Missing path");
	if (NULL != (err = m2db_check_alias_beans_list(url, beans))) {
		g_prefix_error(&err, "Invalid beans: ");
		err->code = 400;
		return err;
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.tmp = g_ptr_array_new();
	ctx.md = g_string_new("");
	ctx.policy = g_string_new("");
	ctx.old_count = G_MININT64;
	ctx.old_version = G_MININT64;
	ctx.old_size = G_MININT64;
	ctx.versioning = VERSIONS_ENABLED(max_versions);
	SHA256_randomized_buffer(ctx.uid, sizeof(ctx.uid));

	// Merge the previous versions of the beans with the new part
	err = m2db_get_alias(db, url, M2V2_FLAG_NOPROPS, _keep_old_bean, &ctx);
	if (err) {
		if (err->code == CODE_CONTENT_NOTFOUND) {
			if (!VERSIONS_ENABLED(max_versions)) {
				g_prefix_error(&err, "Content not found and versions disabled");
			}
			else {
				ctx.fresh = TRUE;
				g_clear_error(&err);
				/* renew the buffer */
				_bean_cleanv2(ctx.tmp);
				ctx.tmp = g_ptr_array_new();
			}
		}
	}
	else if (!VERSIONS_ENABLED(max_versions) && ctx.tmp->len <= 0) {
		err = NEWERROR(CODE_CONTENT_NOTFOUND, "No content and versions disabled");
	}

	/* Append the old beans that will be kept */
	if (!err) {
		if (ctx.fresh) {
			struct m2db_put_args_s args;
			memset(&args, 0, sizeof(args));
			args.db = db;
			args.url = url;
			args.max_versions = max_versions;
			err = m2db_put_alias(&args, beans, cb, u0);
		}
		else {
			GRID_TRACE("M2 already %u beans, version=%"G_GINT64_FORMAT
					" position=%"G_GINT64_FORMAT" size=%"G_GINT64_FORMAT
					" md=[%s]",
					ctx.tmp->len, ctx.old_version, ctx.old_count,
					ctx.old_size, ctx.md->str);
			gint64 append_size = 0;

			ctx.container_version = 1 + m2db_get_version(db);
			ctx.old_count = ctx.tmp->len ? ctx.old_count + 1 : 0;
			if (ctx.old_version == G_MININT64) {
				ctx.old_version = 0;
			}

			/* append and mangle the new beans */
			GRID_TRACE("MANGLE NEW BEAN => v + 1");
			for (; beans ;beans=beans->next) {
				if( _mangle_new_bean(&ctx, beans->data)) {
					append_size = CONTENTS_HEADERS_get_size(beans->data);
				}
			}

			/* Now save the whole */
			if (!(err = m2db_save_beans_array(db, ctx.tmp)) && cb) {
				guint i;
				for (i=0; i<ctx.tmp->len; i++) {
					cb(u0, _bean_dup(ctx.tmp->pdata[i]));
				}
			}
			m2db_set_size(db, m2db_get_size(db) + append_size);
		}
	}


	g_string_free(ctx.md, TRUE);
	g_string_free(ctx.policy, TRUE);
	_bean_cleanv2(ctx.tmp);
	return err;
}

/* ----- MetaInformations update (stgpol, mdsys, etc...) ----- */

struct update_alias_header_ctx_s {
	GPtrArray *tmp;
	guint8 uid[32];
	gint64 container_version;
	gint64 old_version;
	gboolean versioning;
};

static void
_update_new_bean(struct update_alias_header_ctx_s *ctx, gpointer bean)
{
	if (DESCR(bean) == &descr_struct_ALIASES) {
		/* Update id, version, container_version */
		bean = _bean_dup(bean);
		ALIASES_set_container_version(bean, ctx->container_version);
		ALIASES_set_version(bean, ((ctx->versioning) ? ctx->old_version + 1 : ctx->old_version));
		ALIASES_set2_content_id(bean, ctx->uid, sizeof(ctx->uid));
		g_ptr_array_add(ctx->tmp, bean);
		return;
	}

	if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
		/* Update id */
		bean = _bean_dup(bean);
		CONTENTS_HEADERS_set2_id(bean, ctx->uid, sizeof(ctx->uid));
		g_ptr_array_add(ctx->tmp, bean);
		return;
	}

	if (DESCR(bean) == &descr_struct_CONTENTS) {
		bean = _bean_dup(bean);
		/* Update id */
		CONTENTS_set2_content_id(bean, ctx->uid, sizeof(ctx->uid));
		g_ptr_array_add(ctx->tmp, bean);
		return;
	}

	/* other bean types are ignored and discarded */

	g_ptr_array_add(ctx->tmp, bean);
}


GError*
m2db_update_alias_header(sqlite3 *db, gint64 max_versions,
		struct hc_url_s *url, GSList *beans)
{
	struct update_alias_header_ctx_s ctx;
	struct bean_ALIASES_s *latest = NULL;
	GError *err = NULL;

	// Sanity checks
	GRID_TRACE("M2 UPDATE ALIAS HEADER(%s)", hc_url_get(url, HCURL_WHOLE));

	g_assert(db != NULL);
	g_assert(url != NULL);

	if (!hc_url_has(url, HCURL_PATH))
		return NEWERROR(400, "Missing path");
	if (NULL != (err = m2db_check_alias_beans_list(url, beans))) {
		g_prefix_error(&err, "Invalid beans: ");
		err->code = 400;
		return err;
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.tmp = g_ptr_array_new();
	ctx.old_version = G_MININT64;
	ctx.versioning = VERSIONS_ENABLED(max_versions);
	SHA256_randomized_buffer(ctx.uid, sizeof(ctx.uid));

	// Merge the previous versions of the beans with the new part
	if (NULL != (err = m2db_latest_alias(db, url, (gpointer*)(&latest)))) {
		g_prefix_error(&err, "Latest error: ");
		return err;
	}
	ctx.old_version = ALIASES_get_version(latest);
	ctx.container_version = 1 + m2db_get_version(db);

	/* append and mangle the new beans */
	GRID_TRACE("UDPATE NEW BEAN => v + 1");
	for (; beans ;beans=beans->next) {
		_update_new_bean(&ctx, beans->data);
	}

	/* Now save the whole */
	err = m2db_save_beans_array(db, ctx.tmp);

	_bean_cleanv2(ctx.tmp);
	return err;
}


/* GENERATOR ---------------------------------------------------------------- */

struct gen_ctx_s
{
	struct hc_url_s *url;
	struct storage_policy_s *pol;
	struct grid_lb_iterator_s *iter;
	guint8 uid[32];
	guint8 h[32];
	gint64 size;
	gint64 chunk_size;
	m2_onbean_cb cb;
	gpointer cb_data;
	const char *mdsys;
	const char *mdusr;
};

static guint
_policy_parameter(struct storage_policy_s *pol, const gchar *key, guint def)
{
	const char *s;
	s = data_security_get_param(storage_policy_get_data_security(pol), key);
	if (!s)
		return def;
	return (guint) atoi(s);
}

static char *
_generate_mdsys(struct gen_ctx_s *ctx)
{
	GHashTable *unpacked = NULL;

	if(NULL != ctx->mdsys) 
		unpacked = metadata_unpack_string(ctx->mdsys, NULL);
	else 
		unpacked = metadata_create_empty();
	if(!g_hash_table_lookup(unpacked, "chunk-method"))
		metadata_add_printf(unpacked, "chunk-method", "chunk-size");
	if(!g_hash_table_lookup(unpacked, "mime-type"))
		metadata_add_printf(unpacked, "mime-type", "octet/stream");
	if(!g_hash_table_lookup(unpacked, "storage-policy"))
		metadata_add_printf(unpacked, "storage-policy",
			((ctx->pol) ? storage_policy_get_name(ctx->pol) : "none"));

	metadata_add_time(unpacked, "creation-date", NULL);

	GByteArray *pack = metadata_pack(unpacked, NULL);
	g_hash_table_destroy(unpacked);
	char *mdsys = g_strndup((const char *)pack->data, pack->len);
	g_byte_array_free(pack, TRUE);

	return mdsys;
}

static void
_m2_generate_alias_header(struct gen_ctx_s *ctx)
{
	const gchar *p;
	p = ctx->pol ? storage_policy_get_name(ctx->pol) : "none";

	GRID_TRACE2("%s(%s)", __FUNCTION__, hc_url_get(ctx->url, HCURL_WHOLE));

	gchar *mdsys = _generate_mdsys(ctx);

	struct bean_ALIASES_s *alias = _bean_create(&descr_struct_ALIASES);
	ALIASES_set2_alias(alias, hc_url_get(ctx->url, HCURL_PATH));
	ALIASES_set_version(alias, 0);
	ALIASES_set_container_version(alias, 0);
	ALIASES_set_ctime(alias, time(0));
	ALIASES_set_deleted(alias, FALSE);
	ALIASES_set2_mdsys(alias, mdsys);
	ALIASES_set2_content_id(alias, ctx->uid, sizeof(ctx->uid));
	ctx->cb(ctx->cb_data, alias);

	g_free(mdsys);

	struct bean_CONTENTS_HEADERS_s *header;
	header = _bean_create(&descr_struct_CONTENTS_HEADERS);
	CONTENTS_HEADERS_set_size(header, ctx->size);
	CONTENTS_HEADERS_set2_id(header, ctx->uid, sizeof(ctx->uid));
	CONTENTS_HEADERS_set2_policy(header, p);
	CONTENTS_HEADERS_nullify_hash(header);
	ctx->cb(ctx->cb_data, header);

	if(NULL != ctx->mdusr) {
		gpointer prop = _bean_create(&descr_struct_PROPERTIES);
		PROPERTIES_set2_alias(prop, hc_url_get(ctx->url, HCURL_PATH));
		PROPERTIES_set_alias_version(prop, 0);
		PROPERTIES_set2_key(prop, MDUSR_PROPERTY_KEY);
		PROPERTIES_set2_value(prop, (guint8*) ctx->mdusr, strlen(ctx->mdusr));
		PROPERTIES_set_deleted(prop, FALSE);
		ctx->cb(ctx->cb_data, prop);
	}
}

static gchar *
_chunkid(const gchar *straddr, const gchar *strvol, const gchar *strid)
{
	auto void _append(GString *gstr, const gchar *s);

	void _append(GString *gstr, const gchar *s) {
		if (gstr->str[gstr->len - 1] != '/' && *s != '/')
			g_string_append_c(gstr, '/');
		g_string_append(gstr, s);
	}

	GString *gstr = g_string_new("http://");
	_append(gstr, straddr);
	_append(gstr, strvol);
	_append(gstr, strid);
	return g_string_free(gstr, FALSE);
}

static void
_m2_generate_content_chunk(struct gen_ctx_s *ctx, struct service_info_s *si,
		guint pos, gint64 cs)
{
	gchar *chunkid, strpos[32];
	gchar *strvol, straddr[STRLEN_ADDRINFO], strid[65];

	GRID_TRACE2("%s(%s)", __FUNCTION__, hc_url_get(ctx->url, HCURL_WHOLE));

	grid_addrinfo_to_string(&(si->addr), straddr, sizeof(straddr));
	strvol = metautils_rawx_get_volume(si);
	SHA256_randomized_string(strid, sizeof(strid));
	g_snprintf(strpos, sizeof(strpos), "%u", pos);
	chunkid = _chunkid(straddr, strvol, strid);
	g_free(strvol);

	struct bean_CHUNKS_s *chunk = _bean_create(&descr_struct_CHUNKS);
	CHUNKS_set2_id(chunk, chunkid);
	CHUNKS_set_ctime(chunk, time(0));
	CHUNKS_set2_hash(chunk, ctx->h, sizeof(ctx->h));
	CHUNKS_set_size(chunk, cs);
	ctx->cb(ctx->cb_data, chunk);

	struct bean_CONTENTS_s *content = _bean_create(&descr_struct_CONTENTS);
	CONTENTS_set2_chunk_id(content, chunkid);
	CONTENTS_set2_position(content, strpos);
	CONTENTS_set2_content_id(content, ctx->uid, sizeof(ctx->uid));
	ctx->cb(ctx->cb_data, content);

	g_free(chunkid);
}

static GError*
_m2_generate_RAIN(struct gen_ctx_s *ctx)
{
	(void) ctx;
	GRID_TRACE2("%s(%s)", __FUNCTION__, hc_url_get(ctx->url, HCURL_WHOLE));
	return NEWERROR(500, "RAIN generation : Not implemented");
}

static GError*
_m2_generate_DUPLI(struct gen_ctx_s *ctx)
{
	GError *err = NULL;
	gint64 pos, s, cs;
	gint distance, copies;

	GRID_TRACE2("%s(%s)", __FUNCTION__, hc_url_get(ctx->url, HCURL_WHOLE));
	distance = _policy_parameter(ctx->pol, DS_KEY_DISTANCE, 1);
	copies = _policy_parameter(ctx->pol, DS_KEY_COPY_COUNT, 1);
	_m2_generate_alias_header(ctx);

	(void) distance;

	for (pos=0,s=0; s < ctx->size ;) {
		struct service_info_s **psi, **siv = NULL;

		struct lb_next_opt_s opt;
		opt.dupplicates = (copies <= 1);
		opt.max = copies;
		opt.reqdist = distance;

		if (!grid_lb_iterator_next_set(ctx->iter, &siv, &opt)) {
			if ( pos == 0 )
				err = NEWERROR(CODE_PLATFORM_ERROR,"No Rawx available");
			else
				err = NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "Not enough RAWX");
			break;
		}

		if (ctx->chunk_size < (cs = ctx->size - s))
			cs = ctx->chunk_size;

		for (psi=siv; *psi ;++psi)
			_m2_generate_content_chunk(ctx, *psi, pos, cs);

		service_info_cleanv(siv, FALSE);

		++ pos;
		s += ctx->chunk_size;
	}

	return err;
}

static GError*
_m2_generate_NORMAL(struct gen_ctx_s *ctx)
{
	GError *err = NULL;
	gint64 pos, s, cs;

	GRID_TRACE2("%s(%s)", __FUNCTION__, hc_url_get(ctx->url, HCURL_WHOLE));
	_m2_generate_alias_header(ctx);

	for (pos=0,s=0; s < ctx->size ;) {
		struct service_info_s *si = NULL;

		if (!grid_lb_iterator_next(ctx->iter, &si, 300)) {
			if ( pos == 0 )
				err = NEWERROR(CODE_PLATFORM_ERROR,"NO Rawx available");
			else
				err = NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "Not enough RAWX");
			break;
		}
		if (ctx->chunk_size < (cs = ctx->size - s))
			cs = ctx->chunk_size;

		_m2_generate_content_chunk(ctx, si, pos, cs);
		service_info_clean(si);
		++ pos;
		s += ctx->chunk_size;
	}

	return err;
}

GError*
m2_generate_beans(struct hc_url_s *url, gint64 size, gint64 chunk_size,
		struct storage_policy_s *pol, struct grid_lb_iterator_s *iter,
		m2_onbean_cb cb, gpointer cb_data)
{
	return m2_generate_beans_v1(url, size, chunk_size, pol, NULL, NULL,
			iter, cb, cb_data);
}

GError*
m2_generate_beans_v1(struct hc_url_s *url, gint64 size, gint64 chunk_size,
		struct storage_policy_s *pol, const char *mdsys, const char *mdusr,
		struct grid_lb_iterator_s *iter,
		m2_onbean_cb cb, gpointer cb_data)
{
	struct gen_ctx_s ctx;

	GRID_TRACE2("%s(%s)", __FUNCTION__, hc_url_get(url, HCURL_WHOLE));
	g_assert(url != NULL);
	g_assert(iter != NULL);

	if (!hc_url_has(url, HCURL_PATH))
		return NEWERROR(400, "Missing path");
	if (size < 0)
		return NEWERROR(400, "Invalid size");
	if (chunk_size <= 0)
		return NEWERROR(400, "Invalid chunk size");

	memset(ctx.h, 0, sizeof(ctx.h));
	memset(ctx.uid, 0, sizeof(ctx.uid));
	SHA256_randomized_buffer(ctx.uid, sizeof(ctx.uid));
	ctx.iter = iter;
	ctx.pol = pol;
	ctx.url = url;
	ctx.size = size;
	ctx.chunk_size = chunk_size;
	ctx.cb = cb;
	ctx.cb_data = cb_data;
	ctx.mdsys = mdsys;
	ctx.mdusr = mdusr;

	if (!pol)
		return _m2_generate_NORMAL(&ctx);

	switch (data_security_get_type(storage_policy_get_data_security(pol))) {
		case DUPLI:
			return _m2_generate_DUPLI(&ctx);
		case RAIN:
			return _m2_generate_RAIN(&ctx);
		case DS_NONE:
			return _m2_generate_NORMAL(&ctx);
		default:
			return NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid policy type");
	}
}


/* Storage Policy ----------------------------------------------------------- */

static GError*
_get_content_policy(sqlite3 *db, struct hc_url_s *url,
		struct namespace_info_s *nsinfo, struct storage_policy_s **result)
{
	GError *err = NULL;
	GPtrArray *tmp = NULL;
	struct bean_ALIASES_s *latest = NULL;
	struct storage_policy_s *policy = NULL;

	tmp = g_ptr_array_new();

	if (!(err = m2db_latest_alias(db, url, (gpointer*)&latest))) {
		if (latest != NULL) {
			err = _db_get_FK_by_name(latest, "image", db, _bean_buffer_cb, tmp);
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
_get_container_policy(sqlite3 *db, struct namespace_info_s *nsinfo,
		struct storage_policy_s **result)
{
	auto gboolean _onprop(gpointer u, const gchar *k, const guint8 *v, gsize vlen);

	gboolean _onprop(gpointer u, const gchar *k, const guint8 *v, gsize vlen) {
		if (0 != g_ascii_strcasecmp(k, M2V2_PROP_PREFIX_SYS"storage_policy"))
			return TRUE;
		*((gchar**)u) = g_strndup((gchar*)v, vlen);
		return FALSE;
	}

	GError *err = NULL;
	gchar *polname = NULL;
	struct storage_policy_s *policy = NULL;

	err = m2db_get_container_properties(db, 0, &polname, _onprop);
	if (!err && polname)
		policy = storage_policy_init(nsinfo, polname);

	if (!err)
		*result = policy;
	if (polname)
		g_free(polname);
	return err;
}

GError*
m2db_get_storage_policy(sqlite3 *db, struct hc_url_s *url,
		struct namespace_info_s *nsinfo, gboolean from_previous, struct storage_policy_s **result)
{
	GError *err = NULL;
	struct storage_policy_s *policy = NULL;

	GRID_TRACE2("%s(%s)", __FUNCTION__, hc_url_get(url, HCURL_WHOLE));
	g_assert(db != NULL);
	g_assert(url != NULL);
	g_assert(nsinfo != NULL);
	g_assert(result != NULL);

	if(from_previous)
		err = _get_content_policy(db, url, nsinfo, &policy);

	if (!err && !policy)
		err = _get_container_policy(db, nsinfo, &policy);

	if (!err)
		*result = policy;
	return err;
}

GError*
m2db_set_storage_policy(sqlite3 *db, const gchar *polname, int replace)
{
	return sqlx_set_admin_entry(db, M2V2_PROP_PREFIX_SYS"storage_policy", polname,
			replace);
}

void
m2db_set_container_name(sqlite3 *db, struct hc_url_s *url)
{
	const gchar *v;
	GError *err;

	sqlx_exec(db, "INSERT OR IGNORE INTO admin (k,v) "
			"VALUES ('" M2V2_PROP_PREFIX_SYS M2V2_KEY_VERSION "','0')");

	v = hc_url_get(url, HCURL_REFERENCE);
	err = sqlx_set_admin_entry(db, M2V2_PROP_PREFIX_SYS "container_name", v, FALSE);
	if (err) {
		GRID_WARN("Failed to set admin [%s]:[%s] for container [%s]",
			"container_name", v, hc_url_get(url, HCURL_WHOLE));
		g_clear_error(&err);
	}

	v = hc_url_get(url, HCURL_NS);
	err = sqlx_set_admin_entry(db, M2V2_PROP_PREFIX_SYS "namespace", v, FALSE);
	if (err) {
		GRID_WARN("Failed to set admin [%s]:[%s] for container [%s]",
			"namespace", v, hc_url_get(url, HCURL_WHOLE));
		g_clear_error(&err);
	}
}

GError*
m2db_get_container_status(sqlite3 *db, guint32 *status)
{
	g_assert(db != NULL);
	g_assert(status != NULL);

	*status = sqlx_get_int64_admin_value(db, "flags", (gint64)CONTAINER_STATUS_ENABLED);
	return NULL;
}

GError*
m2db_set_container_status(sqlite3 *db, guint32 *expected, guint32 repl)
{
	guint32 status;

	if (expected != NULL) {
		status = sqlx_get_int64_admin_value(db, "flags",
				(gint64)CONTAINER_STATUS_ENABLED);
		if (status != *expected)
			return g_error_new(GQ(), CODE_CONTAINER_DISABLED, "Container disabled");
	}

	sqlx_set_int64_admin_value(db, "flags", (gint64)repl);
	return NULL;
}

/* ------------------------------------------------------------------------- */

static GError*
_purge_exceeding_aliases(sqlite3 *db, gint64 max_versions)
{
	struct elt_s {
		gchar *alias;
		gint64 max, count;
	};

	GRID_TRACE("%s, max_versions = %"G_GINT64_FORMAT, __FUNCTION__, max_versions);

	const gchar *sql_lookup = "SELECT alias, count(*), max(version)"
		"FROM alias_v2 "
		"WHERE 1 "
		"GROUP BY alias "
		"HAVING COUNT(*) > ?";
	const gchar *sql_delete = "DELETE FROM alias_v2 "
		"WHERE alias = ? AND version < ?";

	int rc;
	sqlite3_stmt *stmt = NULL;
	GSList *to_be_deleted = NULL;

	if (VERSIONS_UNLIMITED(max_versions))
		return NULL;
	if (!VERSIONS_ENABLED(max_versions))
		max_versions = 1;

	sqlite3_prepare_debug(rc, db, sql_lookup, -1, &stmt, NULL);
	sqlite3_clear_bindings(stmt);
	sqlite3_reset(stmt);
	sqlite3_bind_int64(stmt, 1, max_versions);
	while (SQLITE_ROW == sqlite3_step(stmt)) {
		struct elt_s *elt = g_malloc0(sizeof(*elt));
		elt->alias = g_strdup((gchar*)sqlite3_column_text(stmt, 0));
		elt->count = sqlite3_column_int64(stmt, 1);
		elt->max = sqlite3_column_int64(stmt, 2);
		to_be_deleted = g_slist_prepend(to_be_deleted, elt);
	}
	(void) sqlite3_finalize(stmt);

	GRID_DEBUG("Nb alias to drop : %d", g_slist_length(to_be_deleted));

	sqlite3_prepare_debug(rc, db, sql_delete, -1, &stmt, NULL);
	for (GSList *l=to_be_deleted; l ;l=l->next) {
		struct elt_s *elt = l->data;
		sqlite3_clear_bindings(stmt);
		sqlite3_reset(stmt);
		sqlite3_bind_text(stmt, 1, elt->alias, -1, NULL);
		sqlite3_bind_int64(stmt, 2, (elt->max - (max_versions - 1)));
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) { }
	}
	(void) sqlite3_finalize(stmt);

	for (GSList *l=to_be_deleted; l ;l=l->next) {
		struct elt_s *elt = l->data;
		g_free(elt->alias);
		g_free(elt);
		l->data = NULL;
	}
	g_slist_free(to_be_deleted);
	to_be_deleted = NULL;
	return NULL;
}

static GSList*
_get_chunks_to_drop(sqlite3 *db)
{
	GVariant *params[] = {NULL};
	GPtrArray *tmp = g_ptr_array_new();
	CHUNKS_load_buffered(db, "id NOT IN (select distinct chunk_id from content_v2)", params, tmp);
	GSList *res = metautils_gpa_to_list(tmp);
	g_ptr_array_free(tmp, TRUE);
	return res;
}

GError*
m2db_purge(sqlite3 *db, gint64 max_versions, GSList** del)
{
	GError *err;

	if (NULL != (err = _purge_exceeding_aliases(db, max_versions))) {
		GRID_WARN("Failed to purge ALIASES : (code=%d) %s",
				err->code, err->message);
		g_clear_error(&err);
	}

	/* purge unreferenced properties */
	sqlx_exec(db, "delete from properties_v2 "
			"WHERE alias NOT IN (select distinct alias from aliases_v2)");

	/* purge unreferenced content_headers, cascading to contents */
	sqlx_exec(db, "delete from content_header_v2 "
			"WHERE id NOT IN (select distinct content_id from alias_v2)");

	sqlx_exec(db, "delete from content_v2 "
			"WHERE content_id NOT IN (select distinct content_id from alias_v2)");

	/* delete chunks if asked */
	if(NULL != del) {
		*del = _get_chunks_to_drop(db);

		GRID_DEBUG("Nb chunks found to delete %d", g_slist_length(*del));

		/* purge unreferenced chunks */
		sqlx_exec(db, "delete from chunk_v2 "
				"WHERE id NOT IN (select distinct chunk_id from content_v2)");
	}

	return NULL;
}

GError*
m2db_deduplicate_chunks(sqlite3 *db, namespace_info_t *nsinfo,
		struct hc_url_s *url)
{
	GError *err = NULL;
	/* List of aliases that failed to be deduplicated */
	GSList *aliases_errors = NULL;

	/* Call m2db_deduplicate_alias_chunks on each alias of container */
	auto void alias_bean_cb(gpointer user_data, struct bean_ALIASES_s *alias);
	void alias_bean_cb(gpointer user_data, struct bean_ALIASES_s *alias) {
		(void) user_data;
		GError *err2 = NULL;
		GString *alias_str = ALIASES_get_alias(alias);
		struct hc_url_s *url2 = hc_url_init(hc_url_get(url, HCURL_WHOLE));
		hc_url_set(url2, HCURL_PATH, alias_str->str);
		err2 = m2db_deduplicate_alias_chunks(db, nsinfo, url2);
		if (err2 != NULL) {
			/* Cannot stop calling function,
			 * so save errors for further handling */
			aliases_errors = g_slist_prepend(aliases_errors, err2);
		}
		_bean_clean(alias);
		hc_url_clean(url2);
	}

	/* List all non-deleted aliases */
	err = m2db_list_aliases(db, M2V2_FLAG_NODELETED,
			(m2_onbean_cb) alias_bean_cb, NULL);

	if (aliases_errors != NULL) {
		if (err == NULL) {
			err = g_error_copy((GError *)aliases_errors->data);
			g_prefix_error(&err,
					"Got %d deduplication errors. The last one was: ",
					g_slist_length(aliases_errors));
		}

		g_slist_free_full(aliases_errors, (GDestroyNotify)g_error_free);
	}

	return err;
}

GError*
m2db_deduplicate_alias_chunks(sqlite3 *db, namespace_info_t *nsinfo,
		struct hc_url_s *url)
{
	GError *err = NULL;
	guint nb_copy = 1;
	struct storage_policy_s *sp = NULL;
	err = _get_content_policy(db, url, nsinfo, &sp);
	if (err != NULL) {
		return err;
	} else {
		nb_copy = _policy_parameter(sp, DS_KEY_COPY_COUNT, 1);
	}
	GString *alias = g_string_new(hc_url_get(url, HCURL_PATH));
	dedup_chunks_of_alias(db, alias, nb_copy, &err);
	g_string_free(alias, TRUE);
	return err;
}

GError*
m2db_deduplicate_contents(sqlite3 *db, struct hc_url_s *url,
		GString **status_message)
{
	GError *err = NULL;
	GSList *impacted_aliases = NULL;
	guint64 size_before = get_container_size(db);
	guint64 saved_space = dedup_aliases(db, url, &impacted_aliases, &err);
	guint64 size_after = get_container_size(db);
	if (status_message != NULL) {
		if (*status_message == NULL) {
			*status_message = g_string_new(NULL);
		}
		g_string_printf(*status_message,
				"%"G_GUINT64_FORMAT" bytes saved "
				"by deduplication of %u contents "
				"(%"G_GUINT64_FORMAT" -> %"G_GUINT64_FORMAT" bytes)",
				saved_space, g_slist_length(impacted_aliases),
				size_before, size_after);
	}
	g_slist_free_full(impacted_aliases, g_free);
	return err;
}

