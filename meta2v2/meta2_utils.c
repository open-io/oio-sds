#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "m2v2.utils"
#endif

#include <string.h>
#include <glib.h>
#include <meta2v2/meta2_backend_internals.h>

#include <meta2v2/meta2_utils.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/meta2_dedup_utils.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>


static GQuark gquark_log = 0;

static GError*
_get_container_policy(struct sqlx_sqlite3_s *sq3, struct namespace_info_s *nsinfo,
		struct storage_policy_s **result);

static GString *
_list_params_to_sql_clause(struct list_params_s *lp)
{
	GString *clause = g_string_new("");
	switch(lp->type) {
		case S3:
			if (NULL != lp->params.s3.marker) {
				g_string_append_printf(clause, "alias > '%s' ",
						lp->params.s3.marker);
			}
			if (clause->len > 0 && NULL != lp->params.s3.prefix)
				g_string_append_printf(clause, "%s ", "AND");
			if (NULL != lp->params.s3.prefix) {
				g_string_append_printf(clause, "alias LIKE '%s%s' ",
						lp->params.s3.prefix, "%%");
			}
			if (clause->len == 0)
				g_string_append(clause, "1 ");
			g_string_append_printf(clause, "%s ", "ORDER BY alias ASC");
			g_string_append_printf(clause, "LIMIT %"G_GINT64_FORMAT,
					(lp->params.s3.maxkeys > 0) ? lp->params.s3.maxkeys : 1000);
			break;
		case DEFAULT:
			if (NULL != lp->params.redc.name_pattern)
				g_string_append_printf(clause, "alias LIKE '%s'",
						lp->params.redc.name_pattern);
		default:
			if (lp->snapshot_name != NULL) {
				if (clause->len > 0)
					g_string_append(clause, " AND ");
				// calling function converts snapshot_name to container_version
				g_string_append_printf(clause, " container_version = ? ");
			}
			if (clause->len == 0)
				clause = g_string_append(clause, "1");
	}

	GRID_DEBUG("Listing clause: [%s]", clause->str);

	return clause;
}

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

static inline gchar*
m2v2_flags(guint32 flags, gchar *d, gsize ds)
{
	memset(d, 0, ds);
	g_snprintf(d, ds, "%08X", flags);
	if (flags & M2V2_FLAG_NODELETED)
		g_strlcat(d, "|NODEL", ds);
	if (flags & M2V2_FLAG_ALLVERSION)
		g_strlcat(d, "|ALLVER", ds);
	if (flags & M2V2_FLAG_NOPROPS)
		g_strlcat(d, "|NOPROP", ds);
	if (flags & M2V2_FLAG_HEADERS)
		g_strlcat(d, "|HEADERS", ds);

	return d;
}

/**
 * @param db
 * @param url
 * @return
 */
static gint64
_m2db_count_alias_versions(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url)
{
	int rc;
	gint64 v;
	sqlite3_stmt *stmt = NULL;

	g_assert(sq3 != NULL);
	g_assert(url != NULL);

	v = 0;
	sqlite3_prepare_debug(rc, sq3->db,
			"SELECT COUNT(version) FROM alias_v2 WHERE alias = ?", -1, &stmt, NULL);
	if (rc == SQLITE_OK) {
		sqlite3_bind_text(stmt, 1, hc_url_get(url, HCURL_PATH), -1, NULL);
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

gboolean
m2v2_parse_chunk_position(const gchar *s, gint *pos, gboolean *par, gint *sub)
{
	gchar *end = NULL;
	gboolean parity = FALSE;
	gint64 p64, s64;

	g_assert(pos != NULL);
	g_assert(par != NULL);
	g_assert(sub != NULL);
	if (!s)
		return FALSE;

	p64 = g_ascii_strtoll(s, &end, 10);
	if (STRTOLL_ERROR(p64, s, end))
		return FALSE;
	if (!*end) { // No sub-position found
		*pos = p64;
		*par = FALSE;
		*sub = -1;
		return TRUE;
	}

	if (*end != '.')
		return FALSE;
	s = end + 1;
	if (!*s) // Trailing dot not accepted
		return FALSE;

	if (*s == 'p') {
		parity = 1;
		++ s;
	}

	end = NULL;
	s64 = g_ascii_strtoll(s, &end, 10);
	if (STRTOLL_ERROR(s64, s, end))
		return FALSE;
	if (*end) // Trailing extra chars not accepted
		return FALSE;

	*pos = p64;
	*par = parity;
	*sub = s64;
	return TRUE;
}

guint64
m2db_get_container_size(sqlite3 *db, gboolean check_alias)
{
	guint64 size = 0;
	gchar tmp[512];
	memset(tmp,'\0', 512);
	g_snprintf(tmp, 512, "%s%s", "SELECT SUM(size) FROM content_header_v2",
			!check_alias ? "" :
			" WHERE EXISTS (SELECT content_id FROM alias_v2 WHERE content_id = id)");
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
	gchar *ns = sqlx_admin_get_str(sq3, M2V2_PROP_PREFIX_SYS
			M2V2_KEY_NAMESPACE);
	if (!ns)
		return def? g_strdup(def) : NULL;
	return ns;
}

gint64
m2db_get_max_versions(struct sqlx_sqlite3_s *sq3, gint64 def)
{
	return sqlx_admin_get_i64(sq3, M2V2_PROP_PREFIX_SYS
			M2V2_KEY_VERSIONING_POLICY, def);
}

void
m2db_set_max_versions(struct sqlx_sqlite3_s *sq3, gint64 max)
{
	sqlx_admin_set_i64(sq3, M2V2_PROP_PREFIX_SYS
			M2V2_KEY_VERSIONING_POLICY, max);
}

gint64
m2db_get_keep_deleted_delay(struct sqlx_sqlite3_s *sq3, gint64 def)
{
	return sqlx_admin_get_i64(sq3, M2V2_PROP_PREFIX_SYS
			M2V2_KEY_KEEP_DELETED_DELAY, def);
}

void
m2db_set_keep_deleted_delay(struct sqlx_sqlite3_s *sq3, gint64 delay)
{
	sqlx_admin_set_i64(sq3, M2V2_PROP_PREFIX_SYS
			M2V2_KEY_KEEP_DELETED_DELAY, delay);
}

gint64
m2db_get_version(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_admin_get_i64(sq3, M2V2_PROP_PREFIX_SYS
			M2V2_KEY_VERSION, 1);
}

void
m2db_increment_version(struct sqlx_sqlite3_s *sq3)
{
	sqlx_admin_inc_i64(sq3, M2V2_PROP_PREFIX_SYS M2V2_KEY_VERSION, 1);
}

gint64
m2db_get_size(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_admin_get_i64(sq3, M2V2_PROP_PREFIX_SYS M2V2_KEY_SIZE, 0);
}

void
m2db_set_size(struct sqlx_sqlite3_s *sq3, gint64 size)
{
	sqlx_admin_set_i64(sq3, M2V2_PROP_PREFIX_SYS
			M2V2_KEY_SIZE, size);
}

gint64
m2db_get_quota(struct sqlx_sqlite3_s *sq3, gint64 def)
{
	return sqlx_admin_get_i64(sq3, M2V2_PROP_PREFIX_SYS
			M2V2_KEY_QUOTA, def);
}

void
m2db_set_quota(struct sqlx_sqlite3_s *sq3, gint64 quota)
{
	sqlx_admin_set_i64(sq3, M2V2_PROP_PREFIX_SYS
			M2V2_KEY_QUOTA, quota);
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

/**
 * Get the size of the contents of an alias.
 *
 * @return The size in bytes, or 0 (no error handling).
 */
static gint64
_get_alias_size(struct sqlx_sqlite3_s *sq3, struct bean_ALIASES_s *alias)
{
	GError *err = NULL;
	gint64 size = 0;

	void _cb(gpointer u, gpointer bean) {
		(void) u;
		size = CONTENTS_HEADERS_get_size(bean);
		_bean_clean(bean);
	}

	GVariant *params[] = {NULL, NULL};
	gchar *clause = " id = ? ";
	params[0] = _gba_to_gvariant(ALIASES_get_content_id(alias));
	err = _db_get_bean(&descr_struct_CONTENTS_HEADERS, sq3->db,
			clause, params, _cb, NULL);
	g_variant_unref(params[0]);
	if (err)
		g_error_free(err); // I don't care
	return size;
}

/**
 * Build SQL clause and GVariant parameters according to the URL.
 * Snapshot has priority over version. If version conversion to int
 * failed, it is considered as a snapshot name.
 */
static GError*
_build_clause_and_params(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		gchar **sql, GVariant **params)
{
	GError *err = NULL;
	gint64 version = -1;
	struct bean_SNAPSHOTS_s *snapshot = NULL;

	// First, check if snapshot specified in URL
	if (hc_url_has(url, HCURL_SNAPSHOT)) {
		err = m2db_get_snapshot_by_name(sq3, hc_url_get(url, HCURL_SNAPSHOT),
					&snapshot);
	// Second, check if version specified in URL
	} else if (hc_url_has(url, HCURL_VERSION)) {
		gchar *s = NULL;
		const gchar *vers_str = hc_url_get(url, HCURL_VERSION);
		gint64 _vers;

		errno = 0;
		s = NULL;
		_vers = g_ascii_strtoll(vers_str, &s, 10);
		// If version conversion failed, check if it is a snapshot name
		if (s == vers_str || _vers < 0) {
			err = m2db_get_snapshot_by_name(sq3, vers_str, &snapshot);
			if (err != NULL && err->code == CODE_SNAPSHOT_NOTFOUND) {
				g_clear_error(&err);
				err = NEWERROR(CODE_BAD_REQUEST,
						"'%s' is neither a valid version nor a snapshot name",
						vers_str);
			}
		} else if (errno != 0) {
			err = NEWERROR(CODE_BAD_REQUEST, "Invalid version: '%s'", vers_str);
			errno = 0;
		} else {
			version = _vers;
		}
	}

	if (snapshot != NULL) {
		*sql = "alias = ? AND container_version = ? ";
		params[1] = g_variant_new_int64(SNAPSHOTS_get_version(snapshot));
		_bean_clean(snapshot);
	} else if (version >= 0) {
		*sql = "alias = ? AND version = ? LIMIT 1";
		params[1] = g_variant_new_int64(version);
	} else if (err == NULL) {
		*sql = "alias = ? ORDER BY version DESC LIMIT 1";
	}

	return err;
}

GError*
m2db_get_alias(struct sqlx_sqlite3_s *sq3, struct hc_url_s *u,
		guint32 flags, m2_onbean_cb cb, gpointer u0)
{
	static guint32 allowed_mask = M2V2_FLAG_NOPROPS|M2V2_FLAG_NODELETED
			|M2V2_FLAG_ALLVERSION;
	gchar d0[64], d1[64];
	(void) d0, (void) d1, (void) allowed_mask;
	GError *err = NULL;
	gchar *sql = NULL;
	GVariant *params[3] = {NULL, NULL, NULL};
	GPtrArray *tmp = g_ptr_array_new();

	/* sanity checks */
	if (!hc_url_has(u, HCURL_PATH))
		return NEWERROR(400, "Missing path");

	GRID_TRACE("GET(%s) Flags got[%s], allowed[%s]", hc_url_get(u, HCURL_WHOLE),
			m2v2_flags(flags, d0, sizeof(d0)),
			m2v2_flags(allowed_mask, d1, sizeof(d1)));

	/* now manage the aliases and recurse on the other types */
	params[0] = g_variant_new_string(hc_url_get(u, HCURL_PATH));
	if (flags & M2V2_FLAG_ALLVERSION) {
		sql = "alias = ?";
	}
	else {
		err = _build_clause_and_params(sq3, u, &sql, params);
	}

	if (!err) {
		err = ALIASES_load_buffered(sq3->db, sql, params, tmp);
	}

	gvariant_unrefv(params);

	if (!err) {
		if (tmp->len <= 0) {
			// Request did not return anything
			err = NEWERROR(CODE_CONTENT_NOTFOUND, "Alias not found");
		} else if (tmp->len == 1 && ALIASES_get_deleted(tmp->pdata[0]) &&
				(flags & M2V2_FLAG_NODELETED)) {
			// Request returned only one content and
			// it is deleted and we don't want deleted contents
			err = NEWERROR(CODE_CONTENT_NOTFOUND, "Alias deleted");
		}
	}
	if (!err) {
		while (tmp->len > 0) {
			struct bean_ALIASES_s *alias = tmp->pdata[0];
			g_ptr_array_remove_index_fast(tmp, 0);
			if (alias) {
				if ((flags & M2V2_FLAG_NODELETED) && ALIASES_get_deleted(alias))
					_bean_clean(alias);
				else {
					if(cb)
						_manage_alias(sq3->db, alias, cb, u0);
					else
						_bean_clean(alias);
				}
			}
		}
	}

	if (!err && !(flags & M2V2_FLAG_NOPROPS) && cb) {
		/* collect the properties */
		if (NULL != (err = m2db_get_properties(sq3, u, flags, cb, u0))) {
			g_prefix_error(&err, "Properties error: ");
			return err;
		}
	}

	_bean_cleanv2(tmp); /* cleans unset beans */
	return err;
}

GError*
m2db_list_aliases(struct sqlx_sqlite3_s *sq3, struct list_params_s *lp,
		m2_onbean_cb cb, gpointer u)
{
	static guint32 allowed_mask = M2V2_FLAG_NODELETED
		|M2V2_FLAG_ALLVERSION|M2V2_FLAG_HEADERS;
	gchar d0[64], d1[64];
	(void) d0, (void) d1, (void) allowed_mask;
	GVariant *params[] = {NULL, NULL};
	GError *err = NULL;
	m2_onbean_cb local_cb = cb;

	g_assert(sq3 != NULL);

	GRID_TRACE("LIST Flags got[%s], allowed[%s]",
			m2v2_flags(lp->flags, d0, sizeof(d0)),
			m2v2_flags(allowed_mask, d1, sizeof(d1)));

	void _load_header_cb(gpointer udata, gpointer bean) {
		GError *err_local = NULL;
		struct bean_ALIASES_s *alias = bean;
		GVariant *ch_params[] = {NULL, NULL};
		ch_params[0] = _gba_to_gvariant(ALIASES_get_content_id(alias));
		// Send content header
		err = CONTENTS_HEADERS_load(sq3->db, "id = ?", ch_params, cb, udata);
		if (err != NULL) {
			GRID_WARN("Failed to load header for alias [%s] version %"G_GINT64_FORMAT,
					ALIASES_get_alias(alias)->str,
					ALIASES_get_version(alias));
			g_clear_error(&err_local);
		}
		// Send alias
		cb(udata, bean);
		gvariant_unrefv(ch_params);
	}

	if (lp->flags & M2V2_FLAG_HEADERS) {
		local_cb = _load_header_cb;
	}

	if (lp->snapshot_name != NULL) {
		struct bean_SNAPSHOTS_s *snapshot = NULL;
		err = m2db_get_snapshot_by_name(sq3, lp->snapshot_name, &snapshot);
		if (err == NULL) {
			// SQL clause uses container_version, not snapshot_name
			params[0] = g_variant_new_int64(SNAPSHOTS_get_version(snapshot));
			_bean_clean(snapshot);
		} else {
			return err;
		}
	}

	gint _compare_version(struct bean_ALIASES_s *a1,
			struct bean_ALIASES_s *a2) {
		return ALIASES_get_version(a2) - ALIASES_get_version(a1);
	}
	gboolean _free_list(gpointer k, gpointer v, gpointer u0) {
		(void) k;
		(void) u0;
		g_slist_free((GSList*)v);
		return FALSE;
	}

	// Build lists of aliases sorted by version,
	// and insert them into a tree indexed by alias.
	// At the end, we just run the tree and forward each
	// element to the caller.
	void wrapper(gpointer u0, gpointer bean) {
		GTree *atree = u0;
		struct bean_ALIASES_s *alias;
		GSList *found;
		alias = (struct bean_ALIASES_s *) bean;
		found = g_tree_lookup(atree, ALIASES_get_alias(alias)->str);
		found = g_slist_insert_sorted(found, alias, (GCompareFunc)_compare_version);
		g_tree_replace(atree, g_strdup(ALIASES_get_alias(alias)->str), found);
	}
	// Function that will be called on each alias list
	gboolean runner(gpointer k, gpointer v, gpointer u0) {
		(void) k;
		GSList *l = (GSList *) v;
		if (!((lp->flags & M2V2_FLAG_NODELETED) && ALIASES_get_deleted(l->data))) {
			// Latest version is not deleted or we are allowed to list deleted
			if (lp->flags & M2V2_FLAG_ALLVERSION) {
				// Reverse to get oldest version first
				for (GSList *cursor = g_slist_reverse(l);
						cursor != NULL; cursor = cursor->next) {
					local_cb(u0, cursor->data);
				}
			} else {
				// M2V2_FLAG_ALLVERSION is not set, list latest version,
				// and clean the rest
				local_cb(u0, l->data);
				_bean_cleanl2(l->next);
				l->next = NULL;
			}
		} else {
			// If latest version is marked deleted and M2V2_FLAG_NODELETED,
			// do not call back, just clean
			for (; l ;l=l->next) {
				_bean_clean(l->data);
			}
		}
		return FALSE;
	}

	GString *clause = _list_params_to_sql_clause(lp);

	GTree *atree = g_tree_new_full(metautils_strcmp3, NULL, g_free, NULL);
	err = ALIASES_load(sq3->db, clause->str, params, wrapper, atree);
	if (!err)
		g_tree_foreach(atree, runner, u);
	g_tree_foreach(atree, _free_list, NULL);
	g_tree_destroy(atree);
	g_string_free(clause, TRUE);
	gvariant_unrefv(params);
	return err;
}

GError*
m2db_get_alias_version(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url, guint32 flags,
		gint64 *version)
{
	GError *err = NULL;
	struct bean_ALIASES_s *latest = NULL;

	(void) flags;
	if (NULL != (err = m2db_latest_alias(sq3, url, (gpointer*)(&latest)))) {
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
m2db_get_versioned_alias(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url, gpointer *result)
{
	GError *err;
	GPtrArray *tmp;
	GVariant *params[3] = { NULL, NULL, NULL };

	g_assert(sq3 != NULL);
	g_assert(url != NULL);
	g_assert(result != NULL);

	if (!hc_url_has(url, HCURL_PATH))
		return NEWERROR(400, "Missing path");
	if (!hc_url_has(url, HCURL_VERSION))
		return NEWERROR(400, "Missing version");

	tmp = g_ptr_array_new();
	params[0] = g_variant_new_string(hc_url_get(url, HCURL_PATH));
	params[1] = g_variant_new_string(hc_url_get(url, HCURL_VERSION));
	err = _db_get_bean(&descr_struct_ALIASES, sq3->db,
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
m2db_latest_alias(struct sqlx_sqlite3_s *sq3,  struct hc_url_s *url, gpointer *result)
{
	GError *err;
	GPtrArray *tmp;
	GVariant *params[2] = { NULL, NULL };

	g_assert(sq3 != NULL);
	g_assert(url != NULL);
	g_assert(result != NULL);

	if (!hc_url_has(url, HCURL_PATH))
		return NEWERROR(400, "Missing path");

	tmp = g_ptr_array_new();
	params[0] = g_variant_new_string(hc_url_get(url, HCURL_PATH));
	err = _db_get_bean(&descr_struct_ALIASES, sq3->db,
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
m2db_delete_content(struct sqlx_sqlite3_s *sq3, gpointer content)
{
	GError *e = NULL;
	sqlite3_stmt *stmt = NULL;
	int rc;

	sqlite3_prepare_debug(rc, sq3->db,
			"DELETE FROM content_v2 WHERE chunk_id = ? AND content_id = ?",
			-1, &stmt, NULL);

	sqlite3_clear_bindings(stmt);
	sqlite3_reset(stmt);
	sqlite3_bind_text(stmt, 1, CONTENTS_get_chunk_id(content)->str,
			CONTENTS_get_chunk_id(content)->len, NULL);
	sqlite3_bind_blob(stmt, 2, CONTENTS_get_content_id(content)->data,
			CONTENTS_get_content_id(content)->len, NULL);
	while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
		if (rc != SQLITE_OK && rc != SQLITE_DONE) {
			e = NEWERROR(500, "SQLite error: (%d) %s", rc, sqlite3_errmsg(sq3->db));
		}
	}

	(void) sqlite3_finalize(stmt);

	return e;
}

GError*
m2db_delete_chunk(struct sqlx_sqlite3_s *sq3, gpointer chunk)
{
	GError *e = NULL;
	sqlite3_stmt *stmt = NULL;
	int rc;

	sqlite3_prepare_debug(rc, sq3->db,
			"DELETE FROM chunk_v2 WHERE id = ?",
			-1, &stmt, NULL);

	sqlite3_clear_bindings(stmt);
	sqlite3_reset(stmt);
	sqlite3_bind_text(stmt, 1, CHUNKS_get_id(chunk)->str,
			CHUNKS_get_id(chunk)->len, NULL);
	while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
		if (rc != SQLITE_OK && rc != SQLITE_DONE) {
			e = NEWERROR(500, "SQLite error: (%d) %s", rc, sqlite3_errmsg(sq3->db));
		}
	}

	(void) sqlite3_finalize(stmt);

	return e;
}

GError*
m2db_substitute_chunk_everywhere(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url,
		struct bean_CHUNKS_s *new_chunk, GSList *old_chunks,
		m2_onbean_cb cb, gpointer udata)
{
	gint count = 0;
	GError *err = NULL;
	GSList *urls = NULL;

	// Save the new chunk
	err = _db_save_bean(sq3->db, new_chunk);
	if (err)
		goto end;
	// Replace old chunks by the new one
	count = substitute_chunk(sq3->db, new_chunk, old_chunks, &err);
	if (count > 0 && !err) {
		GRID_DEBUG("Substituted %d chunks by %s", count,
				CHUNKS_get_id(new_chunk)->str);
		// Notify all contents with the new chunk
		err = m2db_content_urls_from_chunk_id(sq3, url,
				CHUNKS_get_id(new_chunk)->str, -1, &urls);
		if (err) {
			// This error is not fatal
			GRID_WARN("Failed to notify contents with chunks substituted: %s",
					err->message);
			g_clear_error(&err);
		} else {
			for (GSList *l = urls; l ; l = l->next) {
				err = m2db_get_alias(sq3, l->data, 0, cb, udata);
				if (err) {
					GRID_WARN("Notification of chunk substitution failed "
							"for [%s]: %s", hc_url_get(l->data, HCURL_WHOLE),
							err->message);
					g_clear_error(&err);
				}
			}
			g_slist_free_full(urls, (GDestroyNotify)hc_url_clean);
		}
		// TODO: remove the old chunks from the database
		// (currently they are removed by the purge)
	}
end:
	return err;
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
m2db_get_property(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		const gchar *prop_name, guint32 flags, m2_onbean_cb cb, gpointer u0)
{
	gint64 version = -1;
	GError *err = NULL;

	do { // Ensure the ALIAS exists
		struct bean_ALIASES_s *latest = NULL;
		if (NULL != (err = m2db_latest_alias(sq3, url, (gpointer*)&latest)))
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
			err = _db_get_bean(&descr_struct_PROPERTIES, sq3->db, clause, params,
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
			err = _db_get_bean(&descr_struct_PROPERTIES, sq3->db, clause, params,
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
m2db_get_properties(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url, guint32 flags,
		m2_onbean_cb cb, gpointer u0)
{
	return m2db_get_property(sq3, url, NULL, flags, cb, u0);
}

GError*
m2db_set_properties(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		struct hc_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err;
	struct bean_ALIASES_s *latest = NULL;

	if (!beans)
		return NEWERROR(400, "No properties");
	if (NULL != (err = m2db_latest_alias(sq3, url, (gpointer*)(&latest))))
		return err;
	if (!latest)
		return NEWERROR(CODE_CONTENT_NOTFOUND, "Alias not found");

	if (ALIASES_get_deleted(latest))
		err = NEWERROR(CODE_CONTENT_NOTFOUND, "Alias deleted");

	if (!err) {
		gint64 base_version = m2db_get_version(sq3);
		gint64 version = ALIASES_get_version(latest);
		if (VERSIONS_ENABLED(max_versions)) {
			/* Make a new alias revision */
			base_version++;
			version++;

			ALIASES_set_container_version(latest, base_version);
			ALIASES_set_version(latest, version);

			if (!(err = _db_save_bean(sq3->db, latest))) {
				if (cb) {
					cb(u0, latest);
					latest = NULL;
				}
			}
		}

		/* Save each property bean */
		for (; !err && beans ;beans=beans->next) {

			struct bean_PROPERTIES_s *prop = beans->data;
			const GByteArray  *value = NULL;

			if (DESCR(prop) != &descr_struct_PROPERTIES) {
				/* We discard any non-property bean */
				continue;
			}
			prop = _bean_dup(prop);
			PROPERTIES_set2_alias(prop, hc_url_get(url, HCURL_PATH));
			value = PROPERTIES_get_value(prop);
			if (value == NULL || value->len == 0 || PROPERTIES_get_deleted(prop)) {
				GRID_DEBUG("Deleting property %s(%ld) of %s",
						PROPERTIES_get_key(prop)->str,
						PROPERTIES_get_alias_version(prop),
						hc_url_get(url, HCURL_PATH));
				GVariant *params[3] = {NULL, NULL, NULL};
				params[0] = g_variant_new_string(PROPERTIES_get_alias(prop)->str);
				params[1] = g_variant_new_string(PROPERTIES_get_key(prop)->str);
				err = PROPERTIES_delete(sq3->db, "alias = ? AND key = ?", params);
				_bean_clean(prop);
				g_variant_unref(params[1]);
				g_variant_unref(params[0]);
			} else {
				PROPERTIES_set_alias_version(prop, version);
				err = _db_save_bean(sq3->db, prop);
				if (err || !cb)
					_bean_clean(prop);
				else
					cb(u0, prop);
			}
		}
	}

	_bean_clean(latest);
	return err;
}

GError*
m2db_get_container_properties(struct sqlx_sqlite3_s *sq3, guint32 flags,
		gpointer cb_data, m2_onprop_cb cb)
{
	gboolean runner(gchar *k, GByteArray *v, gpointer ignored) {
		(void) ignored;
		if (!(flags & M2V2_FLAG_ALLPROPS) && !g_str_has_prefix(k, M2V2_PROP_PREFIX_SYS)
				&& !g_str_has_prefix(k, M2V2_PROP_PREFIX_USER))
			return FALSE;
		return cb(cb_data, k, v->data, v->len);
	}

	g_tree_foreach(sq3->admin, (GTraverseFunc)runner, NULL);
	return NULL;
}

GError*
m2db_set_container_properties(struct sqlx_sqlite3_s *sq3, guint32 flags, GSList *props)
{
	int delete = 0;
	GError *err = NULL;
	GSList *prop_errs = NULL;

	g_assert(sq3 != NULL);

	/* Properties to be inserted/updated */
	for (GSList *l = props; l; l = l->next) {
		struct meta2_property_s *m2p = l->data;

		if (!m2p || !m2p->name || !m2p->value) {
			delete = delete || (m2p->value == NULL);
			continue;
		}

		if (!(flags & M2V2_FLAG_NOFORMATCHECK) &&
				!g_str_has_prefix(m2p->name, M2V2_PROP_PREFIX_USER)) {
			prop_errs = g_slist_prepend(prop_errs, m2p->name);
			continue;
		}

		sqlx_admin_set_gba(sq3, m2p->name, metautils_gba_dup(m2p->value));
	}

	/* Properties to be deleted */
	if (delete) {
		for (GSList *l = props; l; l=l->next) {
			struct meta2_property_s *m2p = NULL;

			if (!(m2p = l->data) || !m2p->name || NULL != m2p->value)
				continue;

			if (!(flags & M2V2_FLAG_NOFORMATCHECK) &&
					!g_str_has_prefix(m2p->name, M2V2_PROP_PREFIX_USER)) {
				prop_errs = g_slist_prepend(prop_errs, m2p->name);
				continue;
			}

			sqlx_admin_del(sq3, m2p->name);
		}
	}

	if (prop_errs != NULL) {
		GString *msg = NULL;
		msg = g_string_new("Not allowed to set/delete following properties "
				"(not prefixed by 'user.'):");
		for (GSList *l = prop_errs; l != NULL; l = l->next) {
			g_string_append_printf(msg, " %s", (gchar*)l->data);
		}
		err = NEWERROR(CODE_NOT_ALLOWED, msg->str);
		g_string_free(msg, TRUE);
	}

	return err;
}

GError*
m2db_get_all_properties(struct sqlx_sqlite3_s *sq3, const gchar *k, guint32 flags,
		m2_onbean_cb cb, gpointer u0)
{
	GVariant *params[2] = {NULL,NULL};
	GError *err;

	(void) flags;

	params[0] = g_variant_new_string(k);
	err = PROPERTIES_load(sq3->db, "key = ?", params, cb, u0);
	g_variant_unref(params[0]);
	return err;
}

GError*
m2db_del_property(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url, const gchar *k)
{
	guint i;
	GError *err;
	GPtrArray *tmp;

	g_assert(sq3 != NULL);
	g_assert(url != NULL);
	g_assert(k != NULL);

	tmp = g_ptr_array_new();
	err = m2db_get_property(sq3, url, k, M2V2_FLAG_NODELETED, _bean_buffer_cb, tmp);
	if (!err) {
		for (i=0; !err && i<tmp->len ;++i) {
			gpointer bean = tmp->pdata[i];
			PROPERTIES_set_deleted(bean, TRUE);
			err = _db_save_bean(sq3->db, bean);
		}
	}

	_bean_cleanv2(tmp);
	return err;
}

GError*
m2db_flush_property(struct sqlx_sqlite3_s *sq3, const gchar *k)
{
	GVariant *params[] = { NULL, NULL };
	GError *err;

	params[0] = g_variant_new_string(k);
	err = PROPERTIES_delete(sq3->db, "key = ?", params);
	g_variant_unref(params[0]);

	GRID_DEBUG("%i services deleted", sqlite3_changes(sq3->db));
	return err;
}


/* DELETE ------------------------------------------------------------------- */

static GError*
_real_delete(struct sqlx_sqlite3_s *sq3, GSList *beans, GSList **deleted_beans)
{
	// call the purge to know which beans must be really deleted
	GSList *deleted = NULL;
	GError *err = m2db_purge_alias_being_deleted(sq3, beans, &deleted);
	if (err) {
		g_slist_free(deleted);
		g_prefix_error(&err, "Purge error: ");
		return err;
	}

	if (GRID_DEBUG_ENABLED()) {
		GString *gstr = g_string_new("");
		for (GSList *l = deleted; l ;l=l->next) {
			g_string_set_size(gstr, 0);
			_bean_debug(gstr, l->data);
			GRID_DEBUG("PURGE: %.*s", (int) gstr->len, gstr->str);
		}
		g_string_free(gstr, TRUE);
	}

	// Now really delete the beans
	for (GSList *l = deleted; l ;l=l->next) {
		GError *e = NULL;
		if (DESCR(l->data) == &descr_struct_CHUNKS) {
			if (deleted_beans) {
				// The presence of this argument indicates that client
				// will delete the chunk from disk, so we can remove it
				// from the database.
				*deleted_beans = g_slist_prepend(*deleted_beans, l->data);
				e = _db_delete_bean(sq3->db, l->data);
			} else {
				// The chunk stays in the database,
				// and will be deleted later by a purge crawler.
			}
		} else {
			if (deleted_beans) {
				*deleted_beans = g_slist_prepend(*deleted_beans, l->data);
			}
			e = _db_delete_bean(sq3->db, l->data);
		}
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

	if (deleted_beans)
		*deleted_beans = g_slist_reverse(*deleted_beans);

	g_slist_free(deleted);
	deleted = NULL;
	return NULL;
}

GError*
m2db_delete_alias(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		struct hc_url_s *url, gboolean del_chunks,
		m2_onbean_cb cb, gpointer u0)
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

	if (VERSIONS_DISABLED(max_versions) && hc_url_has(url, HCURL_VERSION) &&
			g_ascii_strtoll(hc_url_get(url, HCURL_VERSION), NULL, 10) != 0) {
		return NEWERROR(CODE_BAD_REQUEST,
				"Versioning not supported and version specified");
	}

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

	gint64 alias_version = ALIASES_get_version(alias);
	gboolean is_in_a_snapshot_b = is_in_a_snapshot(sq3, alias);

	GRID_TRACE("CONTENT [%s] uses [%u] beans",
			hc_url_get(url, HCURL_WHOLE), g_slist_length(beans));

	if (VERSIONS_DISABLED(max_versions) || VERSIONS_SUSPENDED(max_versions) ||
			((hc_url_has(url, HCURL_VERSION) || ALIASES_get_deleted(alias)) &&
				!is_in_a_snapshot_b)) {

		GSList *deleted_beans = NULL;
		/* If versions disabled/suspended or version specified
		 * or marked as deleted -> delete alias permanently */
		err = _real_delete(sq3, beans, del_chunks? &deleted_beans : NULL);
		/* Client asked to remove no-more referenced beans, we tell him which */
		for (GSList *bean = deleted_beans; bean; bean = bean->next) {
			if (cb)
				cb(u0, _bean_dup(bean->data)); // Callback frees beans
		}
		g_slist_free(deleted_beans);

	} else if (hc_url_has(url, HCURL_VERSION)) {
		/* Alias is in a snapshot but user explicitly asked for its deletion */
		err = NEWERROR(CODE_NOT_ALLOWED,
				"Cannot delete a content belonging to a snapshot");
	} else {
		/* Create a new version marked as deleted */
		struct bean_ALIASES_s *new_alias = _bean_dup(alias);
		/* Set deleted except if already deleted and in a snapshot (restore) */
		ALIASES_set_deleted(new_alias,
				!(ALIASES_get_deleted(alias) && is_in_a_snapshot_b));
		ALIASES_set_version(new_alias, 1 + ALIASES_get_version(alias));
		ALIASES_set_container_version(new_alias, 1 + m2db_get_version(sq3));
		ALIASES_set_ctime(new_alias, (gint64)time(0));
		if (!(err = _db_save_bean(sq3->db, new_alias))) {
			if (cb) {
				cb(u0, new_alias);
			} else {
				_bean_clean(new_alias);
			}
		}

		// Now ensure that properties for this alias have a DELETED version for
		// the current version.
		if (!err) {
			GPtrArray *tmp = g_ptr_array_new();
			err = m2db_get_properties(sq3, url, 0, _bean_buffer_cb, tmp);
			for (guint i=0; !err && i<tmp->len ;i++) {
				struct bean_PROPERTIES_s *prop = tmp->pdata[i];
				PROPERTIES_set_alias_version(prop, alias_version);
				PROPERTIES_set_deleted(prop, TRUE);
				err = _db_save_bean(sq3->db, prop);
			}
			_bean_cleanv2(tmp);
		}
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

static void
_patch_alias_metadata(struct bean_ALIASES_s *alias)
{
	GHashTable *ht;
	GString *gstr = ALIASES_get_mdsys(alias);
	ht = gstr ? metadata_unpack_string(gstr->str, NULL)
		: metadata_create_empty();
	if (!g_hash_table_lookup(ht,"creation-date"))
		metadata_add_time(ht, "creation-date", NULL);
	if (!g_hash_table_lookup(ht,"chunk-method"))
		metadata_add_printf(ht,"chunk-method","chunk-size");
	if (!g_hash_table_lookup(ht,"mime-type"))
		metadata_add_printf(ht,"mime-type","octet/stream");
	GByteArray *gba = metadata_pack(ht, NULL);
	g_byte_array_append(gba, (guint8*)"", 1);
	ALIASES_set2_mdsys(alias, (gchar*) gba->data);
	g_byte_array_unref(gba);
	g_hash_table_destroy(ht);
}

static GError*
m2db_real_put_alias(struct sqlx_sqlite3_s *sq3, struct put_args_s *args)
{
	gint64 container_version;
	GError *err = NULL;
	GSList *l;

	container_version = 1 + m2db_get_version(sq3);

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
			_patch_alias_metadata(bean);
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

		err = _db_save_bean(sq3->db, bean);
	}

	if (!err && args->cb) {
		for (l=args->beans; l ;l=l->next)
			args->cb(args->cb_data, _bean_dup(l->data));
	}

	return err;
}

static GError*
m2db_merge_alias(struct m2db_put_args_s *m2db_args, struct bean_ALIASES_s *latest,
		struct put_args_s *args)
{
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
	if (NULL != (err = _db_get_FK_by_name(latest, "image", m2db_args->sq3->db, cb, &gba)))
		g_prefix_error(&err, "DB error: ");
	else {
		if (gba == NULL)
			err = NEWERROR(500, "HEADER not found");
		else {
			args->merge_only = TRUE;
			args->uid = gba->data;
			args->uid_size = gba->len;
			err = m2db_real_put_alias(m2db_args->sq3, args);
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
				err = _get_container_policy(args->sq3, &(args->nsinfo), &pol);
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
//m2db_force_alias(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url, GSList *beans)
m2db_force_alias(struct m2db_put_args_s *args, GSList *beans)
{
	guint8 uid[33];
	struct put_args_s args2;
	struct bean_ALIASES_s *latest = NULL;
	GError *err = NULL;

	g_assert(args != NULL);
	g_assert(args->sq3 != NULL);
	g_assert(args->url != NULL);
	if (!hc_url_has(args->url, HCURL_PATH))
		return NEWERROR(400, "Missing path");

	memset(&args2, 0, sizeof(args2));
	args2.beans = beans;

	gint64 size = m2db_patch_alias_beans_list(args, beans);

	if (hc_url_has(args->url, HCURL_VERSION)) {
		const char *tmp = hc_url_get(args->url, HCURL_VERSION);
		args2.version = g_ascii_strtoll(tmp, NULL, 10);
		err = m2db_get_versioned_alias(args->sq3, args->url, (gpointer*)&latest);
	} else {
		err = m2db_latest_alias(args->sq3, args->url, (gpointer*)&latest);
	}

	if (NULL != err) {
		if (err->code != CODE_CONTENT_NOTFOUND)
			g_prefix_error(&err, "Version error: ");
		else {
			g_clear_error(&err);
			SHA256_randomized_buffer(uid, sizeof(uid));
			args2.uid = uid;
			args2.uid_size = sizeof(uid);
			err = m2db_real_put_alias(args->sq3, &args2);
		}
	}
	else {
		if (latest)
			err = m2db_merge_alias(args, latest, &args2);
		else {
			SHA256_randomized_buffer(uid, sizeof(uid));
			args2.uid = uid;
			args2.uid_size = sizeof(uid);
			err = m2db_real_put_alias(args->sq3, &args2);
		}
	}

	if(!err)
       m2db_set_size(args->sq3, m2db_get_size(args->sq3) + size);

	if (latest)
		_bean_clean(latest);

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

	g_assert(args != NULL);
	g_assert(args->sq3 != NULL);
	g_assert(args->url != NULL);
	if (!hc_url_has(args->url, HCURL_PATH))
		return NEWERROR(400, "Missing path");

	gint64 size = m2db_patch_alias_beans_list(args, beans);

	struct check_args_s check_args;
	memset(&check_args, 0, sizeof(check_args));
	check_args.ns_info = &args->nsinfo;
	check_args.lbpool = args->lbpool;
	check_args.mask_checks = m2db_get_mask_check_put(check_args.ns_info);
	GRID_DEBUG("M2 PUT(%s) mask %08X", hc_url_get(args->url, HCURL_WHOLE),
			check_args.mask_checks);

	err = m2db_check_alias_beans_list(args->url, beans, &check_args);
	if (NULL != err) {
		g_prefix_error(&err, "Invalid beans: ");
		err->code = 400;
		return err;
	}

	SHA256_randomized_buffer(uid, sizeof(uid));
	args2.put_args = args;
	args2.uid = uid;
	args2.uid_size = sizeof(uid);
	args2.cb = cb;
	args2.cb_data = u0;
	args2.beans = beans;
	if (VERSIONS_DISABLED(args->max_versions) ||
			VERSIONS_SUSPENDED(args->max_versions)) {
		args2.version = -1; // Will be 0 in m2db_real_put_alias()
	}

	if (NULL != (err = m2db_latest_alias(args->sq3, args->url, (gpointer*)&latest))) {
		if (err->code == CODE_CONTENT_NOTFOUND)
			g_clear_error(&err);
		else
			g_prefix_error(&err, "Version error: ");
	}
	else if (latest) { /* alias present  */
		gint64 count_versions = _m2db_count_alias_versions(args->sq3, args->url);
		args2.version = ALIASES_get_version(latest);

		if (VERSIONS_DISABLED(args->max_versions)) { /* versioning disabled */
			if (!ALIASES_get_deleted(latest)) { /* content online */
				err = NEWERROR(CODE_CONTENT_EXISTS,
						"Versioning disabled and content already available");
			}
		}
		else { /* versioning enabled */
			if (VERSIONS_SUSPENDED(args->max_versions) ||
					(ALIASES_get_deleted(latest) &&
					 !is_in_a_snapshot(args->sq3, latest))) {
				args2.version -= 1; // Overwrite the deleted/unique version
				if (VERSIONS_SUSPENDED(args->max_versions))
					size -= _get_alias_size(args->sq3, latest);
			}
			if (args->max_versions <= count_versions + 1) {
				GRID_DEBUG("About to exceed the maximum of version for [%s]",
						hc_url_get(args->url, HCURL_WHOLE));
				/** @todo TODO trigger a purge on this URL */
			}
		}
	}

	if (!err) {
		err = m2db_real_put_alias(args->sq3, &args2);
		if (!err) {
			gchar buf[16];
			g_snprintf(buf, sizeof(buf), "%"G_GINT64_FORMAT, args2.version+1);
			hc_url_set(args->url, HCURL_VERSION, buf);
			m2db_set_size(args->sq3, m2db_get_size(args->sq3) + size);
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
	struct hc_url_s *orig = NULL;
	GError *err = NULL;

	GRID_TRACE("M2 COPY(%s FROM %s)", hc_url_get(args->url, HCURL_WHOLE), source);
	g_assert(args != NULL);
	g_assert(args->sq3 != NULL);
	g_assert(args->url != NULL);
	g_assert(source != NULL);

	if (!hc_url_has(args->url, HCURL_PATH))
		return NEWERROR(400, "Missing path");

	// Try to use source as an URL
	orig = hc_url_init(source);
	if (!orig || !hc_url_has(orig, HCURL_PATH)) {
		// Source is just the name of the content to copy
		orig = hc_url_init(hc_url_get(args->url, HCURL_WHOLE));
		hc_url_set(orig, HCURL_PATH, source);
	}

	if (hc_url_has(orig, HCURL_VERSION)) {
		err = m2db_get_versioned_alias(args->sq3, orig, (gpointer*)&latest);
	} else {
		err = m2db_latest_alias(args->sq3, orig, (gpointer*)&latest);
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
			ALIASES_set2_alias(latest, hc_url_get(args->url, HCURL_PATH));
			if (VERSIONS_DISABLED(args->max_versions) ||
					VERSIONS_SUSPENDED(args->max_versions)) {
				ALIASES_set_version(latest, 0);
			} else {
				// Will be overwritten a few lines below if content already exists
				ALIASES_set_version(latest, 1);
			}
			/* source ok */
			if (!(err = m2db_latest_alias(args->sq3, args->url, (gpointer*)&dst_latest))) {
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

	hc_url_clean(orig);

	return err;
}

/* APPEND ------------------------------------------------------------------- */

struct append_context_s
{
	GPtrArray *tmp;
	guint8 uid[32];
	GByteArray *old_uid;
	GString *md;
	GString *policy;
	gint64 container_version;
	gint64 old_version;
	gint64 old_count;
	gint64 old_size;
	gboolean fresh;
	gboolean versioning;
	gboolean append_on_deleted;
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
	else if (DESCR(bean) == &descr_struct_CHUNKS) {
		/* We need them for notification purposes */
		g_ptr_array_add(ctx->tmp, bean);
	}
	else {
		if (DESCR(bean) == &descr_struct_ALIASES) {
			/* get the most up-to-date version */
			i64 = ALIASES_get_version(bean);
			if (ctx->old_version < i64) {
				ctx->old_version = i64;
				/* if it's deleted, overwrite (do a PUT instead of append) */
				if (ALIASES_get_deleted(bean)) {
					ctx->old_version -= 1;
					ctx->fresh = TRUE;
				}
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
			// Save old content id so we can find old content beans
			ctx->old_uid = metautils_gba_dup(CONTENTS_HEADERS_get_id(bean));
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

static void _delete_contents_by_id(struct sqlx_sqlite3_s *sq3, GByteArray *cid,
		GError **err)
{
	const gchar *clause = " content_id = ? ";
	GVariant *params[] = {NULL, NULL};
	params[0] = _gba_to_gvariant(cid);
	*err = CONTENTS_delete(sq3->db, clause, params);
	g_variant_unref(params[0]);
}

GError*
m2db_append_to_alias(struct sqlx_sqlite3_s *sq3, namespace_info_t *ni,
		gint64 max_versions, struct hc_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0)
{
	struct append_context_s ctx;
	GError *err = NULL;

	// Sanity checks
	GRID_TRACE("M2 APPEND(%s)", hc_url_get(url, HCURL_WHOLE));
	g_assert(sq3 != NULL);
	g_assert(url != NULL);
	if (!hc_url_has(url, HCURL_PATH))
		return NEWERROR(400, "Missing path");

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
	err = m2db_get_alias(sq3, url, M2V2_FLAG_NOPROPS, _keep_old_bean, &ctx);
	/* Content does not exist or is deleted */
	if (err && err->code == CODE_CONTENT_NOTFOUND &&
			!VERSIONS_DISABLED(max_versions)) {
		ctx.fresh = TRUE; // Do a PUT instead of append
		g_clear_error(&err);
	}
	if (ctx.fresh) {
		/* renew the buffer */
		_bean_cleanv2(ctx.tmp);
		ctx.tmp = g_ptr_array_new();
	}

	/* Append the old beans that will be kept */
	if (!err) {
		if (ctx.fresh) {
			struct m2db_put_args_s args;
			memset(&args, 0, sizeof(args));
			args.sq3 = sq3;
			args.url = url;
			args.max_versions = max_versions;
			args.nsinfo = *ni;
			err = m2db_put_alias(&args, beans, cb, u0);
		}
		else {
			GRID_TRACE("M2 already %u beans, version=%"G_GINT64_FORMAT
					" position=%"G_GINT64_FORMAT" size=%"G_GINT64_FORMAT
					" md=[%s]",
					ctx.tmp->len, ctx.old_version, ctx.old_count,
					ctx.old_size, ctx.md->str);
			gint64 append_size = 0;

			ctx.container_version = 1 + m2db_get_version(sq3);
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
			if (!(err = _db_save_beans_array(sq3->db, ctx.tmp)) && cb) {
				guint i;
				for (i=0; i<ctx.tmp->len; i++) {
					cb(u0, _bean_dup(ctx.tmp->pdata[i]));
				}
			}
			if (VERSIONS_ENABLED(max_versions)) {
				// Container size is cumulative. Even if some chunks are
				// referenced by another alias version, we count them.
				m2db_set_size(sq3,
						m2db_get_size(sq3) + append_size + ctx.old_size);
			} else {
				m2db_set_size(sq3, m2db_get_size(sq3) + append_size);
			}
			if (!err && VERSIONS_DISABLED(max_versions)) {
				// We must not let old contents in the base or
				// synchronous deletion won't delete all chunks.
				_delete_contents_by_id(sq3, ctx.old_uid, &err);
				if (err) {
					GRID_DEBUG("%s", err->message);
					GRID_WARN("Some chunks may be referenced twice, purge recommended");
					g_clear_error(&err);
				}
			}
		}
	}

	g_string_free(ctx.md, TRUE);
	g_string_free(ctx.policy, TRUE);
	_bean_cleanv2(ctx.tmp);
	metautils_gba_unref(ctx.old_uid);
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

	g_ptr_array_add(ctx->tmp, _bean_dup(bean));
}


GError*
m2db_update_alias_header(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		struct hc_url_s *url, GSList *beans, gboolean skip_checks)
{
	struct update_alias_header_ctx_s ctx;
	struct bean_ALIASES_s *latest = NULL;
	GError *err = NULL;

	// Sanity checks
	GRID_TRACE("M2 UPDATE ALIAS HEADER(%s)", hc_url_get(url, HCURL_WHOLE));

	g_assert(sq3 != NULL);
	g_assert(url != NULL);

	if (!hc_url_has(url, HCURL_PATH))
		return NEWERROR(CODE_BAD_REQUEST, "Missing path");

	if (!skip_checks) {
		struct check_args_s check_args;
		memset(&check_args, 0, sizeof(check_args));
		check_args.mask_checks = ~0;

		err = m2db_check_alias_beans_list(url, beans, &check_args);
		if (NULL != err) {
			g_prefix_error(&err, "Invalid beans: ");
			err->code = 400;
			return err;
		}
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.tmp = g_ptr_array_new();
	ctx.old_version = G_MININT64;
	ctx.versioning = VERSIONS_ENABLED(max_versions);
	SHA256_randomized_buffer(ctx.uid, sizeof(ctx.uid));

	// Merge the previous versions of the beans with the new part
	if (NULL != (err = m2db_latest_alias(sq3, url, (gpointer*)(&latest)))) {
		g_prefix_error(&err, "Latest error: ");
		return err;
	}
	ctx.old_version = ALIASES_get_version(latest);
	ctx.container_version = 1 + m2db_get_version(sq3);

	/* append and mangle the new beans */
	GRID_TRACE("UDPATE NEW BEAN => v + 1");
	for (; beans ;beans=beans->next) {
		_update_new_bean(&ctx, beans->data);
	}

	/* Now save the whole */
	err = _db_save_beans_array(sq3->db, ctx.tmp);

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
	if (!pol || !key)
		return def;
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
	if (!g_hash_table_lookup(unpacked,"creation-date"))
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

static void
_m2_generate_content_chunk(struct gen_ctx_s *ctx, struct service_info_s *si,
		guint pos, gint64 cs, gint subpos, gboolean parity)
{
	gchar *chunkid, strpos[64];
	gchar *strvol, straddr[STRLEN_ADDRINFO], strid[STRLEN_CHUNKID];

	GRID_TRACE2("%s(%s)", __FUNCTION__, hc_url_get(ctx->url, HCURL_WHOLE));

	grid_addrinfo_to_string(&(si->addr), straddr, sizeof(straddr));
	strvol = metautils_rawx_get_volume(si);
	SHA256_randomized_string(strid, sizeof(strid));

	if (subpos >= 0)
		g_snprintf(strpos, sizeof(strpos), (parity ? "%u.p%d" : "%u.%d"), pos, subpos);
	else
		g_snprintf(strpos, sizeof(strpos), "%u", pos);

	chunkid = assemble_chunk_id(straddr, strvol, strid);
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
	GError *err = NULL;
	/* Chunk position */
	guint pos;
	/* Current allocated size */
	gint64 s;
	/* Current chunk size */
	gint64 cs;
	/* Storage policy storage class */
	const struct storage_class_s *stgclass;
	gint distance, k, m;

	GRID_TRACE2("%s(%s)", __FUNCTION__, hc_url_get(ctx->url, HCURL_WHOLE));
	distance = _policy_parameter(ctx->pol, DS_KEY_DISTANCE, 1);
	k = _policy_parameter(ctx->pol, DS_KEY_K, 3);
	m = _policy_parameter(ctx->pol, DS_KEY_M, 2);
	stgclass = storage_policy_get_storage_class(ctx->pol);
	_m2_generate_alias_header(ctx);

	(void) distance;

	for (pos=0,s=0; s < MAX(ctx->size,1) ;) {
		struct service_info_s **siv = NULL;

		struct lb_next_opt_s opt;
		memset(&opt, 0, sizeof(opt));
		opt.req.duplicates = (distance <= 0);
		opt.req.max = ((ctx->size>0)?(k + m):1);
		opt.req.distance = distance;
		opt.req.stgclass = stgclass;
		opt.req.strict_stgclass = FALSE; // Accept ersatzes

		if (!grid_lb_iterator_next_set(ctx->iter, &siv, &opt)) {
			if ( pos == 0 )
				err = NEWERROR(CODE_PLATFORM_ERROR,"No Rawx available");
			else
				err = NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "Not enough RAWX");
			break;
		}

		/* meta chunk size */
		if (ctx->chunk_size < (cs = ctx->size - s))
			cs = ctx->chunk_size;

		for (gint i=0; siv[i] ;++i) {
			gboolean parity = (i >= k);
			_m2_generate_content_chunk(ctx, siv[i], pos, cs,
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
	/* Chunk position */
	guint pos;
	/* Current allocated size */
	gint64 s;
	/* Current chunk size */
	gint64 cs;
	/* Storage policy storage class */
	const struct storage_class_s *stgclass;
	gint distance, copies;

	GRID_TRACE2("%s(%s)", __FUNCTION__, hc_url_get(ctx->url, HCURL_WHOLE));
	distance = _policy_parameter(ctx->pol, DS_KEY_DISTANCE, 1);
	copies = _policy_parameter(ctx->pol, DS_KEY_COPY_COUNT, 1);
	stgclass = storage_policy_get_storage_class(ctx->pol);
	_m2_generate_alias_header(ctx);

	(void) distance;

	for (pos=0,s=0; s < MAX(ctx->size,1) ;) {
		struct service_info_s **psi, **siv = NULL;

		struct lb_next_opt_s opt;
		memset(&opt, 0, sizeof(opt));
		// suppose that duplicates have distance=0 between them
		opt.req.duplicates = (distance <= 0);
		opt.req.max = copies;
		opt.req.distance = distance;
		opt.req.stgclass = stgclass;
		opt.req.strict_stgclass = FALSE; // Accept ersatzes

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
			_m2_generate_content_chunk(ctx, *psi, pos, cs, -1, FALSE);

		service_info_cleanv(siv, FALSE);

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

	if (!pol/* || size == 0*/)
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
_get_content_policy(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		struct namespace_info_s *nsinfo, struct storage_policy_s **result)
{
	GError *err = NULL;
	GPtrArray *tmp = NULL;
	struct bean_ALIASES_s *latest = NULL;
	struct storage_policy_s *policy = NULL;

	tmp = g_ptr_array_new();

	if (!(err = m2db_latest_alias(sq3, url, (gpointer*)&latest))) {
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
	g_assert(result != NULL);

	*result = NULL;
	pname = sqlx_admin_get_str(sq3, M2V2_PROP_PREFIX_SYS"storage_policy");
	if (pname) {
		*result = storage_policy_init(nsinfo, pname);
		g_free(pname);
	}

	return NULL;
}

GError*
m2db_get_storage_policy(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		struct namespace_info_s *nsinfo, gboolean from_previous,
		struct storage_policy_s **result)
{
	GError *err = NULL;
	struct storage_policy_s *policy = NULL;

	GRID_TRACE2("%s(%s)", __FUNCTION__, hc_url_get(url, HCURL_WHOLE));
	g_assert(sq3 != NULL);
	g_assert(url != NULL);
	g_assert(nsinfo != NULL);
	g_assert(result != NULL);

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
	const gchar *k = M2V2_PROP_PREFIX_SYS"storage_policy";

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
m2db_set_container_name(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url)
{
	const gchar *v;

	sqlx_admin_init_str(sq3, M2V2_PROP_PREFIX_SYS M2V2_KEY_VERSION, "0");

	v = hc_url_get(url, HCURL_REFERENCE);
	if (v != NULL)
		sqlx_admin_init_str(sq3, M2V2_PROP_PREFIX_SYS "container_name", v);

	v = hc_url_get(url, HCURL_NS);
	if (v != NULL)
		sqlx_admin_init_str(sq3, M2V2_PROP_PREFIX_SYS "namespace", v);
}

GError*
m2db_get_container_status(struct sqlx_sqlite3_s *sq3, guint32 *status)
{
	*status = sqlx_admin_get_i64(sq3, "flags", (gint64)CONTAINER_STATUS_ENABLED);
	return NULL;
}

GError*
m2db_set_container_status(struct sqlx_sqlite3_s *sq3, guint32 repl)
{
	sqlx_admin_set_i64(sq3, "flags", (gint64)repl);
	return NULL;
}

/* ------------------------------------------------------------------------- */

GError *
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

	// Then, only if the HEADER is deleted
	// - we can remove all the CONTENTS
	// - it is worth checking the CHUNKS
	if (header_deleted) {
		for (GSList *l = beans; !err && l ;l=l->next) {
			gpointer bean = l->data;
			if (&descr_struct_CONTENTS == DESCR(bean))
				deleted = g_slist_prepend(deleted, bean);
			else if (&descr_struct_CHUNKS == DESCR(bean)) {
				if (check_FK(bean, "contents"))
					deleted = g_slist_prepend(deleted, bean);
			}
		}
	}

	if (err)
		g_slist_free(deleted);
	else
		*pdeleted = deleted;
	return err;

}

static GError*
_purge_exceeding_aliases(struct sqlx_sqlite3_s *sq3, gint64 max_versions)
{
	struct elt_s {
		gchar *alias;
		gint64 count;
	};

	GRID_TRACE("%s, max_versions = %"G_GINT64_FORMAT, __FUNCTION__, max_versions);

	const gchar *sql_lookup = "SELECT alias, count(*)"
		"FROM alias_v2 "
		"WHERE NOT deleted " // Do not count last extra deleted version
		"AND container_version NOT IN (SELECT version FROM snapshot_v2) "
		"GROUP BY alias "
		"HAVING COUNT(*) > ?";
	const gchar *sql_delete = "DELETE FROM alias_v2 WHERE rowid IN "
		"(SELECT rowid FROM alias_v2 WHERE alias = ? "
		"AND container_version NOT IN (SELECT version FROM snapshot_v2) "
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

	sqlite3_prepare_debug(rc, sq3->db, sql_delete, -1, &stmt, NULL);
	if (rc == SQLITE_OK) {
		// OK, allowed to enter the loop above
		rc = SQLITE_DONE;
	}
	for (GSList *l=to_be_deleted; l ; l=l->next) {
		struct elt_s *elt = l->data;
		sqlite3_clear_bindings(stmt);
		sqlite3_reset(stmt);
		sqlite3_bind_text(stmt, 1, elt->alias, -1, NULL);
		sqlite3_bind_int64(stmt, 2, elt->count - max_versions);
		GRID_TRACE("Dropping %ld oldest versions of %s",
				(elt->count - max_versions),  elt->alias);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) { }
	}
	if (rc == SQLITE_DONE)
		rc = sqlite3_finalize(stmt);

	if (rc != SQLITE_OK) {
		if (!gquark_log)
			gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);
		err = SQLITE_GERROR(sq3->db, rc);
		GRID_ERROR("Failed to remove exceeding alias versions: %s",
				err->message);
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
_purge_deleted_aliases(struct sqlx_sqlite3_s *sq3, gint64 delay)
{
	GError *err = NULL;
	gchar *sql, *sql2;
	GSList *old_deleted = NULL;
	GVariant *params[] = {NULL, NULL};
	gint64 now = (gint64) time(0);
	gint64 time_limit = 0;
	struct dup_alias_params_s dup_params;

	// All aliases which have one version deleted (the last) older than time_limit
	sql = (" alias IN "
			"(SELECT alias FROM "
			"  (SELECT alias,ctime,deleted FROM alias_v2 GROUP BY alias) "
			" WHERE deleted AND ctime < ?) "
			"AND container_version NOT IN (SELECT version FROM snapshot_v2) ");

	// Last snapshoted aliases part of deleted contents.
	// (take some paracetamol)
	sql2 = (" rowid IN (SELECT a1.rowid FROM alias_v2 AS a1"
			" INNER JOIN "
			"(SELECT alias,max(deleted) as mdel FROM alias_v2 GROUP BY alias) AS a2 "
			"ON a1.alias = a2.alias "
			"WHERE mdel AND "
			"container_version IN (SELECT version FROM snapshot_v2) "
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

	// Do the purge.
	GRID_DEBUG("Purging deleted aliases older than %ld seconds (timestamp < %ld)",
			delay, time_limit);
	params[0] = g_variant_new_int64(time_limit);
	err = ALIASES_delete(sq3->db, sql, params);
	gvariant_unrefv(params);

	// Re-delete what needs to.
	memset(&dup_params, 0, sizeof(struct dup_alias_params_s));
	dup_params.sq3 = sq3;
	dup_params.set_deleted = TRUE;
	dup_params.c_version = m2db_get_version(sq3);
	for (GSList *l = old_deleted; l != NULL; l = l->next) {
		if (!ALIASES_get_deleted(l->data)) {
			if (GRID_TRACE_ENABLED()) {
				GRID_TRACE("Copy/delete %s version %ld",
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

static gint64
_get_chunks_to_drop(sqlite3 *db, m2_onbean_cb cb, gpointer u0)
{
	gint64 count = 0;
	GVariant *params[] = {NULL};

	void cb_counter(gpointer udata, gpointer bean) {
		cb(udata, bean);
		count++;
	}
	CHUNKS_load(db,
			" NOT EXISTS (SELECT chunk_id FROM content_v2 WHERE chunk_id = id)",
			params, cb_counter, u0);
	return count;
}

GError*
m2db_purge(struct sqlx_sqlite3_s *sq3, gint64 max_versions, gint64 retention_delay, 
	guint32 flags, m2_onbean_cb cb, gpointer u0)
{
	GError *err;
	gboolean dry_run = flags & M2V2_MODE_DRYRUN;

	if (!dry_run) {
		// TODO: send purged aliases to callback
		if (NULL != (err = _purge_exceeding_aliases(sq3, max_versions))) {
			GRID_WARN("Failed to purge ALIASES: (code=%d) %s",
					err->code, err->message);
			g_clear_error(&err);
		}

		if (retention_delay >= 0) {
			if ((err = _purge_deleted_aliases(sq3, retention_delay)) != NULL) {
				GRID_WARN("Failed to purge deleted ALIASES: (code=%d) %s",
						err->code, err->message);
				g_clear_error(&err);
			}
		}

		/* purge unreferenced properties */
		sqlx_exec(sq3->db, "DELETE FROM properties_v2 WHERE NOT EXISTS "
				"(SELECT alias FROM alias_v2 "
				" WHERE alias_v2.alias = properties_v2.alias)");

		/* purge unreferenced content_headers, cascading to contents */
		sqlx_exec(sq3->db, "DELETE FROM content_header_v2 WHERE NOT EXISTS "
				"(SELECT content_id FROM alias_v2 WHERE content_id = id)");

		sqlx_exec(sq3->db, "DELETE FROM content_v2 WHERE NOT EXISTS "
				"(SELECT content_id FROM alias_v2 "
				" WHERE alias_v2.content_id = content_v2.content_id)");
	}

	/* delete chunks if asked */
	if (NULL != cb) {
		gint64 count = _get_chunks_to_drop(sq3->db, cb, u0);

		GRID_DEBUG("Nb chunks found to delete %ld", count);

		if (!dry_run) {
			/* purge unreferenced chunks */
			sqlx_exec(sq3->db, "DELETE FROM chunk_v2 WHERE NOT EXISTS "
					"(SELECT chunk_id FROM content_v2 WHERE chunk_id = id)");
		}
	}

	if (!dry_run) {
		guint64 size = m2db_get_container_size(sq3->db, FALSE);
		m2db_set_size(sq3, (gint64)size);
	}

	return NULL;
}

GError*
m2db_deduplicate_chunks(struct sqlx_sqlite3_s *sq3, namespace_info_t *nsinfo,
		struct hc_url_s *url)
{
	GError *err = NULL;
	/* List of aliases that failed to be deduplicated */
	GSList *aliases_errors = NULL;

	/* Call m2db_deduplicate_alias_chunks on each alias of container */
	void alias_bean_cb(gpointer user_data, struct bean_ALIASES_s *alias) {
		(void) user_data;
		GError *err2 = NULL;
		GString *alias_str = ALIASES_get_alias(alias);
		struct hc_url_s *url2 = hc_url_init(hc_url_get(url, HCURL_WHOLE));
		hc_url_set(url2, HCURL_PATH, alias_str->str);
		err2 = m2db_deduplicate_alias_chunks(sq3, nsinfo, url2);
		if (err2 != NULL) {
			/* Cannot stop calling function,
			 * so save errors for further handling */
			aliases_errors = g_slist_prepend(aliases_errors, err2);
		}
		_bean_clean(alias);
		hc_url_clean(url2);
	}

	/* List all non-deleted aliases */
	struct list_params_s lp;
	memset(&lp, '\0', sizeof(struct list_params_s));
	lp.flags = M2V2_FLAG_NODELETED;

	err = m2db_list_aliases(sq3, &lp, (m2_onbean_cb) alias_bean_cb, NULL);

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
m2db_deduplicate_alias_chunks(struct sqlx_sqlite3_s *sq3, namespace_info_t *nsinfo,
		struct hc_url_s *url)
{
	GError *err = NULL;
	guint nb_copy = 1;
	struct storage_policy_s *sp = NULL;
	err = _get_content_policy(sq3, url, nsinfo, &sp);
	if (err != NULL) {
		return err;
	} else {
		nb_copy = _policy_parameter(sp, DS_KEY_COPY_COUNT, 1);
	}
	GString *alias = g_string_new(hc_url_get(url, HCURL_PATH));
	dedup_chunks_of_alias(sq3->db, alias, nb_copy, &err);
	g_string_free(alias, TRUE);
	return err;
}

GError*
m2db_deduplicate_contents(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		guint32 flags, GString **status_message)
{
	GError *err = NULL;
	GSList *impacted_aliases = NULL;
	gboolean dry_run = flags & M2V2_MODE_DRYRUN;
	guint64 size_before = m2db_get_container_size(sq3->db, TRUE);
	guint64 saved_space = dedup_aliases(sq3->db, url, dry_run, &impacted_aliases, &err);
	guint64 size_after = m2db_get_container_size(sq3->db, TRUE);
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

GError*
m2db_content_urls_from_chunk_id(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		const gchar* chunk_id, gint64 limit, GSList **urls)
{
	gchar version[16];
	GError *err = NULL;
	void alias_bean_cb(gpointer user_data, struct bean_ALIASES_s *alias) {
		version[0] = '\0';
		struct hc_url_s *new_url = hc_url_empty();
		hc_url_set(new_url, HCURL_NS, hc_url_get(url, HCURL_NS));
		hc_url_set(new_url, HCURL_HEXID, hc_url_get(url, HCURL_HEXID));
		g_snprintf(version, 16, "%"G_GINT64_FORMAT, ALIASES_get_version(alias));
		hc_url_set(new_url, HCURL_PATH, ALIASES_get_alias(alias)->str);
		hc_url_set(new_url, HCURL_VERSION, version);
		*urls = g_slist_prepend(*urls, new_url);
		(void) user_data;
		_bean_clean(alias);
	}
	gchar *sql = (" content_id IN"
			" (SELECT DISTINCT content_id"
			"  FROM content_v2 "
			"  WHERE chunk_id = ?) LIMIT ?");

	GVariant *params[3] = {NULL, NULL, NULL};
	GRID_TRACE("chunk_id to search: %s, limit %"G_GINT64_FORMAT,
			chunk_id, limit);
	params[0] = g_variant_new_string(chunk_id);
	params[1] = g_variant_new_int64(limit);
	err = ALIASES_load(sq3->db, sql, params, (m2_onbean_cb)alias_bean_cb, NULL);
	gvariant_unrefv(params);
	return err;
}

GError*
m2db_flush_container(sqlite3 *db)
{
	GError *err = NULL;
	int rc = SQLITE_OK;

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	rc = sqlx_exec(db, "DELETE FROM snapshot_v2");
	if (rc != SQLITE_OK) {
		err = SQLITE_GERROR(db, rc);
	} else {
		rc = sqlx_exec(db, "DELETE FROM alias_v2");
		if (rc != SQLITE_OK) {
			err = SQLITE_GERROR(db, rc);
		}
	}
	return err;
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
			struct hc_url_s *url = hc_url_empty();
			hc_url_set(url, HCURL_PATH, ALIASES_get_alias(new_alias)->str);
			local_err = m2db_get_alias_version(params->sq3, url, 0, &latest_version);
			if (local_err != NULL) {
				GRID_WARN("Failed to get latest alias version for '%s'",
						ALIASES_get_alias(new_alias)->str);
				g_clear_error(&local_err);
				_bean_clean(new_alias);
				new_alias = NULL;
			}
			hc_url_clean(url);
		}
		if (local_err == NULL) {
			ALIASES_set_version(new_alias,
					(!params->overwrite_latest) + latest_version);
			ALIASES_set_container_version(new_alias, 1 + params->c_version);
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
		clause = " container_version = ? GROUP BY alias "; // FIXME: group by needed ?
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

