/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2025 OVH SAS

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

const struct bean_descriptor_s *TABLE_TO_MERGE[5] = {
	&descr_struct_PROPERTIES,
	&descr_struct_CONTENTS_HEADERS,
	&descr_struct_CHUNKS,
	&descr_struct_ALIASES,
	NULL
};

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

static void
_get_container_size_and_obj_count_by_policy(struct sqlx_sqlite3_s *sq3,
		gboolean check_alias, const gchar *policy,
		guint64 *size_out, gint64 *obj_count_out)
{
	EXTRA_ASSERT(sq3 != NULL && sq3->db != NULL);

	guint64 size = 0;
	gint64 obj_count = 0;
	gchar sql[512];
	g_snprintf(sql, sizeof(sql),
			"SELECT SUM(size),COUNT(id) FROM contents WHERE policy == ?%s",
			!check_alias ? "" :
			" AND EXISTS (SELECT content FROM aliases WHERE content = id)");
	sqlite3_stmt *stmt = NULL;
	int rc;

	// Find used storage policies
	sqlite3_prepare_debug(rc, sq3->db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE) {
		GRID_WARN("Failed to compute size and object count "
				"for storage policy %s: (%d/%s) %s reqid=%s",
				policy, rc, sqlite_strerror(rc), sqlite3_errmsg(sq3->db),
				oio_ext_get_reqid());
		return;
	}
	(void) sqlite3_bind_text(stmt, 1, policy, -1, NULL);
	while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
		size = sqlite3_column_int64(stmt, 0);
		obj_count = sqlite3_column_int64(stmt, 1);
	}
	sqlite3_finalize_debug(rc, stmt);
	if (rc != SQLITE_DONE && rc != SQLITE_OK) {
		GRID_WARN("Failed to compute size and object count "
			"for storage policy %s: (%d/%s) %s reqid=%s",
			policy, rc, sqlite_strerror(rc), sqlite3_errmsg(sq3->db),
			oio_ext_get_reqid());
		return;
	}

	if (size_out)
		*size_out = size;
	if (obj_count_out)
		*obj_count_out = obj_count;
}

void
m2db_recompute_container_size_and_obj_count(struct sqlx_sqlite3_s *sq3,
		gboolean check_alias UNUSED)
{
	GPtrArray *policies = g_ptr_array_new_with_free_func(g_free);
	sqlite3_stmt *stmt = NULL;
	int rc;

	// Reset stats
	m2db_set_size(sq3, 0);
	m2db_set_obj_count(sq3, 0);

	// Find used storage policies
	sqlite3_prepare_debug(rc, sq3->db,
			"SELECT DISTINCT policy FROM contents", -1, &stmt, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE) {
		GRID_WARN("Failed to find storage policies: (%d/%s) %s reqid=%s",
				rc, sqlite_strerror(rc), sqlite3_errmsg(sq3->db),
				oio_ext_get_reqid());
		goto end;
	}
	while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
		g_ptr_array_add(policies, g_strndup(
				(gchar*) sqlite3_column_text(stmt, 0),
					sqlite3_column_bytes(stmt, 0)));
	}
	sqlite3_finalize_debug(rc, stmt);
	if (rc != SQLITE_DONE && rc != SQLITE_OK) {
		GRID_WARN("Failed to find storage policies: (%d/%s) %s reqid=%s",
				rc, sqlite_strerror(rc), sqlite3_errmsg(sq3->db),
				oio_ext_get_reqid());
		goto end;
	}

	guint64 size = 0u;
	gint64 count = 0;
	for (guint i=0; i < policies->len; i++) {
		gchar *policy = policies->pdata[i];
		size = 0u;
		count = 0;
		_get_container_size_and_obj_count_by_policy(sq3, check_alias, policy,
				&size, &count);
		m2db_update_size(sq3, size, policy);
		m2db_update_obj_count(sq3, count, policy);
	}

end:
	g_ptr_array_free(policies, TRUE);
}

void
m2db_get_container_shard_count(struct sqlx_sqlite3_s *sq3,
		gint64 *shard_count_out)
{
	gint64 shard_count = 0;
	const gchar *sql = "SELECT COUNT(*) FROM shard_ranges";
	int rc, grc = SQLITE_OK;
	const gchar *next;
	sqlite3_stmt *stmt = NULL;

	while ((grc == SQLITE_OK) && sql && *sql) {
		next = NULL;
		sqlite3_prepare_debug(rc, sq3->db, sql, -1, &stmt, &next);
		sql = next;
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			grc = rc;
		else if (stmt) {
			while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
				shard_count = sqlite3_column_int64(stmt, 0);
			}
			if (rc != SQLITE_OK && rc != SQLITE_DONE) {
				grc = rc;
			}
			rc = sqlx_sqlite3_finalize(sq3, stmt, NULL);
		}

		stmt = NULL;
	}
	if (shard_count_out)
		*shard_count_out = shard_count;
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

gint64
m2db_get_size_by_policy(struct sqlx_sqlite3_s *sq3, const gchar *policy)
{
	gchar * policy_key = g_strdup_printf(M2V2_ADMIN_SIZE".%s", policy);
	gint64 size = sqlx_admin_get_i64(sq3, policy_key, 0);
	g_free(policy_key);
	return size;
}

static gboolean
_size_property_filter(const gchar *k)
{
	return g_str_has_prefix(k, M2V2_ADMIN_SIZE".");
}

gchar**
m2db_get_size_properties_by_policy(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_admin_get_keyvalues(sq3, _size_property_filter);
}

void
m2db_set_size(struct sqlx_sqlite3_s *sq3, gint64 size)
{
	sqlx_admin_set_i64(sq3, M2V2_ADMIN_SIZE, (size>0)?size:0);
	if (size <= 0) {
		sqlx_admin_del_all_keys_with_prefix(sq3, M2V2_ADMIN_SIZE".",
				NULL, NULL);
	}
}

void
m2db_set_size_by_policy(struct sqlx_sqlite3_s *sq3, gint64 size,
		const gchar *policy)
{
	gchar * policy_key = g_strdup_printf(M2V2_ADMIN_SIZE".%s", policy);
	if (size > 0) {
		sqlx_admin_set_i64(sq3, policy_key, size);
	} else {
		sqlx_admin_del(sq3, policy_key);
	}
	g_free(policy_key);
}

void
m2db_update_size(struct sqlx_sqlite3_s *sq3, gint64 inc, const gchar *policy)
{
	gint64 current_size = m2db_get_size(sq3);
	m2db_set_size(sq3, current_size + inc);
	if (policy) {
		current_size = m2db_get_size_by_policy(sq3, policy);
		m2db_set_size_by_policy(sq3, current_size + inc, policy);
	}
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

gint64
m2db_get_obj_count_by_policy(struct sqlx_sqlite3_s *sq3, const gchar *policy)
{
	gchar * policy_key = g_strdup_printf(M2V2_ADMIN_OBJ_COUNT".%s", policy);
	gint64 count = sqlx_admin_get_i64(sq3, policy_key, 0);
	g_free(policy_key);
	return count;
}

static gboolean
_obj_count_property_filter(const gchar *k)
{
	return g_str_has_prefix(k, M2V2_ADMIN_OBJ_COUNT".");
}

gchar**
m2db_get_obj_count_properties_by_policy(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_admin_get_keyvalues(sq3, _obj_count_property_filter);
}

void
m2db_set_obj_count(struct sqlx_sqlite3_s *sq3, gint64 count)
{
	sqlx_admin_set_i64(sq3, M2V2_ADMIN_OBJ_COUNT, (count>0)?count:0);
	if (count <= 0) {
		sqlx_admin_del_all_keys_with_prefix(sq3, M2V2_ADMIN_OBJ_COUNT".",
				NULL, NULL);
	}
}

void
m2db_set_obj_count_by_policy(struct sqlx_sqlite3_s *sq3, gint64 count,
		const gchar *policy)
{
	gchar * policy_key = g_strdup_printf(M2V2_ADMIN_OBJ_COUNT".%s", policy);
	if (count > 0) {
		sqlx_admin_set_i64(sq3, policy_key, count);
	} else {
		sqlx_admin_del(sq3, policy_key);
	}
	g_free(policy_key);
}

void
m2db_update_obj_count(struct sqlx_sqlite3_s *sq3, gint64 inc,
		const gchar *policy)
{
	gint64 current_count = m2db_get_obj_count(sq3);
	m2db_set_obj_count(sq3, current_count + inc);
	if (policy) {
		current_count = m2db_get_obj_count_by_policy(sq3, policy);
		m2db_set_obj_count_by_policy(sq3, current_count + inc, policy);
	}
}

gint64
m2db_get_shard_count(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_admin_get_i64(sq3, M2V2_ADMIN_SHARD_COUNT, 0);
}

void
m2db_set_shard_count(struct sqlx_sqlite3_s *sq3, gint64 count)
{
	sqlx_admin_set_i64(sq3, M2V2_ADMIN_SHARD_COUNT, (count>0)?count:0);
}

GError *
m2db_get_sharding_lower(struct sqlx_sqlite3_s *sq3, gchar **result)
{
	EXTRA_ASSERT(result != NULL);

	gchar *admin_lower = sqlx_admin_get_str(sq3, M2V2_ADMIN_SHARDING_LOWER);
	if (!admin_lower) {
		return SYSERR("No lower for the shard");
	}
	if (*admin_lower != '>') {
		g_free(admin_lower);
		return SYSERR("Wrong lower prefix for the shard");
	}
	*result = g_strdup(admin_lower + 1);
	g_free(admin_lower);
	return NULL;
}

GError *
m2db_get_sharding_upper(struct sqlx_sqlite3_s *sq3, gchar **result)
{
	EXTRA_ASSERT(result != NULL);

	gchar *admin_upper = sqlx_admin_get_str(sq3, M2V2_ADMIN_SHARDING_UPPER);
	if (!admin_upper) {
		return SYSERR("No upper for the shard");
	}
	if (*admin_upper != '<') {
		g_free(admin_upper);
		return SYSERR("Wrong upper prefix for the shard");
	}
	*result = g_strdup(admin_upper + 1);
	g_free(admin_upper);
	return NULL;
}

gint64
m2db_get_drain_obj_count(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_admin_get_i64(sq3, M2V2_ADMIN_DRAINING_OBJ_COUNT, 0);
}

void
m2db_set_drain_obj_count(struct sqlx_sqlite3_s *sq3, gint64 count)
{
	sqlx_admin_set_i64(sq3, M2V2_ADMIN_DRAINING_OBJ_COUNT, (count>0)?count:0);
}

void
m2db_del_drain_obj_count(struct sqlx_sqlite3_s *sq3)
{
	sqlx_admin_del(sq3, M2V2_ADMIN_DRAINING_OBJ_COUNT);
}

gint64
m2db_get_drain_state(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_admin_get_i64(sq3, M2V2_ADMIN_DRAINING_STATE, 0);
}

void
m2db_set_drain_state(struct sqlx_sqlite3_s *sq3, gint64 state)
{
	sqlx_admin_set_i64(sq3, M2V2_ADMIN_DRAINING_STATE, (state>0)?state:0);
}

void
m2db_del_drain_state(struct sqlx_sqlite3_s *sq3)
{
	sqlx_admin_del(sq3, M2V2_ADMIN_DRAINING_STATE);
}

GError *
m2db_get_drain_marker(struct sqlx_sqlite3_s *sq3, gchar **result)
{
	EXTRA_ASSERT(result != NULL);
	*result = NULL;

	gchar *marker = sqlx_admin_get_str(sq3, M2V2_ADMIN_DRAINING_MARKER);
	if (marker != NULL) {
		*result = marker;
	}
	return NULL;
}

void
m2db_set_drain_marker(struct sqlx_sqlite3_s *sq3, const gchar *marker)
{
	sqlx_admin_set_str(sq3, M2V2_ADMIN_DRAINING_MARKER, marker);
}

void
m2db_del_drain_marker(struct sqlx_sqlite3_s *sq3)
{
	sqlx_admin_del(sq3, M2V2_ADMIN_DRAINING_MARKER);
}

gint64
m2db_get_drain_timestamp(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_admin_get_i64(sq3, M2V2_ADMIN_DRAINING_TIMESTAMP, 0);
}

void
m2db_set_drain_timestamp(struct sqlx_sqlite3_s *sq3, gint64 timestamp)
{
	sqlx_admin_set_i64(sq3, M2V2_ADMIN_DRAINING_TIMESTAMP,
			(timestamp>0)?timestamp:0);
}

void
m2db_del_drain_timestamp(struct sqlx_sqlite3_s *sq3)
{
	sqlx_admin_del(sq3, M2V2_ADMIN_DRAINING_TIMESTAMP);
}

/* GET ---------------------------------------------------------------------- */

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

struct _url_n_pol_s {
	struct oio_url_s *url;
	const gchar *pol;
	GError *err;
};

static gboolean
_foreach_chunk_extend_url(gpointer key UNUSED, gpointer value, gpointer data)
{
	GError *err = NULL;
	struct _url_n_pol_s *url_n_pol = data;

	for (GSList *chunks = value; chunks != NULL; chunks = chunks->next) {
		struct bean_CHUNKS_s *chunk = chunks->data;
		err = m2v2_extend_chunk_url(url_n_pol->url, url_n_pol->pol, chunk);
		if (err) {
			// Discard the previous error
			g_clear_error(&url_n_pol->err);
			url_n_pol->err = err;
		}
	}
	return FALSE;
}

GError *
m2v2_sorted_content_extend_chunk_urls(struct m2v2_sorted_content_s *content,
		struct oio_url_s *url)
{
	if (g_tree_nnodes(content->metachunks) < 1)
		return NULL;  // No chunk, nothing to do.

	gchar* policy = NULL;
	m2v2_policy_decode(CONTENTS_HEADERS_get_policy(content->header), &policy, NULL);

	struct _url_n_pol_s url_n_pol = {
		url,
		policy,
		NULL
	};
	g_tree_foreach(content->metachunks, _foreach_chunk_extend_url, &url_n_pol);
	g_free(policy);
	return url_n_pol.err;
}

GError*
m2v2_check_chunk_uniqueness(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		const GSList *beans, struct namespace_info_s *nsinfo)
{
	GError *err = NULL;
	GPtrArray *tmp = NULL;
	GHashTable *positions_count = g_hash_table_new_full(
		g_str_hash, g_str_equal, NULL, NULL);

	// Get chunk positions to be inserted
	for (const GSList *l = beans; l; l= l->next) {
		gpointer bean = l->data;
		// Process only chunk beans
		if (DESCR(bean) != &descr_struct_CHUNKS) {
			continue;
		}
		GString *position = CHUNKS_get_position(bean);
		gint64 count = GPOINTER_TO_INT(
			g_hash_table_lookup(positions_count, position));
		g_hash_table_replace(
			positions_count, position->str, GINT_TO_POINTER(count + 1));
	}
	if (g_hash_table_size(positions_count) == 0) {
		// No chunks in beans to insert
		goto cleanup;
	}
	tmp = g_ptr_array_new();
	err = m2db_get_alias(
		sq3, url, M2V2_FLAG_MASTER|M2V2_FLAG_NOPROPS, _bean_buffer_cb, tmp);
	if (err) {
		goto cleanup;
	}
	gint64 allowed_copy = 0;
	for (guint i = 0; i < tmp->len; ++i) {
		gpointer bean = tmp->pdata[i];
		if (DESCR(bean) == &descr_struct_CHUNKS) {
			GString *position = CHUNKS_get_position(bean);
			gpointer ptr = NULL;
			gboolean found = g_hash_table_lookup_extended(
				positions_count, position->str, NULL, &ptr);
			if (found) {
				gint64 count = GPOINTER_TO_INT(ptr);
				g_hash_table_replace(
					positions_count, position->str, GINT_TO_POINTER(count + 1));
			}
		} else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
			if (strcmp(CONTENTS_HEADERS_get_chunk_method(bean)->str,
					CHUNK_METHOD_DRAINED) == 0) {
				// Drained content should not have chunks
				continue;
			}
			gchar *policy_name = NULL;
			m2v2_policy_decode(
				CONTENTS_HEADERS_get_policy(bean), &policy_name, NULL);
			struct storage_policy_s *policy = storage_policy_init(
				nsinfo, policy_name);
			const struct data_security_s *dsec = \
				storage_policy_get_data_security(policy);
			allowed_copy = data_security_get_int64_param(
				dsec, DS_KEY_COPY_COUNT, 1);
			g_free(policy_name);
			storage_policy_clean(policy);
		}
	}
	GList *counts = g_hash_table_get_values(positions_count);
	for (GList *l = counts; l;l = l->next) {
		gint64 count = GPOINTER_TO_INT(l->data);
		if (count > allowed_copy) {
			err = NEWERROR(
				CODE_CONTENT_EXISTS, "Too many copies of the same chunk");
			break;
		}
	}
	g_list_free(counts);
cleanup:
	g_hash_table_unref(positions_count);
	_bean_cleanv2(tmp);

	return err;
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

void
m2v2_shorten_chunk_id(struct bean_CHUNKS_s *bean)
{
	EXTRA_ASSERT(bean != NULL);
	GString *url = CHUNKS_get_id(bean);
	gchar *netloc = NULL;
	oio_parse_chunk_url(url->str, NULL, &netloc, NULL);
	if (oio_str_is_set(netloc)) {
		CHUNKS_set2_id(bean, netloc);
	}
	g_free(netloc);
}

void
m2v2_shorten_chunk_ids(GSList *beans)
{
	if (meta2_flag_store_chunk_ids)
		return;

	for (GSList *l = beans; l; l = l->next) {
		gpointer bean = l->data;
		if (DESCR(bean) != &descr_struct_CHUNKS)
			continue;

		m2v2_shorten_chunk_id(bean);
	}
}

/** Load all chunks related to the specified content header,
 * pass them to the callback function. */
static GError*
_manage_header(struct sqlx_sqlite3_s *sq3, struct bean_CONTENTS_HEADERS_s *bean,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;

	GPtrArray *tmp = g_ptr_array_new();
	err = _db_get_FK_by_name_buffered(bean, "chunks", sq3, tmp);
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

/** Load the content header and all chunks related to the specified alias,
 * pass them to the callback function. If "deeper" is false, load only
 * the content header. */
static GError*
_manage_alias(struct sqlx_sqlite3_s *sq3, struct bean_ALIASES_s *bean,
		gboolean deeper, m2_onbean_cb cb, gpointer u0)
{
	GPtrArray *tmp = g_ptr_array_new();
	GError *err = _db_get_FK_by_name_buffered(bean, "image", sq3, tmp);
	if (!err) {
		while (tmp->len > 0) {
			struct bean_CONTENTS_HEADERS_s *header = tmp->pdata[0];
			g_ptr_array_remove_index_fast(tmp, 0);
			if (!header)
				continue;
			if (deeper)
				_manage_header(sq3, header, cb, u0);
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
			_manage_alias(sq3, alias, !(flags & M2V2_FLAG_NORECURSION), cb, u0);
		}
	}

	/* recurse on properties if allowed */
	if (!err && cb && !(flags & M2V2_FLAG_NOPROPS)) {
		for (guint i = 0; !err && i < beans->len; i++) {
			struct bean_ALIASES_s *alias = beans->pdata[i];
			if (!alias)
				continue;
			GPtrArray *props = g_ptr_array_new();
			err = _db_get_FK_by_name_buffered(alias, "properties", sq3, props);
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
		err = ALIASES_load(sq3, sql, params, _bean_buffer_cb, tmp);
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

	if (lp->marker_start && g_strcmp0(lp->marker_start, lp->prefix) >= 0) {
		lazy_and();
		if (lp->flag_allversion && lp->version_marker) {
			g_string_append_static(clause,
					" ((alias == ? AND version < ?) OR alias > ?)");
			g_ptr_array_add(params, g_variant_new_string(lp->marker_start));
			g_ptr_array_add(params, g_variant_new_string(lp->version_marker));
			g_ptr_array_add(params, g_variant_new_string(lp->marker_start));
		} else {
			g_string_append_static(clause, " alias > ?");
			g_ptr_array_add(params, g_variant_new_string (lp->marker_start));
		}
	} else if (lp->prefix) {
		lazy_and();
		g_string_append_static(clause, " alias >= ?");
		g_ptr_array_add(params, g_variant_new_string (lp->prefix));
	}

	if (lp->marker_end) {
		lazy_and();
		g_string_append_static (clause, " alias < ?");
		g_ptr_array_add (params, g_variant_new_string (lp->marker_end));
	}

	if (lp->flag_mpu_marker_only) {
		lazy_and();
		g_string_append_static (clause, " SUBSTR(alias, -10, 10) NOT LIKE '%_/_%'");
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
	GError *err = _db_get_FK_by_name_buffered(alias, fk_name, sq3, t0);
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
		GSList *headers, m2_onbean_cb cb, gpointer u, gchar **next_marker)
{
	GError *err = NULL;
	/* Number of aliases generated by each iteration of the while loop.
	 * Declared here because we use it inside a callback. */
	gint64 count_aliases = 0;
	// Last encountered alias and version, for pagination
	gchar *last_alias_name = NULL;
	gchar *last_alias_version = NULL;
	gchar *last_added = NULL;
	struct list_params_s lp = *lp0;
	gboolean done = FALSE;
	gboolean added = FALSE;
	GPtrArray *cur_aliases = NULL;
	guint prefix_len = 0;
	guint delimiter_len = 0;

	if (lp.prefix) {
		prefix_len = strlen(lp.prefix);
	}
	if (lp.delimiter) {
		delimiter_len = strlen(lp.delimiter);
	}

	gboolean _load_header_and_send(struct bean_ALIASES_s *alias) {
		const gchar *name = ALIASES_get_alias(alias)->str;
		const gchar *suffix = NULL;
		if (delimiter_len) {
			suffix = strstr(name + prefix_len, lp.delimiter);
		}
		if (suffix) {  // It's a sub-prefix
			if (last_added &&
					strncmp(last_added, name,
							(suffix - name)  + delimiter_len) == 0) {
				/* Same sub-prefix as the previous alias,
				 * only one alias is enough. */
				return FALSE;
			}
			// The alias (name) is enough.
			// Content and properties will not be used.
		} else {
			if (lp.flag_headers)
				_manage_alias(sq3, alias, lp.flag_recursion, cb, u);
			if (lp.flag_properties)
				_load_fk_by_name(sq3, alias, "properties", cb, u);
		}
		g_free(last_added);
		last_added = g_strdup(name);
		cb(u, alias);
		count_aliases++;
		return TRUE;
	}
	void cleanup(void) {
		if (cur_aliases) {
			g_ptr_array_set_free_func(cur_aliases, _bean_clean);
			g_ptr_array_free(cur_aliases, TRUE);
			cur_aliases = NULL;
		}
	}

	/* XXX: why do we loop? Because "maxkeys" is in terms of keys, whereas
	 * the SQL query returns versions, and since there can be several versions
	 * for each key, we may not get enough keys from the first query. */
	while (!done) {
		/* If there are a lot of delete markers, and we are not asked to
		 * return them, we will reach the deadline before finding lp.maxkeys
		 * aliases. In that case, return a truncated listing along with the
		 * name of the last alias we encountered (even if it is deleted). */
		if (oio_str_is_set(last_alias_name)
				&& oio_ext_monotonic_time() > oio_ext_get_deadline()) {
			*next_marker = last_alias_name;
			last_alias_name = NULL;
			break;  // not an error!
		}
		cur_aliases = g_ptr_array_new();

		if (lp.maxkeys > 0)
			lp.maxkeys -= count_aliases;

		/* Optimize only if the previous iteration did return something useful.
		 * If every version we found yet was marked deleted, we need to
		 * continue without optimization.
		 * Also, do not try to optimize the first iteration: oio-proxy has
		 * already optimized the first marker.*/
		if (count_aliases > 0 && last_alias_name) {
			const gchar *suffix = NULL;
			if (delimiter_len) {
				suffix = strstr(last_alias_name + prefix_len, lp.delimiter);
			}
			if (suffix) {  // It's a sub-prefix
				/* HACK: we have found a "sub-prefix" which will be returned
				 * to the client. Objects containing this prefix won't be
				 * returned (because the request has a delimiter), and thus
				 * we can skip them.
				 *
				 * There are very few chances that an object has it in
				 * its name, and even if it has, it won't be listed
				 * (because it would be behind the delimiter).
				 * With such a marker, we will force the next SQL request
				 * to skip objects that won't be listed, and won't even be used
				 * to generate new prefixes (they all share the current prefix).
				 *
				 * Here is a trivial example:
				 * - a/b/0
				 * - a/b/1
				 * - a/b/2
				 * - a/c/3
				 * - d/e/4
				 * With a page size of 3, and '/' as a delimiter:
				 * - the first request will return "a/b/0", "a/b/1", "a/b/2",
				 *   generating the prefix "a/";
				 * - the marker for the next iteration will be
				 *   "a/\xf4\x8f\xbf\xbd";
				 * - the second request will skip "a/c/3", and return "d/e/4",
				 *   generating the prefix "d/".
				 *
				 * Notice that the version marker will be ignored.
				 *
				 * Notice that there is the same mechanism in the oioproxy
				 * service. It is used to directly access the correct shard. */
				gchar *marker = g_strdup_printf("%.*s"LAST_UNICODE_CHAR,
						(int)((suffix - last_alias_name) + delimiter_len),
						last_alias_name);
				g_free(last_alias_name);
				last_alias_name = marker;
				g_free(last_alias_version);
				last_alias_version = NULL;
			}
			lp.marker_start = last_alias_name;
			lp.version_marker = last_alias_version;
		} else if (last_alias_name) {
			/* If last_alias_name is defined, we have already looped once.
			 * We must overwrite the marker sent by the client or we will loop
			 * indefinitely. */
			lp.marker_start = last_alias_name;
			if (last_alias_version) {
				lp.version_marker = last_alias_version;
			}
		}

		// --- List the next items ---
		count_aliases = 0;
		GString *clause = g_string_sized_new(128);
		GVariant **params = _list_params_to_sql_clause (&lp, clause, headers);
		err = ALIASES_load(sq3, clause->str, params,
				_bean_buffer_cb, cur_aliases);
		metautils_gvariant_unrefv(params);
		g_free(params), params = NULL;
		g_string_free(clause, TRUE);
		// ---------------------------

		if (err || !cur_aliases->len)
			break;
		done = lp.maxkeys <= 0 || cur_aliases->len < lp.maxkeys;

		metautils_gpa_reverse(cur_aliases);

		if (lp.flag_allversion) {
			g_free(last_alias_version);
			last_alias_version = g_strdup_printf("%"G_GINT64_FORMAT,
					ALIASES_get_version(cur_aliases->pdata[0]));
		}
		for (guint i = cur_aliases->len; i > 0; i--) {
			struct bean_ALIASES_s *alias = cur_aliases->pdata[i-1];
			gchar *name = g_strdup(ALIASES_get_alias(alias)->str);
			added = FALSE;
			if (lp.prefix && !g_str_has_prefix(name, lp.prefix)) {
				g_free(name);
				goto label_end;
			}

			g_ptr_array_remove_index_fast(cur_aliases, i-1);

			if (lp.flag_allversion) {
				added = _load_header_and_send(alias);
			} else {
				if (last_alias_name && strcmp(last_alias_name, name) >= 0) {
					/* The last_alias_name variable can be greater than the
					 * current name, if it is a sub-prefix.
					 * And if the 2 are equal, it's an old alias version. */
				} else {
					if (!lp.flag_nodeleted || !ALIASES_get_deleted(alias)) {
						added = _load_header_and_send(alias);
					} else {
						/* The latest version of the alias is a deletion marker,
						 * so do not list any version of this alias. */
					}
				}
			}
			g_free(last_alias_name);
			last_alias_name = name;
			if (added) {
				if (lp.maxkeys > 0 && count_aliases >= lp.maxkeys) {
					goto label_end;
				}
			} else {
				_bean_clean(alias);
			}
		}

		cleanup();
	}

label_end:
	cleanup();
	g_free(last_alias_name);
	g_free(last_alias_version);
	g_free(last_added);
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
			err = _db_delete_bean(sq3, prop);
			// In case it is empty but not NULL
			PROPERTIES_set_value(prop, NULL);
		} else {
			err = _db_save_bean(sq3, prop);
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
						err = _db_delete_bean(sq3, bean);
						if (err)
							goto end;
						tmp->pdata[i] = NULL;  // Prevent double free
						PROPERTIES_set_value(bean, NULL);  // Signal deletion
						deleted = g_slist_prepend(deleted, bean);
						break;
					}
				}
			} else {
				/* all properties to be deleted */
				err = _db_delete_bean(sq3, bean);
				if (err)
					goto end;
				tmp->pdata[i] = NULL;  // Prevent double free
				PROPERTIES_set_value(bean, NULL);  // Signal deletion
				deleted = g_slist_prepend(deleted, bean);
			}
		}
		deleted = g_slist_prepend(deleted, alias);
	}

end:
	if (err)
		_bean_cleanl2(deleted);
	else
		*out = deleted;
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
		err = _db_count_FK_by_name(bean, fk, sq3, &count);
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
	for (GSList *l = deleted; l; l = l->next) {
		err = _db_delete_bean(sq3, l->data);
		if (err != NULL) {
			GRID_WARN("Bean delete failed: (%d) %s", err->code, err->message);
			goto end;
		}
	}

	for (GSList *l = deleted; l; l = l->next) {
		// recompute container size and object count
		if (&descr_struct_CONTENTS_HEADERS == DESCR(l->data)) {
			gint64 decrement = CONTENTS_HEADERS_get_size(l->data);
			gchar *policy = NULL;
			m2v2_policy_decode(CONTENTS_HEADERS_get_policy(l->data), NULL, &policy);
			m2db_update_size(sq3, -decrement, policy);
			m2db_update_obj_count(sq3, -1, policy);
			g_free(policy);
		}

		// But do not notify ALIAS already marked deleted
		// (they have already been notified)
		if (DESCR(l->data) != &descr_struct_ALIASES
				|| !ALIASES_get_deleted(l->data)) {
			*deleted_beans = g_slist_prepend(*deleted_beans, l->data);
			l->data = NULL;
		}
	}

end:
	// deleted contains direct pointers to the original beans
	g_slist_free(deleted);
	return err;
}

GError *
m2db_drain_content(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	GSList *beans = NULL;
	err = m2db_get_alias(sq3, url, M2V2_FLAG_NOPROPS|M2V2_FLAG_HEADERS,
			_bean_list_cb, &beans);
	if (!err) {
		for (GSList *l = beans; l && !err; l = l->next) {
			if (DESCR(l->data) == &descr_struct_CHUNKS) {
				err = _db_delete_bean(sq3, l->data);
			} else if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS) {
				CONTENTS_HEADERS_set2_chunk_method(l->data, CHUNK_METHOD_DRAINED);
				err = _db_save_bean(sq3, l->data);
			}
		}
	}
	if (err) {
		_bean_cleanl2(beans);
	} else {
		for (GSList *l = beans; l; l = l->next) {
			cb(u0, l->data);
		}
		g_slist_free(beans);
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
		err = _db_del_FK_by_name(alias, "properties", sq3);

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
		gboolean bypass_governance, gboolean create_delete_marker,
		struct oio_url_s *url, m2_onbean_cb cb, gpointer u0,
		gboolean *delete_marker_created)
{
	GError *err = NULL;
	gint64 version = 0;
	struct oio_url_s *delete_marker_url = NULL;

	if (oio_url_has(url, OIOURL_VERSION)) {
		version = g_ascii_strtoll(oio_url_get(url, OIOURL_VERSION), NULL, 10);
		if (VERSIONS_DISABLED(max_versions) && version != 0) {
			return NEWERROR(CODE_BAD_REQUEST,
					"Versioning not supported and version specified");
		}
	}

	if (create_delete_marker) {
		// Force to create a delete marker to the specific version
		if (!oio_url_has(url, OIOURL_PATH)) {
			err = BADREQ("Delete marker specified, but missing path");
		} else if (!oio_url_has(url, OIOURL_VERSION)) {
			err = BADREQ("Delete marker specified, but missing version");
		} else {
			// Since the URL contains a version, the check for disabling
			// versioning has already been done
			delete_marker_url = oio_url_dup(url);
			oio_url_unset(delete_marker_url, OIOURL_CONTENTID);
		}

		GRID_TRACE("DELETE_MARKER %s maxvers=%"G_GINT64_FORMAT" ver=%s",
				oio_url_get(delete_marker_url, OIOURL_WHOLE), max_versions,
				oio_url_get(delete_marker_url, OIOURL_VERSION));
	} else {
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

		err = m2db_get_alias(sq3, url, M2V2_FLAG_NOPROPS|M2V2_FLAG_HEADERS,
				_search_alias_and_size, NULL);
		if (err) {
			goto clean;
		}
		if (!alias || !beans) {
			err = NEWERROR(CODE_CONTENT_NOTFOUND, "No content to delete");
			goto clean;
		}

		GRID_TRACE("CONTENT %s beans=%u maxvers=%"G_GINT64_FORMAT
				" deleted=%d ver=%u/%s",
				oio_url_get(url, OIOURL_WHOLE), g_slist_length(beans),
				max_versions, ALIASES_get_deleted(alias),
				oio_url_has(url, OIOURL_VERSION), oio_url_get(url, OIOURL_VERSION));

		if (VERSIONS_DISABLED(max_versions) || VERSIONS_SUSPENDED(max_versions) ||
				oio_url_has(url, OIOURL_VERSION)) {
			// Actually delete the object
			if (bypass_governance && !ALIASES_get_deleted(alias)) {
				// Allow to delete object (with data) despite retention
				struct bean_PROPERTIES_s *prop = _bean_create(
						&descr_struct_PROPERTIES);
				PROPERTIES_set_alias(prop, ALIASES_get_alias(alias));
				PROPERTIES_set_version(prop, ALIASES_get_version(alias));
				PROPERTIES_set2_key(prop, OBJ_PROP_BYPASS_GOVERNANCE);
				PROPERTIES_set2_value(prop, (guint8*)"True", 4);
				err = _db_save_bean(sq3, prop);
				_bean_clean(prop);
			}

			if (!err) {
				err = _real_delete_and_save_deleted_beans(sq3, beans,
						alias, header, cb, u0);
			}
		} else {
			// Create a delete marker on latest version
			delete_marker_url = oio_url_dup(url);
			oio_url_set(delete_marker_url, OIOURL_PATH,
					ALIASES_get_alias(alias)->str);
			version = ALIASES_get_version(alias) + 1;
			gchar *str_delete_marker_version = g_strdup_printf(
					"%"G_GINT64_FORMAT, version);
			oio_url_set(delete_marker_url, OIOURL_VERSION,
					str_delete_marker_version);
			g_free(str_delete_marker_version);
			oio_url_unset(delete_marker_url, OIOURL_CONTENTID);
		}

clean:
		_bean_clean(alias);
		_bean_cleanl2(beans);
	}

	if (!err && delete_marker_url) {
		/* Check if delete marker already exists */
		err = check_alias_doesnt_exist(sq3, delete_marker_url);
		if (err) {
			if (err->code == CODE_CONTENT_EXISTS) {
				g_error_free(err);
				err = NEWERROR(CODE_CONTENT_PRECONDITION,
						"An object already exists with the same version");
			} else {
				g_prefix_error(&err, "Delete marker error: ");
			}
		}

		if (!err) {
			gint64 now = oio_ext_real_seconds();
			/* Create a new version marked as deleted */
			struct bean_ALIASES_s *new_alias = _bean_create(
					&descr_struct_ALIASES);
			ALIASES_set_deleted(new_alias, TRUE);
			ALIASES_set2_alias(new_alias, oio_url_get(
				delete_marker_url, OIOURL_PATH));
			ALIASES_set_version(new_alias, version);
			ALIASES_set2_content(new_alias, (guint8 *) "DELETED", 7);
			ALIASES_set_ctime(new_alias, now);
			ALIASES_set_mtime(new_alias, now);
			err = _db_save_bean(sq3, new_alias);
			if (!err && delete_marker_created != NULL) {
				*delete_marker_created = TRUE;
			}
			if (!err && cb) {
				ALIASES_set2_content(new_alias, (guint8 *) "NEW", 3);
				cb(u0, new_alias);
			} else {
				_bean_clean(new_alias);
			}
		}
	}

	oio_url_clean(delete_marker_url);
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
		err = _db_delete_bean(sq3, l->data);
	if (err)
		goto cleanup;

	/* The header is required to compute the chunk IDs,
	 * make a copy before modifying it. */
	struct bean_CONTENTS_HEADERS_s *original_header = _bean_dup(content.header);
	discarded = g_slist_prepend(discarded, original_header);
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
	err = _db_save_beans_list(sq3, kept);

	if (!err) {
		gchar *policy = NULL;
		m2v2_policy_decode(CONTENTS_HEADERS_get_policy(original_header), NULL, &policy);
		m2db_update_size(sq3, -sz_gap, policy);
		*out_added = kept;
		*out_deleted = discarded;
		// prevent cleanup
		kept = NULL;
		discarded = NULL;
		g_free(policy);
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

static void _patch_beans_with_time(GSList *beans,
		struct bean_ALIASES_s *latest, gboolean keep_mtime) {
	gint64 now = oio_ext_real_seconds();
	gint64 ctime = now;
	gint64 mtime = now;
	if (latest) {
		/* Keep the same ctime if the object already exists */
		ctime = ALIASES_get_ctime(latest);
		if (keep_mtime) {
			mtime = ALIASES_get_mtime(latest);
		}
	}
	for (GSList *l = beans; l; l = l->next) {
		gpointer bean = l->data;
		if (DESCR(bean) == &descr_struct_ALIASES) {
			ALIASES_set_ctime(bean, ctime);
			ALIASES_set_mtime(bean, mtime);
		} else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
			CONTENTS_HEADERS_set_ctime(bean, mtime);
			CONTENTS_HEADERS_set_mtime(bean, mtime);
		} else if (DESCR(bean) == &descr_struct_CHUNKS) {
			CHUNKS_set_ctime(bean, mtime);
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

static gint64
_fetch_content_size(GSList *beans)
{
	for (GSList *l = beans; l; l = l->next) {
		gpointer bean = l->data;
		if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS)
			return CONTENTS_HEADERS_get_size(bean);
	}
	return 0;
}

static const GString*
_fetch_content_policy(GSList *beans)
{
	for (GSList *l = beans; l; l = l->next) {
		gpointer bean = l->data;
		if (DESCR(bean) != &descr_struct_CONTENTS_HEADERS) {
			continue;
		}
		GString *policy = CONTENTS_HEADERS_get_policy(bean);
		if (policy && policy->str) {
			return policy;
		}
		return NULL;
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
			err = _db_save_bean(sq3, l->data);
	}
	if (!err && cb) {
		for (GSList *l = beans; l; l = l->next)
			cb(cb_data, _bean_dup(l->data));
	}
	return err;
}

/* Returns NULL if the content is absent, an explicit error indicating it is
 * present or the error that occurred while checking (if any) */
static GError* m2db_check_content_absent(struct sqlx_sqlite3_s *sq3,
		const guint8 *uid, const gsize len) {
	GPtrArray *tmp = g_ptr_array_new ();
	GVariant *params[2] = {NULL, NULL};
	params[0] = _bytes_to_gvariant(uid, len);
	GError *err = CONTENTS_HEADERS_load(sq3, " id = ? LIMIT 1", params,
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
	_patch_beans_with_time(beans, latest, FALSE);

	if (!latest) {
		/* put everything (and patch everything */
		RANDOM_UID(uid, uid_size);
		_patch_beans_with_contentid(beans, (guint8*)&uid, uid_size);
		_patch_beans_with_version(beans, find_alias_version(beans));
		err = m2db_real_put_alias(args->sq3, beans, cb_added, u0_added);
		if (!err) {
			const GString *policy_str = _fetch_content_policy(beans);
			gchar* policy = NULL;
			m2v2_policy_decode(policy_str, NULL, &policy);
			m2db_update_size(args->sq3, _fetch_content_size(beans), policy);
			m2db_update_obj_count(args->sq3, 1, policy);
			g_free(policy);
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
			if (!(err = _db_insert_bean(args->sq3, bean))) {
				if (cb_added)
					cb_added(u0_added, _bean_dup(bean));
			}
		}
		/* TODO need to recompute the container's size */
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
	err = _db_save_beans_list(sq3, new_beans);
	if (err)
		goto cleanup;

	/* Remove old chunks from the database */
	for (GSList *l = old_beans; l && !err; l = l->next) {
		err = _db_delete_bean(sq3, l->data);
	}
	if (err)
		goto cleanup;

	/* Update the size of the container and notify the caller with new beans */
	gchar *policy = NULL;
	m2v2_policy_decode(CONTENTS_HEADERS_get_policy(header), NULL, &policy);
	m2db_update_size(sq3, added_size, policy);
	if (cb_deleted) {
		cb_deleted(u0_deleted, g_slist_prepend(old_beans, header));
		header = NULL;
		old_beans = NULL;
	}
	if (cb_added) {
		for (GSList *l = new_beans; l; l = l->next)
			cb_added(u0_added, _bean_dup(l->data));
	}
	g_free(policy);

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
	/* version explicitly specified */
	if (version == latest_version) {
		err = NEWERROR(CODE_CONTENT_EXISTS,
				"Alias already saved version=%"G_GINT64_FORMAT", "
				"latest_version=%"G_GINT64_FORMAT,
				version, latest_version);
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
					"New object version=%"G_GINT64_FORMAT
					" is older than latest version=%"G_GINT64_FORMAT,
					version, latest_version);
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
		_patch_beans_with_time(beans, latest, FALSE);
		_patch_beans_with_version(beans, version);
		if (!args->preserve_chunk_ids)
			m2v2_shorten_chunk_ids(beans);

		err = m2db_real_put_alias(args->sq3, beans, cb_added, u0_added);
	}
	if (!err) {

		const GString *policy_str = _fetch_content_policy(beans);
		gchar* policy = NULL;
		m2v2_policy_decode(policy_str, NULL, &policy);
		m2db_update_size(args->sq3,  _fetch_content_size(beans), policy);
		m2db_update_obj_count(args->sq3, 1, policy);
		g_free(policy);
	}

	/* Purge the latest alias if the condition was met */
	if (!err && purge_latest && latest) {
		GRID_TRACE("Need to purge the previous LATEST");
		GSList *inplace = g_slist_prepend (NULL, _bean_dup(latest));
		err = _manage_alias(args->sq3, latest, TRUE, _bean_list_cb, &inplace);
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
			err = _db_del_FK_by_name(latest, "properties", args->sq3);
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
	/* This pointer is a helper to manipulate the current header.
	 * A next variable <beans_to_delete> also works with this same pointer.
	 * <beans_to_delete> is responsible for cleaning the pointer, this is why
	 * <new_header> is not explicitly freed.
	 */
	struct bean_CONTENTS_HEADERS_s *current_header = NULL;
	struct bean_ALIASES_s *new_alias = NULL;
	struct bean_CONTENTS_HEADERS_s *new_header = NULL;
	GSList *beans_to_delete = NULL;
	GSList *deleted_beans = NULL;
	guint8 *content_id = NULL;
	GString *current_mime_type = NULL;

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
	if (!oio_url_has(args->url, OIOURL_VERSION)) {
		gchar *version_str = g_strdup_printf("%"G_GINT64_FORMAT, version);
		oio_url_set(args->url, OIOURL_VERSION, version_str);
		g_free(version_str);
	}
	err = m2db_get_alias(args->sq3, args->url,
			M2V2_FLAG_NOPROPS|M2V2_FLAG_HEADERS, _search_alias_and_size, NULL);
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

	// Validate policy
	gchar* actual_policy = NULL;
	gchar* target_policy = NULL;
	m2v2_policy_decode(
		CONTENTS_HEADERS_get_policy(current_header), &actual_policy, &target_policy);
	gboolean policies_match = \
		g_strcmp0(target_policy, CONTENTS_HEADERS_get_policy(new_header)->str) == 0;
	g_free(actual_policy);
	g_free(target_policy);

	if (!policies_match) {
		err = BADREQ(
			"Invalid policy (does not match target policy %s)",
			CONTENTS_HEADERS_get_policy(new_header)->str);
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

	current_mime_type = CONTENTS_HEADERS_get_mime_type(current_header);
	err = _real_delete_and_save_deleted_beans(args->sq3,
			beans_to_delete, NULL, current_header,
			_bean_list_cb, &deleted_beans);
	if (err) {
		goto label_end;
	}

	/* Patch the beans, before inserting */
	_patch_beans_defaults(new_beans);
	_patch_beans_with_time(new_beans, current_alias, TRUE);
	/* Ensure the beans are all linked to the content (with their content-id) */
	_patch_beans_with_contentid(new_beans, content_id, content_idlen);
	/* Overwrite default mime-type with current one */
	CONTENTS_HEADERS_set_mime_type(new_header, current_mime_type);

	err = m2db_real_put_alias(args->sq3, new_beans, cb_added, u0_added);
	if (!err) {
		/* The function <_real_delete_and_save_deleted_beans> updated the
		 * counters, we need to update them again.
		 */
		gint64 size = CONTENTS_HEADERS_get_size(new_header);
		gchar *policy = NULL;
		m2v2_policy_decode(CONTENTS_HEADERS_get_policy(new_header), NULL, &policy);
		m2db_update_size(args->sq3, size, policy);
		m2db_update_obj_count(args->sq3, 1, policy);
		g_free(policy);
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

GError*
m2db_restore_drained(struct m2db_put_args_s *args, GSList *new_beans,
		m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added)
{
	EXTRA_ASSERT(args != NULL);
	EXTRA_ASSERT(args->sq3 != NULL);
	EXTRA_ASSERT(args->url != NULL);

	GError *err;
	GSList *deleted_beans = NULL;
	struct bean_ALIASES_s *current_alias = NULL;
	struct bean_CONTENTS_HEADERS_s *new_header = NULL;
	/* This pointer is a helper to manipulate the current header.
	 * A next variable <beans_to_delete> also works with this same pointer.
	 * <beans_to_delete> is responsible for cleaning the pointer, this is why
	 * <new_header> is not explicitly freed.
	 */
	struct bean_CONTENTS_HEADERS_s *current_header = NULL;
	GSList *beans_to_delete = NULL;

	if (args->worm_mode) {
		err = NEWERROR(CODE_CONTENT_EXISTS, "NS wormed! Cannot overwrite.");
		goto label_end;
	}

	/* Extract new beans */
	for (GSList *l = new_beans; l; l = l->next) {
		if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS) {
			new_header = l->data;
		}
	}

	/* Get current existing beans */
	void _get_current_beans(gpointer ignored, gpointer bean) {
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
	err = m2db_get_alias(args->sq3, args->url,
			M2V2_FLAG_NOPROPS|M2V2_FLAG_HEADERS, _get_current_beans, NULL);
	if (err) {
		goto label_end;
	}

	/* Checks and consistency */
	gint64 container_draining_state = m2db_get_drain_state(args->sq3);
	if (container_draining_state == DRAINING_STATE_NEEDED ||
			container_draining_state == DRAINING_STATE_IN_PROGRESS) {
		err = NEWERROR(CODE_CONTAINER_DRAINING,
				"Container draining needed or in progress, cannot restore");
		goto label_end;
	}
	if (g_strcmp0(CONTENTS_HEADERS_get_chunk_method(current_header)->str,
				  CHUNK_METHOD_DRAINED) != 0) {
		err = NEWERROR(CODE_NOT_ALLOWED,
				"Restoring is only allowed on drained objects");
		goto label_end;
	}
	if (CONTENTS_HEADERS_get_size(current_header) !=
			CONTENTS_HEADERS_get_size(new_header)) {
		err = BADREQ("Different size: current=%ld; new=%ld)",
					 CONTENTS_HEADERS_get_size(current_header),
					 CONTENTS_HEADERS_get_size(new_header));
		goto label_end;
	}
	if (!metautils_gba_equal(CONTENTS_HEADERS_get_hash(current_header),
							 CONTENTS_HEADERS_get_hash(new_header))) {
		GString *current_hash = metautils_gba_to_hexgstr(NULL,
				CONTENTS_HEADERS_get_hash(current_header));
		GString *new_hash = metautils_gba_to_hexgstr(NULL,
				CONTENTS_HEADERS_get_hash(new_header));
		err = BADREQ("Different hash: current=%s; new=%s)",
				current_hash->str, new_hash->str);
		g_string_free(current_hash, TRUE);
		g_string_free(new_hash, TRUE);
		goto label_end;
	}

	/* Modify new beans with current mtime and ctime */
	CONTENTS_HEADERS_set_mime_type(new_header,
		CONTENTS_HEADERS_get_mime_type(current_header));
	_patch_beans_with_time(new_beans, current_alias, TRUE);
	m2v2_shorten_chunk_ids(new_beans);

	err = _real_delete_and_save_deleted_beans(args->sq3,
			beans_to_delete, NULL, current_header,
			_bean_list_cb, &deleted_beans);
	if (err) {
		goto label_end;
	}

	err = m2db_real_put_alias(args->sq3, new_beans, cb_added, u0_added);
	if (!err) {
		/* The function <_real_delete_and_save_deleted_beans> updated the
		 * counters, we need to update them again.
		 */
		gint64 size = CONTENTS_HEADERS_get_size(new_header);
		gchar *policy = NULL;
		m2v2_policy_decode(CONTENTS_HEADERS_get_policy(new_header), NULL, &policy);
		m2db_update_size(args->sq3, size, policy);
		m2db_update_obj_count(args->sq3, 1, policy);
		g_free(policy);
	}
label_end:

	_bean_clean(current_alias);
	if (!err && cb_deleted && deleted_beans) {
		cb_deleted(u0_deleted, deleted_beans);
	} else {
		_bean_cleanl2(deleted_beans);
	}
	_bean_cleanl2(beans_to_delete);

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
	if (!oio_url_has(url, OIOURL_VERSION)) {
		err = m2db_get_alias(sq3, url, M2V2_FLAG_LATEST|M2V2_FLAG_NOPROPS,
							 _bean_buffer_cb, tmp);
	} else {
		err = m2db_get_alias(sq3, url, M2V2_FLAG_NOPROPS,
							 _bean_buffer_cb, tmp);
	}

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
		args.preserve_chunk_ids = TRUE;
		return m2db_put_alias(&args, beans, NULL, NULL, cb, u0);
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
	if ((err = _db_save_bean(sq3, header)))
		goto out;

	/* Now insert each chunk bean */
	if (!(err = _db_insert_beans_list(sq3, newchunks))) {
		if (cb) {
			for (GSList *l = newchunks; l; l = l->next) {
				cb (u0, l->data);
				l->data = NULL;  // prevent double free
			}
			cb(u0, _bean_dup(header));
		}
	}
	if (!err) {
		gchar *policy = NULL;
		m2v2_policy_decode(CONTENTS_HEADERS_get_policy(header), NULL, &policy);
		m2db_update_size(sq3, added_size, policy);
		g_free(policy);
	}

out:
	_bean_cleanl2(newchunks);
	_bean_cleanv2(tmp);
	return err;
}

/* GENERATOR ---------------------------------------------------------------- */


GError*
m2_generate_beans(struct oio_url_s *url, gint64 size, gint64 chunk_size,
		struct storage_policy_s *pol, struct oio_lb_s *lb,
		m2_onbean_cb cb, gpointer cb_data, gboolean *flawed)
{
	GSList *beans = NULL;
	GError *err = oio_generate_beans(url, size, chunk_size, pol, lb, &beans,
			flawed);
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

GError *
m2db_check_content(struct m2v2_sorted_content_s *sorted_content,
		struct namespace_info_s *nsinfo,
		struct checked_content_s **checked_content_p, gboolean partial)
{
	GError *err = NULL;

	struct storage_policy_s *pol = NULL;
	gchar* policy = NULL;

	if (sorted_content->header != NULL) {
		m2v2_policy_decode(
			CONTENTS_HEADERS_get_policy(sorted_content->header),  &policy, NULL);
	}
	if (policy) {
		pol = storage_policy_init(nsinfo, policy);
	}
	if (!pol) {
		err = NEWERROR(CODE_POLICY_NOT_SUPPORTED,
				"Invalid policy: %s", policy ? policy : "not found");
	}
	if (!err) {
		err = _m2db_check_content_validity(sorted_content, pol,
				checked_content_p, partial);
	}

	if (pol) {
		storage_policy_clean(pol);
	}

	g_free(policy);

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
			err = _db_get_FK_by_name(latest, "image", sq3, _bean_buffer_cb, tmp);
			if (!err && tmp->len > 0) {
				struct bean_CONTENTS_HEADERS_s *header = tmp->pdata[0];
				gchar *policy_name = NULL;
				m2v2_policy_decode(
					CONTENTS_HEADERS_get_policy(header), &policy_name, NULL);
				if (policy_name) {
					policy = storage_policy_init(nsinfo, policy_name);
				}
				g_free(policy_name);
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
	EXTRA_ASSERT(sq3 != NULL && sq3->db != NULL);

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
	GSList *deleted_aliases = NULL;

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
	sqlx_sqlite3_finalize(sq3, stmt, err);

	GRID_DEBUG("Nb alias to drop: %d", g_slist_length(to_be_deleted));

	// Delete the alias bean and send it to callback
	void _delete_cb(gpointer udata, struct bean_ALIASES_s *alias_to_delete)
	{
		GError *local_err = _db_delete_bean(sq3, alias_to_delete);
		if (!local_err) {
			_bean_list_cb(udata, alias_to_delete);
		} else {
			GRID_WARN("Failed to drop %s (v%"G_GINT64_FORMAT"): %s",
					ALIASES_get_alias(alias_to_delete)->str,
					ALIASES_get_version(alias_to_delete),
					local_err->message);
			_bean_clean(alias_to_delete);
			if (!err)
				err = local_err;
			else
				g_clear_error(&local_err);
		}
	}

	for (GSList *l = to_be_deleted; l && !err; l = l->next) {
		GVariant *params[] = {NULL, NULL, NULL};
		struct elt_s *elt = l->data;
		params[0] = g_variant_new_string(elt->alias);
		params[1] = g_variant_new_int64(elt->count - max_versions);
		err = ALIASES_load(sq3, sql_delete, params,
				(m2_onbean_cb)_delete_cb, &deleted_aliases);
		if (err) {
			GRID_WARN("Failed to drop exceeding copies of %s: %s",
					elt->alias, err->message);
		}
		metautils_gvariant_unrefv(params);
	}
	if (err) {
		_bean_cleanl2(deleted_aliases);
	} else {
		for (GSList *l = deleted_aliases; l; l = l->next) {
			cb(u0, l->data);
		}
		g_slist_free(deleted_aliases);  // alias is cleaned by callback
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
	GSList *deleted_aliases = NULL;
	gint64 now = oio_ext_real_time();
	gint64 time_limit = 0;

	// All aliases which have one version deleted (the last) older than time_limit
	if (alias) {
		sql = (" alias IN "
				"(SELECT alias FROM "
				"  (SELECT alias, MAX(version) as version, deleted "
				"   FROM aliases WHERE alias = ? GROUP BY alias) "
				" WHERE deleted AND version < ?) ");
	} else {
		sql = (" alias IN "
				"(SELECT alias FROM "
				"  (SELECT alias, MAX(version) as version, deleted "
				"   FROM aliases GROUP BY alias) "
				" WHERE deleted AND version < ?) ");
	}

	if (now < 0) {
		err = g_error_new(GQ(), CODE_INTERNAL_ERROR,
				"Cannot get current time: %s", g_strerror(errno));
		return err;
	}

	delay = delay * G_TIME_SPAN_SECOND;
	if (delay >= 0 && delay < now) {
		time_limit = now - delay;
	}

	// Delete the alias bean and send it to callback
	void _delete_cb(gpointer udata, struct bean_ALIASES_s *alias_to_delete)
	{
		GError *local_err = _db_delete_bean(sq3, alias_to_delete);
		if (!local_err) {
			_bean_list_cb(udata, alias_to_delete);
		} else {
			GRID_WARN("Failed to drop %s (v%"G_GINT64_FORMAT"): %s",
					ALIASES_get_alias(alias_to_delete)->str,
					ALIASES_get_version(alias_to_delete),
					local_err->message);
			_bean_clean(alias_to_delete);
			if (!err)
				err = local_err;
			else
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
	err = ALIASES_load(sq3, sql, params,
			(m2_onbean_cb)_delete_cb, &deleted_aliases);
	if (err) {
		_bean_cleanl2(deleted_aliases);
	} else {
		for (GSList *l = deleted_aliases; l; l = l->next) {
			cb(u0, l->data);
		}
		g_slist_free(deleted_aliases);  // alias is cleaned by callback
	}
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
	err = ALIASES_load(sq3, sql, params, _bean_buffer_cb, aliases);
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

static GError*
_real_drain_beans(struct sqlx_sqlite3_s *sq3, GSList *beans,
				  m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;

	for (GSList *bean = beans; bean && ! err; bean = bean->next) {
		if (DESCR(bean->data) == &descr_struct_CHUNKS) {
			err = _db_delete_bean(sq3, bean->data);
		} else if (DESCR(bean->data) == &descr_struct_CONTENTS_HEADERS) {
			CONTENTS_HEADERS_set2_chunk_method(bean->data, CHUNK_METHOD_DRAINED);
			err = _db_save_bean(sq3, bean->data);
		}
	}
	if (err) {
		_bean_cleanl2(beans);
	} else {
		for (GSList *l = beans; l; l = l->next) {
			cb(u0, l->data);
		}
		g_slist_free(beans);
	}

	return err;
}

static GVariant **
_build_drain_container_clause(gchar *marker_start, gchar *marker_end,
		GString *clause, gint64 limit)
{
	GPtrArray *params = g_ptr_array_new ();
	g_string_append_static(clause, " deleted == 0");
	if (marker_start != NULL) {
		g_string_append_static(clause, " AND alias > ?");
		g_ptr_array_add(params, g_variant_new_string(marker_start));
	}
	if (marker_end != NULL) {
		g_string_append_static(clause, " AND alias < ?");
		g_ptr_array_add(params, g_variant_new_string(marker_end));
	}

	g_string_append_static(clause, " ORDER BY alias ASC, version DESC");

	if (limit > 0) {
		g_string_append_printf(clause, " LIMIT %"G_GINT64_FORMAT, limit);
	}

	g_ptr_array_add (params, NULL);
	return (GVariant**) g_ptr_array_free (params, FALSE);
}

GError*
m2db_drain_container(struct sqlx_sqlite3_s *sq3, m2_onbean_cb cb, gpointer u0,
		gint64 limit, gboolean *truncated)
{
	GError *err = NULL;
	gint64 drain_count = 0;
	gchar *marker_start = NULL;
	gchar *marker_end = NULL;
	gchar *next_marker = NULL;
	GPtrArray *tmp = NULL;
	GPtrArray *aliases = NULL;

	gint64 draining_state = m2db_get_drain_state(sq3);
	if (draining_state == DRAINING_STATE_NEEDED) {
		if (sqlx_admin_has(sq3, M2V2_ADMIN_SHARDING_ROOT)) {  // shard
			// Drain only objects managed by this shard.
			// Other objects will be drained by their respective shard.
			err = m2db_get_sharding_lower(sq3, &marker_start);
			if (err) {
				goto end;
			}
			gchar *upper = NULL;
			err = m2db_get_sharding_upper(sq3, &upper);
			if (err) {
				goto end;
			}
			if (*upper) {
				/* HACK: "\x01" is the (UTF-8 encoded) first unicode */
				marker_end = g_strdup_printf("%s\x01", upper);
			}
			g_free(upper);
		}
	} else if (draining_state == DRAINING_STATE_IN_PROGRESS) {
		drain_count = m2db_get_drain_obj_count(sq3);
		err = m2db_get_drain_marker(sq3, &marker_start);
		if (err) {
			g_free(marker_start);
			goto end;
		}
		if (marker_start == NULL) {
			err = SYSERR("Marker is missing");
			goto end;
		}
	} else {
		err = BADREQ("No draining in progress");
		goto end;
	}

	tmp = g_ptr_array_new();
	g_ptr_array_add(tmp, NULL);

	GString *clause = g_string_sized_new(128);
	GVariant **params = _build_drain_container_clause(marker_start, marker_end,
			clause, limit + 1);

	aliases = g_ptr_array_new();
	err = ALIASES_load(sq3, clause->str, params, _bean_buffer_cb, aliases);
	metautils_gvariant_unrefv(params);
	g_free(params), params = NULL;
	g_string_free(clause, TRUE);

	guint nb_aliases = aliases->len;
	if (nb_aliases == limit + 1) {
		next_marker = g_strdup(ALIASES_get_alias(aliases->pdata[limit-1])->str);
		_bean_clean(aliases->pdata[limit]);
		aliases->pdata[limit] = NULL;
		g_ptr_array_remove_index_fast(aliases, limit);
		*truncated = TRUE;
	}

	GSList *beans = NULL;
	GSList *deleted_beans = NULL;
	for (guint i = 0; !err && i < aliases->len; i++) {
		tmp->pdata[0] = aliases->pdata[i];
		beans = NULL;
		deleted_beans = NULL;

		err = _alias_fetch_info(sq3, 0, tmp, _bean_list_cb, &beans);
		if (!err) {
			if (cb) {
				err = _real_drain_beans(sq3, beans, _bean_list_cb, &deleted_beans);
				if (deleted_beans != NULL) {
					cb(u0, deleted_beans);
				}
			} else {
				err = _real_drain_beans(sq3, beans, NULL, NULL);
			}
			drain_count++;
		}

		aliases->pdata[i] = NULL;
	}

	gint64 obj_count = m2db_get_obj_count(sq3);
	if (drain_count < obj_count) {
		if (!*truncated) {
			err = SYSERR("Error during draining (not all expected objects "
					"have been processed)");
			goto end;
		}
		GRID_DEBUG("Draining not over yet: %ld/%ld", drain_count, obj_count);
		m2db_set_drain_state(sq3, DRAINING_STATE_IN_PROGRESS);
		m2db_set_drain_timestamp(sq3, oio_ext_real_time());
		m2db_set_drain_obj_count(sq3, drain_count);
		m2db_set_drain_marker(sq3, next_marker);
	} else if (drain_count == obj_count) {
		GRID_DEBUG("Container is drained");
		if (*truncated) {
			err = SYSERR("Error during draining (more objects have been "
					"processed than expected)");
			goto end;
		}
		/* Delete all temporary properties (objects are marked as drained
		 * individually) */
		m2db_del_drain_state(sq3);
		m2db_del_drain_timestamp(sq3);
		m2db_del_drain_obj_count(sq3);
		m2db_del_drain_marker(sq3);
	} else {
		err = SYSERR("More objects drained than in the container");
	}

end:
	if (tmp != NULL) {
		tmp->pdata[0] = NULL;
		g_ptr_array_free(tmp, TRUE);
	}
	_bean_cleanv2(aliases);
	g_free(marker_start);
	g_free(marker_end);
	g_free(next_marker);

	return err;
}

GError*
m2db_transition_policy(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		struct namespace_info_s* nsinfo, gboolean* updated,
		gboolean* send_event, const gchar *new_policy)
{
	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(url != NULL);

	GError *err = NULL;
	gchar* actual_policy = NULL;
	gchar* target_policy = NULL;
	struct storage_policy_s* pol = NULL;
	struct bean_ALIASES_s *current_alias = NULL;
	struct bean_CONTENTS_HEADERS_s *current_header = NULL;

	void _search_alias_and_size(gpointer ignored, gpointer bean) {
		(void) ignored;
		if (DESCR(bean) == &descr_struct_ALIASES) {
			current_alias = bean;
		} else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
			current_header = bean;
		}
	}

	*updated = FALSE;
	*send_event = FALSE;

	// Ensure policy is valid
	pol = storage_policy_init(nsinfo, new_policy);
	if (!pol) {
		err = NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid policy: %s", new_policy);
		goto cleanup;
	}

	err = m2db_get_alias(
		sq3, url,
		M2V2_FLAG_NOPROPS|M2V2_FLAG_HEADERS|M2V2_FLAG_NORECURSION,
		_search_alias_and_size, NULL);
	if (err) {
		goto cleanup;
	}

	m2v2_policy_decode(
		CONTENTS_HEADERS_get_policy(current_header), &actual_policy, &target_policy);

	// Ensure new policy is not already applied
	if (g_strcmp0(new_policy, target_policy) == 0) {
		goto cleanup;
	}
	if (g_strcmp0(new_policy, actual_policy) == 0) {
		if (g_strcmp0(target_policy, actual_policy) == 0) {
			// Nothing to do
			goto cleanup;
		}
		// Only update stats and policy but do not emit an event as data
		// is already in the right location
	} else {
		*send_event = TRUE;
	}

	gchar* previous_policy = actual_policy;
	if (target_policy != NULL) {
		previous_policy = target_policy;
	}
	// Update bean
	gint64 size = CONTENTS_HEADERS_get_size(current_header);
	const gchar* new_policy_str = m2v2_policy_encode(actual_policy, new_policy);
	CONTENTS_HEADERS_set2_policy(current_header, new_policy_str);
	err = _db_save_bean(sq3, current_header);
	// Decrement old policy
	m2db_update_size(sq3, -size, previous_policy);
	m2db_update_obj_count(sq3, -1, previous_policy);
	// Increment new policy
	m2db_update_size(sq3, size, new_policy);
	m2db_update_obj_count(sq3, 1, new_policy);

	*updated = TRUE;


cleanup:
	if (pol) {
		storage_policy_clean(pol);
	}
	g_free(actual_policy);
	g_free(target_policy);
	_bean_clean(current_alias);
	_bean_clean(current_header);

	return err;
}


/* Sharding ----------------------------------------------------------------- */

static gint
_shard_range_compare_lower(gconstpointer b0, gconstpointer b1)
{
	if (!b0 && !b1)
		return 0;
	if (!b0)
		return 1;
	if (!b1)
		return -1;
	struct bean_SHARD_RANGE_s *shard_range0 = (struct bean_SHARD_RANGE_s *) b0;
	struct bean_SHARD_RANGE_s *shard_range1 = (struct bean_SHARD_RANGE_s *) b1;
	return strcmp(SHARD_RANGE_get_lower(shard_range0)->str,
			SHARD_RANGE_get_lower(shard_range1)->str);
}

static GVariant **
_sharding_get_params_to_sql_clause(const gchar *lower, const gchar *upper,
		GString *clause)
{
	void lazy_and () {
		if (clause->len > 0) g_string_append_static(clause, " AND");
	}
	GPtrArray *params = g_ptr_array_new();

	if (lower && *lower) {
		lazy_and();
		g_string_append_static(clause, " lower >= ? AND lower != ''");
		g_ptr_array_add(params, g_variant_new_string(lower));
	}

	if (upper && *upper) {
		lazy_and();
		g_string_append_static(clause, " upper <= ? AND upper != ''");
		g_ptr_array_add(params, g_variant_new_string(upper));
	}

	if (clause->len == 0)
		clause = g_string_append_static(clause, " 1");

	g_string_append_static(clause, " ORDER BY lower ASC");

	g_ptr_array_add(params, NULL);
	return (GVariant**) g_ptr_array_free(params, FALSE);
}

static GError*
_m2db_get_shard_ranges(struct sqlx_sqlite3_s *sq3, const gchar *lower,
		const gchar *upper, m2_onbean_cb cb, gpointer u)
{
	GPtrArray *beans = g_ptr_array_new();
	GString *clause = g_string_sized_new(128);
	GVariant **params = _sharding_get_params_to_sql_clause(lower, upper,
			clause);
	GError *err = SHARD_RANGE_load(sq3, clause->str, params, _bean_buffer_cb,
			beans);
	if (!err) {
		if (beans->len > 0) {
			struct bean_SHARD_RANGE_s *first_shard_range = g_ptr_array_index(
					beans, 0);
			struct bean_SHARD_RANGE_s *last_shard_range = g_ptr_array_index(
					beans, beans->len - 1);
			if (strcmp(lower ? lower : "",
					SHARD_RANGE_get_lower(first_shard_range)->str) != 0) {
				err = BADREQ("No shard range starts with this lower");
			} else if (strcmp(upper ? upper : "",
					SHARD_RANGE_get_upper(last_shard_range)->str) != 0) {
				err = BADREQ("No shard range starts with this upper");
			} else {
				for (guint i = 0; i < beans->len; i++) {
					cb(u, beans->pdata[i]);
					beans->pdata[i] = NULL;
				}
			}
		} else if ((lower && *lower) || (upper && *upper)) {
			err = BADREQ("No shard range starts with this lower "
					"and/or no shard range starts with this upper");
		}
	}
	metautils_gvariant_unrefv(params);
	g_free(params), params = NULL;
	g_string_free(clause, TRUE);
	_bean_cleanv2(beans);
	return err;
}

static GVariant **
_sharding_find_upper__sql(const gchar *lower, gint64 shard_size,
		const gchar *max_upper, GString *clause)
{
	void lazy_and () {
		if (clause->len > 0) g_string_append_static(clause, " AND");
	}
	GPtrArray *params = g_ptr_array_new();
	g_string_append_static(clause, " deleted == 0");

	if (lower && *lower) {
		lazy_and();
		g_string_append_static(clause, " alias > ?");
		g_ptr_array_add(params, g_variant_new_string(lower));
	}

	if (max_upper && *max_upper) {
		lazy_and();
		g_string_append_static(clause, " alias <= ?");
		g_ptr_array_add(params, g_variant_new_string(max_upper));
	}

	g_string_append_static(clause, " ORDER BY alias ASC");
	// Fetch 2 aliases
	// - the first alias will be used as upper
	// - the second alias will be used to know
	//   if the first alias is the last alias of the container
	g_string_append_static(clause, " LIMIT 2");
	g_string_append_printf(clause, " OFFSET %"G_GINT64_FORMAT, shard_size - 1);

	g_ptr_array_add(params, NULL);
	return (GVariant**) g_ptr_array_free(params, FALSE);
}

static GVariant **
_sharding_compute_size__sql(const gchar *lower, const gchar *upper,
		GString *clause)
{
	void lazy_and () {
		if (clause->len > 0) g_string_append_static(clause, " AND");
	}
	GPtrArray *params = g_ptr_array_new();
	g_string_append_static(clause, " deleted == 0");

	if (lower && *lower) {
		lazy_and();
		g_string_append_static(clause, " alias > ?");
		g_ptr_array_add(params, g_variant_new_string(lower));
	}

	if (upper && *upper) {
		lazy_and();
		g_string_append_static(clause, " alias <= ?");
		g_ptr_array_add(params, g_variant_new_string(upper));
	}

	g_ptr_array_add(params, NULL);
	return (GVariant**) g_ptr_array_free(params, FALSE);
}

static GVariant **
_sharding_list_params_to_sql_clause(struct list_params_s *lp, GString *clause)
{
	void lazy_and () {
		if (clause->len > 0) g_string_append_static(clause, " AND");
	}
	GPtrArray *params = g_ptr_array_new();

	if (lp->marker_start) {
		lazy_and();
		g_string_append_static(clause, " upper > ? OR upper == ''");
		g_ptr_array_add(params, g_variant_new_string (lp->marker_start));
	}

	if (clause->len == 0)
		clause = g_string_append_static(clause, " 1");

	g_string_append_static(clause, " ORDER BY lower ASC");

	if (lp->maxkeys > 0)
		g_string_append_printf(clause, " LIMIT %"G_GINT64_FORMAT, lp->maxkeys);

	g_ptr_array_add(params, NULL);
	return (GVariant**) g_ptr_array_free(params, FALSE);
}

static GVariant **
_build_aliases_sql_clause(const gchar *lower,
		const gchar *upper, gint64 limit, GString *clause)
{
	void lazy_or() {
		if (clause->len > 0) g_string_append_static(clause, " OR");
	}
	GPtrArray *params = g_ptr_array_new();

	if (lower && *lower) {
		lazy_or();
		g_string_append_static(clause, " alias <= ?");
		g_ptr_array_add(params, g_variant_new_string(lower));
	}

	if (upper && *upper) {
		lazy_or();
		g_string_append_static(clause, " alias > ?");
		g_ptr_array_add(params, g_variant_new_string(upper));
	}

	if (clause->len == 0)
		clause = g_string_append_static(clause, " 0");
	if (limit > 0) {
		g_string_append_static(clause, " LIMIT ?");
		g_ptr_array_add(params, g_variant_new_int64(limit));
	}

	g_ptr_array_add(params, NULL);
	return (GVariant**) g_ptr_array_free(params, FALSE);
}

GError*
m2db_find_shard_ranges(struct sqlx_sqlite3_s *sq3, gint64 threshold,
		GError* (*get_shard_size)(gint64, guint, gint64*),
		m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	gchar *lower = NULL;
	gchar *upper = NULL;
	gchar *max_upper = NULL;
	GPtrArray *shard_ranges = g_ptr_array_new();

	if (sqlx_admin_has(sq3, M2V2_ADMIN_SHARDING_ROOT)) {
		err = m2db_get_sharding_lower(sq3, &lower);
		if (err) {
			goto end;
		}
		err = m2db_get_sharding_upper(sq3, &max_upper);
		if (err) {
			goto end;
		}
	} else {
		lower = g_strdup("");
		max_upper = g_strdup("");
	}

	gint64 obj_count = m2db_get_obj_count(sq3);
	if (obj_count < threshold) {
		// Do nothing
		upper = g_strdup(max_upper);
		struct bean_SHARD_RANGE_s *shard_range = _bean_create(
				&descr_struct_SHARD_RANGE);
		SHARD_RANGE_set2_lower(shard_range, lower);
		SHARD_RANGE_set2_upper(shard_range, upper);
		GString * metadata = g_string_new("{");
		OIO_JSON_append_int(metadata, "count", obj_count);
		g_string_append_c(metadata, '}');
		SHARD_RANGE_set_metadata(shard_range, metadata);
		g_string_free(metadata, TRUE);
		g_ptr_array_add(shard_ranges, shard_range);
		// The function expects the lower to be the value of the last upper
		g_free(lower);
		lower = upper;
		upper = NULL;
		goto end;
	}

	gboolean is_finished = FALSE;
	for (guint i = 0; !err && !is_finished; i++) {
		GPtrArray *aliases = g_ptr_array_new();

		// Compute the shard size for the new shard
		gint64 shard_size = 0;
		err = get_shard_size(obj_count, i, &shard_size);
		if (err) {
			goto end_for;
		}

		// Find alias at the specific position
		GString *clause = g_string_sized_new(128);
		GVariant **params = _sharding_find_upper__sql(
				lower, shard_size, max_upper, clause);
		err = ALIASES_load(sq3, clause->str, params, _bean_buffer_cb, aliases);
		metautils_gvariant_unrefv(params);
		g_free(params);
		g_string_free(clause, TRUE);
		if (err) {
			goto end_for;
		}

		// Prepare upper and actual shard size
		if (aliases->len < 2) {
			// Set the upper for the last shard range for this container
			// - if there is no alias, this is the end of the container
			// - if there is only one alias,
			//   it's the last alias of the container
			is_finished = TRUE;
			upper = g_strdup(max_upper);

			// Compute the actual count for this shards
			clause = g_string_sized_new(128);
			params = _sharding_compute_size__sql(lower, upper, clause);
			err = _db_count_bean(&descr_struct_ALIASES, sq3,
					clause->str, params, &shard_size);
			metautils_gvariant_unrefv(params);
			g_free(params);
			g_string_free(clause, TRUE);
			if (err) {
				goto end_for;
			}

			if (shard_size == 0 && shard_ranges->len > 0) {
				// If the last shard range is empty, delete it
				// and merge with the before last
				SHARD_RANGE_set2_upper(shard_ranges->pdata[shard_ranges->len-1],
						upper);
				goto end_for;
			}
		} else {
			upper = g_strdup(ALIASES_get_alias(aliases->pdata[0])->str);
		}
		if (*lower && *upper && g_strcmp0(lower, upper) >= 0) {
			err = SYSERR("Lower must be lower than upper");
			goto end_for;
		}

		// Create the shard
		struct bean_SHARD_RANGE_s *shard_range = _bean_create(
				&descr_struct_SHARD_RANGE);
		SHARD_RANGE_set2_lower(shard_range, lower);
		SHARD_RANGE_set2_upper(shard_range, upper);
		GString * metadata = g_string_new("{");
		OIO_JSON_append_int(metadata, "count", shard_size);
		g_string_append_c(metadata, '}');
		SHARD_RANGE_set_metadata(shard_range, metadata);
		g_string_free(metadata, TRUE);
		g_ptr_array_add(shard_ranges, shard_range);

end_for:
		// Prepare the next shard
		if (upper) {
			g_free(lower);
			lower = upper;
			upper = NULL;
		}
		_bean_cleanv2(aliases);
	}

end:
	if (!err) {
		if (shard_ranges->len == 0) {
			err = SYSERR("No shard range");
		} else if (g_strcmp0(lower, max_upper) != 0) {
			// When shard(s) have been found, the lower is the last upper
			err = SYSERR("Wrong upper for the last shard");
		}
	}

	if (!err && cb) {
		for (guint i = 0; i < shard_ranges->len; i++) {
			cb(u0, shard_ranges->pdata[i]);
			shard_ranges->pdata[i] = NULL;
		}
	}

	g_free(lower);
	g_free(max_upper);
	_bean_cleanv2(shard_ranges);
	return err;
}

GError* m2db_get_shards_in_range(struct sqlx_sqlite3_s *sq3,const gchar *req_lower,
		const gchar *req_upper, m2_onbean_cb cb, gpointer u0)
{
	GError *err = NULL;
	/* Build query */
	GPtrArray *params_list = g_ptr_array_new();
	GString *clause = g_string_sized_new(128);

	if (!oio_str_is_set(req_lower) && !oio_str_is_set(req_upper)) {
		// No filter, all shards will be returned
		g_string_append_static(clause,"1");
	} else if (!oio_str_is_set(req_lower)) {
		g_string_append_static(clause,"? > lower");
		g_ptr_array_add(params_list, g_variant_new_string(req_upper));
	} else if (!oio_str_is_set(req_upper)) {
		g_string_append_static(clause, "? < upper OR upper == ''");
		g_ptr_array_add(params_list, g_variant_new_string(req_lower));
	} else {
		g_string_append_static(clause, "(? < upper OR upper == '') AND (lower < ?)");
		g_ptr_array_add(params_list, g_variant_new_string(req_lower));
		g_ptr_array_add(params_list, g_variant_new_string(req_upper));
	}
	g_string_append_static(clause, " ORDER BY lower ASC");
	// Close params
	g_ptr_array_add(params_list, NULL);
	GVariant **params = (GVariant**) g_ptr_array_free(params_list, FALSE);

	err = SHARD_RANGE_load(sq3, clause->str, params, cb, u0);
	metautils_gvariant_unrefv(params);

	g_free(params);
	g_string_free(clause, TRUE);
	return err;
}

GError*
m2db_merge_shards(struct sqlx_sqlite3_s *sq3,
		struct sqlx_sqlite3_s *to_merge_sq3, gboolean *truncated)
{
	GError *err = NULL;
	gchar *current_lower = NULL, *current_upper = NULL;
	gchar *to_merge_lower = NULL, *to_merge_upper = NULL;
	gchar *new_lower = NULL, *new_upper = NULL;
	gchar *sql = NULL;
	gint64 max_entries_merged = meta2_sharding_max_entries_merged;
	gboolean is_shard = sqlx_admin_has(sq3, M2V2_ADMIN_SHARDING_ROOT);

	if (is_shard) {
		current_lower = sqlx_admin_get_str(sq3, M2V2_ADMIN_SHARDING_LOWER);
		if (!current_lower || *current_lower != '>') {
			err = BADREQ("Missing current lower");
			goto end;
		}
		current_upper = sqlx_admin_get_str(sq3, M2V2_ADMIN_SHARDING_UPPER);
		if (!current_upper || *current_upper != '<') {
			err = BADREQ("Missing current upper");
			goto end;
		}
	}
	to_merge_lower = sqlx_admin_get_str(to_merge_sq3,
			M2V2_ADMIN_SHARDING_LOWER);
	if (!to_merge_lower || *to_merge_lower != '>') {
		err = BADREQ("Missing shard to merge's lower");
		goto end;
	}
	to_merge_upper = sqlx_admin_get_str(to_merge_sq3,
			M2V2_ADMIN_SHARDING_UPPER);
	if (!to_merge_upper || *to_merge_upper != '<') {
		err = BADREQ("Missing shard to merge's upper");
		goto end;
	}

	if (!is_shard) {
		if (to_merge_lower[1] || to_merge_upper[1]) {
			err = BADREQ("Root container can be merged only "
					"with the one and last shard");
			goto end;
		}
	} else if (current_lower[1]
			&& strcmp(current_lower + 1, to_merge_upper + 1) == 0) {
		new_lower = to_merge_lower;
		new_upper = current_upper;
	} else if (current_upper[1]
			&& strcmp(current_upper + 1, to_merge_lower + 1) == 0) {
		new_lower = current_lower;
		new_upper = to_merge_upper;
	} else {
		err = BADREQ("Shard to merge and current shard must be consecutive");
		goto end;
	}

	sql = g_strdup_printf("ATTACH DATABASE '%s' AS toMerge",
			to_merge_sq3->path_inline);
	err = _db_execute(sq3, sql, strlen(sql), NULL);
	g_free(sql);
	if (err) {
		goto end;
	}
	for (const struct bean_descriptor_s **table=TABLE_TO_MERGE; *table;
			table+=1) {
		sql = g_strdup_printf(
				"INSERT INTO %s SELECT * FROM toMerge.%s ORDER BY ROWID LIMIT %"G_GINT64_FORMAT,
				(*table)->sql_name, (*table)->sql_name,
				max_entries_merged);
		err = _db_execute(sq3, sql, strlen(sql), NULL);
		g_free(sql);
		if (err) {
			goto end;
		}

		max_entries_merged -= sqlite3_changes(sq3->db);
		if (max_entries_merged <= 0) {
			break;
		}
	}

end:
	if (!err) {
		*truncated = max_entries_merged <= 0;
		if (!(*truncated) && is_shard) {
			sqlx_admin_set_str(sq3, M2V2_ADMIN_SHARDING_PREVIOUS_LOWER,
					current_lower);
			sqlx_admin_set_str(sq3, M2V2_ADMIN_SHARDING_PREVIOUS_UPPER,
					current_upper);
			sqlx_admin_set_str(sq3, M2V2_ADMIN_SHARDING_LOWER, new_lower);
			sqlx_admin_set_str(sq3, M2V2_ADMIN_SHARDING_UPPER, new_upper);
		}
	}
	g_free(current_lower);
	g_free(current_upper);
	g_free(to_merge_lower);
	g_free(to_merge_upper);
	return err;
}

GError*
m2db_remove_merged_entries(struct sqlx_sqlite3_s *sq3)
{
	GError *err = NULL;
	gchar *clause = NULL;
	gint64 max_entries_merged = meta2_sharding_max_entries_merged;

	for (const struct bean_descriptor_s **table=TABLE_TO_MERGE; *table;
			table+=1) {
		clause = g_strdup_printf("1 ORDER BY ROWID LIMIT %"G_GINT64_FORMAT,
				max_entries_merged);
		err = _db_delete(*table, sq3, clause, NULL);
		g_free(clause);
		if (err) {
			goto end;
		}

		max_entries_merged -= sqlite3_changes(sq3->db);
		if (max_entries_merged <= 0) {
			break;
		}
	}

end:
	return err;
}

GError*
m2db_replace_shard_ranges(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url, GSList *new_shard_ranges)
{
	if (!new_shard_ranges)
		return BADREQ("No shard range");
	for (GSList *new_shard_range = new_shard_ranges; new_shard_range; new_shard_range=new_shard_range->next) {
		if (!(new_shard_range->data)) {
			return BADREQ("Invalid type: shard range is NULL");
		}
		if (DESCR(new_shard_range->data) != &descr_struct_SHARD_RANGE) {
			return BADREQ("Invalid type: not a shard range");
		}
	}
	GSList *new_shard_ranges_sorted = g_slist_copy(new_shard_ranges);
	new_shard_ranges_sorted = g_slist_sort(new_shard_ranges_sorted,
			_shard_range_compare_lower);
	gchar *first_lower = NULL;
	gchar *last_upper = NULL;
	for (GSList *new_shard_range = new_shard_ranges_sorted; new_shard_range;
			new_shard_range=new_shard_range->next) {
		gchar *lower = SHARD_RANGE_get_lower(
				new_shard_range->data)->str;
		gchar *upper = SHARD_RANGE_get_upper(
				new_shard_range->data)->str;
		if (*upper && strcmp(lower, upper) >= 0) {
			return BADREQ("The lower must be lower than the upper");
		}
		if (last_upper && strcmp(last_upper, lower) != 0) {
			return BADREQ("Non-consecutive shard ranges");
		}
		if (first_lower == NULL) {
			first_lower = lower;
		}
		last_upper = upper;
	}
	g_slist_free(new_shard_ranges_sorted);
	if (g_slist_length(new_shard_ranges) == 1
			&& !(*first_lower) && !(*last_upper)) {
		gchar *cid = g_string_free(metautils_gba_to_hexgstr(NULL,
				SHARD_RANGE_get_cid(new_shard_ranges->data)), FALSE);
		if (strcmp(cid, oio_url_get(url, OIOURL_HEXID)) == 0) {
			// Switch back to a container without shards
			new_shard_ranges = NULL;
		}
		g_free(cid);
	}

	GError *err = NULL;
	GSList *deleted = NULL;
	err = _m2db_get_shard_ranges(sq3, first_lower, last_upper, _bean_list_cb,
			&deleted);
	for (GSList *l = deleted; !err && l; l = l->next) {
		err = _db_delete_bean(sq3, l->data);
	}
	if (!err) {
		err = _db_save_beans_list(sq3, new_shard_ranges);
	}
	if (!err) {
		gint64 shard_count = m2db_get_shard_count(sq3);
		shard_count -= g_slist_length(deleted);
		shard_count += g_slist_length(new_shard_ranges);
		m2db_set_shard_count(sq3, shard_count);
	}
	g_slist_free_full(deleted, _bean_clean);
	return err;
}

GError*
m2db_list_shard_ranges(struct sqlx_sqlite3_s *sq3, struct list_params_s *lp,
		m2_onbean_cb cb, gpointer u)
{
	GString *clause = g_string_sized_new(128);
	GVariant **params = _sharding_list_params_to_sql_clause(lp, clause);
	GError *err = SHARD_RANGE_load(sq3, clause->str, params, cb, u);
	metautils_gvariant_unrefv(params);
	g_free(params), params = NULL;
	g_string_free(clause, TRUE);
	return err;
}

GError*
m2db_get_shard_range(struct sqlx_sqlite3_s *sq3, const gchar *path,
		struct bean_SHARD_RANGE_s **pshard_range)
{
	/* sanity checks */
	if (!path) {
		return BADREQ("Missing path");
	}

	/* query */
	GError *err = NULL;
	const gchar *sql = "(lower == '' OR lower < ?) "
			"AND (upper == '' OR upper >= ?) ORDER BY lower ASC LIMIT 1";
	GVariant *params[3] = {
		g_variant_new_string(path),
		g_variant_new_string(path),
		NULL
	};

	GPtrArray *beans = g_ptr_array_new();
	err = SHARD_RANGE_load(sq3, sql, params, _bean_buffer_cb, beans);
	metautils_gvariant_unrefv(params);
	if (!err) {
		if (beans->len <= 0) {
			err = SYSERR("No shard range found");
		} else {
			*pshard_range = beans->pdata[0];
			beans->pdata[0] = NULL;
		}
	}
	_bean_cleanv2(beans);
	return err;
}

GError*
m2db_check_shard_range(struct sqlx_sqlite3_s *sq3, const gchar *path)
{
	/* sanity checks */
	if (!path) {
		return BADREQ("Missing path");
	}

	GError *err = NULL;
	gchar *lower = NULL;
	gchar *upper = NULL;

	err = m2db_get_sharding_lower(sq3, &lower);
	if (err) {
		goto end;
	}
	err = m2db_get_sharding_upper(sq3, &upper);
	if (err) {
		goto end;
	}

	if (*lower && strncmp(path, lower, LIMIT_LENGTH_CONTENTPATH) <= 0) {
		err = BADREQ("Out of range: Not managed by this shard");
		goto end;
	}
	if (*upper && strncmp(path, upper, LIMIT_LENGTH_CONTENTPATH) > 0) {
		err = BADREQ("Out of range: Not managed by this shard");
		goto end;
	}
	// lower < path <= upper

end:
	g_free(lower);
	g_free(upper);
	return err;
}

/** Compute an iteration limit for the loop which will check the request
 * deadline while cleaning databases. */
static gint64
_compute_reasonable_limit(gint64 allowed_changes)
{	gint64 limit;
	/** This condition checks if the request is local or not.
	 * Starting with a "allowed_changes" at G_MAXINT64,
	 * this test will always be true for local requests. */
	if (allowed_changes > meta2_sharding_max_entries_cleaned) {
		/* Check the deadline from time to time. */
		limit = meta2_sharding_max_entries_cleaned * 10;
	} else {
		/* Check the deadline half-way. */
		limit = MAX(1, allowed_changes / 2);
	}
	return limit;
}

/** Clean "beans" of the specified type matching the provided SELECT clause.
 * The cleaning is done in several iterations, until the allow number
 * of changes is exceeded. */
static GError*
_clean_shard_beans(struct sqlx_sqlite3_s *sq3,
		const struct bean_descriptor_s *descr, const gchar *select_clause,
		gint64 *allowed_changes, gint64 deadline, gboolean *finished)
{
	/* A previous call may force this function to return early. */
	if (*allowed_changes <= 0) {
		return NULL;
	}

	gint64 changes = 1;
	gboolean dl_ok = TRUE;
	GError *err = NULL;
	gint64 limit = _compute_reasonable_limit(*allowed_changes);

	// XXX: we generate the clause once, *allowed_changes can go negative
	gchar *clause_str = g_strdup_printf(
			"%s LIMIT %"G_GINT64_FORMAT, select_clause, limit);
	do {
		err = _db_delete(descr, sq3, clause_str, NULL);
		changes = sqlite3_changes(sq3->db);
		*allowed_changes -= changes;
	} while (!err && changes > 0 && *allowed_changes > 0
			&& (dl_ok = oio_ext_monotonic_time() < deadline));

	/* We left the loop because of the deadline,
	 * force the next calls to return early.
	 * Notice that we check the deadline only if there has been
	 * at least one change, or an error. */
	if (!dl_ok) {
		/* By changing the sign, this allows the value to be retained
		 * to calculate the number of cleaned entries. */
		*allowed_changes *= -1;
	} else if (!err && changes <= 0) {
		*finished = TRUE;
	}

	g_free(clause_str);
	return err;
}

static GError*
_clean_shard_aliases(struct sqlx_sqlite3_s *sq3,
		const struct bean_descriptor_s *descr,
		const gchar *lower, const gchar *upper,
		gint64 *allowed_changes, gint64 deadline, gboolean *finished)
{
	/* A previous call may force this function to return early. */
	if (*allowed_changes <= 0) {
		return NULL;
	}

	gint64 changes = 1;
	gboolean dl_ok = TRUE;
	GError *err = NULL;
	gint64 limit = _compute_reasonable_limit(*allowed_changes);
	GString *clause = g_string_sized_new(128);
	GVariant **params = _build_aliases_sql_clause(
			lower, upper, limit, clause);
	do {
		err = _db_delete(descr, sq3, clause->str, params);
		changes = sqlite3_changes(sq3->db);
		*allowed_changes -= changes;
	} while (!err && changes > 0 && *allowed_changes > 0
			&& (dl_ok = oio_ext_monotonic_time() < deadline));

	/* We left the loop because of the deadline,
	 * force the next calls to return early.
	 * Notice that we check the deadline only if there has been
	 * at least one change, or an error. */
	if (!dl_ok) {
		/* By changing the sign, this allows the value to be retained
		 * to calculate the number of cleaned entries. */
		*allowed_changes *= -1;
	} else if (!err && changes <= 0) {
		*finished = TRUE;
	}

	metautils_gvariant_unrefv(params);
	g_free(params), params = NULL;
	g_string_free(clause, TRUE);
	return err;
}

/** Shorten the deadline so we don't start a costly operation,
 * right before the actual deadline is reached,
 * and also keep some time to replicate the operation to other peers
 * and to compute the response payload. */
static gint64
_compute_reasonable_deadline(gint64 now, gboolean local)
{
	gint64 available = oio_ext_get_deadline() - now;
	if (local) {
		/* Keep a little time to compute the response payload. */
		available -= 5 * G_TIME_SPAN_MILLISECOND;
	} else {
		/* After the request is executed locally, we have to replicate the
		 * diff to other peers. If the time we are given is shorter than the
		 * replication timeout, cut it in half. */
		/* XXX(FVE): we should use oio_election_replicate_timeout_req,
		 * but we cannot access this variable from here. */
		available -= MIN(available / 2, 5 * G_TIME_SPAN_SECOND);
		/* The request is made on a database accessible to the client.
		 * Do not lock the meta2 database for more than 1 second. */
		available = MIN(available, meta2_sharding_replicated_clean_timeout);
	}
	return now + MAX(available, 0);
}

#define _update_cleaned_tables(table) do { \
	new_cleaned_tables = g_strconcat(current_cleaned_tables, "#"table";", NULL); \
	g_free(current_cleaned_tables); \
	current_cleaned_tables = new_cleaned_tables; \
	new_cleaned_tables = NULL; \
} while (0)

#define _not_in_cleaned_tables(table) \
	(!g_strstr_len(current_cleaned_tables, -1, "#"table";"))

GError*
m2db_clean_shard(struct sqlx_sqlite3_s *sq3, gboolean local,
		gint64 max_entries_cleaned, gchar *lower, gchar *upper,
		gboolean *truncated)
{
	GError *err = NULL;
	gchar *current_lower = NULL;
	gchar *current_upper = NULL;
	gchar *current_cleaned_tables = NULL;
	gchar *new_cleaned_tables = NULL;
	gint64 now = 0;
	gint64 entries_cleaned = 0;
	gint64 duration = 0;
	gboolean finished = FALSE;

	if (max_entries_cleaned <= 0) {
		max_entries_cleaned = G_MAXINT64;
	}
	gint64 _max_entries_cleaned = max_entries_cleaned;

	if (!lower) {
		err = m2db_get_sharding_lower(sq3, &current_lower);
		if (err) {
			goto end;
		}
		lower = current_lower;
	}
	if (!upper) {
		err = m2db_get_sharding_upper(sq3, &current_upper);
		if (err) {
			goto end;
		}
		upper = current_upper;
	}
	current_cleaned_tables = sqlx_admin_get_str(sq3,
			M2V2_ADMIN_SHARDING_CLEANED_TABLES);
	if (!current_cleaned_tables) {
		current_cleaned_tables = g_strdup("");
	}

	now = oio_ext_monotonic_time();
	gint64 dl = _compute_reasonable_deadline(now, local);

	// Remove orphan properties
	finished = FALSE;
	if (_not_in_cleaned_tables("properties")) {
		if ((err = _clean_shard_aliases(
				sq3, &descr_struct_PROPERTIES, lower, upper, &max_entries_cleaned,
				dl, &finished))) {
			goto end;
		} else if (finished) {
			_update_cleaned_tables("properties");
		}
	} else {
		GRID_DEBUG("Ignore the properties table, it is already cleaned "
				"(shard=%s) (local=%d) (reqid=%s)",
				sq3->name.base, local, oio_ext_get_reqid());
	}
	// Remove aliases out of range
	finished = FALSE;
	if (_not_in_cleaned_tables("aliases")) {
		if ((err = _clean_shard_aliases(
				sq3, &descr_struct_ALIASES, lower, upper, &max_entries_cleaned,
				dl, &finished))) {
			goto end;
		} else if (finished) {
			_update_cleaned_tables("aliases");
		}
	} else {
		GRID_DEBUG("Ignore the aliases table, it is already cleaned "
				"(shard=%s) (local=%d) (reqid=%s)",
				sq3->name.base, local, oio_ext_get_reqid());
	}
	// Remove orphan contents
	finished = FALSE;
	if (_not_in_cleaned_tables("contents")) {
		if ((err = _clean_shard_beans(
				sq3, &descr_struct_CONTENTS_HEADERS,
				"id NOT IN (SELECT content FROM aliases)",
				&max_entries_cleaned, dl, &finished))) {
			goto end;
		} else if (finished) {
			_update_cleaned_tables("contents");
		}
	} else {
		GRID_DEBUG("Ignore the contents table, it is already cleaned "
				"(shard=%s) (local=%d) (reqid=%s)",
				sq3->name.base, local, oio_ext_get_reqid());
	}
	// Remove orphan chunks
	finished = FALSE;
	if (_not_in_cleaned_tables("chunks")) {
		if ((err = _clean_shard_beans(
				sq3, &descr_struct_CHUNKS,
				"content NOT IN (SELECT content FROM aliases)",
				&max_entries_cleaned, dl, &finished))) {
			goto end;
		} else if (finished) {
			_update_cleaned_tables("chunks");
		}
	} else {
		GRID_DEBUG("Ignore the chunks table, it is already cleaned "
				"(shard=%s) (local=%d) (reqid=%s)",
				sq3->name.base, local, oio_ext_get_reqid());
	}

end:
	if (now) {
		duration = oio_ext_monotonic_time() - now;
	}
	if (!err) {
		/* Save tables that have already been processed so as not
		 * to clean them again during the next request. */
		sqlx_admin_set_str(sq3, M2V2_ADMIN_SHARDING_CLEANED_TABLES,
				current_cleaned_tables);

		// max_entries_cleaned will be negative if the deadline is reached
		entries_cleaned = _max_entries_cleaned - labs(max_entries_cleaned);

		/* We don't check the deadline here, on purpose: there is a chance
		 * that the last check of an already cleaned database finishes after
		 * the deadline. If we get here whereas the cleaning is not finished:
		 * - either we exhausted our "changes" budget,
		 * - or the deadline is reached and the changes budget has been
		 *   set to zero. */
		if (max_entries_cleaned > 0) {
			sqlx_admin_del_all_user(sq3, NULL, NULL);
			if (!local) {
				m2db_recompute_container_size_and_obj_count(sq3, FALSE);
			}
			/* else {
			 *   In the following operations, the counters will be reset
			 *   (container/sharding/create_shard) and recalculated
			 *   (replcated container/sharding/clean).
			 *   So there's no point spending time doing it here.
			 * } */
			*truncated = FALSE;
		} else {
			*truncated = TRUE;
		}
	}
	GRID_INFO("%"G_GINT64_FORMAT" entries cleaned in %"G_GINT64_FORMAT" ms "
			"(truncated=%d) [%s] reqid=%s",
			entries_cleaned, duration / G_TIME_SPAN_MILLISECOND,
			*truncated, sq3->name.base, oio_ext_get_reqid());
	g_free(current_lower);
	g_free(current_upper);
	g_free(current_cleaned_tables);
	g_free(new_cleaned_tables);
	return err;
}

GError*
m2db_clean_root_container(struct sqlx_sqlite3_s *sq3, gboolean local,
		gint64 max_entries_cleaned, gboolean *truncated)
{
	GError *err = NULL;
	gchar *current_cleaned_tables = NULL;
	gchar *new_cleaned_tables = NULL;
	gint64 now = 0;
	gint64 entries_cleaned = 0;
	gint64 duration = 0;
	gboolean finished = FALSE;

	current_cleaned_tables = sqlx_admin_get_str(sq3,
			M2V2_ADMIN_SHARDING_CLEANED_TABLES);
	if (!current_cleaned_tables) {
		current_cleaned_tables = g_strdup("");
	}
	if (max_entries_cleaned <= 0) {
		max_entries_cleaned = G_MAXINT64;
	}
	gint64 _max_entries_cleaned = max_entries_cleaned;

	now = oio_ext_monotonic_time();
	gint64 dl = _compute_reasonable_deadline(now, local);

	// Remove all chunks
	finished = FALSE;
	if (_not_in_cleaned_tables("chunks")) {
		if ((err = _clean_shard_beans(
				sq3, &descr_struct_CHUNKS, "1", &max_entries_cleaned,
				dl, &finished))) {
			goto end;
		} else if (finished) {
			_update_cleaned_tables("chunks");
		}
	} else {
		GRID_DEBUG("Ignore the chunks table, it is already cleaned "
				"(root=%s) (local=%d) (reqid=%s)",
				sq3->name.base, local, oio_ext_get_reqid());
	}
	// Remove all contents
	finished = FALSE;
	if (_not_in_cleaned_tables("contents")) {
		if ((err = _clean_shard_beans(
				sq3, &descr_struct_CONTENTS_HEADERS, "1", &max_entries_cleaned,
				dl, &finished))) {
			goto end;
		} else if (finished) {
			_update_cleaned_tables("contents");
		}
	} else {
		GRID_DEBUG("Ignore the contents table, it is already cleaned "
				"(root=%s) (local=%d) (reqid=%s)",
				sq3->name.base, local, oio_ext_get_reqid());
	}
	// Remove all properties
	finished = FALSE;
	if (_not_in_cleaned_tables("properties")) {
		if ((err = _clean_shard_beans(
				sq3, &descr_struct_PROPERTIES, "1", &max_entries_cleaned,
				dl, &finished))) {
			goto end;
		} else if (finished) {
			_update_cleaned_tables("properties");
		}
	} else {
		GRID_DEBUG("Ignore the properties table, it is already cleaned "
				"(root=%s) (local=%d) (reqid=%s)",
				sq3->name.base, local, oio_ext_get_reqid());
	}
	// Remove all aliases
	finished = FALSE;
	if (_not_in_cleaned_tables("aliases")) {
		if ((err = _clean_shard_beans(
				sq3, &descr_struct_ALIASES, "1", &max_entries_cleaned,
				dl, &finished))) {
		} else if (finished) {
			_update_cleaned_tables("aliases");
		}
	} else {
		GRID_DEBUG("Ignore the aliases table, it is already cleaned "
				"(root=%s) (local=%d) (reqid=%s)",
				sq3->name.base, local, oio_ext_get_reqid());
	}

end:
	if (now) {
		duration = oio_ext_monotonic_time() - now;
	}
	if (!err) {
		/* Save tables that have already been processed so as not
		 * to clean them again during the next request. */
		sqlx_admin_set_str(sq3, M2V2_ADMIN_SHARDING_CLEANED_TABLES,
				current_cleaned_tables);

		// max_entries_cleaned will be negative if the deadline is reached
		entries_cleaned = _max_entries_cleaned - labs(max_entries_cleaned);

		m2db_set_size(sq3, 0);
		m2db_set_obj_count(sq3, 0);
		/* There is an explanation in m2db_clean_shard
		 * about why we do not check the deadline here. */
		*truncated = max_entries_cleaned <= 0;
	}
	GRID_INFO("%"G_GINT64_FORMAT" entries cleaned in %"G_GINT64_FORMAT" ms "
			"(truncated=%d) [%s] reqid=%s",
			entries_cleaned, duration / G_TIME_SPAN_MILLISECOND,
			*truncated, sq3->name.base, oio_ext_get_reqid());
	g_free(current_cleaned_tables);
	g_free(new_cleaned_tables);
	return err;
}

GError*
m2db_create_triggers(struct sqlx_sqlite3_s *sq3)
{
	int rc = SQLITE_OK;
	rc = sqlx_exec(sq3->db, TRIGGER_LEGAL_HOLD);
	GError *err = NULL;
	if (rc != SQLITE_OK) {
		GRID_WARN("Failed to setup trigger_object_lock_delete");
		err = SQLITE_GERROR(sq3->db, rc);
		return err;
	}

	rc = sqlx_exec(sq3->db, TRIGGER_RETAIN_UNTIL);
	if (rc != SQLITE_OK) {
		GRID_WARN("Failed to setup trigger_object_retain_until_delete");
		err = SQLITE_GERROR(sq3->db, rc);
		return err;
	}
	return NULL;
}

void
m2db_drop_triggers(struct sqlx_sqlite3_s *sq3)
{
	int rc = SQLITE_OK;
	if (rc != SQLITE_OK) {
		GRID_WARN("Failed to drop trigger_object_lock_delete");
		return;
	}

	rc = sqlx_exec(sq3->db, DROP_TRIGGER_RETAIN_UNTIL);
	if (rc != SQLITE_OK) {
		GRID_WARN("Failed to drop trigger_object_retain_until_delete");
		return;
	}
}

GError*
m2db_enable_triggers(struct sqlx_sqlite3_s *sq3, gboolean enabled)
{
	GError *err = NULL;
	int rc = sqlx_exec(sq3->db, enabled? ENABLE_TRIGGERS : DISABLE_TRIGGERS);
	if (rc != SQLITE_OK)
		err = SQLITE_GERROR(sq3->db, rc);
	return err;
}
