/*
OpenIO SDS meta0v2
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

#include <errno.h>

#include <json-c/json.h>

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/version.h>

#include "meta0_utils.h"
#include "meta0_backend.h"

struct meta0_backend_s
{
	gchar *id;
	gchar *ns;
	GRWLock rwlock;
	GPtrArray *array_by_prefix;
	GPtrArray *array_meta1_ref;
	struct sqlx_repository_s *repository;
	gboolean reload_requested;
};

static GError* _open_and_lock(struct meta0_backend_s *m0,
		enum m0v2_open_type_e how, struct sqlx_sqlite3_s **handle);

static void _unlock_and_close(struct sqlx_sqlite3_s *sq3);

/* ------------------------------------------------------------------------- */

static enum sqlx_open_type_e
m0_to_sqlx(enum m0v2_open_type_e t)
{
	switch (t & 0x03) {
		case M0V2_OPENBASE_LOCAL:
			return SQLX_OPEN_CREATE|SQLX_OPEN_LOCAL;
		case M0V2_OPENBASE_MASTERONLY:
			return SQLX_OPEN_CREATE|SQLX_OPEN_MASTERONLY;
		case M0V2_OPENBASE_MASTERSLAVE:
			return SQLX_OPEN_CREATE|SQLX_OPEN_MASTERSLAVE;
		case M0V2_OPENBASE_SLAVEONLY:
			return SQLX_OPEN_CREATE|SQLX_OPEN_SLAVEONLY;
	}
	g_assert_not_reached();
	return SQLX_OPEN_CREATE|SQLX_OPEN_LOCAL;
}

struct meta0_backend_s *
meta0_backend_init(const gchar *ns, const gchar *id,
		struct sqlx_repository_s *repo)
{
	struct meta0_backend_s *m0 = g_malloc0(sizeof(*m0));
	g_rw_lock_init(&(m0->rwlock));
	m0->id = g_strdup(id);
	m0->ns = g_strdup(ns);
	m0->array_by_prefix = NULL;
	m0->array_meta1_ref = NULL;
	m0->repository = repo;
	m0->reload_requested = FALSE;

	return m0;
}

void
meta0_backend_clean(struct meta0_backend_s *m0)
{
	if (!m0)
		return;
	oio_str_clean (&m0->ns);
	oio_str_clean (&m0->id);
	if (m0->array_by_prefix)
		meta0_utils_array_clean(m0->array_by_prefix);
	if (m0->array_meta1_ref)
		meta0_utils_array_meta1ref_clean(m0->array_meta1_ref);
	g_rw_lock_clear (&m0->rwlock);
	g_free(m0);
}

void
meta0_backend_reload_requested(struct meta0_backend_s *m0)
{
	EXTRA_ASSERT(m0 != NULL);
	m0->reload_requested = TRUE;
}

/* ------------------------------------------------------------------------- */

static GError*
_load_from_base(struct sqlx_sqlite3_s *sq3, GPtrArray **result)
{
	GError *err = NULL;
	GPtrArray *array;
	sqlite3_stmt *stmt;
	int rc;
	guint count = 0;

	sqlite3_prepare_debug(rc, sq3->db, "SELECT prefix,addr,ROWID FROM meta1",
			-1, &stmt, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		return SQLITE_GERROR(sq3->db, rc);

	array = meta0_utils_array_create();

	for (;;) {
		rc = sqlite3_step(stmt);
		if (rc == SQLITE_ROW) {
			gint64 rowid;
			const guint8 *prefix, *url;
			gsize prefix_len;

			prefix_len = sqlite3_column_bytes(stmt, 0);
			prefix = sqlite3_column_blob(stmt, 0);
			url = sqlite3_column_text(stmt, 1);
			rowid = sqlite3_column_int64(stmt, 2);

			if (prefix_len != 2)
				GRID_WARN("Invalid prefix for URL [%s] ROWID %"G_GINT64_FORMAT,
						url, rowid);
			else {
				meta0_utils_array_add(array, prefix, (gchar*)url);
				count ++;
			}
		}
		else if (rc == SQLITE_DONE || rc == SQLITE_OK)
			break;
		else {
			err = SQLITE_GERROR(sq3->db, rc);
			break;
		}
	}

	sqlite3_finalize_debug(rc, stmt);
	meta0_utils_array_finalize(array);

	if (!err) {
		*result = array;
		GRID_INFO("Reloaded %u prefixes in %p (%u)",
				count, array, array->len);
	} else {
		meta0_utils_array_clean(array);
	}

	return err;
}

static GError*
_load_meta1ref_from_base(struct sqlx_sqlite3_s *sq3, GPtrArray **result)
{
	GError *err = NULL;
	GPtrArray *array;
	sqlite3_stmt *stmt;
	int rc;
	guint count = 0;

	array = g_ptr_array_new();

	sqlite3_prepare_debug(rc, sq3->db, "SELECT addr,state,prefixes FROM meta1_ref",
			-1, &stmt, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE) {
		if ( rc == SQLITE_ERROR ) {
			GRID_DEBUG("Missing table meta1ref in DB");
			*result = array;
			return NULL;
		}
		return SQLITE_GERROR(sq3->db, rc);
	}

	for (;;) {
		rc = sqlite3_step(stmt);
		if (rc == SQLITE_ROW) {
			const unsigned char *url,*prefix_nb,*ref;
			url = sqlite3_column_text(stmt,0);
			ref = sqlite3_column_text(stmt,1);
			prefix_nb = sqlite3_column_text(stmt,2);

			GRID_INFO("url %s, ref %s,prefix_nb %s ",url,ref,prefix_nb);
			g_ptr_array_add(array,meta0_utils_pack_meta1ref((gchar *)url,(gchar *)ref,(gchar *)prefix_nb));
			count++;
		}
		else if (rc == SQLITE_DONE || rc == SQLITE_OK)
			break;
		else {
			err = SQLITE_GERROR(sq3->db, rc);
			break;
		}

	}
	sqlite3_finalize_debug(rc, stmt);

	if (!err) {
		*result = array;
		GRID_INFO("Reloaded %u meta1 in %p (%u)",
				count, array, array->len);
	}

	return err;
}

static GError*
_load(struct meta0_backend_s *m0)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_TRACE2("%s(%p)", __FUNCTION__, m0);

	err = _open_and_lock(m0,M0V2_OPENBASE_MASTERSLAVE, &sq3);
	if (err != NULL) {
		return err;
	}

	err = _load_from_base(sq3, &(m0->array_by_prefix));
	if (err != NULL)
		g_prefix_error(&err, "Query error: ");

	err = _load_meta1ref_from_base(sq3, &(m0->array_meta1_ref));
	if (err != NULL)
                g_prefix_error(&err, "Query error: ");

	_unlock_and_close(sq3);
	return err;
}

static GError *
_json_to_meta0_mapping(const char *json_mapping, GPtrArray **result)
{
	GError *err = NULL;
	GPtrArray *urls_by_pfx = NULL;
	json_object *jbody = NULL;
	json_tokener *parser = json_tokener_new();

	jbody = json_tokener_parse_ex(parser, json_mapping, strlen(json_mapping));

	if (json_tokener_get_error(parser) != json_tokener_success) {
		err = NEWERROR(CODE_BAD_REQUEST, "Invalid JSON");
	} else if (!json_object_is_type(jbody, json_type_object)) {
		err = NEWERROR(CODE_BAD_REQUEST,
				"Invalid JSON object: must be a hash");
	} else {
		urls_by_pfx = meta0_utils_array_create();
		json_object_object_foreach(jbody, pfx_str, urls_obj) {
			guint8 pfx[2] = {0, 0};
			int url_count = json_object_array_length(urls_obj);
			oio_str_hex2bin(pfx_str, pfx, 2);
			for (int i = 0; i < url_count; i++) {
				const char *url = json_object_get_string(
						json_object_array_get_idx(urls_obj, i));
				meta0_utils_array_add(urls_by_pfx, pfx, url);
			}
		}
	}

	if (jbody)
		json_object_put(jbody);
	json_tokener_free(parser);

	if (urls_by_pfx)
		meta0_utils_array_finalize(urls_by_pfx);

	if (err)
		meta0_utils_array_clean(urls_by_pfx);
	else
		*result = urls_by_pfx;
	return err;
}

static GError*
_fill_mapping_holes(struct meta0_backend_s *m0, GPtrArray *mapping)
{
	GError *err = NULL;

	for (int idx = 0; idx < CID_PREFIX_COUNT && !err; idx++) {
		gchar **url = mapping->pdata[idx];
		guint16 index16 = idx;

		if (url && *url)
			continue;

		err = meta0_backend_get_one(m0,
				(guint8*)&index16, (gchar***)&mapping->pdata[idx]);
	}

	return err;
}

static GError *
_reload(struct meta0_backend_s *m0, gboolean lazy)
{
	GError *err = NULL;

	EXTRA_ASSERT(m0 != NULL);
	GRID_TRACE("%s(%p,lazy=%d)", __FUNCTION__, m0, lazy);

	g_rw_lock_writer_lock(&(m0->rwlock));

	if (!lazy || m0->reload_requested || !m0->array_by_prefix || !m0->array_meta1_ref) {
		if (m0->array_by_prefix) {
			meta0_utils_array_clean(m0->array_by_prefix);
			m0->array_by_prefix = NULL;
		}
		if (m0->array_meta1_ref) {
			meta0_utils_array_meta1ref_clean(m0->array_meta1_ref);
			m0->array_meta1_ref = NULL;
		}

		err = _load(m0);
		m0->reload_requested = FALSE;
		if (NULL != err)
			g_prefix_error(&err, "Loading error: ");
	}

	g_rw_lock_writer_unlock(&(m0->rwlock));
	return err;
}

static GError*
_open_and_lock(struct meta0_backend_s *m0, enum m0v2_open_type_e how,
		struct sqlx_sqlite3_s **handle)
{
	GError *err = NULL;

	EXTRA_ASSERT(m0 != NULL);
	EXTRA_ASSERT(handle != NULL);

	/* Now open/lock the base in a way suitable for our op */
	enum sqlx_open_type_e flag = m0_to_sqlx(how);
	struct sqlx_name_s n = {.base=m0->ns, .type=NAME_SRVTYPE_META0, .ns=m0->ns};
	err = sqlx_repository_open_and_lock(m0->repository, &n, flag, handle, NULL);

	if (err != NULL) {
		if (!CODE_IS_REDIRECT(err->code))
			g_prefix_error(&err, "Open/Lock error: ");
		return err;
	}

	EXTRA_ASSERT(*handle != NULL);
	GRID_TRACE("Opened and locked [%s/%s]", m0->id, NAME_SRVTYPE_META0);

	return NULL;
}

static void
_unlock_and_close(struct sqlx_sqlite3_s *sq3)
{
	EXTRA_ASSERT(sq3 != NULL);
	sqlx_admin_save_lazy (sq3);
	sqlx_repository_unlock_and_close_noerror(sq3);
}

static GError *
_assign_prefixes(sqlite3 *db, const GPtrArray *new_assign_prefixes,
		gboolean init)
{
	gint rc;
	guint idx;
	sqlite3_stmt *stmt = NULL;

	if (!init) {
		sqlite3_prepare_debug(rc, db, "DELETE FROM meta1", -1, &stmt, NULL);
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			return SQLITE_GERROR(db, rc);
		for (;;) {
			rc = sqlite3_step(stmt);
			if (rc == SQLITE_OK || rc == SQLITE_DONE)
				break;
			return SQLITE_GERROR(db,rc);
		}
		sqlite3_finalize_debug(rc, stmt);
	}

	sqlite3_prepare_debug(rc, db, "INSERT INTO meta1"
			" (prefix,addr) VALUES (?,?)", -1, &stmt, NULL);

	if (rc != SQLITE_OK && rc != SQLITE_DONE) {
		return SQLITE_GERROR(db, rc);
	}

	GError *err = NULL;
	for (idx = 0; idx < CID_PREFIX_COUNT && !err; idx++) {
		gchar **url = new_assign_prefixes->pdata[idx];
		guint16 index16 = idx;

		if (!url || !*url)
			continue;

		for (; *url; url++) {
			sqlite3_reset(stmt);
			sqlite3_clear_bindings(stmt);
			sqlite3_bind_blob(stmt, 1, &index16, 2, NULL);
			sqlite3_bind_text(stmt, 2, *url, -1, NULL);
			while (!err) {
				rc = sqlite3_step(stmt);
				if (rc == SQLITE_OK || rc == SQLITE_DONE)
					break;
				else {
					err = SQLITE_GERROR(db, rc);
					break;
				}
			}
		}
	}
	sqlite3_finalize_debug(rc, stmt);
	return err;
}

static GError *
_record_meta1ref(sqlite3 *db, const GPtrArray *new_assign_meta1ref)
{
	GError *err = NULL;
	gint rc;
	guint idx;
	sqlite3_stmt *stmt = NULL;

	sqlite3_prepare_debug(rc, db, "REPLACE INTO meta1_ref"
			" (addr,state,prefixes) VALUES (?,?,?)", -1, &stmt, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE) {
		if ( rc == SQLITE_ERROR ) {
			GRID_DEBUG("Missing table meta1ref in DB");
			return NULL;
		}
		return SQLITE_GERROR(db, rc);
	}

	for (idx=0; idx < new_assign_meta1ref->len; idx++) {
		gchar *m1ref = new_assign_meta1ref->pdata[idx];
		gchar *addr, *ref, *nb;
		if (!meta0_utils_unpack_meta1ref(m1ref,&addr,&ref,&nb))
			continue;
		sqlite3_reset(stmt);
		sqlite3_clear_bindings(stmt);
		sqlite3_bind_text(stmt, 1, addr, -1, NULL);
		sqlite3_bind_text(stmt, 2, ref, -1, NULL);
		sqlite3_bind_text(stmt, 3, nb, -1, NULL);

		while (!err) {
			rc = sqlite3_step(stmt);
			if (rc == SQLITE_OK || rc == SQLITE_DONE)
				break;
			else
				err = SQLITE_GERROR(db, rc);
		}

		g_free0(addr);
		g_free0(ref);
		g_free0(nb);
	}
	sqlite3_finalize_debug(rc, stmt);
	return err;
}

static GError *
_delete_meta1_ref(sqlite3 *db, gchar *meta1_ref)
{
	GError *err = NULL;
	gint rc;
	sqlite3_stmt *stmt = NULL;

	sqlite3_prepare_debug(rc, db, "DELETE FROM meta1_ref where addr=?",
			-1, &stmt, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		return SQLITE_GERROR(db, rc);

	(void) sqlite3_bind_text(stmt,1,meta1_ref, strlen(meta1_ref), NULL);
	do { rc = sqlite3_step(stmt); } while (rc == SQLITE_ROW );
	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		err = SQLITE_GERROR(db, rc);

	sqlite3_finalize_debug(rc, stmt);
	return err;
}

/* ------------------------------------------------------------------------- */

GError*
meta0_backend_fill_from_json(struct meta0_backend_s *m0,
		const char *json_mapping)
{
	EXTRA_ASSERT(m0 != NULL);
	EXTRA_ASSERT(json_mapping != NULL);

	GError *err = NULL;
	GPtrArray *mapping = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	err = _json_to_meta0_mapping(json_mapping, &mapping);
	if (err)
		goto cleanup;

	err = _fill_mapping_holes(m0, mapping);
	if (err)
		goto cleanup;

	err = _open_and_lock(m0, M0V2_OPENBASE_MASTERONLY, &sq3);
	if (err)
		goto cleanup;

	if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
		err = _assign_prefixes(sq3->db, mapping, 0);
		if (!err)
			sqlx_transaction_notify_huge_changes(repctx);
		err = sqlx_transaction_end(repctx, err);
	}
	_unlock_and_close(sq3);

cleanup:
	meta0_utils_array_clean(mapping);
	return err;
}

GError *
meta0_backend_reload(struct meta0_backend_s *m0)
{
	EXTRA_ASSERT(m0 != NULL);
	return _reload(m0, FALSE);
}

GError *
meta0_backend_reset(struct meta0_backend_s *m0, gboolean flag_local)
{
	EXTRA_ASSERT(m0 != NULL);

	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	err = _open_and_lock(m0, flag_local ? M0V2_OPENBASE_LOCAL : M0V2_OPENBASE_MASTERONLY, &sq3);
	if (err) return err;

	if (!(err = sqlx_transaction_begin (sq3, &repctx))) {
		gint rc;
		sqlite3_stmt *stmt = NULL;
		sqlite3_prepare_debug (rc, sq3->db, "DELETE FROM meta1", -1, &stmt, NULL);
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			err = SQLITE_GERROR(sq3->db, rc);
		else {
			sqlite3_step_debug_until_end (rc, stmt);
			if (rc != SQLITE_OK && rc != SQLITE_DONE)
				err = SQLITE_GERROR(sq3->db, rc);
			else
				sqlx_transaction_notify_huge_changes (repctx);
			sqlite3_finalize_debug (rc, stmt);
		}
		err = sqlx_transaction_end (repctx, err);
	}

	_unlock_and_close (sq3);
	return err;
}

GError*
meta0_backend_get_all(struct meta0_backend_s *m0, GPtrArray **result)
{
	GError *err = NULL;

	EXTRA_ASSERT(m0 != NULL);
	EXTRA_ASSERT(result != NULL);

	if (NULL != (err = _reload(m0, TRUE))) {
		g_prefix_error(&err, "Reload error: ");
		return err;
	}

	g_rw_lock_reader_lock(&(m0->rwlock));
	EXTRA_ASSERT(m0->array_by_prefix != NULL);
	*result = meta0_utils_array_dup(m0->array_by_prefix);
	g_rw_lock_reader_unlock(&(m0->rwlock));

	return NULL;
}

GError*
meta0_backend_get_one(struct meta0_backend_s *m0, const guint8 *prefix,
		gchar ***u)
{
	GError *err;

	EXTRA_ASSERT(m0 != NULL);
	EXTRA_ASSERT(u != NULL);

	GRID_TRACE("%s(%p,%02X%02X,%p)", __FUNCTION__,
			m0, prefix[0], prefix[1], u);

	if (NULL != (err = _reload(m0, TRUE))) {
		g_prefix_error(&err, "Reload error: ");
		return err;
	}

	g_rw_lock_reader_lock(&(m0->rwlock));
	EXTRA_ASSERT(m0->array_by_prefix != NULL);
	*u = meta0_utils_array_get_urlv(m0->array_by_prefix, prefix);
	g_rw_lock_reader_unlock(&(m0->rwlock));

	return *u ? NULL : NEWERROR(EINVAL, "META0 partially missing");
}

GError*
meta0_backend_assign(struct meta0_backend_s *m0,
		const GPtrArray *new_assign_prefixes,
		const GPtrArray *new_assign_meta1ref, const gboolean init)
{
	GError *err;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(m0 != NULL);
	EXTRA_ASSERT(new_assign_prefixes != NULL);
	EXTRA_ASSERT(new_assign_meta1ref != NULL);

	err = _open_and_lock(m0, M0V2_OPENBASE_MASTERONLY, &sq3);
	if (NULL != err)
		return err;

	err = sqlx_transaction_begin(sq3, &repctx);
	if (NULL == err) {
		err = _assign_prefixes(sq3->db, new_assign_prefixes,init);
		if (!err) {
			err = _record_meta1ref(sq3->db, new_assign_meta1ref);
			if (!err)
				sqlx_transaction_notify_huge_changes(repctx);
		}
		err = sqlx_transaction_end(repctx, err);
	}
	_unlock_and_close(sq3);
	return err;
}

GError*
meta0_backend_get_all_meta1_ref(struct meta0_backend_s *m0, GPtrArray **result)
{
	GError *err;

	EXTRA_ASSERT(m0 != NULL);
	EXTRA_ASSERT(result != NULL);

	if (NULL != (err = _reload(m0, TRUE))) {
		g_prefix_error(&err, "Reload error: ");
		return err;
	}

	g_rw_lock_reader_lock(&(m0->rwlock));
	EXTRA_ASSERT(m0->array_meta1_ref != NULL);
	*result = meta0_utils_array_meta1ref_dup(m0->array_meta1_ref);
	g_rw_lock_reader_unlock(&(m0->rwlock));

	return NULL;
}

GError*
meta0_backend_destroy_meta1_ref(struct meta0_backend_s *m0, gchar *meta1)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	GPtrArray *result;
	gchar *v, *addr, *ref, *nb;
	guint i, max, cmpaddr, cmpstate;

	EXTRA_ASSERT(m0 != NULL);
	EXTRA_ASSERT(meta1 != NULL);

	/* check if meta1 is disable */
	if (NULL != (err = _reload(m0, TRUE))) {
		g_prefix_error(&err, "Reload error: ");
		return err;
	}

	g_rw_lock_reader_lock(&(m0->rwlock));
	EXTRA_ASSERT(m0->array_meta1_ref != NULL);
	result = meta0_utils_array_meta1ref_dup(m0->array_meta1_ref);
	g_rw_lock_reader_unlock(&(m0->rwlock));

	for (i=0,max=result->len; i<max ;i++) {
		if (!(v = result->pdata[i]))
			continue;
		meta0_utils_unpack_meta1ref(v,&addr,&ref,&nb);
		cmpaddr = g_ascii_strcasecmp(addr,meta1);
		cmpstate = g_ascii_strcasecmp(ref,"0");
		g_free(addr);
		g_free(ref);
		g_free(nb);
		if ( cmpaddr == 0) {
			if (cmpstate != 0)
				return NEWERROR(EINVAL, "meta1 always available to prefix allocation");
			err = _open_and_lock(m0, M0V2_OPENBASE_MASTERONLY, &sq3);
			if (NULL != err)
				return err;

			err = sqlx_transaction_begin(sq3, &repctx);
			if (NULL == err) {
				err = _delete_meta1_ref(sq3->db, meta1);
				err = sqlx_transaction_end(repctx, err);
			}
			_unlock_and_close(sq3);
			return err;
		}
	}
	return NEWERROR(EINVAL, "UNKNOWN meta1");
}

