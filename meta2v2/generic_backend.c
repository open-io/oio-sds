/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

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

#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <sqlite3.h>

#include <sqliterepo/sqliterepo.h>
#include <metautils/lib/metautils.h>
#include <meta2v2/generic.h>

/* GVariant utils ---------------------------------------------------------- */

GVariant*
_gba_to_gvariant(GByteArray *gba)
{
	GBytes *gb = g_bytes_new_static (gba->data, gba->len);
	GVariant *gv = _gb_to_gvariant (gb);
	g_bytes_unref (gb);
	return gv;
}

GVariant*
_gb_to_gvariant(GBytes *gb)
{
	gsize max = 0;
	gconstpointer b = g_bytes_get_data(gb, &max);
	return _bytes_to_gvariant(b, max);
}

GVariant*
_bytes_to_gvariant(gconstpointer bytes, gsize len)
{
	GVariant *result = g_variant_new_fixed_array(
			G_VARIANT_TYPE("y"), bytes, len, 1);
	return result;
}

static void
gv_freev(GVariant **gv, gboolean content_only)
{
	if (!content_only) {
		gv_freev(gv, TRUE);
		g_free(gv);
	}
	else {
		for (; *gv ;gv++) {
			g_variant_unref(*gv);
			*gv = NULL;
		}
	}
}

static GVariant*
_field_to_gvariant(gpointer bean, guint position)
{
	gpointer pf = FIELD(bean, position);

	if (!_bean_has_field(bean, position))
		return g_variant_new_tuple(NULL, 0);

	switch (DESCR_FIELD(bean,position)->type) {
		case FT_BOOL:
			return g_variant_new_byte(*((gboolean*)pf) ? 1 : 0);
		case FT_INT:
			return g_variant_new_int64(*((gint64*)pf));
		case FT_REAL:
			return g_variant_new_double(*((gdouble*)pf));
		case FT_TEXT:
			if (!*((gpointer*)(pf)))
				return g_variant_new_tuple(NULL, 0);
			return g_variant_new_string(GSTR(pf)->str);
		case FT_BLOB:
			if (!*((gpointer*)(pf)))
				return g_variant_new_tuple(NULL, 0);
			return _gba_to_gvariant(GBA(pf));
		default:
			g_assert_not_reached();
			break;
	}

	g_assert_not_reached();
	return NULL;
}

/* Bean utils -------------------------------------------------------------- */

static GError*
_db_del_FK(gpointer bean,
		const struct fk_field_s *fkf0,
		const struct bean_descriptor_s *descr,
		const struct fk_field_s *fkf1,
		sqlite3 *db)
{
	GError *err;
	guint count;
	const struct fk_field_s *fkf;

	/* build the query string */
	GString *gsql = g_string_sized_new(128);
	for (count=0,fkf=fkf0; fkf->name ;fkf++) {
		if (count++)
			g_string_append_static(gsql, " AND ");
		g_string_append(gsql, fkf->name);
		g_string_append_c(gsql, '=');
		g_string_append_c(gsql, '?');
	}

	/* build the parameter string */
	GPtrArray *p = g_ptr_array_new();
	for (fkf=fkf1; fkf->name ;fkf++)
		g_ptr_array_add(p, _field_to_gvariant(bean, fkf->i));
	g_ptr_array_add(p, NULL);

	/* execute the query */
	err = _db_delete(descr, db, gsql->str, (GVariant**)(p->pdata));

	g_string_free(gsql, TRUE);
	gv_freev((GVariant**) g_ptr_array_free(p, FALSE), FALSE);

	return err;
}

static GError*
_db_get_FK(gpointer bean,
		const struct fk_field_s *fkf0,
		const struct bean_descriptor_s *descr,
		const struct fk_field_s *fkf1,
		sqlite3 *db,
		on_bean_f cb, gpointer u)
{
	GError *err;
	guint count;
	const struct fk_field_s *fkf;

	/* build the query string */
	GString *gsql = g_string_sized_new(128);
	for (count=0,fkf=fkf0; fkf->name ;fkf++) {
		if (count++)
			g_string_append_static(gsql, " AND ");
		g_string_append(gsql, fkf->name);
		g_string_append_c(gsql, '=');
		g_string_append_c(gsql, '?');
	}

	/* build the parameter string */
	GPtrArray *p = g_ptr_array_new();
	for (fkf=fkf1; fkf->name ;fkf++)
		g_ptr_array_add(p, _field_to_gvariant(bean, fkf->i));
	g_ptr_array_add(p, NULL);

	/* execute the query */
	err = _db_get_bean(descr, db, gsql->str, (GVariant**)(p->pdata), cb, u);

	g_string_free(gsql, TRUE);
	gv_freev((GVariant**) g_ptr_array_free(p, FALSE), FALSE);

	return err;
}

GError*
_db_del_FK_by_name(gpointer bean, const gchar *name, sqlite3 *db)
{
	const struct fk_descriptor_s *fk;

	EXTRA_ASSERT(name != NULL);
	EXTRA_ASSERT(bean != NULL);
	EXTRA_ASSERT(db != NULL);

	for (fk=DESCR(bean)->fk; fk->src ;fk++) {
		if (!strcmp(fk->name, name)) {
			EXTRA_ASSERT(DESCR(bean) == fk->src || DESCR(bean) == fk->dst);
			if (DESCR(bean) == fk->src)
				return _db_del_FK(bean, fk->dst_fields, fk->dst,
						fk->src_fields, db);
			if (DESCR(bean) == fk->dst)
				return _db_del_FK(bean, fk->src_fields, fk->src,
						fk->dst_fields, db);
		}
	}

	g_assert_not_reached();
	return NEWERROR(CODE_INTERNAL_ERROR, "BUG"); /* makes the compilers happy */
}

GError*
_db_get_FK_by_name(gpointer bean, const gchar *name, sqlite3 *db,
		on_bean_f cb, gpointer u)
{
	const struct fk_descriptor_s *fk;

	EXTRA_ASSERT(name != NULL);
	EXTRA_ASSERT(bean != NULL);
	EXTRA_ASSERT(db != NULL);
	EXTRA_ASSERT(cb != NULL);

	for (fk=DESCR(bean)->fk; fk->src ;fk++) {
		if (!strcmp(fk->name, name)) {
			EXTRA_ASSERT(DESCR(bean) == fk->src || DESCR(bean) == fk->dst);
			if (DESCR(bean) == fk->src)
				return _db_get_FK(bean, fk->dst_fields, fk->dst,
						fk->src_fields, db, cb, u);
			if (DESCR(bean) == fk->dst)
				return _db_get_FK(bean, fk->src_fields, fk->src,
						fk->dst_fields, db, cb, u);
		}
	}

	g_assert_not_reached();
	return NEWERROR(CODE_INTERNAL_ERROR, "BUG"); /* makes the compilers happy */
}

static GError*
_db_count_FK(gpointer bean,
		const struct fk_field_s *fkf0,
		const struct bean_descriptor_s *descr,
		const struct fk_field_s *fkf1,
		sqlite3 *db,
		gint64 *pcount)
{
	GError *err;
	guint count;
	const struct fk_field_s *fkf;

	/* build the query string */
	GString *gsql = g_string_sized_new(128);
	for (count=0,fkf=fkf0; fkf->name ;fkf++) {
		if (count++)
			g_string_append_static(gsql, " AND ");
		g_string_append(gsql, fkf->name);
		g_string_append_c(gsql, '=');
		g_string_append_c(gsql, '?');
	}

	/* build the parameter string */
	GPtrArray *p = g_ptr_array_new();
	for (fkf=fkf1; fkf->name ;fkf++)
		g_ptr_array_add(p, _field_to_gvariant(bean, fkf->i));
	g_ptr_array_add(p, NULL);

	/* execute the query */
	err = _db_count_bean(descr, db, gsql->str, (GVariant**)(p->pdata), pcount);

	g_string_free(gsql, TRUE);
	gv_freev((GVariant**) g_ptr_array_free(p, FALSE), FALSE);

	return err;
}

GError*
_db_count_FK_by_name(gpointer bean, const gchar *name,
		sqlite3 *db, gint64 *pcount)
{
	const struct fk_descriptor_s *fk;

	EXTRA_ASSERT(name != NULL);
	EXTRA_ASSERT(bean != NULL);
	EXTRA_ASSERT(pcount != NULL);

	for (fk=DESCR(bean)->fk; fk->src ;fk++) {
		if (!strcmp(fk->name, name)) {
			EXTRA_ASSERT(DESCR(bean) == fk->src || DESCR(bean) == fk->dst);
			if (DESCR(bean) == fk->src)
				return _db_count_FK(bean, fk->dst_fields, fk->dst,
						fk->src_fields, db, pcount);
			if (DESCR(bean) == fk->dst)
				return _db_count_FK(bean, fk->src_fields, fk->src,
						fk->dst_fields, db, pcount);
		}
	}

	g_assert_not_reached();
	return NEWERROR(CODE_INTERNAL_ERROR, "BUG"); /* makes the compilers happy */
}

GError*
_db_get_FK_by_name_buffered(gpointer bean, const gchar *name,
		sqlite3 *db, GPtrArray *result)
{
	return _db_get_FK_by_name(bean, name, db, _bean_buffer_cb, result);
}

/* SQLite/Bean utils ------------------------------------------------------- */

static GString*
_bean_clause(gpointer bean, GString *gstr, gboolean pk_only)
{
	guint count;
	const struct field_descriptor_s *fd;

	if (!gstr)
		gstr = g_string_sized_new(16 * DESCR(bean)->count_fields);

	for (count=0,fd=DESCR(bean)->fields; fd->type ;fd++) {
		if (pk_only && !fd->pk)
			continue;
		if (count)
			g_string_append_static(gstr, " AND ");
		g_string_append(gstr, fd->name);
		g_string_append_c(gstr, '=');
		g_string_append_c(gstr, '?');
		count ++;
	}

	return gstr;
}

static inline const char *
bean_strtype(int t)
{
	switch (t) {
		case FT_BOOL: return "BOOL";
		case FT_INT: return "INT";
		case FT_REAL: return "REAL";
		case FT_TEXT: return "TEXT";
		case FT_BLOB: return "BLOB";
		default: return "???";
	}
}

static inline const char *
sqlite_strtype(int t)
{
	switch (t) {
		case SQLITE_INTEGER: return "INT";
		case SQLITE_FLOAT: return "FLOAT";
		case SQLITE_TEXT: return "TEXT";
		case SQLITE_BLOB: return "BLOB";
		case SQLITE_NULL: return "NULL";
		default: return "???";
	}
}

static GError *
_stmt_apply_GV_parameter_simple(sqlite3_stmt *stmt, int pos, GVariant *p)
{
	int rc;
	gsize slen = 0;
	const gchar *s;

	switch (*((gchar*)g_variant_get_type(p))) {
		case 'b':
			rc = sqlite3_bind_int64(stmt, pos, g_variant_get_boolean(p));
			EXTRA_ASSERT(rc == SQLITE_OK);
			return NULL;
		case 'i':
			rc = sqlite3_bind_int64(stmt, pos, g_variant_get_int32(p));
			EXTRA_ASSERT(rc == SQLITE_OK);
			return NULL;
		case 'n':
			rc = sqlite3_bind_int64(stmt, pos, g_variant_get_int16(p));
			EXTRA_ASSERT(rc == SQLITE_OK);
			return NULL;
		case 'q':
			rc = sqlite3_bind_int64(stmt, pos, g_variant_get_uint16(p));
			EXTRA_ASSERT(rc == SQLITE_OK);
			return NULL;
		case 's':
			s = g_variant_get_string(p, &slen);
			rc = sqlite3_bind_text(stmt, pos, s, slen, NULL);
			EXTRA_ASSERT(rc == SQLITE_OK);
			return NULL;
		case 't':
			rc = sqlite3_bind_int64(stmt, pos, g_variant_get_uint64(p));
			EXTRA_ASSERT(rc == SQLITE_OK);
			return NULL;
		case 'u':
			rc = sqlite3_bind_int64(stmt, pos, g_variant_get_uint32(p));
			EXTRA_ASSERT(rc == SQLITE_OK);
			return NULL;
		case 'x':
			rc = sqlite3_bind_int64(stmt, pos, g_variant_get_int64(p));
			EXTRA_ASSERT(rc == SQLITE_OK);
			return NULL;
		case 'y':
			rc = sqlite3_bind_int64(stmt, pos, g_variant_get_byte(p));
			EXTRA_ASSERT(rc == SQLITE_OK);
			return NULL;
		/* XXX TODO manage the G_VARIANT_UNIT associtaed to NULL'd fields */
		default:
			return NEWERROR(CODE_BAD_REQUEST, "Unexpected parameter at position %d ('%s')",
					pos, (gchar*)g_variant_get_type(p));
	}
	(void) rc;
}

static GError *
_stmt_apply_GV_parameter(sqlite3_stmt *stmt, int pos, GVariant *p)
{
	if (g_variant_is_of_type(p, G_VARIANT_TYPE_UNIT)) {
		sqlite3_bind_null(stmt, pos);
		return NULL;
	}

	if (g_variant_is_of_type(p, G_VARIANT_TYPE_BASIC)) {
		return _stmt_apply_GV_parameter_simple(stmt, pos, p);
	}

	if (g_variant_is_of_type(p, G_VARIANT_TYPE_UNIT)) {
		sqlite3_bind_null(stmt, pos);
		return NULL;
	}

	if (g_variant_is_of_type(p, G_VARIANT_TYPE_BYTESTRING)) {
		sqlite3_bind_blob(stmt, pos, g_variant_get_data(p),
				g_variant_get_size(p), NULL);
		return NULL;
	}

	return NEWERROR(CODE_BAD_REQUEST, "Unexpected parameter at position %d (type '%s')",
			pos, (gchar*)g_variant_get_type(p));
}

static GError *
_stmt_apply_GV_parameters(sqlite3_stmt *stmt, GVariant **params)
{
	int i;
	GVariant *p;
	guint count_binds, count_params;

	count_binds = sqlite3_bind_parameter_count(stmt);
	count_params = g_strv_length((gchar**)params);

	if (count_params != count_binds)
		return NEWERROR(CODE_INTERNAL_ERROR, "Bad parameters : %u expected, %u received",
				count_binds, count_params);

	for (i=1; (p=*params) ;i++,params++) {
		GError *err = _stmt_apply_GV_parameter(stmt, i, p);
		if (NULL != err)
			return err;
	}

	return NULL;
}

static GError *
_db_prepare_statement(sqlite3 *db, const gchar *sql, int len, sqlite3_stmt **result)
{
	gint rc;
	sqlite3_stmt *stmt = NULL;

	sqlite3_prepare_debug(rc, db, sql, len, &stmt, NULL);

	if (rc != SQLITE_OK && rc != SQLITE_ROW)
		return M2_SQLITE_GERROR(db,rc);
	EXTRA_ASSERT(stmt != NULL);

	*result = stmt;
	return NULL;
}

static GError*
_db_execute(sqlite3 *db, const gchar *query, int len, GVariant **params)
{
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	gint rc;

	err = _db_prepare_statement(db, query, len, &stmt);
	if (NULL != err) {
		g_prefix_error(&err, "Prepare error: ");
		return err;
	}

	if (NULL != (err = _stmt_apply_GV_parameters(stmt, params))) {
		g_prefix_error(&err, "Parameters error: ");
	}
	else {
		while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) { }
		if (rc != SQLITE_DONE && rc != SQLITE_OK) {
			err = M2_SQLITE_GERROR(db,rc);
			g_prefix_error(&err, "Step error: ");
		}
	}

	sqlite3_finalize(stmt);
	return err;
}

/* SELECT ------------------------------------------------------------------- */

static gpointer
_row_to_bean(const struct bean_descriptor_s *descr, sqlite3_stmt *stmt)
{
	const struct field_descriptor_s *fd;
	gpointer res;
	int col, s;

	res = _bean_create(descr);

	for (fd=descr->fields; fd->type ;fd++) {
		col = fd->position;

		if (sqlite3_column_type(stmt, col) == SQLITE_NULL) {
			_bean_del_field(res, fd->position);
			continue;
		}

		_bean_set_field(res, fd->position);
		gpointer pf = ((guint8*)res) + descr->offset_fields + fd->offset;
		switch (fd->type) {
			case FT_BOOL:
				*((gboolean*)pf) = sqlite3_column_int(stmt, col);
				continue;
			case FT_INT:
				*((gint64*)pf) = sqlite3_column_int64(stmt, col);
				continue;
			case FT_REAL:
				*((gdouble*)pf) = sqlite3_column_double(stmt, col);
				continue;
			case FT_TEXT:
				s = sqlite3_column_bytes(stmt, col);
				g_string_append_len(GSTR(pf), (const gchar*)sqlite3_column_text(stmt, col), s);
				continue;
			case FT_BLOB:
				s = sqlite3_column_bytes(stmt, col);
				g_byte_array_append(GBA(pf), (guint8*)sqlite3_column_blob(stmt, col), s);
				continue;
			default:
				g_assert_not_reached();
				continue;
		}
	}

	return res;
}

GError *
_db_get_bean(const struct bean_descriptor_s *descr,
		sqlite3 *db, const gchar *clause, GVariant **params,
		on_bean_f cb, gpointer u)
{
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	gint rc;

	EXTRA_ASSERT(descr != NULL);
	EXTRA_ASSERT(db != NULL);
	EXTRA_ASSERT(params != NULL);
	EXTRA_ASSERT(cb != NULL);

	if (!clause || !*clause)
		err = _db_prepare_statement(db, descr->sql_select, descr->sql_select_len, &stmt);
	else {
		GString *sql = g_string_sized_new(128 + descr->sql_select_len);
		g_string_append_len (sql, descr->sql_select, descr->sql_select_len);
		g_string_append_static (sql, " WHERE ");
		g_string_append (sql, clause);
		err = _db_prepare_statement(db, sql->str, sql->len, &stmt);
		g_string_free(sql, TRUE);
	}

	if (NULL != err) {
		g_prefix_error(&err, "Prepare error: ");
		return err;
	}

	if (!(err = _stmt_apply_GV_parameters(stmt, params))) {
		while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
			cb(u, _row_to_bean(descr, stmt));
		if (unlikely(!(rc == SQLITE_OK || rc == SQLITE_DONE))) {
			err = NEWERROR(CODE_INTERNAL_ERROR,
					"Got an error from sqlite: (%d) %s",
					rc, sqlite_strerror(rc));
		}
	}

	sqlite3_finalize(stmt);
	stmt = NULL;
	return err;
}

GError*
_db_count_bean(const struct bean_descriptor_s *descr,
		sqlite3 *db, const gchar *clause, GVariant **params,
		gint64 *pcount)
{
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	gint rc;

	EXTRA_ASSERT(descr != NULL);
	EXTRA_ASSERT(db != NULL);
	EXTRA_ASSERT(pcount != NULL);

	if (!clause || !*clause)
		err = _db_prepare_statement(db, descr->sql_count, descr->sql_count_len, &stmt);
	else {
		GString *sql = g_string_sized_new(128 + descr->sql_count_len);
		g_string_append_len (sql, descr->sql_count, descr->sql_count_len);
		g_string_append_static (sql, " WHERE ");
		g_string_append (sql, clause);
		err = _db_prepare_statement(db, sql->str, sql->len, &stmt);
		g_string_free(sql, TRUE);
	}

	if (NULL != err) {
		g_prefix_error(&err, "Prepare error: ");
		return err;
	}

	if (!(err = _stmt_apply_GV_parameters(stmt, params))) {
		while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
			*pcount = sqlite3_column_int64(stmt, 0);
		}
		if (unlikely(!(rc == SQLITE_OK || rc == SQLITE_DONE))) {
			err = NEWERROR(CODE_INTERNAL_ERROR,
					"Got an error from sqlite: (%d) %s",
					rc, sqlite_strerror(rc));
		}
	}

	sqlite3_finalize(stmt);
	stmt = NULL;
	return err;
}

/* DELETE ------------------------------------------------------------------- */

static GString *
_bean_query_DELETE(gpointer bean)
{
	GString *gstr = g_string_sized_new(128 + DESCR(bean)->sql_delete_len);
	g_string_append_len(gstr, DESCR(bean)->sql_delete, DESCR(bean)->sql_delete_len);
	return _bean_clause(bean, gstr, TRUE);
}

GError*
_db_delete_bean(sqlite3 *db, gpointer bean)
{
	GVariant** _params_delete() {
		GPtrArray *v = g_ptr_array_sized_new(1 + DESCR(bean)->count_fields);
		const struct field_descriptor_s *fd;
		for (fd=DESCR(bean)->fields; fd->type ;fd++) {
			if (!fd->pk)
				continue;
			g_ptr_array_add(v, _field_to_gvariant(bean, fd->position));
		}

		g_ptr_array_add(v, NULL);
		return (GVariant**) g_ptr_array_free(v, FALSE);
	}

	GVariant **params = _params_delete();
	GString *sql = _bean_query_DELETE(bean);
	GError *err = _db_execute(db, sql->str, sql->len, params);
	gv_freev(params, FALSE);
	g_string_free(sql, TRUE);

	return err;
}

GError*
_db_delete(const struct bean_descriptor_s *descr, sqlite3 *db,
		const gchar *clause, GVariant **params)
{
	GString *sql = g_string_sized_new(128 + descr->sql_delete_len);
	g_string_append_len (sql, descr->sql_delete, descr->sql_delete_len);
	g_string_append(sql, clause);
	GError *err = _db_execute(db, sql->str, sql->len, params);
	g_string_free(sql, TRUE);
	return err;
}

/* REPLACE ------------------------------------------------------------------ */

static GVariant**
_bean_params_update (gpointer bean)
{
	GPtrArray *v = g_ptr_array_sized_new(1 + DESCR(bean)->count_fields);

	const struct field_descriptor_s *fd;
	for (fd=DESCR(bean)->fields; fd->type ;fd++) {
		if (!fd->pk) {
			GVariant *gv = _field_to_gvariant(bean, fd->position);
			EXTRA_ASSERT(gv != NULL);
			g_ptr_array_add(v, gv);
		}
	}
	for (fd=DESCR(bean)->fields; fd->type ;fd++) {
		if (fd->pk) {
			GVariant *gv = _field_to_gvariant(bean, fd->position);
			EXTRA_ASSERT(gv != NULL);
			g_ptr_array_add(v, gv);
		}
	}

	g_ptr_array_add(v, NULL);
	return (GVariant**) g_ptr_array_free(v, FALSE);
}

static GVariant**
_bean_params_insert_or_replace (gpointer bean)
{
	GPtrArray *v = g_ptr_array_sized_new(1 + DESCR(bean)->count_fields);

	const struct field_descriptor_s *fd;
	for (fd=DESCR(bean)->fields; fd->type ;fd++) {
		GVariant *gv = _field_to_gvariant(bean, fd->position);
		EXTRA_ASSERT(gv != NULL);
		g_ptr_array_add(v, gv);
	}

	g_ptr_array_add(v, NULL);
	return (GVariant**) g_ptr_array_free(v, FALSE);
}

static GVariant**
_bean_params_substitute (gpointer bean0, gpointer bean1)
{
	GPtrArray *v = g_ptr_array_sized_new(1 + 2 * DESCR(bean0)->count_fields);

	const struct field_descriptor_s *fd;
	for (fd=DESCR(bean1)->fields; fd->type ;fd++) {
		GVariant *gv = _field_to_gvariant(bean1, fd->position);
		EXTRA_ASSERT(gv != NULL);
		g_ptr_array_add(v, gv);
	}
	for (fd=DESCR(bean0)->fields; fd->type ;fd++) {
		if (fd->pk) {
			GVariant *gv = _field_to_gvariant(bean0, fd->position);
			EXTRA_ASSERT(gv != NULL);
			g_ptr_array_add(v, gv);
		}
	}

	g_ptr_array_add(v, NULL);
	return (GVariant**) g_ptr_array_free(v, FALSE);
}

GError*
_db_insert_bean(sqlite3 *db, gpointer bean)
{
	EXTRA_ASSERT(db != NULL);
	EXTRA_ASSERT(bean != NULL);

	GVariant **params = _bean_params_insert_or_replace (bean);
	GError *err = _db_execute(db, DESCR(bean)->sql_insert,
			DESCR(bean)->sql_insert_len, params);
	gv_freev(params, FALSE);
	return err;
}

GError *
_db_insert_beans_list (sqlite3 *db, GSList *list)
{
	EXTRA_ASSERT(db != NULL);
	GError *err = NULL;
	for (; !err && list ;list=list->next)
		err = _db_insert_bean (db, list->data);
	return err;
}

GError*
_db_substitute_bean(sqlite3 *db, gpointer bean0, gpointer bean1)
{
	EXTRA_ASSERT(db != NULL);
	EXTRA_ASSERT(bean0 != NULL);
	EXTRA_ASSERT(bean1 != NULL);
	EXTRA_ASSERT(DESCR(bean0) == DESCR(bean1));

	/* an UPDATE query with the form '... SET [all] WHERE [pk]' */
	GVariant **params = _bean_params_substitute(bean0, bean1);
	GError *err = _db_execute(db,
			DESCR(bean0)->sql_substitute, DESCR(bean0)->sql_substitute_len,
			params);
	gv_freev(params, FALSE);

	if (!err) {
		if (0 == sqlite3_changes(db))
			err = NEWERROR(CODE_CONTENT_NOTFOUND, "bean not found");
	}
	return err;
}

GError*
_db_save_bean(sqlite3 *db, gpointer bean)
{
	EXTRA_ASSERT(db != NULL);
	EXTRA_ASSERT(bean != NULL);

	/* an UPDATE query with the form '... SET [non-pk] WHERE [pk]' */
	GError *err = NULL;
	GVariant **params = NULL;
	if (HDR(bean)->flags & BEAN_FLAG_TRANSIENT) {
		params = _bean_params_insert_or_replace (bean);
		err = _db_execute(db, DESCR(bean)->sql_replace,
				DESCR(bean)->sql_replace_len, params);
	} else {
		params = _bean_params_update (bean);
		err = _db_execute(db, DESCR(bean)->sql_update,
				DESCR(bean)->sql_update_len, params);
	}

	gv_freev(params, FALSE);
	return err;
}

GError*
_db_save_beans_list(sqlite3 *db, GSList *list)
{
	EXTRA_ASSERT(db != NULL);
	GError *err = NULL;
	for (; !err && list ;list=list->next)
		err = _db_save_bean(db, list->data);
	return err;
}
