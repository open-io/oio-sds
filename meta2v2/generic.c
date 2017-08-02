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

#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>
#include <glib.h>

#include <metautils/lib/metautils.h>
#include <meta2v2/generic.h>
#include <sqliterepo/sqliterepo.h>

/* GVariant utils ---------------------------------------------------------- */

static gchar random_chars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789"
	",?;.:!*$%#+-[](){}/\\";

static GString *
_gstr_assign(GString *base, GString *gstr)
{
	if (!base)
		base = g_string_sized_new(gstr ? gstr->len : 8);
	if (base != gstr) {
		g_string_set_size(base, 0);
		g_string_append_len(base, gstr->str, gstr->len);
	}
	return base;
}

static void
_gstr_randomize(GString *gstr)
{
	g_string_set_size(gstr, oio_ext_rand_int_range(1, 17));
	oio_str_randomize(gstr->str, gstr->len, random_chars);
}

static void
_gba_randomize(GByteArray *gba)
{
	g_byte_array_set_size(gba, oio_ext_rand_int_range(1, 19));
	oio_buf_randomize (gba->data, gba->len);
}

static GByteArray *
_gba_assign(GByteArray *base, GByteArray *gba)
{
	if (!base)
		base = g_byte_array_sized_new(gba ? gba->len : 8);
	if (base != gba) {
		g_byte_array_set_size(base, 0);
		g_byte_array_append(base, gba->data, gba->len);
	}
	return base;
}

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
	const guint8 *b8 = b;

	GVariantBuilder *builder = g_variant_builder_new(G_VARIANT_TYPE("ay"));
	for (gsize i=0; i<max ;i++)
		g_variant_builder_add_value(builder, g_variant_new_byte(b8[i]));
	GVariant *result = g_variant_builder_end(builder);
	g_variant_builder_unref(builder);
	return result;
}

/* GVariant utils ---------------------------------------------------------- */

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

/* SQLite/Bean utils ------------------------------------------------------- */

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
#if 0
		GRID_TRACE2("SQL column[%d,%d/%s,%s] field[%d,%ld,%d/%s,%s]",
				col,
				sqlite3_column_type(stmt, col),
				sqlite_strtype(sqlite3_column_type(stmt, col)),
				sqlite3_column_name(stmt, col),
				fd->position,
				fd->offset,
				fd->type,
				bean_strtype(fd->type),
				fd->name);
#endif
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

/* -------------------------------------------------------------------------- */

void
_bean_clean(gpointer bean)
{
	size_t offset_fields;
	const struct field_descriptor_s *fd;

	if (!bean)
		return;

	offset_fields = DESCR(bean)->offset_fields;
	for (fd=DESCR(bean)->fields; fd->type ;fd++) {
		gpointer pf = ((guint8*)bean) + offset_fields + fd->offset;
		if (!*((gpointer*)pf))
			continue;
		switch (fd->type) {
			case FT_BOOL:
			case FT_INT:
			case FT_REAL:
				break;
			case FT_TEXT:
				g_string_free(GSTR(pf), TRUE);
				break;
			case FT_BLOB:
				g_byte_array_free(*((GByteArray**)pf), TRUE);
				break;
			default:
				g_assert_not_reached();
				break;
		}
	}

	memset(bean, 0, DESCR(bean)->struct_size);
	g_free(bean);
}

void
_bean_cleanv(gpointer *beanv)
{
	gpointer *pb;

	if (!beanv)
		return;
	for (pb = beanv; *pb ;pb++) {
		_bean_clean(*pb);
		*pb = NULL;
	}
	g_free(beanv);
}

void
_bean_cleanv2(GPtrArray *v)
{
	if (!v)
		return;
	while (v->len) {
		gpointer p = v->pdata[0];
		v->pdata[0] = NULL;
		g_ptr_array_remove_index_fast(v, 0);
		if (p)
			_bean_clean(p);
	}
	g_ptr_array_free(v, TRUE);
}

void
_bean_cleanl2(GSList *v)
{
	GSList *l;

	if (!v)
		return;
	for (l=v; l ;l=l->next) {
		_bean_clean(l->data);
		l->data = NULL;
	}
	g_slist_free(v);
}

/* -------------------------------------------------------------------------- */

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

void
_bean_buffer_cb(gpointer gpa, gpointer bean)
{
	EXTRA_ASSERT(gpa != NULL);
	EXTRA_ASSERT(bean != NULL);
	g_ptr_array_add((GPtrArray*)gpa, bean);
}

void
_bean_list_cb(gpointer plist, gpointer bean)
{
	EXTRA_ASSERT(plist != NULL);
	EXTRA_ASSERT(bean != NULL);
	*((GSList**)plist) = g_slist_prepend (*((GSList**)plist), bean);
}

/* -------------------------------------------------------------------------- */

GString*
_bean_debug(GString *gstr, gpointer bean)
{
	if (!gstr)
		gstr = g_string_sized_new(256);

	g_string_append_printf(gstr, "<%s:%p>(", DESCR(bean)->name, bean);

	const struct field_descriptor_s *fd;
	for (fd=DESCR(bean)->fields; fd->type ;fd++) {
		register gpointer pf = FIELD(bean, fd->position);
		EXTRA_ASSERT(pf != NULL);

		switch (fd->type) {
			case FT_BOOL:
				g_string_append_printf(gstr, "%s:%d, ",
						fd->name, *((gboolean*)pf));
				continue;
			case FT_INT:
				g_string_append_printf(gstr, "%s:%"G_GINT64_FORMAT", ",
						fd->name, *((gint64*)pf));
				continue;
			case FT_REAL:
				g_string_append_printf(gstr, "%s:%f, ",
						fd->name, *((gdouble*)pf));
				continue;
			case FT_TEXT:
				if (!*((gpointer*)pf))
					g_string_append_printf(gstr, "%s:NULL, ", fd->name);
				else
					g_string_append_printf(gstr, "%s:\"%s\", ",
							fd->name, GSTR(pf)->str);
				continue;
			case FT_BLOB:
				if (!*((gpointer*)pf))
					g_string_append_printf(gstr, "%s:NULL, ", fd->name);
				else {
					g_string_append_printf(gstr, "%s:0x\"", fd->name);
					metautils_gba_to_hexgstr(gstr, GBA(pf));
					g_string_append_static(gstr, "\", ");
				}
				continue;
			default:
				g_assert_not_reached();
				break;
		}
	}
	g_string_append_c(gstr, ')');

	return gstr;
}

void
_bean_debugl2 (const char *tag, GSList *beans)
{
	if (!GRID_DEBUG_ENABLED())
		return;
	GString *gs = g_string_sized_new(512);
	for (; beans ;beans=beans->next) {
		g_string_set_size (gs, 0);
		gs = _bean_debug (gs, beans->data);
		GRID_DEBUG ("%s %s", tag, gs->str);
	}
	g_string_free (gs, TRUE);
}

void
_bean_randomize(gpointer bean, gboolean avoid_pk)
{
	GRand *r = oio_ext_local_prng ();
	const struct field_descriptor_s *fd;

	EXTRA_ASSERT(bean != NULL);
	HDR(bean)->flags = BEAN_FLAG_DIRTY | (avoid_pk?0:BEAN_FLAG_TRANSIENT);

	for (fd = DESCR(bean)->fields; fd->type != FT_NONE; fd++) {
		register gpointer pf = FIELD(bean, fd->position);
		EXTRA_ASSERT(pf != NULL);

		if (fd->pk && avoid_pk)
			continue;

		switch (fd->type) {
			case FT_BOOL:
				*((gboolean*)pf) = g_rand_boolean(r);
				break;
			case FT_INT:
				*((gint64*)pf) = g_rand_int(r);
				break;
			case FT_REAL:
				*((gdouble*)pf) = g_rand_double(r);
				break;
			case FT_TEXT:
				_gstr_randomize(GSTR(pf));
				break;
			case FT_BLOB:
				_gba_randomize(GBA(pf));
				break;
			default:
				g_assert_not_reached();
				break;
		}
	}
}

const gchar *
_bean_get_typename(gpointer bean)
{
	EXTRA_ASSERT(bean != NULL);
	return DESCR(bean)->name;
}

gchar **
_bean_get_FK_names(gpointer bean)
{
	EXTRA_ASSERT(bean != NULL);
	return DESCR(bean)->fk_names;
}

gpointer
_bean_create(const struct bean_descriptor_s *descr)
{
	const struct field_descriptor_s *fd;
	gpointer result;

	EXTRA_ASSERT(descr != NULL);
	result = g_malloc0(descr->struct_size);
	HDR(result)->descr = descr;
	HDR(result)->flags = BEAN_FLAG_TRANSIENT|BEAN_FLAG_DIRTY;

	for (fd=descr->fields; fd->type ;fd++) {
		register gpointer pf = FIELD(result, fd->position);
		EXTRA_ASSERT(pf != NULL);

		switch (fd->type) {
			case FT_BOOL:
			case FT_INT:
			case FT_REAL:
				break;
			case FT_TEXT:
				GSTR(pf) = g_string_sized_new(8);
				break;
			case FT_BLOB:
				GBA(pf) = g_byte_array_sized_new(8);
				break;
			default:
				g_assert_not_reached();
				break;
		}
	}

	return result;
}

gpointer
_bean_create_child(gpointer bean, const gchar *fkname)
{
	const struct fk_descriptor_s *fk;
	const struct bean_descriptor_s *src_descr, *dst_descr;

	EXTRA_ASSERT(bean != NULL);
	EXTRA_ASSERT(fkname != NULL);
	src_descr = DESCR(bean);

	inline gpointer _build(struct fk_field_s *f0, struct fk_field_s *f1) {
		gpointer res = _bean_create(dst_descr);
		for (; f0->i >= 0 && f1->i >=0 ;f0++,f1++) {
			register gpointer pf0, pf1;

			const struct field_descriptor_s *fd0 = src_descr->fields + f0->i;
#ifdef HAVE_EXTRA_ASSERT
			const struct field_descriptor_s *fd1 = dst_descr->fields + f1->i;
			EXTRA_ASSERT(fd0->type == fd1->type);
#endif

			pf0 = FIELD(bean, f0->i);
			pf1 = FIELD(res, f1->i);
			switch (fd0->type) {
				case FT_BOOL:
					*((gboolean*)pf1) = *((gboolean*)pf0);
					break;
				case FT_INT:
					*((gint64*)pf1) = *((gint64*)pf0);
					break;
				case FT_REAL:
					*((gdouble*)pf1) = *((gdouble*)pf0);
					break;
				case FT_TEXT:
					GSTR(pf1) = _gstr_assign(GSTR(pf1), GSTR(pf0));
					break;
				case FT_BLOB:
					GBA(pf1) = _gba_assign(GBA(pf1), GBA(pf0));
					break;
				default:
					g_assert_not_reached();
					break;
			}
		}
		return res;
	}

	for (fk=DESCR(bean)->fk; fk->src ;fk++) {
		if (!strcmp(fk->name, fkname)) {
			EXTRA_ASSERT(DESCR(bean) == fk->src || DESCR(bean) == fk->dst);
			if (DESCR(bean) == fk->src) {
				dst_descr = fk->dst;
				return _build(fk->src_fields, fk->dst_fields);
			}
			if (DESCR(bean) == fk->dst) {
				dst_descr = fk->src;
				return _build(fk->dst_fields, fk->src_fields);
			}
		}
	}

	g_assert_not_reached();
	return NULL;
}

void
_bean_set_field_value(gpointer bean, guint pos, gpointer pv)
{
	const struct field_descriptor_s *fd;
	register gpointer pf;

	_bean_set_field(bean, pos);
	pf = FIELD(bean, pos);
	fd = DESCR(bean)->fields + pos;
	HDR(bean)->flags |= BEAN_FLAG_DIRTY;

	switch (fd->type) {
		case FT_BOOL:
			*((gboolean*)pf) = *((gboolean*)pv);
			return;
		case FT_INT:
			*((gint64*)pf) = *((gint64*)pv);
			return;
		case FT_REAL:
			*((gdouble*)pf) = *((gdouble*)pv);
			return;
		case FT_TEXT:
			GSTR(pf) = _gstr_assign(GSTR(pf), GSTR(pv));
			return;
		case FT_BLOB:
			GBA(pf) = _gba_assign(GBA(pf), GBA(pv));
			return;
		default:
			g_assert_not_reached();
			return;
	}
}

gpointer
_bean_dup(gpointer bean)
{
	const struct field_descriptor_s *fd;
	EXTRA_ASSERT(bean != NULL);
	gpointer copy = _bean_create(DESCR(bean));
	for (fd=DESCR(bean)->fields; fd->type ;fd++) {
		if (_bean_has_field(bean, fd->position)) {
			_bean_set_field_value(copy, fd->position,
					FIELD(bean, fd->position));
		}
	}
	return copy;
}

gint
_bean_compare_kind (gconstpointer b0, gconstpointer b1)
{
	if (!b0 && !b1) return 0;
	if (!b0) return 1;
	if (!b1) return -1;
	return DESCR(b1)->order - DESCR(b0)->order;
}

