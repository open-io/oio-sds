#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "m2v2"
#endif

#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

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
		base = g_string_sized_new(0);
	if (base != gstr) {
		g_string_set_size(base, 0);
		g_string_append_len(base, gstr->str, gstr->len);
	}
	return base;
}

static void
_gstr_randomize(GRand *r, GString *gstr)
{
	gint i, max;

	g_string_set_size(gstr, 0);
	max = g_rand_int_range(r, 1, 15);
	for (i=0; i<max ; i++) {
		guint32 u32 = g_rand_int_range(r, 0, sizeof(random_chars)-1);
		g_string_append_c(gstr, random_chars[u32]);
	}
}

static void
_gba_randomize(GRand *r, GByteArray *gba)
{
	gint i, max;

	g_byte_array_set_size(gba, 0);
	max = g_rand_int_range(r, 1, 15);
	for (i=0; i<max ; i+=4) {
		guint32 u32 = g_rand_int(r);
		g_byte_array_append(gba, (guint8*)&u32, sizeof(u32));
	}
	g_byte_array_set_size(gba, max);
}

static GByteArray *
_gba_assign(GByteArray *base, GByteArray *gba)
{
	if (!base)
		base = g_byte_array_new();
	if (base != gba) {
		g_byte_array_set_size(base, 0);
		g_byte_array_append(base, gba->data, gba->len);
	}
	return base;
}

GVariant*
_gba_to_gvariant(GByteArray *gba)
{
	guint8 *b;
	size_t i, max;

	GVariantBuilder *builder = g_variant_builder_new(G_VARIANT_TYPE("ay"));
	for (b=gba->data,max=gba->len,i=0; i<max ;i++)
		g_variant_builder_add_value(builder, g_variant_new_byte(b[i]));
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
		gstr = g_string_sized_new(3 * DESCR(bean)->count_fields);

	for (count=0,fd=DESCR(bean)->fields; fd->name ;fd++) {
		if (pk_only && !fd->pk)
			continue;
		if (count)
			g_string_append(gstr, " AND ");
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
	register int rc;
	gsize slen = 0;
	const gchar *s;

	switch (*((gchar*)g_variant_get_type(p))) {
		case 'b':
			rc = sqlite3_bind_int64(stmt, pos, g_variant_get_boolean(p));
			g_assert(rc == SQLITE_OK);
			return NULL;
		case 'i':
			rc = sqlite3_bind_int64(stmt, pos, g_variant_get_int32(p));
			g_assert(rc == SQLITE_OK);
			return NULL;
		case 'n':
			rc = sqlite3_bind_int64(stmt, pos, g_variant_get_int16(p));
			g_assert(rc == SQLITE_OK);
			return NULL;
		case 'q':
			rc = sqlite3_bind_int64(stmt, pos, g_variant_get_uint16(p));
			g_assert(rc == SQLITE_OK);
			return NULL;
		case 's': 
			s = g_variant_get_string(p, &slen);
			rc = sqlite3_bind_text(stmt, pos, s, slen, NULL);
			g_assert(rc == SQLITE_OK);
			return NULL;
		case 't':
			rc = sqlite3_bind_int64(stmt, pos, g_variant_get_uint64(p));
			g_assert(rc == SQLITE_OK);
			return NULL;
		case 'u':
			rc = sqlite3_bind_int64(stmt, pos, g_variant_get_uint32(p));
			g_assert(rc == SQLITE_OK);
			return NULL;
		case 'x':
			rc = sqlite3_bind_int64(stmt, pos, g_variant_get_int64(p));
			g_assert(rc == SQLITE_OK);
			return NULL;
		case 'y':
			rc = sqlite3_bind_int64(stmt, pos, g_variant_get_byte(p));
			g_assert(rc == SQLITE_OK);
			return NULL;
		/* XXX TODO manage the G_VARIANT_UNIT associtaed to NULL'd fields */
		default:
			return NEWERROR(400, "Unexpected parameter at position %d ('%s')",
					pos, (gchar*)g_variant_get_type(p));
	}
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

	return NEWERROR(400, "Unexpected parameter at position %d (type '%s')",
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
		return NEWERROR(500, "Bad parameters : %u expected, %u received",
				count_binds, count_params);

	for (i=1; (p=*params) ;i++,params++) {
		GError *err = _stmt_apply_GV_parameter(stmt, i, p);
		if (NULL != err)
			return err;
	}

	return NULL;
}

static GError *
_db_prepare_statement(sqlite3 *db, const gchar *sql, sqlite3_stmt **result)
{
	gint rc;
	sqlite3_stmt *stmt = NULL;

	sqlite3_prepare_debug(rc, db, sql, -1, &stmt, NULL);

	if (rc != SQLITE_OK && rc != SQLITE_ROW)
		return M2_SQLITE_GERROR(db,rc);
	g_assert(stmt != NULL);

	*result = stmt;
	return NULL;
}

static GError*
_db_execute(sqlite3 *db, const gchar *query, GVariant **params)
{
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	gint rc;

	err = _db_prepare_statement(db, query, &stmt);
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

	for (fd=descr->fields; fd->name ;fd++) {
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

	g_assert(descr != NULL);
	g_assert(db != NULL);
	g_assert(params != NULL);
	g_assert(cb != NULL);

	if (!clause || !*clause)
		err = _db_prepare_statement(db, descr->sql_select, &stmt);
	else {
		gchar *sql = g_strconcat(descr->sql_select, " WHERE ", clause, NULL);
		err = _db_prepare_statement(db, sql, &stmt);
		g_free(sql);
	}

	if (NULL != err) {
		g_prefix_error(&err, "Prepare error: ");
		return err;
	}

	if (!(err = _stmt_apply_GV_parameters(stmt, params))) {
		while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
			cb(u, _row_to_bean(descr, stmt));
		g_assert(rc == SQLITE_OK || rc == SQLITE_DONE);
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

	g_assert(descr != NULL);
	g_assert(db != NULL);
	g_assert(pcount != NULL);

	if (!clause || !*clause)
		err = _db_prepare_statement(db, descr->sql_count, &stmt);
	else {
		gchar *sql = g_strconcat(descr->sql_count, " WHERE ", clause, NULL);
		err = _db_prepare_statement(db, sql, &stmt);
		g_free(sql);
	}

	if (NULL != err) {
		g_prefix_error(&err, "Prepare error: ");
		return err;
	}

	if (!(err = _stmt_apply_GV_parameters(stmt, params))) {
		while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
			*pcount = sqlite3_column_int64(stmt, 0);
		}
		g_assert(rc == SQLITE_OK || rc == SQLITE_DONE);
	}

	sqlite3_finalize(stmt);
	stmt = NULL;
	return err;
}

/* DELETE ------------------------------------------------------------------- */

static gchar *
_bean_query_DELETE(gpointer bean)
{
	GString *gstr = g_string_new("");
	g_string_printf(gstr, "DELETE FROM %s WHERE ", DESCR(bean)->sql_name);
	return g_string_free(_bean_clause(bean, gstr, TRUE), FALSE);
}

GError*
_db_delete_bean(sqlite3 *db, gpointer bean)
{
	GVariant** _params_delete() {
		const struct field_descriptor_s *fd;
		GPtrArray *v;

		v = g_ptr_array_sized_new(DESCR(bean)->count_fields);
		for (fd=DESCR(bean)->fields; fd->name ;fd++) {
			if (!fd->pk)
				continue;
			g_ptr_array_add(v, _field_to_gvariant(bean, fd->position));
		}

		g_ptr_array_add(v, NULL);
		return (GVariant**) g_ptr_array_free(v, FALSE);
	}

	gchar *sql;
	GVariant **params;
	GError *err;

	sql = _bean_query_DELETE(bean);
	params = _params_delete();
	err = _db_execute(db, sql, params);
	gv_freev(params, FALSE);
	g_free(sql);

	return err;
}

GError*
_db_delete(const struct bean_descriptor_s *descr, sqlite3 *db,
		const gchar *clause, GVariant **params)
{
	gchar *sql;
	GError *err;

	sql = g_strdup_printf("DELETE FROM %s WHERE %s", descr->sql_name, clause);
	err = _db_execute(db, sql, params);
	g_free(sql);

	return err;
}


/* REPLACE ------------------------------------------------------------------ */

GError*
_db_save_bean(sqlite3 *db, gpointer bean)
{
	/* an UPDATE query has the form '... SET [non-pk] WHERE [pk]' */
	GVariant** _params_update() {
		const struct field_descriptor_s *fd;
		GPtrArray *v;
		GVariant *gv;

		v = g_ptr_array_sized_new(1 + DESCR(bean)->count_fields);
		for (fd=DESCR(bean)->fields; fd->name ;fd++) {
			if (!fd->pk) {
				gv = _field_to_gvariant(bean, fd->position);
				EXTRA_ASSERT(gv != NULL);
				g_ptr_array_add(v, gv);
			}
		}
		for (fd=DESCR(bean)->fields; fd->name ;fd++) {
			if (fd->pk) {
				gv = _field_to_gvariant(bean, fd->position);
				EXTRA_ASSERT(gv != NULL);
				g_ptr_array_add(v, gv);
			}
		}

		g_ptr_array_add(v, NULL);
		return (GVariant**) g_ptr_array_free(v, FALSE);
	}

	/* a REPLACE query sets all the fields following their declaration order */
	GVariant** _params_replace() {
		const struct field_descriptor_s *fd;
		GPtrArray *v;

		v = g_ptr_array_sized_new(1 + DESCR(bean)->count_fields);
		for (fd=DESCR(bean)->fields; fd->name ;fd++)
			g_ptr_array_add(v, _field_to_gvariant(bean, fd->position));

		g_ptr_array_add(v, NULL);
		return (GVariant**) g_ptr_array_free(v, FALSE);
	}

	GError *err;
	GVariant **params = NULL;

	g_assert(db != NULL);
	g_assert(bean != NULL);

	if (HDR(bean)->flags & BEAN_FLAG_TRANSIENT) {
		params = _params_replace();
		err = _db_execute(db, DESCR(bean)->sql_replace, params);
	}
	else {
		params = _params_update();
		err = _db_execute(db, DESCR(bean)->sql_update, params);
	}

	gv_freev(params, FALSE);
	return err;
}

GError*
_db_save_beans_list(sqlite3 *db, GSList *list)
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

GError*
_db_save_beans_array(sqlite3 *src, GPtrArray *tmp)
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

/* -------------------------------------------------------------------------- */

void
_bean_clean(gpointer bean)
{
	size_t offset_fields;
	const struct field_descriptor_s *fd;

	if (!bean)
		return;

	offset_fields = DESCR(bean)->offset_fields;
	for (fd=DESCR(bean)->fields; fd->name ;fd++) {
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
		if (!p)
			continue;
		g_ptr_array_remove_index_fast(v, 0);
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
	}
	g_slist_free(v);
}

/* -------------------------------------------------------------------------- */

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
	GString *gsql = g_string_new("");
	for (count=0,fkf=fkf0; fkf->name ;fkf++) {
		if (count++)
			g_string_append(gsql, " AND ");
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
_db_get_FK_by_name(gpointer bean, const gchar *name, sqlite3 *db,
		on_bean_f cb, gpointer u)
{
	const struct fk_descriptor_s *fk;

	g_assert(name != NULL);
	g_assert(bean != NULL);
	g_assert(db != NULL);
	g_assert(cb != NULL);

	for (fk=DESCR(bean)->fk; fk->name ;fk++) {
		if (!g_ascii_strcasecmp(fk->name, name)) {
			g_assert(DESCR(bean) == fk->src || DESCR(bean) == fk->dst);
			if (DESCR(bean) == fk->src)
				return _db_get_FK(bean, fk->dst_fields, fk->dst,
						fk->src_fields, db, cb, u);
			if (DESCR(bean) == fk->dst)
				return _db_get_FK(bean, fk->src_fields, fk->src,
						fk->dst_fields, db, cb, u);
		}
	}

	g_assert_not_reached();
	return NEWERROR(500, "BUG"); /* makes the compilers happy */
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
	GString *gsql = g_string_new("");
	for (count=0,fkf=fkf0; fkf->name ;fkf++) {
		if (count++)
			g_string_append(gsql, " AND ");
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

	g_assert(name != NULL);
	g_assert(bean != NULL);
	g_assert(pcount != NULL);

	for (fk=DESCR(bean)->fk; fk->name ;fk++) {
		if (!g_ascii_strcasecmp(fk->name, name)) {
			g_assert(DESCR(bean) == fk->src || DESCR(bean) == fk->dst);
			if (DESCR(bean) == fk->src)
				return _db_count_FK(bean, fk->dst_fields, fk->dst,
						fk->src_fields, db, pcount);
			if (DESCR(bean) == fk->dst)
				return _db_count_FK(bean, fk->src_fields, fk->src,
						fk->dst_fields, db, pcount);
		}
	}

	g_assert_not_reached();
	return NEWERROR(500, "BUG"); /* makes the compilers happy */
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
	g_assert(gpa != NULL);
	g_assert(bean != NULL);
	g_ptr_array_add((GPtrArray*)gpa, bean);
}

/* -------------------------------------------------------------------------- */

GString*
_bean_debug(GString *gstr, gpointer bean)
{
	const struct field_descriptor_s *fd;

	if (!gstr)
		gstr = g_string_new("");

	g_string_append_printf(gstr, "<%s:%p>(", DESCR(bean)->name, bean);

	for (fd=DESCR(bean)->fields; fd->name ;fd++) {
		register gpointer pf = FIELD(bean, fd->position);
		g_assert(pf != NULL);

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
					g_string_append(gstr, "\", ");
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
_bean_randomize(gpointer bean, gboolean avoid_pk)
{
	const struct field_descriptor_s *fd;
	GRand *r = g_rand_new();

	g_assert(bean != NULL);
	HDR(bean)->flags = BEAN_FLAG_DIRTY | (avoid_pk?0:BEAN_FLAG_TRANSIENT);

	for (fd=DESCR(bean)->fields; fd->name ;fd++) {
		register gpointer pf = FIELD(bean, fd->position);
		g_assert(pf != NULL);

		if (fd->pk && avoid_pk)
			continue;

		switch (fd->type) {
			case FT_BOOL:
				*((gboolean*)pf) = g_rand_int(r);
				break;
			case FT_INT:
				*((gint64*)pf) = g_rand_int(r);
				break;
			case FT_REAL:
				*((gdouble*)pf) = g_rand_double(r);
				break;
			case FT_TEXT:
				_gstr_randomize(r, GSTR(pf));
				break;
			case FT_BLOB:
				_gba_randomize(r, GBA(pf));
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
	g_assert(bean != NULL);
	return DESCR(bean)->name;
}

gchar **
_bean_get_FK_names(gpointer bean)
{
	g_assert(bean != NULL);
	return DESCR(bean)->fk_names;
}

gpointer
_bean_create(const struct bean_descriptor_s *descr)
{
	const struct field_descriptor_s *fd;
	gpointer result;

	g_assert(descr != NULL);
	result = g_malloc0(descr->struct_size);
	HDR(result)->descr = descr;
	HDR(result)->flags = BEAN_FLAG_TRANSIENT|BEAN_FLAG_DIRTY;

	for (fd=descr->fields; fd->name ;fd++) {
		register gpointer pf = FIELD(result, fd->position);
		g_assert(pf != NULL);

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

	g_assert(bean != NULL);
	g_assert(fkname != NULL);
	src_descr = DESCR(bean);

	inline gpointer _build(struct fk_field_s *f0, struct fk_field_s *f1) {
		gpointer res = _bean_create(dst_descr);
		for (; f0->i >= 0 && f1->i >=0 ;f0++,f1++) {
			const struct field_descriptor_s *fd0, *fd1;
			register gpointer pf0, pf1;

			fd0 = src_descr->fields + f0->i;
			fd1 = dst_descr->fields + f1->i;
			g_assert(fd0->type == fd1->type);

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

	for (fk=DESCR(bean)->fk; fk->name ;fk++) {
		if (!g_ascii_strcasecmp(fk->name, fkname)) {
			g_assert(DESCR(bean) == fk->src || DESCR(bean) == fk->dst);
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
	g_assert(bean != NULL);
	gpointer copy = _bean_create(DESCR(bean));
	for (fd=DESCR(bean)->fields; fd->name ;fd++) {
		if (_bean_has_field(bean, fd->position)) {
			_bean_set_field_value(copy, fd->position,
					FIELD(bean, fd->position));
		}
	}
	return copy;
}

static GChecksum*
_unique_random_SHA256(void)
{
	static guint64 seq = 0;
	struct {
		time_t now;
		pid_t pid, ppid;
		uid_t uid;
		gid_t gid;
		guint64 seq;
		long r[4];
		gchar hostname[128];
	} bulk;

	memset(&bulk, 0, sizeof(bulk));
	bulk.now = time(0);
	bulk.pid = getpid();
	bulk.ppid = getppid();
	bulk.uid = geteuid();
	bulk.gid = getegid();
	bulk.seq = ++seq;
	bulk.r[0] = random();
	bulk.r[1] = random();
	bulk.r[2] = random();
	bulk.r[3] = random();
	gethostname(bulk.hostname, sizeof(bulk.hostname));

	GChecksum *h = g_checksum_new(G_CHECKSUM_SHA256);
	g_checksum_update(h, (guint8*)&bulk, sizeof(bulk));
	return h;
}

gsize
SHA256_randomized_buffer(guint8 *d, gsize dlen)
{
	GChecksum *h = _unique_random_SHA256();
	g_checksum_get_digest(h, d, &dlen);
	g_checksum_free(h);
	return dlen;
}

gsize
SHA256_randomized_string(gchar *d, gsize dlen)
{
	const gchar *hexa;
	gsize s;
	GChecksum *h;

	h = _unique_random_SHA256();
	hexa = g_checksum_get_string(h);
	EXTRA_ASSERT(strlen(hexa) == 64);
	s = g_strlcpy(d, hexa, dlen);
	for (; *d ;d++)
		*d = g_ascii_toupper(*d);
	g_checksum_free(h);
	return MIN(s,dlen);
}

