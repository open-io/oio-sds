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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.sqlx.disp"
#endif

#include <glib.h>
#include <sqlite3.h>

#include "../metautils/lib/metautils.h"
#include "../metautils/lib/metacomm.h"
#include "../server/transport_gridd.h"

#include "./internals.h"
#include "./version.h"
#include "./sqliterepo.h"
#include "./sqlx_remote.h"
#include "./gridd_client.h"
#include "./replication_dispatcher.h"

#include <RowFieldValue.h>
#include <RowField.h>
#include <RowFieldSequence.h>
#include <Row.h>
#include <RowSet.h>
#include <RowName.h>
#include <TableHeader.h>
#include <Table.h>
#include <TableSequence.h>

#include <asn_codecs.h>
#include <ber_decoder.h>

static GQuark gquark_log = 0;

#define EXTRACT_FLAG(Name,Flag) do { \
	err = message_extract_flag(reply->request, Name, FALSE, &(Flag)); \
	if (NULL != err) { \
		reply->send_error(0, err); \
		return TRUE; \
	} \
} while (0)

#define EXTRACT_STRING(Name,Dst) do { \
	err = message_extract_string(reply->request, Name, Dst, sizeof(Dst)); \
	if (NULL != err) { \
		reply->send_error(0, err); \
		return TRUE; \
	} \
} while (0)

#define EXTRACT_CID(CID) do { \
	err = message_extract_cid(reply->request, "CONTAINER_ID", &CID); \
	if (NULL != err) { \
		reply->send_error(0, err); \
		return TRUE; \
	} \
} while (0)

/* ------------------------------------------------------------------------- */

static gchar *
_prepare_statement(Table_t *t)
{
	gint i;
	GString *gstr;

	gstr = g_string_new("REPLACE INTO ");
	g_string_append_len(gstr, (char*)t->name.buf, t->name.size);
	g_string_append(gstr, " (ROWID");
	for (i=0; i < t->header.list.count; i++) {
		RowName_t *r = t->header.list.array[i];
		g_string_append_c(gstr, ',');
		g_string_append_len(gstr, (char*)r->name.buf, r->name.size);
	}
	g_string_append(gstr, ") VALUES (?");
	for (i=0; i < t->header.list.count; i++) {
		g_string_append_len(gstr, ",?", 2);
	}
	g_string_append(gstr, ")");

	return g_string_free(gstr, FALSE);
}

static GError *
replicate_table_updates(struct sqlx_sqlite3_s *sq3, Table_t *table)
{
	gchar *sql;
	gint i, j, rc;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;

	sql = _prepare_statement(table);
	sqlite3_prepare_debug(rc, sq3->db, sql, -1, &stmt, NULL);
	g_free(sql);

	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		return SQLITE_GERROR(sq3->db, rc);

	for (i=0; i<table->rows.list.count; i++) {
		Row_t *row = table->rows.list.array[i];
		if (row->fields && row->fields->list.count > 0) {
			gint64 rowid;

			asn_INTEGER_to_int64(&(row->rowid), &rowid);
			sqlite3_reset(stmt);
			sqlite3_clear_bindings(stmt);

			sqlite3_bind_int64(stmt, 1, rowid);
			/*GRID_TRACE("%d <- %"G_GINT64_FORMAT, 1, rowid);*/

			/* Now apply all the field values */
			for (j=0; j<row->fields->list.count ;j++) {
				int pos = 0;
				long lpos = 0;
				RowField_t *field;

				field = row->fields->list.array[j];
				asn_INTEGER2long(&(field->pos), &lpos);
				pos = lpos + 2;
				switch (field->value.present) {
					case RowFieldValue_PR_NOTHING:
					case RowFieldValue_PR_n:
						sqlite3_bind_null(stmt, pos);
						break;
					case RowFieldValue_PR_i:
						do {
							gint64 i64;
							asn_INTEGER_to_int64(&(field->value.choice.i), &i64);
							sqlite3_bind_int64(stmt, pos, i64);
						} while (0);
						break;
					case RowFieldValue_PR_f:
						do {
							gdouble d;
							asn_REAL2double(&(field->value.choice.f), &d);
							sqlite3_bind_double(stmt, pos, d);
						} while (0);
						break;
					case RowFieldValue_PR_b:
						sqlite3_bind_blob(stmt, pos,
							(char*)field->value.choice.b.buf,
							field->value.choice.b.size,
							NULL);
						break;
					case RowFieldValue_PR_s:
						sqlite3_bind_text(stmt, pos,
							(char*)field->value.choice.s.buf,
							field->value.choice.s.size,
							NULL);
						break;
					default:
						g_assert_not_reached();
				}
			}

			do { rc = sqlite3_step(stmt); } while (rc == SQLITE_ROW);

			if (rc != SQLITE_OK && rc != SQLITE_DONE)
				err = SQLITE_GERROR(sq3->db, rc);
		}
	}

	sqlite3_finalize_debug(rc, stmt);
	return err;
}

static guint
_count_deletes(Table_t *table)
{
	gint i;
	guint count = 0;

	for (i=0; i<table->rows.list.count; i++) {
		Row_t *row = table->rows.list.array[i];
		if (!row->fields || row->fields->list.count <= 0)
			++ count; 
	}

	return count;
}

static GError *
replicate_table_deletes(struct sqlx_sqlite3_s *sq3, Table_t *table)
{
	gchar *sql;
	gint i, rc;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;

	if (!_count_deletes(table)) {
		GRID_DEBUG("No delete to perform on %.*s",
				table->name.size, table->name.buf);
		return NULL;
	}

	sql = g_strdup_printf("DELETE FROM %.*s WHERE ROWID = ?",
			table->name.size, table->name.buf);
	sqlite3_prepare_debug(rc, sq3->db, sql, -1, &stmt, NULL);
	g_free(sql);

	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		return SQLITE_GERROR(sq3->db, rc);

	for (i=0; !err && i<table->rows.list.count; i++) {
		Row_t *row = table->rows.list.array[i];
		if (!row->fields || row->fields->list.count <= 0) {
			gint64 rowid;

			asn_INTEGER_to_int64(&(row->rowid), &rowid);
			sqlite3_reset(stmt);
			sqlite3_clear_bindings(stmt);
			sqlite3_bind_int64(stmt, 1, rowid);

			do { rc = sqlite3_step(stmt); } while (rc == SQLITE_ROW);

			if (rc != SQLITE_OK && rc != SQLITE_DONE)
				err = SQLITE_GERROR(sq3->db, rc);
		}
	}

	sqlite3_finalize_debug(rc, stmt);
	return err;
}

static GError*
_table_name_check(Table_t *table)
{
	static guint8 bad[256];

	if (!bad[1]) { /* lazy init */
		guint8 i = 255;
		do { bad[i] = !g_ascii_isprint(i); } while (i--);
		bad[1] = 1;
		bad[' '] = 1;
		bad[';'] = 1;
		bad[','] = 1;
		bad['\''] = 1;
		bad['\"'] = 1;
	}

	if (!table->name.buf || table->name.size <= 0)
		return g_error_new(gquark_log, 400, "Empty table name");

	do {
		gint i;
		guint8 *b = table->name.buf;
		for (i=0; i<table->name.size ;i++) {
			if (bad[b[i]]) {
				return g_error_new(gquark_log, 400, "Invalid table name");
			}
		}
	} while (0);

	GRID_TRACE("Table name validated size=%u name[%.*s]",
				table->name.size, table->name.size, table->name.buf);
	return NULL;
}

static GError *
replicate_table(struct sqlx_sqlite3_s *sq3, Table_t *table)
{
	GError *err;

	err = _table_name_check(table);
	if (NULL != err) {
		g_prefix_error(&err, "table error: ");
		return err;
	}

	err = replicate_table_deletes(sq3, table);
	if (NULL != err) {
		g_prefix_error(&err, "Error on delete: ");
		return err;
	}

	err = replicate_table_updates(sq3, table);
	if (NULL != err) {
		g_prefix_error(&err, "Error on updates: ");
		return err;
	}

	return NULL;
}

static GError *
_replicate_now(struct sqlx_sqlite3_s *sq3, TableSequence_t *seq)
{
	gint i;
	GError *err = NULL;

	for (i=0; !err && i<seq->list.count ;i++) {
		Table_t *table = seq->list.array[i];
		if (table && (err = replicate_table(sq3, table))) {
			GRID_WARN("Replication failed on table [%.*s]",
					table->name.size, table->name.buf);
		}
	}

	return err;
}

static GError *
replicate_body_manage(struct sqlx_sqlite3_s *sq3, TableSequence_t *seq)
{
	gint rc;
	GError *err = NULL;
	GTree *expected_version, *oldvers;

	if (!seq)
		return g_error_new(gquark_log, 400, "Invalid tables sequence");
	if (seq->list.count <= 0) {
		GRID_DEBUG("Empty tables sequence, nothing to replicate");
		return NULL;
	}

	oldvers = NULL;
	expected_version = version_extract_expected(sq3->versions, seq);
	version_debug("EXPECTED:", expected_version);

	sqlx_exec(sq3->db, "BEGIN");
	err = _replicate_now(sq3, seq);

	if (NULL != err) {
label_rollback:
		rc = sqlx_exec(sq3->db, "ROLLBACK");
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			GRID_WARN("ROLLBACK failed!");
		version_load(sq3, TRUE);
	}
	else {
		oldvers = sq3->versions;
		sq3->versions = NULL;
		version_load(sq3, FALSE);
		version_debug("CURRENT:", sq3->versions);
		
		err = version_validate_diff(sq3->versions, expected_version, NULL);
		if (err != NULL) {
			g_tree_destroy(sq3->versions);
			sq3->versions = oldvers;
			oldvers = NULL;
			goto label_rollback;
		}

		rc = sqlx_exec(sq3->db, "COMMIT");

		if (rc != SQLITE_OK && rc != SQLITE_DONE) {
			err = SQLITE_GERROR(sq3->db, rc);
			g_prefix_error(&err, "COMMIT failed: ");
			g_tree_destroy(sq3->versions);
			sq3->versions = oldvers;
			oldvers = NULL;
			goto label_rollback;
		}
	}

	if (oldvers)
		g_tree_destroy(oldvers);
	if (expected_version)
		g_tree_destroy(expected_version);
	return err;
}

static GError *
replicate_body_parse(struct sqlx_sqlite3_s *sq3, guint8 *body, gsize bodysize)
{
	asn_dec_rval_t rv;
	asn_codec_ctx_t ctx;
	TableSequence_t *seq = NULL;
	GError *err = NULL;

	GRID_TRACE2("%s(%p,%p,%"G_GSIZE_FORMAT")", __FUNCTION__,
			sq3, body, bodysize);

	memset(&ctx, 0, sizeof(ctx));
	ctx.max_stack_size = 512 * 1024;
	rv = ber_decode(&ctx, &asn_DEF_TableSequence, (void**)&seq,
			body, bodysize);
	if (rv.code != RC_OK)
		return g_error_new(gquark_log, 400, "body decoding error");

	err = replicate_body_manage(sq3, seq);
	asn_DEF_TableSequence.free_struct(&asn_DEF_TableSequence, seq, FALSE);
	
	return err;
}

static GError *
_restore(struct sqlx_repository_s *repo, const gchar *base, const gchar *type,
		guint8 *dump, gsize dump_size)
{
	GError *err;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_TRACE2("%s(%p,%s,%s,%p,%"G_GSIZE_FORMAT")", __FUNCTION__,
			repo, base, type, dump, dump_size);

	err = sqlx_repository_open_and_lock(repo, type, base,
				SQLX_OPEN_LOCAL, &sq3, NULL);
	if (NULL != err)
		return err;

	err = sqlx_repository_restore_base(sq3, dump, dump_size);
	if (NULL != err) {
		GRID_TRACE("Restore failed!");
		return err;
	}
	GRID_TRACE("Restore done!");

	sqlx_repository_unlock_and_close_noerror(sq3);
	return NULL;
}

static GError *
_dump(struct sqlx_repository_s *repo, const gchar *base, const gchar *type,
		GByteArray **result)
{
	GByteArray *dump = NULL;
	GError *err;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_TRACE2("%s(%p,%s,%s,%p)", __FUNCTION__, repo, base, type, result);

	err = sqlx_repository_open_and_lock(repo, type, base,
			SQLX_OPEN_LOCAL, &sq3, NULL);
	if (NULL != err)
		return err;

	err = sqlx_repository_dump_base(sq3, &dump);
	if (!err) {
		GRID_TRACE("Dump done!");
		*result = dump;
	}
	else {
		GRID_TRACE("Dump failed!");
		if (dump)
			g_byte_array_free(dump, TRUE);
	}

	sqlx_repository_unlock_and_close_noerror(sq3);
	return err;
}

static GError *
_pipe_from(const gchar *source, struct sqlx_repository_s *repo,
		const gchar *base, const gchar *type)
{
	GError *err;
	struct sqlx_name_s name;
	GByteArray *dump = NULL;

	GRID_TRACE2("%s(%s,%p,%s,%s)", __FUNCTION__, source, repo, base, type);
	name.ns = "";
	name.base = base;
	name.type = type;

	err = peer_dump(source, &name, &dump);
	if (NULL != err)
		return err;

	if (!dump)
		return g_error_new(gquark_log, 500, "No dump generated!");

	err = _restore(repo, base, type, dump->data, dump->len);
	g_byte_array_unref(dump);

	return err;
}

static void
apply_parameters(sqlite3_stmt *stmt, Row_t *row)
{
	gint32 j;
	gint64 i64;
	gdouble d;

	for (j=0; j<row->fields->list.count ;j++) {
		int pos = 0;
		long lpos = 0;
		RowField_t *field;

		field = row->fields->list.array[j];
		asn_INTEGER2long(&(field->pos), &lpos);
		pos = lpos;

		switch (field->value.present) {
			case RowFieldValue_PR_i:
				asn_INTEGER_to_int64(&(field->value.choice.i), &i64);
				sqlite3_bind_int64(stmt, pos, i64);
				GRID_TRACE2("bind(%d,%"G_GINT64_FORMAT")", pos, i64);
				break;
			case RowFieldValue_PR_f:
				asn_REAL2double(&(field->value.choice.f), &d);
				sqlite3_bind_double(stmt, pos, d);
				GRID_TRACE2("bind(%d,%f)", pos, d);
				break;
			case RowFieldValue_PR_b:
				sqlite3_bind_blob(stmt, pos,
						(char*)field->value.choice.b.buf,
						field->value.choice.b.size,
						NULL);
				GRID_TRACE2("bind(%d,blob(%d))", pos, field->value.choice.b.size);
				break;
			case RowFieldValue_PR_s:
				sqlite3_bind_text(stmt, pos,
						(char*)field->value.choice.s.buf,
						field->value.choice.s.size,
						NULL);
				GRID_TRACE2("bind(%d,string(%d))", pos, field->value.choice.s.size);
				break;
			default:
			case RowFieldValue_PR_NOTHING:
				GRID_DEBUG("invalid type to bind, considering NULL");
			case RowFieldValue_PR_n:
				sqlite3_bind_null(stmt, pos);
				GRID_TRACE2("bind(%d,NULL)", pos);
				break;
		}
	}
}

enum query_action_e
{
	QA_READ      = 0x00,
	QA_WRITE     = 0x02,
	QA_SCHEMA    = 0x04,
	QA_BEGIN     = 0x08,
	QA_COMMIT    = 0x10,
	QA_ROLLBACK  = 0x20,
};

static gboolean
_pragma_is_allowed(const gchar *pragma)
{
	static const gchar *allowed_pragmas[] = {
		"table_info", "index_info", "index_list",
		"page_count", "quick_check", "collation_list", 
		"database_list", "freelist_count",
		NULL
	};
	const gchar **p;

	for (p=allowed_pragmas; *p ;p++) {
		if (!g_ascii_strcasecmp(pragma, *p))
			return TRUE;
	}
	
	return FALSE;	
}

enum query_rights_e
{
	QUERY_ERROR  = 0x01,
	QUERY_SCHEMA = 0x02,
	QUERY_WRITE  = 0x04,
	QUERY_TNX    = 0x08,
};

/* Get the kind of actions tried by this request */
static enum query_rights_e
_query_get_rights(struct sqlite3 *h, const gchar *query)
{
	enum query_rights_e rights = 0;

	int authorizer(void *u, int op,
			const char *s1, const char *s2,
			const char *s3, const char *s4)
	{
		(void)u; (void)s1; (void)s2; (void)s3; (void)s4;
		switch (op) {
			case SQLITE_CREATE_INDEX:
			case SQLITE_CREATE_TABLE:
			case SQLITE_ALTER_TABLE:
			case SQLITE_CREATE_TRIGGER:
			case SQLITE_CREATE_VIEW:
			case SQLITE_DROP_TRIGGER:
			case SQLITE_DROP_VIEW:
			case SQLITE_DROP_INDEX:
			case SQLITE_DROP_TABLE:
				sqlite3_set_authorizer(h, NULL, NULL);
				rights |= QUERY_SCHEMA;
				return SQLITE_OK;

			case SQLITE_CREATE_TEMP_INDEX:
			case SQLITE_CREATE_TEMP_TABLE:
			case SQLITE_CREATE_TEMP_TRIGGER:
			case SQLITE_CREATE_TEMP_VIEW:
			case SQLITE_DROP_TEMP_INDEX:
			case SQLITE_DROP_TEMP_TABLE:
			case SQLITE_DROP_TEMP_TRIGGER:
			case SQLITE_DROP_TEMP_VIEW:
				sqlite3_set_authorizer(h, NULL, NULL);
				rights |= QUERY_ERROR;
				return SQLITE_DENY;

			case SQLITE_SELECT:
				sqlite3_set_authorizer(h, NULL, NULL);
			case SQLITE_READ:
				return SQLITE_OK;

			case SQLITE_TRANSACTION:
			case SQLITE_SAVEPOINT:
				sqlite3_set_authorizer(h, NULL, NULL);
				rights |= QUERY_TNX;
				return SQLITE_IGNORE;

			case SQLITE_INSERT:
			case SQLITE_UPDATE:
			case SQLITE_DELETE:
				sqlite3_set_authorizer(h, NULL, NULL);
				rights |= QUERY_WRITE;
				return SQLITE_OK;

			case SQLITE_PRAGMA:
				sqlite3_set_authorizer(h, NULL, NULL);
				if (_pragma_is_allowed(s1)) {
					rights |= QUERY_WRITE;
					return SQLITE_OK;
				}
				rights |= QUERY_ERROR;
				return SQLITE_DENY;

			case SQLITE_REINDEX:
			case SQLITE_ANALYZE:
			case SQLITE_FUNCTION:
				return SQLITE_IGNORE;

			case SQLITE_CREATE_VTABLE:
			case SQLITE_DROP_VTABLE:
			case SQLITE_ATTACH:
			case SQLITE_DETACH:
			case SQLITE_COPY:
			default:
				sqlite3_set_authorizer(h, NULL, NULL);
				rights |= QUERY_ERROR;
				return SQLITE_DENY;
		}
	}

	while (!rights && query && *query) {
		int rc;
		sqlite3_stmt *stmt = NULL;
		const gchar *next = NULL;

		(void) sqlite3_set_authorizer(h, authorizer, NULL);
		sqlite3_prepare_debug(rc, h, query, -1, &stmt, &next);
		sqlite3_set_authorizer(h, NULL, NULL);
		query = next;

		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			rights |= QUERY_ERROR;
		if (stmt)
			(void) sqlite3_finalize(stmt);
	}

	return rights;
}

static void
_table_set_error(Table_t *table, GError *err, int changes)
{
	gint64 status;

	if (table->status) {
		ASN_STRUCT_FREE(asn_DEF_INTEGER, table->status);
		table->status = NULL;
	}
	if (table->statusString) {
		ASN_STRUCT_FREE(asn_DEF_PrintableString, table->statusString);
		table->statusString = NULL;
	}

	if (!err) {
		status = changes;
		GRID_DEBUG("STATUS: %"G_GINT64_FORMAT" %s (changes = %d)", status, "OK", changes);
	}
	else {
		status = - err->code;
		GRID_DEBUG("STATUS: %"G_GINT64_FORMAT" %s", status, err->message);
		table->statusString = OCTET_STRING_new_fromBuf(&asn_DEF_PrintableString, err->message, strlen(err->message));
	}

	table->status = g_malloc0(sizeof(INTEGER_t));
	asn_int64_to_INTEGER(table->status, status);

	if (err)
		g_error_free(err);
}

/**
 * @param sq3
 *
 * @param query
 *
 * @param params input query parameters
 *
 * @param result output query's status, rows (and command)
 * 
 * @param replication_ctx it input, the replication contaxt potentially
 *                        associated to the client session. At output,
 *                        the replication context to be associated to
 *                        the client session.
 * @return
 */
static void
_execute_next_query(struct sqlx_sqlite3_s *sq3, const gchar *query,
		Table_t *params, Table_t *result,
		struct sqlx_repctx_s **replication_ctx,
		gboolean noreal)
{
	GError *err = NULL;
	gint rc = 0;
	sqlite3_stmt *stmt = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	enum query_action_e action = QA_READ;
	int changes = 0;

	int qualifier(void *u, int op,
			const char *s1, const char *s2,
			const char *s3, const char *s4)
	{
		(void)u; (void)s1; (void)s2; (void)s3; (void)s4;
		switch (op) {
			case SQLITE_CREATE_INDEX:
			case SQLITE_CREATE_TABLE:
			case SQLITE_ALTER_TABLE:
			case SQLITE_CREATE_TRIGGER:
			case SQLITE_CREATE_VIEW:
			case SQLITE_DROP_TRIGGER:
			case SQLITE_DROP_VIEW:
			case SQLITE_DROP_INDEX:
			case SQLITE_DROP_TABLE:
				sqlite3_set_authorizer(sq3->db, NULL, NULL);
				action = QA_SCHEMA;
				return SQLITE_OK;

			case SQLITE_CREATE_TEMP_INDEX:
			case SQLITE_CREATE_TEMP_TABLE:
			case SQLITE_CREATE_TEMP_TRIGGER:
			case SQLITE_CREATE_TEMP_VIEW:
			case SQLITE_DROP_TEMP_INDEX:
			case SQLITE_DROP_TEMP_TABLE:
			case SQLITE_DROP_TEMP_TRIGGER:
			case SQLITE_DROP_TEMP_VIEW:
				sqlite3_set_authorizer(sq3->db, NULL, NULL);
				return SQLITE_DENY;

			case SQLITE_READ:
			case SQLITE_SELECT:
				return SQLITE_OK;

			case SQLITE_TRANSACTION:
				sqlite3_set_authorizer(sq3->db, NULL, NULL);
				switch (*s1) {
					case 'B':
					case 'b':
						action = QA_BEGIN;
						return SQLITE_IGNORE;
					case 'C':
					case 'c':
						action = QA_COMMIT;
						return SQLITE_IGNORE;
					case 'R':
					case 'r':
						action = QA_ROLLBACK;
						return SQLITE_IGNORE;
					default:
						return SQLITE_DENY;
				}

			case SQLITE_SAVEPOINT:
				sqlite3_set_authorizer(sq3->db, NULL, NULL);
				return SQLITE_DENY;

			case SQLITE_INSERT:
			case SQLITE_UPDATE:
			case SQLITE_DELETE:
				if (!action)
					action = QA_WRITE;
				return SQLITE_OK;

			case SQLITE_PRAGMA:
				sqlite3_set_authorizer(sq3->db, NULL, NULL);
				if (_pragma_is_allowed(s1))
					return SQLITE_OK;
				if (s2)
					err = g_error_new(gquark_log, 403, "Forbidden PRAGMA %s(%s)", s1, s2);
				else
					err = g_error_new(gquark_log, 403, "Forbidden PRAGMA %s", s1);
				return SQLITE_DENY;

			case SQLITE_REINDEX:
			case SQLITE_ANALYZE:
			case SQLITE_FUNCTION:
			case SQLITE_CREATE_VTABLE:
			case SQLITE_DROP_VTABLE:
			case SQLITE_ATTACH:
			case SQLITE_DETACH:
			case SQLITE_COPY:
			default:
				err = g_error_new(gquark_log, 403, "Forbidden '%s'", sqlite_op2str(op));
				sqlite3_set_authorizer(sq3->db, NULL, NULL);
				return SQLITE_DENY;
		}
	}

	GRID_DEBUG("QUERY : %s", query);

	/* Prepare the request */
	(void) sqlite3_set_authorizer(sq3->db, qualifier, NULL);
	sqlite3_prepare_debug(rc, sq3->db, query, -1, &stmt, NULL);
	(void) sqlite3_set_authorizer(sq3->db, NULL, NULL);

	OCTET_STRING_fromBuf(&(result->name), query, strlen(query));

	if (rc != SQLITE_OK && rc != SQLITE_DONE) {
		if (!err)
			err = SQLITE_GERROR(sq3->db, rc);
		GRID_DEBUG("Invalid statement : [%s]", query);
		_table_set_error(result, err, 0);
		return ;
	}

	if (!stmt) {
		GRID_DEBUG("Empty statement : [%s]", query);
		_table_set_error(result, NULL, 0);
		return ;
	}

	repctx = *replication_ctx;
	GRID_TRACE("ACTION : %X/%i repctx=%p", action, action, repctx);

	/* Manages the need of a replication context, maybe reusing an
	 * existing context. */
	switch (action) {

		case QA_BEGIN:
			if (repctx) { /* error ?! */
				GRID_DEBUG("Unexpected BEGIN");
				break;
			}
			else {
				GRID_DEBUG("Explicit BEGIN");
				sqlite3_finalize_debug(rc, stmt);
				*replication_ctx = repctx = sqlx_transaction_begin(sq3);
				_table_set_error(result, err, 0);
				return ;
			}

		case QA_COMMIT:
			if (!repctx) { /* error ?! */
				GRID_DEBUG("Unexpected COMMIT");
				break;
			}
			else {
				GRID_DEBUG("Explicit COMMIT");
				sqlite3_finalize_debug(rc, stmt);
				err = sqlx_transaction_end(repctx, NULL);
				*replication_ctx = repctx = NULL;
				_table_set_error(result, err, sqlite3_changes(sq3->db));
				return ;
			}

		case QA_ROLLBACK:
			if (!repctx) { /* error ?! */
				GRID_DEBUG("Unexpected ROLLBACK");
				break;
			}
			else {
				GRID_DEBUG("Explicit ROLLBACK");
				sqlite3_finalize_debug(rc, stmt);
				err = sqlx_transaction_end(repctx, g_error_new(gquark_log, 0, "aborted by user"));
				*replication_ctx = repctx = NULL;
				_table_set_error(result, err, sqlite3_changes(sq3->db));
				return ;
			}

		case QA_WRITE:
		case QA_SCHEMA:
			if (repctx) {
				GRID_DEBUG("EXPLICIT COMMIT detected");
			}
			else {
				/* AUTOCOMMIT (no session-related replication context):
				 * ensure there is a replication context */
				GRID_DEBUG("AUTOCOMMIT detected");
				sqlite3_finalize_debug(rc, stmt);
				repctx = sqlx_transaction_begin(sq3);
				sqlite3_prepare_debug(rc, sq3->db, query, -1, &stmt, NULL);
			}
			/* FALLTHROUGH */

		case QA_READ: /* no change */
			break;
	}

	/* Apply the parameters now and really execute the statement */
	if (sqlite3_bind_parameter_count(stmt) > 0) {
		gint32 irow;

		if (params->rows.list.count <= 0)
			GRID_DEBUG("The request expects parameters but no input has been provided");

		for (irow=0; !err && irow < params->rows.list.count ;irow++) {
			if (irow) {
				sqlite3_clear_bindings(stmt);
				sqlite3_reset(stmt);
			}
			apply_parameters(stmt, params->rows.list.array[irow]);
			for (rc = SQLITE_ROW; rc == SQLITE_ROW ;) {
				rc = sqlite3_step(stmt);
				if (rc == SQLITE_ROW) {
					Row_t *rrow = g_malloc0(sizeof(Row_t));
					load_statement(stmt, rrow, result, noreal);
					asn_sequence_add(&(result->rows.list), rrow);
				}
			}
			if (rc != SQLITE_DONE && rc != SQLITE_OK)
				err = SQLITE_GERROR(sq3->db, rc);
		}
	}
	else {

		if (params->rows.list.count > 0)
			GRID_DEBUG("The request does not expects parameters but an input has been provided");

		/* Only one STEP */
		for (rc = SQLITE_ROW; rc == SQLITE_ROW ;) {
			rc = sqlite3_step(stmt);
			if (rc == SQLITE_ROW) {
				Row_t *rrow = g_malloc0(sizeof(Row_t));
				load_statement(stmt, rrow, result, noreal);
				asn_sequence_add(&(result->rows.list), rrow);
			}
		}
		if (rc != SQLITE_DONE && rc != SQLITE_OK)
			err = SQLITE_GERROR(sq3->db, rc);
	}
	
	sqlite3_finalize_debug(rc, stmt);

	if (action == QA_SCHEMA && repctx != NULL)
		sqlx_transaction_notify_huge_changes(repctx);

	changes = sqlite3_changes(sq3->db);

	if (repctx && !*replication_ctx) {
		err = sqlx_transaction_end(repctx, err);
		repctx = NULL;
	}

	_table_set_error(result, err, changes); /* err cleaned inside */
	return ;
}

static void
_abort_tnx_and_close_db(gpointer p)
{
	GError *err;
	struct sqlx_repctx_s *repctx;
	struct sqlx_sqlite3_s *sq3;

	if (!(repctx = p))
		return;
	sq3 = sqlx_transaction_get_base(repctx);
	
	/* Abort the transaction */
	err = sqlx_transaction_end(repctx, g_error_new(gquark_log, 0, "CNX abort"));
	GRID_INFO("Aborted transaction on [%s][%s] : (%d) %s",
			sq3->logical_name, sq3->logical_type,
			err ? err->code : 0, err ? err->message : "no error");
	if (err)
		g_clear_error(&err);

	/* now close the database */
	sqlx_repository_unlock_and_close_noerror(sq3);
}

static gchar *
_table_to_query(Table_t *t)
{
	SQLX_ASSERT(t != NULL);
	return g_strndup((char*)t->name.buf, t->name.size);
}

static GError *
do_query_after_open(struct gridd_reply_ctx_s *reply_ctx, 
		struct sqlx_sqlite3_s *sq3, TableSequence_t *params,
		TableSequence_t *result, gboolean noreal)
{
	gint32 i32;
	GError *err = NULL;
	enum query_rights_e action;

	/* Check this server can manage the request, i.e. if the request contains
	 * write operations or schema changes, we immediately check we are the
	 * master, to redirect the request to another server. */
	for (i32=0; i32 < params->list.count && !err ;i32++) {
		gchar *query;

		query = _table_to_query(params->list.array[i32]);
		action = _query_get_rights(sq3->db, query);
		g_free(query);

		if (0 != action) {
			err = sqlx_repository_status_base(sq3->repo,
					sq3->logical_type, sq3->logical_name);
			if (NULL != err) {
				if (err->code != CODE_REDIRECT)
					g_prefix_error(&err, "Status error: ");
				return err;
			}
			break;
		}
	}

	/* Now execute the batch received */
	for (i32=0; i32 < params->list.count ;i32++) {
		struct sqlx_repctx_s *replication_ctx = NULL;
		struct Table *req, *res;
		gchar *query;

		req = params->list.array[i32];
		res = g_malloc0(sizeof(struct Table));
		query = _table_to_query(req);
		replication_ctx = reply_ctx->get_cnx_data("repctx");
		reply_ctx->forget_cnx_data("repctx");
		_execute_next_query(sq3, query, req, res, &replication_ctx, noreal);
		g_free(query);

		asn_sequence_add(&(result->list), res);
		if (replication_ctx)
			reply_ctx->register_cnx_data("repctx", replication_ctx,
					_abort_tnx_and_close_db);
	}

	return NULL;
}

static GError *
do_query(struct gridd_reply_ctx_s *reply_ctx, sqlx_repository_t *repo,
		const gchar *t, const gchar *n,
		TableSequence_t *params, TableSequence_t *result,
		gboolean noreal)
{
	GError *err;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *replication_ctx;

	/* Maybe is the base still open */
	if (NULL != (replication_ctx = reply_ctx->get_cnx_data("repctx"))) {
		sq3 = sqlx_transaction_get_base(replication_ctx);
		if (strcmp(n, sq3->logical_name) || strcmp(t, sq3->logical_type)) {
			err = g_error_new(gquark_log, 400,
					"Another base is still open [%s].[%s]",
					sq3->logical_name, sq3->logical_type);
			return err;
		}
	}
	else { /* Normal open */
		err = sqlx_repository_open_and_lock(repo, t, n,
				SQLX_OPEN_MASTERSLAVE, &sq3, NULL);
		if (NULL != err) {
			g_prefix_error(&err, "Open/Lock: ");
			return err;
		}
	}

	err = do_query_after_open(reply_ctx, sq3, params, result, noreal);

	/* If a transaction is pending, we do not close the base, but without
	 * a transaction, we can close the base */
	if (!reply_ctx->get_cnx_data("repctx"))
		sqlx_repository_unlock_and_close_noerror(sq3);

	return err;
}

/* ------------------------------------------------------------------------- */

static gboolean
sqlx_dispatch_GETVERS(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GTree *version = NULL;
	GError *err = NULL;
	gchar base[256], type[64];

	(void) ignored;
	EXTRACT_STRING("BASE_NAME", base);
	EXTRACT_STRING("BASE_TYPE", type);
	reply->subject("%s.%s", base, type);

	err = sqlx_repository_open_and_lock(repo, type, base,
			SQLX_OPEN_LOCAL, &sq3, NULL);

	if (NULL != err) {
		g_prefix_error(&err, "Open/lock: ");
		reply->send_error(0, err);
		return TRUE;
	}

	err = sqlx_repository_get_version(sq3, &version);
	if (NULL != err) {
		reply->send_error(0, err);
	}
	else {
		GByteArray *encoded = version_encode(version);
		if (!encoded) {
			err = g_error_new(gquark_log, 500, "Encoding error (version)");
			reply->send_error(0, err);
		}
		else {
			reply->add_body(encoded);
			reply->send_reply(200, "OK");
		}
	}
	
	sqlx_repository_unlock_and_close_noerror(sq3);
	if (version)
		g_tree_destroy(version);
	return TRUE;
}

static gboolean
sqlx_dispatch_REPLICATE(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = NULL;
	gchar base[256], type[64];
	void *b = NULL;
	gsize bsize = 0;

	(void) ignored;
	EXTRACT_STRING("BASE_NAME", base);
	EXTRACT_STRING("BASE_TYPE", type);
	reply->subject("%s.%s", base, type);

	if (0 >= message_get_BODY(reply->request, &b, &bsize, NULL)) {
		err = g_error_new(gquark_log, 400, "missing body");
		reply->send_error(400, err);
		return TRUE;
	}

	reply->send_reply(100, "received");

	/* Starts an election without being an initiator ... because I receive
	 * this request from a master, so an election is already running */
	err = sqlx_repository_use_base(repo, type, base);
	if (NULL != err) {
		reply->send_error(0, err);
		return TRUE;
	}

	/* Open and lock the base */
	err = sqlx_repository_open_and_lock(repo, type, base,
			SQLX_OPEN_LOCAL|SQLX_OPEN_CREATE, &sq3, NULL);

	if (NULL != err) {
		reply->send_error(0, err);
		return TRUE;
	}

	/* Unpack the body from the message, decode it */
	err = replicate_body_parse(sq3, b, bsize);
	if (NULL != err) {
		if (err->code == CODE_PIPEFROM) {
			GError *e0 = sqlx_repository_retore_from_master(sq3);
			if (NULL != e0) {
				GRID_WARN("RESYNC deferral failed: (%d) %s",
						e0->code, e0->message);
				g_clear_error(&e0);
			}
		}

		reply->send_error(0, err);
		err = NULL;
	}
	else
		reply->send_reply(200, "OK");

	sqlx_repository_unlock_and_close_noerror(sq3);

	return TRUE;
}

static gboolean
sqlx_dispatch_STATUS(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored)
{
	GError *err = NULL;
	gchar base[256], type[64];

	(void) ignored;
	EXTRACT_STRING("BASE_NAME", base);
	EXTRACT_STRING("BASE_TYPE", type);
	reply->subject("%s.%s", base, type);

	/* Open and lock the base */
	if (NULL != (err = sqlx_repository_status_base(repo, type, base)))
		reply->send_error(0, err);
	else
		reply->send_reply(200, "MASTER");

	return TRUE;
}

static gboolean
sqlx_dispatch_DESCR(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored)
{
	GError *err = NULL;
	gchar base[256], type[64], descr[512];

	/* Unpack the base name */
	(void) ignored;
	EXTRACT_STRING("BASE_NAME", base);
	EXTRACT_STRING("BASE_TYPE", type);
	reply->subject("%s.%s", base, type);

	/* Open and lock the base */
	memset(descr, 0, sizeof(descr));
	descr[0] = '?';
	sqlx_repository_whatabout(repo, type, base, descr, sizeof(descr));
	reply->add_body(metautils_gba_from_string(descr));
	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
sqlx_dispatch_USE(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored)
{
	GError *err = NULL;
	gchar base[256], type[64];

	(void) ignored;
	EXTRACT_STRING("BASE_NAME", base);
	EXTRACT_STRING("BASE_TYPE", type);
	reply->subject("%s.%s", base, type);

	/* Open and lock the base */
	if (NULL != (err = sqlx_repository_use_base(repo, type, base)))
		reply->send_error(0, err);
	else
		reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
sqlx_dispatch_PIPETO(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored)
{
	GError *err = NULL;
	GByteArray *dump = NULL;
	gchar base[256], type[64], target[256];

	(void) ignored;
	EXTRACT_STRING("BASE_NAME", base);
	EXTRACT_STRING("BASE_TYPE", type);
	EXTRACT_STRING("DST", target);
	reply->subject("%s.%s|%s", base, type, target);

	/* Dump the base in a locked manner */
	err = _dump(repo, base, type, &dump);
	if (NULL != err) {
		g_prefix_error(&err, "Dump failed: ");
		reply->send_error(0, err);
		return TRUE;
	}

	reply->send_reply(100, "Dump done");

	/* forward the dump to the target */
	struct sqlx_name_s n;
	n.base = base;
	n.type = type;
	n.ns = "";

	if (NULL != (err = peer_restore(target, &n, dump->data, dump->len)))
		reply->send_error(500, err);
	else
		reply->send_reply(200, "OK");

	g_byte_array_free(dump, TRUE);
	dump = NULL;
	return TRUE;
}

static gboolean
sqlx_dispatch_DUMP(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored)
{
	GError *err = NULL;
	GByteArray *dump = NULL;
	gchar base[256], type[64];

	(void) ignored;
	EXTRACT_STRING("BASE_NAME", base);
	EXTRACT_STRING("BASE_TYPE", type);
	reply->subject("%s.%s", base, type);

	/* Open and lock the base */
	err = _dump(repo, base, type, &dump);
	if (NULL != err) {
		reply->send_error(0, err);
		return TRUE;
	}

	reply->add_body(dump);
	reply->add_header("format", metautils_gba_from_string("sqlite3"));
	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
sqlx_dispatch_RESTORE(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored)
{
	GError *err;
	gchar base[256], type[64];
	guint8 *dump;
	gsize dump_size;

	(void) ignored;
	EXTRACT_STRING("BASE_NAME", base);
	EXTRACT_STRING("BASE_TYPE", type);
	reply->subject("%s.%s", base, type);

	/* The body is the raw base */
	if (0 >= message_get_BODY(reply->request, (void**)&dump, &dump_size, NULL)) {
		reply->send_error(400, g_error_new(gquark_log, 400, "Missing body"));
		return TRUE;
	}
	if (!dump || dump_size < 1024) {
		reply->send_error(400, g_error_new(gquark_log, 400, "Body too short"));
		return TRUE;
	}

	err = _restore(repo, base, type, dump, dump_size);
	if (NULL != err)
		reply->send_error(500, err);
	else
		reply->send_reply(200, "OK");

	return TRUE;
}

static gboolean
sqlx_dispatch_PIPEFROM(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored)
{
	GError *err;
	gchar base[256], type[64], source[64];

	(void) ignored;
	EXTRACT_STRING("BASE_NAME", base);
	EXTRACT_STRING("BASE_TYPE", type);
	EXTRACT_STRING("SRC", source);
	reply->subject("%s.%s|%s", base, type, source);

	if (NULL != (err = _pipe_from(source, repo, base, type)))
		reply->send_error(0, err);
	else
		reply->send_reply(200, "OK");

	return TRUE;
}

static gboolean
sqlx_dispatch_RESYNC(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored)
{
	GError *err = NULL;
	gchar base[256], type[64];

	(void) ignored;
	EXTRACT_STRING("BASE_NAME", base);
	EXTRACT_STRING("BASE_TYPE", type);
	reply->subject("%s.%s", base, type);

	/* Open and lock the base */
	err = sqlx_repository_use_base(repo, type, base);
	if (NULL != err) {
		reply->send_error(0, err);
		return TRUE;
	}

	struct sqlx_sqlite3_s *sq3 = NULL;
	err = sqlx_repository_open_and_lock(repo, type, base,
			SQLX_OPEN_SLAVEONLY, &sq3, NULL);
	if (NULL != err) {
		reply->send_error(0, err);
		return TRUE;
	}

	err = sqlx_repository_retore_from_master(sq3);
	sqlx_repository_unlock_and_close_noerror(sq3);

	if (NULL != err) {
		reply->send_error(0, err);
		return TRUE;
	}

	reply->send_reply(200, "resync triggered");
	return TRUE;
}

static GError*
_extract_params(struct message_s *msg, TableSequence_t **params)
{
	gint rc;
	void *b = NULL;
	gsize bsize = 0;
	asn_dec_rval_t rv;
	asn_codec_ctx_t ctx;

	rc = message_get_BODY(msg, &b, &bsize, NULL);

	if (0 > rc)
		return g_error_new(gquark_log, 400, "Bad body");

	if (rc > 0) {
		memset(&ctx, 0, sizeof(ctx));
		ctx.max_stack_size = 8192;
		rv = ber_decode(&ctx, &asn_DEF_TableSequence, (void**)params, b, bsize);
		if (rv.code != RC_OK)
			return g_error_new(gquark_log, 400, "body decoding error");
	}

	return NULL;
}

static gboolean
sqlx_dispatch_QUERY(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored)
{
	GError *err;
	gint64 shard = 1;
	gboolean noreal = FALSE;
	gchar base[256], schema[256], *ename = NULL;
	TableSequence_t *params, *result;

	/* unpack the parameters */
	(void) ignored;
	params = result = NULL;
	EXTRACT_STRING("BASE_NAME", base);
	EXTRACT_STRING("BASE_TYPE", schema);
	if (NULL != (err = message_extract_strint64(reply->request, "BASE_SEQ", &shard))) {
		reply->send_error(0, err);
		return TRUE;
	}
	reply->subject("%"G_GINT64_FORMAT"@%s|%s)", shard, base, schema);

	if (NULL != (err = message_extract_flag(reply->request, "NOREAL", FALSE, &noreal))) {
		reply->send_error(0, err);
		return TRUE;
	}

	if (!g_str_has_prefix(schema, "sqlx.")) {
		reply->send_error(0, NEWERROR(400, "Invalid schema name, not prefixed with 'sqlx.'"));
		return TRUE;
	}
	if (NULL != (err = _extract_params(reply->request, &params))) {
		reply->send_error(0, err);
		return TRUE;
	}
	if (!params) {
		reply->send_error(400, g_error_new(gquark_log, 400, "No BODY"));
		return TRUE;
	}

	/* execute the request now */
	ename = g_strdup_printf("%"G_GINT64_FORMAT"@%s", shard, base);
	result = g_malloc0(sizeof(struct TableSequence));
	err = do_query(reply, repo, schema, ename, params, result, noreal);
	g_free(ename);

	if (params)
		asn_DEF_Row.free_struct(&asn_DEF_Row, params, FALSE);

	if (result) {
		if (!err) {
			asn_enc_rval_t rv;
			GByteArray *encoded;

			encoded = g_byte_array_new();
			rv = der_encode(&asn_DEF_TableSequence, result, write_to_gba, encoded);
			if (0 < rv.encoded)
				reply->add_body(encoded);
			else {
				g_byte_array_free(encoded, TRUE);
				err = g_error_new(gquark_log, 500, "Table encoding error: %s",
						rv.failed_type->name);
			}
			encoded = NULL;
		}
		asn_DEF_TableSequence.free_struct(&asn_DEF_TableSequence, result, FALSE);
	}

	if (err)
		reply->send_error(0, err);
	else
		reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
sqlx_dispatch_ADMGET(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = NULL;
	gchar k[512], base[256], type[64];
	gboolean flag_local = FALSE;

	(void) ignored;
	EXTRACT_STRING("BASE_NAME", base);
	EXTRACT_STRING("BASE_TYPE", type);
	reply->subject("%s.%s", base, type);
	EXTRACT_FLAG("LOCAL", flag_local);
	EXTRACT_STRING("K", k);
	reply->subject("%s.%s|%s|%s", base, type, flag_local?"LOC":"REP", k);

	err = sqlx_repository_open_and_lock(repo, type, base,
			flag_local ? SQLX_OPEN_LOCAL : SQLX_OPEN_MASTERSLAVE,
			&sq3, NULL);
	if (NULL != err) {
		g_prefix_error(&err, "Open/lock: ");
		reply->send_error(0, err);
		return TRUE;
	}

	gchar *v = sqlx_get_admin_entry_noerror(sq3->db, k);
	if (!v)
		reply->send_error(0, NEWERROR(CODE_CONTENT_NOTFOUND, "no such value"));
	else {
		reply->add_body(metautils_gba_from_string(v));
		reply->send_reply(200, v);
		g_free(v);
	}

	sqlx_repository_unlock_and_close_noerror(sq3);
	return TRUE;
}

static gboolean
sqlx_dispatch_ADMSET(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = NULL;
	gchar k[512], v[2048], base[256], type[64];
	gboolean flag_local = FALSE;

	(void) ignored;
	EXTRACT_STRING("BASE_NAME", base);
	EXTRACT_STRING("BASE_TYPE", type);
	reply->subject("%s.%s", base, type);
	EXTRACT_FLAG("LOCAL", flag_local);
	EXTRACT_STRING("K", k);
	reply->subject("%s.%s|%s|%s", base, type, flag_local?"LOC":"REP", k);
	EXTRACT_STRING("V", v);

	err = sqlx_repository_open_and_lock(repo, type, base,
			flag_local ? SQLX_OPEN_LOCAL : SQLX_OPEN_MASTERSLAVE,
			&sq3, NULL);
	if (NULL != err) {
		g_prefix_error(&err, "Open/lock: ");
		reply->send_error(0, err);
		return TRUE;
	}

	struct sqlx_repctx_s *repctx = NULL;
	if (!flag_local)
		repctx = sqlx_transaction_prepare(sq3);
	err = sqlx_set_admin_entry(sq3->db, k, v, TRUE);
	err = sqlx_transaction_end(repctx, err);

	if (NULL != err)
		reply->send_error(0, err);
	else
		reply->send_reply(200, "OK");

	sqlx_repository_unlock_and_close_noerror(sq3);
	return TRUE;
}

/* ------------------------------------------------------------------------- */


typedef gboolean (*hook) (struct gridd_reply_ctx_s *, gpointer, gpointer);

const struct gridd_request_descr_s *
sqlx_repli_gridd_get_requests(void)
{
	static struct gridd_request_descr_s descriptions[] = {
		{"SQLX_DESCR",	   (hook) sqlx_dispatch_DESCR,     NULL},
		{"SQLX_STATUS",	   (hook) sqlx_dispatch_STATUS,    NULL},
		{"SQLX_USE",	   (hook) sqlx_dispatch_USE,       NULL},
		{"SQLX_ELECTION",  (hook) sqlx_dispatch_USE,       NULL},
		{"SQLX_PIPETO",	   (hook) sqlx_dispatch_PIPETO,    NULL},
		{"SQLX_PIPEFROM",  (hook) sqlx_dispatch_PIPEFROM,  NULL},
		{"SQLX_DUMP",	   (hook) sqlx_dispatch_DUMP,      NULL},
		{"SQLX_RESTORE",   (hook) sqlx_dispatch_RESTORE,   NULL},
		{"SQLX_REPLICATE", (hook) sqlx_dispatch_REPLICATE, NULL},
		{"SQLX_GETVERS",   (hook) sqlx_dispatch_GETVERS,   NULL},
		{"SQLX_RESYNC",    (hook) sqlx_dispatch_RESYNC,    NULL},
		{"SQLX_ADMSET",    (hook) sqlx_dispatch_ADMSET,    NULL},
		{"SQLX_ADMGET",    (hook) sqlx_dispatch_ADMGET,    NULL},
		{NULL, NULL, NULL}
	};

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	return descriptions;
}

const struct gridd_request_descr_s *
sqlx_sql_gridd_get_requests(void)
{
	static struct gridd_request_descr_s descriptions[] = {
		{"SQLX_QUERY",   (hook) sqlx_dispatch_QUERY, NULL},
		{NULL, NULL, NULL}
	};

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	return descriptions;
}
