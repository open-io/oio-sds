/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

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

#include <errno.h>
#include <sys/stat.h>

#include <glib.h>
#include <sqlite3.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/codec.h>

#include <server/transport_gridd.h>
#include <server/network_server.h>
#include <server/internals.h>
#include <sqliterepo/sqliterepo_variables.h>

#include "sqliterepo.h"
#include "version.h"
#include "election.h"
#include "cache.h"
#include "sqlx_macros.h"
#include "sqlx_remote.h"
#include "sqlx_remote_ex.h"
#include "replication_dispatcher.h"
#include "internals.h"
#include "restoration.h"

#define EXTRACT_STRING(Name,Dst) do { \
	err = metautils_message_extract_string(reply->request, Name, Dst, sizeof(Dst)); \
	if (NULL != err) { \
		reply->send_error(0, err); \
		return TRUE; \
	} \
} while (0)

#define ADMIN "admin"

/* ------------------------------------------------------------------------- */

static void
version_debug(GTree *current, GTree *expected, GTree *post)
{
	if (!GRID_TRACE_ENABLED())
		return;
	gchar *s0 = version_dump(current); STRING_STACKIFY(s0);
	gchar *s1 = version_dump(expected); STRING_STACKIFY(s1);
	gchar *s2 = version_dump(post); STRING_STACKIFY(s2);
	GRID_TRACE("CURRENT:%s EXPECTED:%s POST:%s", s0, s1, s2);
}

static gchar *
_prepare_statement(Table_t *t, gboolean is_admin)
{
	GString *gstr = g_string_sized_new(256);
	g_string_append_static(gstr, "REPLACE INTO ");
	g_string_append_len(gstr, (char*)t->name.buf, t->name.size);
	g_string_append_static(gstr, " (");
	if (!is_admin)
		g_string_append_static(gstr, "ROWID,");

	for (int i=0; i < t->header.list.count; i++) {
		RowName_t *r = t->header.list.array[i];
		if (i > 0)
			g_string_append_c(gstr, ',');
		g_string_append_len(gstr, (char*)r->name.buf, r->name.size);
	}

	g_string_append_static(gstr, ") VALUES (");
	if (!is_admin)
		g_string_append_static(gstr, " ?,");

	for (int i=0; i < t->header.list.count; i++) {
		if (i > 0)
			g_string_append_c(gstr, ',');
		g_string_append_static(gstr, "?");
	}
	g_string_append_c(gstr, ')');

	return g_string_free(gstr, FALSE);
}

static GError *
replicate_table_updates(struct sqlx_sqlite3_s *sq3, Table_t *table)
{
	gchar *sql;
	gint i, j, rc;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;

	/* if there is no table header, we won't be able to generate a valid
	 * UPDATE/REPLACE statement. The current table at best only carries
	 * DELETE commands (with only a ROWID) */
	if (table->header.list.count <= 0)
		return NULL;

	gboolean is_admin = !(g_strcmp0((char*)table->name.buf, ADMIN));
	sql = _prepare_statement(table, is_admin);
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

			if (!is_admin)
				sqlite3_bind_int64(stmt, 1, rowid);
			/* Now apply all the field values */
			for (j=0; j<row->fields->list.count ;j++) {
				int pos = 0;
				long lpos = 0;
				RowField_t *field;

				field = row->fields->list.array[j];
				asn_INTEGER2long(&(field->pos), &lpos);
				pos = lpos + (is_admin? 1 : 2);
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
	static guint8 bad[256] = {0};

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
		return NEWERROR(CODE_BAD_REQUEST, "Empty table name");

	do {
		gint i;
		guint8 *b = table->name.buf;
		for (i=0; i<table->name.size ;i++) {
			if (bad[b[i]]) {
				return NEWERROR(CODE_BAD_REQUEST, "Invalid table name");
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
			GRID_WARN("Replication failed on table [%.*s] : (%d) %s",
					table->name.size, table->name.buf,
					err->code, err->message);
		}
	}

	return err;
}

static GError *
replicate_body_manage(struct sqlx_sqlite3_s *sq3, TableSequence_t *seq)
{
	gint rc;
	GError *err = NULL;

	if (!seq)
		return NEWERROR(CODE_BAD_REQUEST, "Invalid tables sequence");

	if (seq->list.count <= 0) {
		GRID_DEBUG("Empty tables sequence, nothing to replicate");
		return NULL;
	}

	GTree *oldvers, *expected_version, *postvers;

	oldvers = version_extract_from_admin(sq3);
	expected_version = version_extract_expected(oldvers, seq);
	postvers = NULL;

	sqlx_exec(sq3->db, "BEGIN");
	err = _replicate_now(sq3, seq);

	if (NULL != err) {
		if (err->code == SQLITE_ERROR || err->code == SQLITE_SCHEMA) {
			g_prefix_error(&err, "Schema error: ");
			/* XXX This is the error returned to the peer, so we tell it
			   to "pipe to" us. */
			err->code = CODE_PIPETO;
		}
label_rollback:
		rc = sqlx_exec(sq3->db, "ROLLBACK");
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			GRID_WARN("ROLLBACK failed!");
		sqlx_admin_reload(sq3);
	}
	else {
		/* keep the current version for later */
		sqlx_admin_reload(sq3);
		postvers = version_extract_from_admin(sq3);
		version_debug(oldvers, expected_version, postvers);

		gint64 worst = 0;
		err = version_validate_diff(postvers, expected_version, &worst);
		if (err == NULL) {
			if (worst != 0) /* Diff missed */
				err = NEWERROR(CODE_CONCURRENT, "Concurrent change detected");
		}
		if (err != NULL)
			goto label_rollback;

		rc = sqlx_exec(sq3->db, "COMMIT");
		if (rc != SQLITE_OK && rc != SQLITE_DONE) {
			err = SQLITE_GERROR(sq3->db, rc);
			g_prefix_error(&err, "COMMIT failed: ");
			sqlx_admin_reload(sq3);
		}
		else {
			/* If the database has just been created, the cached admin table
			 * does not contain new entries. These entries may be required
			 * by the change callback, thus we need to reload the whole
			 * admin table. */
			sqlx_admin_reload(sq3);
			sqlx_repository_call_change_callback(sq3);
		}
	}

	if (postvers)
		g_tree_destroy(postvers);
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

	ctx.max_stack_size = ASN1C_MAX_STACK;
	rv = ber_decode(&ctx, &asn_DEF_TableSequence, (void**)&seq,
			body, bodysize);
	if (rv.code != RC_OK)
		return NEWERROR(CODE_BAD_REQUEST, "body decoding error");

	err = replicate_body_manage(sq3, seq);
	asn_DEF_TableSequence.free_struct(&asn_DEF_TableSequence, seq, FALSE);
	return err;
}

static GError *
_restore(struct sqlx_repository_s *repo, struct sqlx_name_s *name,
		guint8 *dump, gsize dump_size)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = sqlx_repository_open_and_lock(repo, name,
			SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK|SQLX_OPEN_CREATE, &sq3, NULL);
	if (NULL != err)
		return err;

	err = sqlx_repository_restore_base(sq3, dump, dump_size);
	if (NULL != err) {
		sqlx_repository_unlock_and_close_noerror(sq3);
		GRID_TRACE("Restore failed!");
		return err;
	}
	GRID_TRACE("Restore done!");

	if (!err) {
		/* See the comment in replicate_body_manage */
		sqlx_admin_reload(sq3);
		sqlx_repository_call_change_callback(sq3);
	}

	sqlx_repository_unlock_and_close_noerror(sq3);
	return NULL;
}

static GError *
_restore2(struct sqlx_repository_s *repo, struct sqlx_name_s *name,
		const gchar *path)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = sqlx_repository_open_and_lock(repo, name,
		SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK|SQLX_OPEN_CREATE, &sq3, NULL);
	if (!err) {
		err = sqlx_repository_restore_from_file(sq3, path);
		if (!err) {
			/* See the comment in replicate_body_manage */
			sqlx_admin_reload(sq3);
			sqlx_repository_call_change_callback(sq3);
		}
	}

	sqlx_repository_unlock_and_close_noerror(sq3);
	return err;
}

static GError *
_restore_snapshot(struct sqlx_repository_s *repo, struct sqlx_name_s *name,
		const gchar *path, const gchar *peers)
{
	struct stat bstats;
	if (stat(path, &bstats) != 0) {
		return NEWERROR(errno, "Failed to read snapshot: %s", strerror(errno));
	}
	/* Synchronous replication is only possible if the file is "small".
	 * If it is not, do not start a transaction, write only in the local base,
	 * and rely on asynchronous replication mechanisms. */
	gboolean sync_repli = bstats.st_size < sqliterepo_dump_max_size;
	struct sqlx_sqlite3_s *sq3 = NULL;
	/* The database snapshot file is here, open the base locally to avoid
	 * a redirection, in case the local service does not become the master. */
	GError *err = sqlx_repository_timed_open_and_lock(repo, name,
			SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK|SQLX_OPEN_CREATE, peers,
			&sq3, NULL, oio_ext_get_deadline());
	if (!err) {
		struct sqlx_repctx_s *repctx = NULL;
		if (sync_repli)
			err = sqlx_transaction_begin(sq3, &repctx);
		if (!err) {
			err = sqlx_repository_restore_from_file(sq3, path);
			if (!err) {
				sqlx_repository_call_change_callback(sq3);
				/* Set the new set of peers, avoid a lookup from meta1. */
				sqlx_admin_set_str(sq3, SQLX_ADMIN_PEERS, peers);
				sqlx_admin_save_lazy(sq3);
				/* The slaves do not have the base, trigger synchronous
				 * replication and prevent "Remote diff missed" errors. */
				if (sync_repli)
					sqlx_transaction_notify_huge_changes(repctx);
			}
		}
		if (sync_repli)
			err = sqlx_transaction_end(repctx, err);
	}

	sqlx_repository_unlock_and_close_noerror(sq3);
	return err;
}

static GError *
_dump(struct sqlx_repository_s *repo, struct sqlx_name_s *name,
		gint check_type, GByteArray **result)
{
	GRID_TRACE2("%s(%p,%s,%s,%p)", __FUNCTION__, repo, name->base, name->type, result);

	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = sqlx_repository_open_and_lock(repo, name,
			SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK, &sq3, NULL);
	if (NULL != err)
		return err;

	GByteArray *dump = NULL;
	err = sqlx_repository_dump_base_gba(sq3, check_type, &dump);
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
_dump_chunked(struct sqlx_repository_s *repo, struct sqlx_name_s *name,
		gint check_type,
		void (*_send_chunk)(GByteArray *chunk, gint64 remaining))
{
	guint64 sent = 0;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_TRACE2("%s(%p,%s,%s,%p)", __FUNCTION__,
			repo, name->base, name->type, _send_chunk);

	GError *err = sqlx_repository_open_and_lock(repo, name,
			SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK, &sq3, NULL);
	if (NULL != err)
		return err;

	GError *_dump_chunked_cb(GByteArray *gba, gint64 remaining, gpointer arg) {
		(void) arg;
		sent += gba->len;
		_send_chunk(gba, remaining);
		return NULL;
	}

	err = sqlx_repository_dump_base_chunked(sq3, sqliterepo_dump_chunk_size,
			check_type, _dump_chunked_cb, NULL);

	sqlx_repository_unlock_and_close_noerror(sq3);
	return err;
}

static GError *
_pipe_base_from(const gchar *source, struct sqlx_repository_s *repo,
		struct sqlx_name_s *name, gint check_type, struct restore_ctx_s **ctx)
{
	GError *err;
	gboolean try_slash_tmp = FALSE, autocreate = TRUE;
	gchar tmpdir[LIMIT_LENGTH_VOLUMENAME+4] = {0};
	gchar path[LIMIT_LENGTH_VOLUMENAME+32] = {0};

	GRID_TRACE2("%s(%s,%p,%s,%s)", __FUNCTION__,
			source, repo, name->base, name->type);

retry:
	g_snprintf(tmpdir, sizeof(tmpdir), "%s/tmp",
			try_slash_tmp ? "" : repo->basedir);
	g_snprintf(path, sizeof(path), "%s/restore.sqlite3.XXXXXX", tmpdir);
	err = restore_ctx_create(path, ctx);
	if (err != NULL) {
		if (err->code == ENOENT) {
			if (autocreate) {
				autocreate = FALSE;
				if (g_mkdir(tmpdir, 0755) == 0) {
					g_clear_error(&err);
					goto retry;
				}
			}
		}
		if (!try_slash_tmp) {
			try_slash_tmp = TRUE;
			g_clear_error(&err);
			goto retry;
		}
		return err;
	}

	GError *_pipe_from_cb(GByteArray *part, gint64 remaining, gpointer arg)
	{
		(void) arg;
		GError *err2 = NULL;
		GRID_DEBUG ("PIPEFROM received block of %u bytes, %"
				G_GINT64_FORMAT" bytes remaining", part->len, remaining);
		err2 = restore_ctx_append(*ctx, part->data, part->len);
		metautils_gba_unref (part);
		return err2;
	}

	return peer_dump(source, name, TRUE, check_type, _pipe_from_cb, NULL,
			oio_ext_get_deadline());
}

static GError *
_pipe_from(const gchar *source, struct sqlx_repository_s *repo,
		struct sqlx_name_s *name, gint check_type)
{
	GError *err;
	struct restore_ctx_s *ctx = NULL;
	gint64 now = oio_ext_monotonic_time();
	err = _pipe_base_from(source, repo, name, check_type, &ctx);
	gint64 elapsed = oio_ext_monotonic_time();
	GRID_INFO("pipe_base_from took %"G_GINT64_FORMAT" ms",
		(elapsed - now) / G_TIME_SPAN_MILLISECOND);

	if (!err) {
		now = elapsed;
		err = _restore2(repo, name, ctx->path);
		GRID_INFO("PIPEFROM restore db %s took %"G_GINT64_FORMAT" ms",
			name->base, (oio_ext_monotonic_time() - now) / G_TIME_SPAN_MILLISECOND);
	}

	restore_ctx_clear(&ctx);
	return err;
}

static GError *
_snapshot_from(const gchar *source, struct sqlx_repository_s *repo,
		struct sqlx_name_s *source_name, struct sqlx_name_s *dest_name,
		const gchar *peers)
{
	GError *err = NULL;
	struct restore_ctx_s *ctx = NULL;
	err = _pipe_base_from(source, repo, source_name, -1, &ctx);
	if (!err)
		err = _restore_snapshot(repo, dest_name, ctx->path, peers);

	restore_ctx_clear(&ctx);
	return err;
}

static void
apply_parameters(sqlite3_stmt *stmt, Row_t *row)
{
	gint64 i64;
	gdouble d;

	if (!row->fields) {
		GRID_DEBUG("Row without field");
		return;
	}
	for (gint32 j=0; j<row->fields->list.count ;j++) {
		RowField_t *field = row->fields->list.array[j];
		if (!field)
			continue;
		long lpos = 0;
		asn_INTEGER2long(&(field->pos), &lpos);
		int pos = lpos;

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
				// FALLTHROUGH
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
	static const gchar * const allowed_pragmas[] = {
		"table_info", "index_info", "index_list",
		"page_count", "quick_check", "collation_list",
		"database_list", "freelist_count",
		NULL
	};
	return pragma ? oio_strv_has(allowed_pragmas, pragma) : TRUE;
}

static gboolean
_function_is_allowed(const gchar *func)
{
	static const gchar * const forbidden_funcs[] = {
		"load_extension", "sqlite_compileoption_get",
		"sqlite_compileoption_get", "sqlite_source_id",
		NULL
	};
	return func ? ! oio_strv_has(forbidden_funcs, func) : TRUE;
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
			case SQLITE_READ:
				return SQLITE_OK;

			case SQLITE_TRANSACTION:
			case SQLITE_SAVEPOINT:
				rights |= QUERY_TNX;
				return SQLITE_IGNORE;

			case SQLITE_INSERT:
			case SQLITE_UPDATE:
			case SQLITE_DELETE:
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

			case SQLITE_ANALYZE:
				return SQLITE_OK;

			case SQLITE_REINDEX:
				return SQLITE_IGNORE;

			case SQLITE_FUNCTION:
				return _function_is_allowed(s2) ? SQLITE_OK : SQLITE_DENY;

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
		if (stmt) {
			sqlite3_finalize_debug(rc, stmt);
		}
	}

	return rights;
}

static void
_table_set_error(Table_t *table, GError *err,
		int local_changes, int total_changes, gint64 rowid)
{
	void _reset_integer (INTEGER_t **pi, gint64 v) {
		ASN_STRUCT_FREE(asn_DEF_INTEGER, *pi);
		*pi = ASN1C_CALLOC(1, sizeof(INTEGER_t));
		asn_int64_to_INTEGER(*pi, v);
	}

	gint64 status = 0;
	if (table->statusString) {
		ASN_STRUCT_FREE(asn_DEF_PrintableString, table->statusString);
		table->statusString = NULL;
	}

	if (err) {
		status = - err->code;
		GRID_DEBUG("STATUS: %"G_GINT64_FORMAT" %s", status, err->message);
		table->statusString = OCTET_STRING_new_fromBuf(&asn_DEF_PrintableString,
				err->message, strlen(err->message));
		g_error_free(err);
	}

	_reset_integer (&table->status, status);
	_reset_integer (&table->localChanges, local_changes);
	_reset_integer (&table->totalChanges, total_changes);
	_reset_integer (&table->lastRowId, rowid);
}

/**
 * @param sq3
 * @param query
 * @param params input query parameters
 * @param result output query's status, rows (and command)
 * @param replication_ctx its input, the replication contaxt potentially
 *                        associated to the client session. At output,
 *                        the replication context to be associated to
 *                        the client session.
 * @return
 */
static void
_execute_next_query(struct sqlx_sqlite3_s *sq3, const gchar *query,
		Table_t *params, Table_t *result,
		struct sqlx_repctx_s **replication_ctx)
{
	GError *err = NULL;
	gint rc = 0;
	sqlite3_stmt *stmt = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	enum query_action_e action = QA_READ;

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
				err = NEWERROR(CODE_NOT_ALLOWED, "Forbidden PRAGMA %s(%s)", s1, s2);
				return SQLITE_DENY;

			case SQLITE_REINDEX:
				err = NEWERROR(CODE_NOT_ALLOWED, "Forbidden REINDEX");
				return SQLITE_DENY;

			case SQLITE_ANALYZE:
				return SQLITE_OK;

			case SQLITE_FUNCTION:
				if (_function_is_allowed(s2))
					return SQLITE_OK;
				err = NEWERROR(CODE_NOT_ALLOWED, "Forbidden FUNCTION "
						"%s(%s,%s,%s)", s1, s2, s3, s4);
				return SQLITE_DENY;

			case SQLITE_CREATE_VTABLE:
			case SQLITE_DROP_VTABLE:
			case SQLITE_ATTACH:
			case SQLITE_DETACH:
			case SQLITE_COPY:
			default:
				err = NEWERROR(CODE_NOT_ALLOWED, "Forbidden '%s'", sqlite_op2str(op));
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
		_table_set_error(result, err, 0,
						sqlite3_total_changes(sq3->db),
						sqlite3_last_insert_rowid(sq3->db));
		return ;
	}

	if (!stmt) {
		GRID_DEBUG("Empty statement : [%s]", query);
		_table_set_error(result, NULL, 0,
				sqlite3_total_changes(sq3->db),
				sqlite3_last_insert_rowid(sq3->db));
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
				err = sqlx_transaction_begin(sq3, &repctx);
				if (NULL == err)
					*replication_ctx = repctx;
				_table_set_error(result, err, 0,
						sqlite3_total_changes(sq3->db),
						sqlite3_last_insert_rowid(sq3->db));
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
				_table_set_error(result, err,
						sqlite3_changes(sq3->db),
						sqlite3_total_changes(sq3->db),
						sqlite3_last_insert_rowid(sq3->db));
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
				err = sqlx_transaction_end(repctx, NEWERROR(0, "aborted by user"));
				*replication_ctx = repctx = NULL;
				_table_set_error(result, err, 0,
						sqlite3_total_changes(sq3->db),
						sqlite3_last_insert_rowid(sq3->db));
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
				err = sqlx_transaction_begin(sq3, &repctx);
				if (NULL != err) {
					_table_set_error(result, err,
							sqlite3_changes(sq3->db),
							sqlite3_total_changes(sq3->db),
							sqlite3_last_insert_rowid(sq3->db));
					return;
				}
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
					struct Row *rrow = ASN1C_CALLOC(1, sizeof(struct Row));
					load_statement(stmt, rrow, result);
					asn_sequence_add(&(result->rows.list), rrow);
				}
			}
			if (rc != SQLITE_DONE && rc != SQLITE_OK)
				err = SQLITE_GERROR(sq3->db, rc);
		}
	}
	else {

		if (params->rows.list.count > 0)
			GRID_DEBUG("No parameter expected, %u provided", params->rows.list.count);

		/* Only one STEP */
		for (rc = SQLITE_ROW; rc == SQLITE_ROW ;) {
			rc = sqlite3_step(stmt);
			if (rc == SQLITE_ROW) {
				struct Row *rrow = ASN1C_CALLOC(1, sizeof(struct Row));
				load_statement(stmt, rrow, result);
				asn_sequence_add(&(result->rows.list), rrow);
			}
		}
		if (rc != SQLITE_DONE && rc != SQLITE_OK)
			err = SQLITE_GERROR(sq3->db, rc);
	}

	sqlite3_finalize_debug(rc, stmt);

	if (action == QA_SCHEMA && repctx != NULL)
		sqlx_transaction_notify_huge_changes(repctx);

	int local_changes = sqlite3_changes(sq3->db);
	int total_changes = sqlite3_changes(sq3->db);
	gint64 last_rowid = sqlite3_last_insert_rowid(sq3->db);

	if (repctx && !*replication_ctx) {
		err = sqlx_transaction_end(repctx, err);
		repctx = NULL;
	}

	/* err cleaned inside */
	_table_set_error(result, err, local_changes, total_changes, last_rowid);
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
	err = sqlx_transaction_end(repctx, NEWERROR(0, "CNX abort"));
	GRID_INFO("Aborted transaction on [%s][%s] : (%d) %s",
			sq3->name.base, sq3->name.type,
			err ? err->code : 0, err ? err->message : "no error");
	if (err)
		g_clear_error(&err);

	/* now close the database */
	sqlx_repository_unlock_and_close_noerror(sq3);
}

static gchar *
_table_to_query(Table_t *t)
{
	EXTRA_ASSERT(t != NULL);
	return g_strndup((char*)t->name.buf, t->name.size);
}

static GError *
do_query_after_open(struct gridd_reply_ctx_s *reply_ctx,
		struct sqlx_sqlite3_s *sq3, TableSequence_t *params,
		TableSequence_t *result)
{
	gint32 i32;
	guint32 admin_status = ADMIN_STATUS_ENABLED;
	GError *err = NULL;
	enum query_rights_e action;

	/* Check the base has not been disabled (eg. during a migration) */
	admin_status = sqlx_admin_get_status(sq3);
	if (admin_status == ADMIN_STATUS_DISABLED) {
		err = NEWERROR(CODE_NOT_ALLOWED, "Base is disabled");
		return err;
	}

	/* Check this server can manage the request, i.e. if the request contains
	 * write operations or schema changes, we immediately check we are the
	 * master, to redirect the request to another server. */
	for (i32=0; i32 < params->list.count && !err ;i32++) {
		gchar *query = _table_to_query(params->list.array[i32]);
		action = _query_get_rights(sq3->db, query);
		g_free(query);

		if (0 != action) {
			NAME2CONST(n, sq3->name);
			err = sqlx_repository_status_base(sq3->repo, &n, reply_ctx->deadline);
			if (NULL != err) {
				if (err->code != CODE_REDIRECT)
					g_prefix_error(&err, "Status error: ");
				return err;
			}
			if (admin_status == ADMIN_STATUS_FROZEN) {
				err = NEWERROR(CODE_NOT_ALLOWED, "Base is frozen");
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
		res = ASN1C_CALLOC(1, sizeof(struct Table));
		query = _table_to_query(req);
		replication_ctx = reply_ctx->get_cnx_data("repctx");
		reply_ctx->forget_cnx_data("repctx");
		_execute_next_query(sq3, query, req, res, &replication_ctx);
		g_free(query);

		asn_sequence_add(&(result->list), res);
		if (replication_ctx) {
			reply_ctx->register_cnx_data("repctx", replication_ctx,
					_abort_tnx_and_close_db);
			GRID_TRACE2("REPCTX attached to the CNX");
		}
	}

	return NULL;
}

static GError *
_checked_open(struct gridd_reply_ctx_s *reply_ctx, sqlx_repository_t *repo,
		struct sqlx_name_s *name, enum sqlx_open_type_e open_mode,
		struct sqlx_sqlite3_s **out_sq3)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_repctx_s *replication_ctx;

	replication_ctx = reply_ctx->get_cnx_data("repctx");
	if (NULL != replication_ctx) { /* Maybe is the base still open */
		sq3 = sqlx_transaction_get_base(replication_ctx);
		if (strcmp(name->base, sq3->name.base) || strcmp(name->type, sq3->name.type)) {
			err = NEWERROR(CODE_BAD_REQUEST, "Another base is still open [%s].[%s]",
					sq3->name.base, sq3->name.type);
			return err;
		}
	} else { /* Normal open */
		err = sqlx_repository_open_and_lock(repo, name, open_mode, &sq3, NULL);
		if (NULL != err) {
			if (err->code != CODE_REDIRECT)
				g_prefix_error(&err, "Open/Lock: ");
			return err;
		}
	}
	*out_sq3 = sq3;
	return err;
}

static GError *
_check_init_flag(struct sqlx_sqlite3_s *sq3, gboolean autocreate, gint64 deadline)
{
	GError *err = NULL;
	if (!sqlx_admin_has(sq3, SQLX_ADMIN_INITFLAG)) {
		if (!autocreate) {
			GRID_DEBUG("Autocreate %s, flag %s not found, returning error",
					autocreate? "on":"off", SQLX_ADMIN_INITFLAG);
			err = NEWERROR(CODE_CONTAINER_NOTFOUND, "Base does not exist");
		} else {
			NAME2CONST(n, sq3->name);
			err = sqlx_repository_status_base(sq3->repo, &n, deadline);
			if (!err) { /* We are master */
				struct sqlx_repctx_s *repctx = NULL;
				GRID_DEBUG("Autocreate %s, inserting %s flag",
						autocreate? "on":"off", SQLX_ADMIN_INITFLAG);
				err = sqlx_transaction_begin(sq3, &repctx);
				sqlx_admin_init_i64(sq3, SQLX_ADMIN_INITFLAG, 1);
				err = sqlx_transaction_end(repctx, err);
			}
		}
	}
	return err;
}

static GError *
do_query(struct gridd_reply_ctx_s *reply_ctx, sqlx_repository_t *repo,
		struct sqlx_name_s *name,
		TableSequence_t *params, TableSequence_t *result)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_DEBUG("Opening and querying [%s][%s]", name->base, name->type);

	err = _checked_open(reply_ctx, repo, name, SQLX_OPEN_CREATE|SQLX_OPEN_MASTERSLAVE, &sq3);
	if (err != NULL)
		return err;

	err = _check_init_flag(sq3, TRUE, reply_ctx->deadline);
	if (!err)
		err = do_query_after_open(reply_ctx, sq3, params, result);

	/* If a transaction is pending, we do not close the base, but without
	   a transaction, we can close the base */
	if (!reply_ctx->get_cnx_data("repctx"))
		sqlx_repository_unlock_and_close_noerror(sq3);

	return err;
}

static GError *
do_destroy(struct gridd_reply_ctx_s *reply, struct sqlx_repository_s *repo,
		struct sqlx_name_s *name, gboolean local)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_DEBUG("Opening for destruction [%s][%s] (%s)",
			name->base, name->type, local? "local" : "master");

	guint32 flags = local? SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK : SQLX_OPEN_MASTERONLY;
	if (NULL != (err = _checked_open(reply, repo, name, flags, &sq3)))
		return err;

	if (!local) {
		gchar **peers = NULL;
		err = election_get_peers(sq3->manager, name, FALSE, &peers);
		if (err) {
			EXTRA_ASSERT(peers == NULL);
			goto end_label;
		} else {
			EXTRA_ASSERT(peers != NULL);
			err = sqlx_remote_execute_DESTROY_many(peers, NULL, name, oio_ext_get_deadline());
			g_strfreev(peers);
		}
	}

	if (!err) {
		GRID_DEBUG("Destroying [%s][%s]", name->base, name->type);
		sq3->deleted = TRUE;
	}

end_label:
	err = sqlx_repository_unlock_and_close(sq3);
	if (!err && !local)
		err = election_exit(sqlx_repository_get_elections_manager(repo), name);
	return err;
}

/* ------------------------------------------------------------------------- */

#define FLAG_LOCAL      0x02
#define FLAG_NOCHECK    0x08
#define FLAG_CHUNKED    0x10
#define FLAG_FLUSH      0x20

static GError *
_load_sqlx_name (struct gridd_reply_ctx_s *ctx,
		struct sqlx_name_inline_s *n, guint32 *pflags)
{
	GError *err;
	gchar
		ns[LIMIT_LENGTH_NSNAME],
		base[LIMIT_LENGTH_BASENAME],
		type[LIMIT_LENGTH_BASETYPE];
	gboolean flush, nocheck, local, chunked;

	flush = local = nocheck = chunked = FALSE;

	err = metautils_message_extract_string(ctx->request,
			NAME_MSGKEY_NAMESPACE, ns, sizeof(ns));
	if (NULL != err)
		return err;
	err = metautils_message_extract_string(ctx->request,
			NAME_MSGKEY_BASENAME, base, sizeof(base));
	if (NULL != err)
		return err;
	err = metautils_message_extract_string(ctx->request,
			NAME_MSGKEY_BASETYPE, type, sizeof(type));
	if (NULL != err)
		return err;

	local = metautils_message_extract_flag(ctx->request,
			NAME_MSGKEY_LOCAL, FALSE);
	nocheck = metautils_message_extract_flag(ctx->request,
			NAME_MSGKEY_NOCHECK, FALSE);
	chunked = metautils_message_extract_flag(ctx->request,
			NAME_MSGKEY_CHUNKED, FALSE);
	flush = metautils_message_extract_flag(ctx->request,
			NAME_MSGKEY_FLUSH, FALSE);

	ctx->subject("%s.%s%s", base, type, local?"|LOCAL":"");

	memset(n, 0, sizeof(*n));
	g_strlcpy(n->ns, ns, sizeof(n->ns));
	g_strlcpy(n->base, base, sizeof(n->base));
	g_strlcpy(n->type, type, sizeof(n->type));

	if (pflags) {
		*pflags = 0;
		*pflags |= (local ? FLAG_LOCAL : 0);
		*pflags |= (nocheck ? FLAG_NOCHECK : 0);
		*pflags |= (chunked ? FLAG_CHUNKED : 0);
		*pflags |= (flush ? FLAG_FLUSH : 0);
	}
	return NULL;
}

static void
_load_sqlx_peers(struct gridd_reply_ctx_s *ctx, gchar **peers)
{
	EXTRA_ASSERT(peers != NULL);
	gsize msglen;
	gchar pbuf[256];
	const char *msg = metautils_message_get_NAME(ctx->request, &msglen);
	GError *err = metautils_message_extract_string(ctx->request,
			SQLX_ADMIN_PEERS, pbuf, sizeof(pbuf));
	if (!err && oio_str_is_set(pbuf)) {
		*peers = g_strndup(pbuf, sizeof(pbuf));
		GRID_TRACE("%.*s request received peers: %s (reqid=%s)",
				(int)msglen, msg, *peers, oio_ext_get_reqid());
	} else {
		GRID_INFO("%.*s request received no peers (reqid=%s)",
				(int)msglen, msg, oio_ext_get_reqid());
	}
	g_clear_error(&err);
}

static void
_maybe_override_check_type(struct gridd_reply_ctx_s *ctx, gint *check_type)
{
	gint64 _check_type = -1;
	GError *err = metautils_message_extract_strint64(ctx->request,
			NAME_MSGKEY_CHECK_TYPE, &_check_type);
	if (err) {
		g_clear_error(&err);
	} else if (_check_type >= 0) {
		*check_type = (gint)_check_type;
	}
}

/* ------------------------------------------------------------------------- */

static gboolean
_handler_GETVERS(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GTree *version = NULL;
	GError *err = NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	reply->no_access();

	if ((err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}
	gchar *peers = NULL;
	_load_sqlx_peers(reply, &peers);

	err = sqlx_repository_timed_open_and_lock(repo, &n0,
			SQLX_OPEN_CREATE|SQLX_OPEN_LOCAL|SQLX_OPEN_URGENT,
			peers, &sq3, NULL, oio_ext_get_deadline());
	g_free(peers);
	if (err) {
		g_prefix_error(&err, "Open/lock: ");
		reply->send_error(0, err);
		return TRUE;
	}

	err = sqlx_repository_get_version(sq3, &version);
	sqlx_repository_unlock_and_close_noerror(sq3);

	if (err) {
		reply->send_error(0, err);
	} else {
		GByteArray *encoded = version_encode(version);
		if (!encoded) {
			err = NEWERROR(CODE_INTERNAL_ERROR, "Encoding error (version)");
			reply->send_error(0, err);
		}
		else {
			reply->add_body(encoded);
			reply->send_reply(CODE_FINAL_OK, "OK");
		}
	}

	if (version)
		g_tree_destroy(version);
	return TRUE;
}

static gboolean
_handler_REPLICATE(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);
	GError *err = NULL;

	reply->no_access();

	if (NULL != (err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}

	gsize bsize = 0;
	void *b = metautils_message_get_BODY(reply->request, &bsize);
	if (!b) {
		reply->send_error(CODE_BAD_REQUEST, NEWERROR(CODE_BAD_REQUEST, "missing body"));
		return TRUE;
	}

	reply->send_reply(CODE_TEMPORARY, "received");

	err = sqlx_repository_open_and_lock(repo, &n0,
			SQLX_OPEN_LOCAL|SQLX_OPEN_URGENT, &sq3, NULL);
	if (NULL != err) {
		if (err->code == CODE_CONTAINER_NOTFOUND) {
			reply->send_error(CODE_PIPEFROM, err);
			return TRUE;
		}
		reply->send_error(0, err);
		return TRUE;
	}

	/* Unpack the body from the message, decode it */
	err = replicate_body_parse(sq3, b, bsize);
	if (NULL != err)
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	sqlx_repository_unlock_and_close_noerror(sq3);

	return TRUE;
}

static gboolean
_handler_HAS(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	GError *err = NULL;
	gchar *bddname=NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	if (NULL != (err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}

	if (NULL != (err = sqlx_repository_has_base2(repo, &n0, &bddname))) {
		GError *e = sqlx_repository_remove_from_cache(repo, &n0);
		if (e)
			g_clear_error(&e);
		reply->send_error(0, err);
	} else {
		GString *body = g_string_new("\"");
		if (bddname) {
			g_string_append(body, bddname);
			g_free(bddname);
		} else {
			g_string_append(body, "Not found");
		}
		g_string_append_c(body, '"');
		reply->add_body(metautils_gba_from_string(body->str));
		g_string_free(body, TRUE);
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	return TRUE;
}

static gboolean
_handler_STATUS(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	GError *err;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	reply->no_access();

	if (NULL != (err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}

	if (NULL != (err = sqlx_repository_status_base(repo, &n0, reply->deadline)))
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "MASTER");

	return TRUE;
}

static gboolean
_handler_ISMASTER(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	GError *err;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	reply->no_access();

	if (NULL != (err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}

	err = sqlx_repository_status_base(repo, &n0, reply->deadline);
	if (NULL == err)
		reply->send_reply(CODE_FINAL_OK, "MASTER");
	else {
		if (err->code == CODE_REDIRECT) {
			reply->send_reply(CODE_FINAL_OK, "LOST");
			g_clear_error(&err);
		} else {
			reply->send_error(0, err);
		}
	}

	return TRUE;
}

static gboolean
_handler_DESCR(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	GError *err = NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	reply->no_access();

	if (NULL != (err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}

	/* Tests made with short base names show JSON lengths around 1780 bytes,
	 * so 2048 should be enough for most names. */
	GString *body = g_string_sized_new(2048);
	election_manager_whatabout(sqlx_repository_get_elections_manager(repo),
			&n0, body);
	reply->add_body(g_bytes_unref_to_array(g_string_free_to_bytes(body)));
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
_handler_USE(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	GError *err;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	reply->no_access();

	if ((err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}

	const gboolean master = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_MASTER, FALSE);
	gchar *peers = NULL;
	_load_sqlx_peers(reply, &peers);

	if ((err = sqlx_repository_use_base(repo, &n0, peers, master, TRUE, NULL)))
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	g_free(peers);
	return TRUE;
}

static gboolean
_handler_EXIT(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	GError *err;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	if (NULL != (err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}

	if (NULL != (err = sqlx_repository_exit_election(repo, &n0)))
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
_handler_PIPETO(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	GError *err = NULL;
	GByteArray *dump = NULL;
	gchar target[STRLEN_ADDRINFO];
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	if (NULL != (err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}
	EXTRACT_STRING("DST", target);
	reply->subject("%s.%s|%s", name.base, name.type, target);

	/* Dump the base in a locked manner */
	err = _dump(repo, &n0, sqliterepo_dump_check_type, &dump);
	if (NULL != err) {
		g_prefix_error(&err, "Dump failed: ");
		reply->send_error(0, err);
		return TRUE;
	}

	reply->send_reply(CODE_TEMPORARY, "Dump done");

	/* forward the dump to the target */
	if (NULL != (err = peer_restore(target, &n0, dump, oio_ext_get_deadline())))
		reply->send_error(CODE_INTERNAL_ERROR, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
_handler_REMOVE(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	if (NULL != (err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}

	err = sqlx_repository_open_and_lock(repo, &n0,
			SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK, &sq3, NULL);
	if (err) {
		reply->send_error(0, err);
		return TRUE;
	}
	sq3->deleted = TRUE;
	sqlx_repository_unlock_and_close_noerror(sq3);

	/* TODO(FVE): send an event telling this service is no more responsible
	 * for the base, and use this event to deindex the base from rdir. */

	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
_handler_DUMP(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	GError *err = NULL;
	guint32 flags = 0;
	gint check_type = sqliterepo_dump_check_type;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	if (NULL != (err = _load_sqlx_name(reply, &name, &flags))) {
		reply->send_error(0, err);
		return TRUE;
	}
	_maybe_override_check_type(reply, &check_type);

	void _send_part(GByteArray *part, gint64 remaining)
	{
		gchar tmp[32] = {0};
		g_snprintf(tmp, 32, "%"G_GINT64_FORMAT, remaining);
		GRID_DEBUG("DUMP sending block of %u bytes, %"
				G_GINT64_FORMAT" bytes remaining",
				part->len, remaining);
		reply->add_body(part);
		reply->add_header("remaining", metautils_gba_from_string(tmp));
		reply->send_reply(CODE_PARTIAL_CONTENT, "Partial content");
	}

	if (flags & FLAG_CHUNKED) {
		err = _dump_chunked(repo, &n0, (gint)check_type, _send_part);
	} else {
		GByteArray *dump = NULL;
		/* Open and lock the base */
		err = _dump(repo, &n0, (gint)check_type, &dump);
		if (!err) {
			reply->add_body(dump);
		}
	}

	if (NULL != err) {
		reply->send_error(0, err);
	} else {
		reply->add_header("format", metautils_gba_from_string("sqlite3"));
		reply->send_reply(CODE_FINAL_OK, "OK");
	}
	return TRUE;
}

static gboolean
_handler_RESTORE(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	GError *err;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	if (NULL != (err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}

	/* The body is the raw base */
	gsize dump_size = 0;
	guint8 *dump = metautils_message_get_BODY(reply->request, &dump_size);
	if (!dump) {
		reply->send_error(0, NEWERROR(CODE_BAD_REQUEST, "Missing body"));
		return TRUE;
	}
	if (dump_size < 1024) {
		reply->send_error(0, NEWERROR(CODE_BAD_REQUEST,
				"Body too short (%zd bytes)", dump_size));
		return TRUE;
	}

	err = _restore(repo, &n0, dump, dump_size);
	if (NULL != err)
		reply->send_error(CODE_INTERNAL_ERROR, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	return TRUE;
}

static gboolean
_handler_PIPEFROM(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	GError *err;
	gchar source[64];
	gint check_type = -1;  // -1 -> user server default
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	if (NULL != (err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}
	EXTRACT_STRING("SRC", source);
	_maybe_override_check_type(reply, &check_type);
	reply->subject("%s.%s|%s", name.base, name.type, source);

	if (NULL != (err = _pipe_from(source, repo, &n0, check_type)))
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	return TRUE;
}

static gboolean
_handler_SNAPSHOT(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	GError *err;
	gchar source[64];
	gchar cid[STRLEN_CONTAINERID];
	gchar seq_num[10];
	gchar *full_base_name;
	gchar *peers = NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(no, name);

	if ((err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}

	EXTRACT_STRING(NAME_MSGKEY_SRC, source);
	EXTRACT_STRING(NAME_MSGKEY_CONTAINERID, cid);
	EXTRACT_STRING(NAME_MSGKEY_SEQNUM, seq_num);
	reply->subject("%s.%s|%s", name.base, name.type, source);
	_load_sqlx_peers(reply, &peers);

	full_base_name = g_strconcat(cid, seq_num, NULL);
	struct sqlx_name_s src = {name.ns, full_base_name ,name.type};
	if ((err = _snapshot_from(source, repo, &src, &no, peers)))
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	g_free(peers);
	g_free(full_base_name);
	return TRUE;
}

static gboolean
_handler_RESYNC(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	GError *err = NULL;
	gint check_type = -1;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	if (NULL != (err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}
	_maybe_override_check_type(reply, &check_type);

	struct sqlx_sqlite3_s *sq3 = NULL;
	err = sqlx_repository_open_and_lock(repo, &n0,
			SQLX_OPEN_CREATE|SQLX_OPEN_SLAVEONLY, &sq3, NULL);
	if (NULL != err) {
		reply->send_error(0, err);
		return TRUE;
	}

	err = sqlx_repository_restore_from_master(sq3, check_type);
	sqlx_repository_unlock_and_close_noerror(sq3);

	if (NULL != err) {
		reply->send_error(0, err);
		return TRUE;
	}

	reply->send_reply(CODE_FINAL_OK, "resync triggered");
	return TRUE;
}

static gboolean
_handler_VACUUM(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);
	GError *err = NULL;
	guint32 flags = 0;

	if (NULL != (err = _load_sqlx_name(reply, &name, &flags))) {
		reply->send_error(0, err);
		return TRUE;
	}

	const enum sqlx_open_type_e how = (flags & FLAG_LOCAL)
		? (SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK) : SQLX_OPEN_MASTERONLY;
	err = sqlx_repository_open_and_lock(repo, &n0, how, &sq3, NULL);
	if (err)
		goto label_exit;

	gchar **peers = NULL;
	if (!(flags & FLAG_LOCAL)) {
		err = election_get_peers(sq3->manager, &n0, FALSE, &peers);
		if (err) {
			goto label_exit;
		}
	}

	/* Do not explicitly open a transaction! A transaction would trigger
	 * a synchronous replication, which would fail when the database is big.
	 * Instead, we will trigger an asyncronous resync. */
	sqlx_admin_set_i64(sq3, SQLX_ADMIN_LAST_VACUUM, oio_ext_real_seconds());
	/* This is to prevent concurrent changes in case the resync is not
	 * performed quickly enough. */
	sqlx_admin_inc_all_versions(sq3, 2);
	sqlx_admin_save_lazy_tnx(sq3);
	sqlx_exec(sq3->db, "VACUUM");

	if (!(flags & FLAG_LOCAL)) {
		/* Trigger the resync before unlocking the database, to increase
		 * the chance that the first request handled by the service after
		 * the current one is the DB_DUMP triggered by the resync.
		 * No-op if replication is not enabled. */
		err = sqlx_remote_execute_RESYNC_many(
				peers, NULL, &n0, oio_ext_get_deadline());
		g_strfreev(peers);
	}

	sqlx_repository_unlock_and_close_noerror(sq3);

label_exit:
	if (err) {
		reply->send_error(0, err);
	} else {
		reply->send_reply(CODE_FINAL_OK, "VACUUM done");
	}
	return TRUE;
}


/* ------------------------------------------------------------------------- */

static gboolean
_db_properties_add(gpointer key, gpointer value, gpointer data)
{
	db_properties_add(data, key, value);
	return FALSE;
}

static gboolean
_handler_PROPDEL(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);
	GError *err = NULL;
	guint32 flags = 0;
	struct db_properties_s *db_properties = NULL;

	if (NULL != (err = _load_sqlx_name(reply, &name, &flags))) {
		reply->send_error(0, err);
		return TRUE;
	}

	gsize len = 0;
	void *buf = metautils_message_get_BODY(reply->request, &len);
	if (!buf) {
		reply->send_error(0, BADREQ("Missing body"));
		return TRUE;
	}

	gchar **keys = NULL;
	err = STRV_decode_buffer(buf, len, &keys);
	if (NULL != err) {
		reply->send_error(CODE_BAD_REQUEST, err);
		return TRUE;
	}

	const enum sqlx_open_type_e how = (flags&FLAG_LOCAL)
		? (SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK) : SQLX_OPEN_MASTERONLY;
	err = sqlx_repository_open_and_lock(repo, &n0, how, &sq3, NULL);
	if (err)
		goto label_exit;

	db_properties = db_properties_new();
	struct sqlx_repctx_s *repctx = NULL;
	if (!(flags & FLAG_LOCAL))
		err = sqlx_transaction_begin(sq3, &repctx);
	if (!err) {
		if (!keys || !*keys)
			sqlx_admin_del_all_user(sq3, _db_properties_add,
					db_properties);
		else {
			for (gchar **pk = keys; keys && *pk; ++pk) {
				sqlx_admin_del(sq3, *pk);
				db_properties_add(db_properties, *pk, NULL);
			}
		}

		if (repctx) {
			err = sqlx_transaction_end(repctx, err);
		} else {
			sqlx_admin_save_lazy_tnx (sq3);
		}
	}

	if (!err && db_properties) {
		struct oio_url_s *url = metautils_message_extract_url(
				reply->request);
		sqlx_repository_call_db_properties_change_callback(
				sq3, url, db_properties);
		oio_url_clean(url);
	}

	sqlx_repository_unlock_and_close_noerror(sq3);

label_exit:
	if (err) {
		reply->send_error(0, err);
	} else {
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	if (db_properties)
		db_properties_free(db_properties);
	if (keys)
		g_strfreev(keys);
	return TRUE;
}

static gboolean
_handler_PROPGET(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);
	GError *err;
	guint32 flags = 0;

	/* Extraction */
	if (NULL != (err = _load_sqlx_name(reply, &name, &flags))) {
		reply->send_error(0, err);
		return TRUE;
	}

	/* Action */
	const enum sqlx_open_type_e how = (flags&FLAG_LOCAL)
		? (SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK) : SQLX_OPEN_MASTERSLAVE;
	err = sqlx_repository_open_and_lock(repo, &n0, how, &sq3, NULL);
	if (err) {
		reply->send_error(0, err);
	} else {
		GPtrArray *tmp = g_ptr_array_new();
		gchar **keys = sqlx_admin_get_keys (sq3);
		if (keys) {
			for (gchar **p=keys; *p ;++p) {
				gchar *v = sqlx_admin_get_str(sq3, *p);
				g_ptr_array_add(tmp, *p);
				g_ptr_array_add(tmp, v ? v : g_strdup(""));
			}
		}
		g_free (keys); /*< pointers reused! */

		if (oio_ext_is_admin()) {
			GPtrArray *stats = sqlx_admin_get_usage(sq3);
			if (stats) {
				for(guint i=0; i < stats->len; i++) {
					g_ptr_array_add(tmp, g_ptr_array_index(stats, i));
				}
				g_ptr_array_free(stats, FALSE); /*< pointers reused! */
			}
		}
		g_ptr_array_add(tmp, NULL);

		gchar **pairs = (gchar**) g_ptr_array_free(tmp, FALSE);
		GByteArray *body = KV_encode_gba (pairs);
		g_strfreev(pairs);

		sqlx_repository_unlock_and_close_noerror(sq3);

		reply->add_body(body);
		reply->send_reply(CODE_FINAL_OK, "OK");
	}
	return TRUE;
}

static gboolean
_handler_PROPSET(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);
	GError *err;
	guint32 flags = 0;
	struct db_properties_s *db_properties = NULL;

	/* Extraction */
	if (NULL != (err = _load_sqlx_name(reply, &name, &flags))) {
		reply->send_error(0, err);
		return TRUE;
	}

	gchar **pairs = NULL;
	gsize length = 0;
	void *body = metautils_message_get_BODY(reply->request, &length);
	err = KV_decode_buffer (body, length, &pairs);
	EXTRA_ASSERT((err != NULL) ^ (pairs != NULL));

	if (NULL != err) {
		reply->send_error(CODE_BAD_REQUEST, err);
		return TRUE;
	}

	/* check the format */
	for (gchar **p=pairs; !err && *p && *(p+1); p+=2) {
		if (!(flags & FLAG_NOCHECK)
				&& !g_str_has_prefix (*p, SQLX_ADMIN_PREFIX_SYS)
				&& !g_str_has_prefix (*p, SQLX_ADMIN_PREFIX_USER)) {
			err = NEWERROR(CODE_BAD_REQUEST, "Invalid property name");
			break;
		}
	}
	if (err)
		goto label_exit;

	/* Open */
	const enum sqlx_open_type_e how = (flags&FLAG_LOCAL)
			? (SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK) : SQLX_OPEN_MASTERONLY;
	err = sqlx_repository_open_and_lock(repo, &n0, how, &sq3, NULL);
	if (err)
		goto label_exit;

	db_properties = db_properties_new();
	/* Action */
	struct sqlx_repctx_s *repctx = NULL;
	if (!(flags & FLAG_LOCAL))
		err = sqlx_transaction_begin(sq3, &repctx);
	if (!err) {
		if (flags & FLAG_FLUSH)
			sqlx_admin_del_all_user(sq3, _db_properties_add,
					db_properties);
		/* insertion */
		for (gchar **p=pairs; !err && *p && *(p+1); p+=2) {
			if (oio_str_is_set(*(p+1))) {
				sqlx_admin_set_str(sq3, *p, *(p+1));
			} else {
				sqlx_admin_del(sq3, *p);
			}
			db_properties_add(db_properties, *p, *(p+1));
		}

		if (repctx) {
			err = sqlx_transaction_end(repctx, err);
		} else {
			sqlx_admin_save_lazy_tnx(sq3);
		}
	}

	if (!err && db_properties) {
		struct oio_url_s *url = metautils_message_extract_url(
				reply->request);
		sqlx_repository_call_db_properties_change_callback(
				sq3, url, db_properties);
		oio_url_clean(url);
	}

	sqlx_repository_unlock_and_close_noerror(sq3);

label_exit:
	if (err) {
		reply->send_error(0, err);
	} else {
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	if (db_properties)
		db_properties_free(db_properties);
	g_strfreev(pairs);
	return TRUE;
}

static gboolean
_handler_ENABLE(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);
	GError *err;
	guint32 flags = 0;

	if (NULL != (err = _load_sqlx_name(reply, &name, &flags))) {
		reply->send_error(0, err);
		return TRUE;
	}

	const enum sqlx_open_type_e how = (flags&FLAG_LOCAL)
		? (SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK) : SQLX_OPEN_MASTERONLY;
	err = sqlx_repository_open_and_lock(repo, &n0, how, &sq3, NULL);
	if (err) {
		reply->send_error(0, err);
		return TRUE;
	}

	struct sqlx_repctx_s *repctx = NULL;
	if (!(flags&FLAG_LOCAL))
		err = sqlx_transaction_begin(sq3, &repctx);
	if (NULL == err) {
		if (ADMIN_STATUS_ENABLED != sqlx_admin_get_status(sq3))
			sqlx_admin_set_status(sq3, ADMIN_STATUS_ENABLED);
		else
			err = NEWERROR(CODE_CONTAINER_ENABLED, "Already enabled");

		if (repctx) {
			err = sqlx_transaction_end(repctx, err);
		} else {
			sqlx_admin_save_lazy_tnx (sq3);
		}
	}
	sqlx_repository_unlock_and_close_noerror(sq3);

	if (NULL != err)
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	return TRUE;
}

static gboolean
_handler_FREEZE(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);
	GError *err;
	guint32 flags = 0;

	if (NULL != (err = _load_sqlx_name(reply, &name, &flags))) {
		reply->send_error(0, err);
		return TRUE;
	}

	const enum sqlx_open_type_e how = (flags&FLAG_LOCAL)
		? (SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK) : SQLX_OPEN_MASTERONLY;
	err = sqlx_repository_open_and_lock(repo, &n0, how, &sq3, NULL);
	if (err) {
		reply->send_error(0, err);
		return TRUE;
	}

	struct sqlx_repctx_s *repctx = NULL;
	if (!(flags&FLAG_LOCAL))
		err = sqlx_transaction_begin(sq3, &repctx);
	if (NULL == err) {
		gint64 status = sqlx_admin_get_status(sq3);
		if (ADMIN_STATUS_ENABLED == status)
			sqlx_admin_set_status(sq3, ADMIN_STATUS_FROZEN);
		else if (ADMIN_STATUS_FROZEN == status)
			err = NEWERROR(CODE_CONTAINER_FROZEN, "Container frozen");
		else
			err = NEWERROR(CODE_CONTAINER_DISABLED, "Container disabled");

		if (repctx) {
			err = sqlx_transaction_end(repctx, err);
		} else {
			sqlx_admin_save_lazy_tnx (sq3);
		}
	}
	sqlx_repository_unlock_and_close_noerror(sq3);

	if (NULL != err)
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	return TRUE;
}

static gboolean
_handler_DISABLE(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);
	GError *err;
	guint32 flags = 0;

	if (NULL != (err = _load_sqlx_name(reply, &name, &flags))) {
		reply->send_error(0, err);
		return TRUE;
	}

	const enum sqlx_open_type_e how = (flags&FLAG_LOCAL)
		? (SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK) : SQLX_OPEN_MASTERONLY;
	err = sqlx_repository_open_and_lock(repo, &n0, how, &sq3, NULL);
	if (err) {
		reply->send_error(0, err);
		return TRUE;
	}

	struct sqlx_repctx_s *repctx = NULL;
	if (!(flags&FLAG_LOCAL))
		err = sqlx_transaction_begin(sq3, &repctx);
	if (NULL == err) {
		gint64 status = sqlx_admin_get_status(sq3);
		if (ADMIN_STATUS_ENABLED == status)
			sqlx_admin_set_status(sq3, ADMIN_STATUS_DISABLED);
		else if (ADMIN_STATUS_FROZEN == status)
			err = NEWERROR(CODE_CONTAINER_FROZEN, "Container frozen");
		else
			err = NEWERROR(CODE_CONTAINER_DISABLED, "Container disabled");

		if (repctx) {
			err = sqlx_transaction_end(repctx, err);
		} else {
			sqlx_admin_save_lazy_tnx (sq3);
		}
	}
	sqlx_repository_unlock_and_close_noerror(sq3);

	if (NULL != err)
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	return TRUE;
}

static gboolean
_handler_DISABLE2(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);
	GError *err;
	guint32 flags = 0;

	if (NULL != (err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}

	const enum sqlx_open_type_e how = (flags&FLAG_LOCAL)
		? (SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK) : SQLX_OPEN_MASTERONLY;
	err = sqlx_repository_open_and_lock(repo, &n0, how, &sq3, NULL);
	if (err) {
		reply->send_error(0, err);
		return TRUE;
	}

	struct sqlx_repctx_s *repctx = NULL;
	if (!(flags&FLAG_LOCAL))
		err = sqlx_transaction_begin(sq3, &repctx);
	if (NULL == err) {
		gint64 status = sqlx_admin_get_status(sq3);
		if (ADMIN_STATUS_ENABLED == status)
			err = NEWERROR(CODE_CONTAINER_ENABLED, "Container enabled");
		else
			sqlx_admin_set_status(sq3, ADMIN_STATUS_DISABLED);

		if (repctx) {
			err = sqlx_transaction_end(repctx, err);
		} else {
			sqlx_admin_save_lazy_tnx (sq3);
		}
	}

	if (NULL != err)
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	sqlx_repository_unlock_and_close_noerror(sq3);
	return TRUE;
}

/* ------------------------------------------------------------------------- */

static void
_info_sqlite(GString *gstr)
{
	const char *s;

	g_string_append_static(gstr, "\"sqlite\":[");
	for (int i=0; NULL != (s = sqlite3_compileoption_get(i)); ++i) {
		if (i!=0)
			g_string_append_c(gstr, ',');
		oio_str_gstring_append_json_quote(gstr, s);
	}
	g_string_append_c(gstr, ']');
}

static void
_info_repository(struct sqlx_repository_s *r, GString *gstr)
{
	g_string_append_static(gstr, "\"sqliterepo\":{");
	oio_str_gstring_append_json_pair_int(gstr, "width", r->hash_width);
	g_string_append_c(gstr, ',');
	oio_str_gstring_append_json_pair_int(gstr, "depth", r->hash_depth);
	g_string_append_c(gstr, ',');
	oio_str_gstring_append_json_pair_boolean(gstr, "vacuum", r->flag_autovacuum);
	g_string_append_c(gstr, ',');
	oio_str_gstring_append_json_pair_boolean(gstr, "delete", r->flag_delete_on);
	g_string_append_c(gstr, '}');
}

static void
_info_elections(struct sqlx_repository_s *repo, GString *gstr)
{
	struct election_counts_s count = election_manager_count(
			sqlx_repository_get_elections_manager(repo));
	g_string_append_static(gstr, "\"elections\":{");
	oio_str_gstring_append_json_pair_int(gstr, "total", count.total);
	g_string_append_c(gstr, ',');
	oio_str_gstring_append_json_pair_int(gstr, "none", count.none);
	g_string_append_c(gstr, ',');
	oio_str_gstring_append_json_pair_int(gstr, "pending", count.pending);
	g_string_append_c(gstr, ',');
	oio_str_gstring_append_json_pair_int(gstr, "failed", count.failed);
	g_string_append_c(gstr, ',');
	oio_str_gstring_append_json_pair_int(gstr, "slave", count.slave);
	g_string_append_c(gstr, ',');
	oio_str_gstring_append_json_pair_int(gstr, "master", count.master);
	g_string_append_c(gstr, '}');
}

static void
_info_replication(struct sqlx_repository_s *repo, GString *gstr)
{
	const char* _mode2str(enum election_mode_e mode) {
		switch (mode) {
			case ELECTION_MODE_NONE:
				return "NONE";
			case ELECTION_MODE_QUORUM:
				return "QUORUM";
			case ELECTION_MODE_GROUP:
				return "GROUP";
			default:
				return "INVALID";
		}
	}

	oio_str_gstring_append_json_pair(gstr, "replication",
			_mode2str(election_manager_get_mode(
					sqlx_repository_get_elections_manager(repo))));
}

static void
_info_cache(struct sqlx_repository_s *repo, GString *gstr)
{
	struct cache_counts_s count = sqlx_cache_count(
			sqlx_repository_get_cache(repo));
	g_string_append_static(gstr, "\"cache\":{");
	oio_str_gstring_append_json_pair_int(gstr, "max", count.max);
	g_string_append_c(gstr, ',');
	oio_str_gstring_append_json_pair_int(gstr, "soft_max", count.soft_max);
	g_string_append_c(gstr, ',');
	oio_str_gstring_append_json_pair_int(gstr, "hot", count.hot);
	g_string_append_c(gstr, ',');
	oio_str_gstring_append_json_pair_int(gstr, "cold", count.cold);
	g_string_append_c(gstr, ',');
	oio_str_gstring_append_json_pair_int(gstr, "used", count.used);
	g_string_append_c(gstr, '}');
}

static void
_info_server(struct gridd_reply_ctx_s *reply, GString *gstr)
{
	g_string_append_static(gstr, "\"server\":{\"threads\":{");
	oio_str_gstring_append_json_pair_int(gstr, "active",
			g_thread_pool_get_num_threads(reply->client->server->pool_tcp));
	g_string_append_static(gstr, "},\"connections\":{");
	oio_str_gstring_append_json_pair_int(gstr, "clients",
			reply->client->server->cnx_clients);
	g_string_append_static(gstr, "}}");
}

static gboolean
_handler_INFO(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	reply->no_access();

	GString *gstr = g_string_sized_new(2048);
	g_string_append_c(gstr, '{');
	_info_sqlite(gstr);
	g_string_append_c(gstr, ',');
	_info_repository(repo, gstr);
	g_string_append_c(gstr, ',');
	_info_replication(repo, gstr);
	g_string_append_c(gstr, ',');
	_info_elections(repo, gstr);
	g_string_append_c(gstr, ',');
	_info_cache(repo, gstr);
	g_string_append_c(gstr, ',');
	_info_server(reply, gstr);
	g_string_append_c(gstr, ',');
	oio_str_gstring_append_json_pair(gstr, "version", OIOSDS_PROJECT_VERSION);
	g_string_append_c(gstr, '}');
	reply->add_body(metautils_gba_from_string(gstr->str));
	g_string_free(gstr, TRUE);

	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
_handler_LEANIFY(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo UNUSED, gpointer ignored UNUSED)
{
	guint size = 0;
	GError *err = metautils_message_extract_struint (reply->request,
			NAME_MSGKEY_SIZE, &size);
	if (err) {
		g_clear_error (&err);
		size = sqliterepo_release_size;
	}
	sqlite3_release_memory (size);
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
_handler_BALM(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	guint max = 0;
	gint64 inactivity = 0;
	GError *err = NULL;

	err = metautils_message_extract_struint(
			reply->request, NAME_MSGKEY_SIZE, &max);
	if (err) {
		g_clear_error(&err);
		max = 100;
	}

	err = metautils_message_extract_strint64(
			reply->request, NAME_MSGKEY_TIMEOUT, &inactivity);
	if (err) {
		g_clear_error(&err);
		inactivity = 0;
	}

	max = CLAMP(max,1,9999);
	inactivity = CLAMP(inactivity, 0, 86400);
	reply->subject("max=%u inactivity=%"G_GINT64_FORMAT, max, inactivity);

	guint count = election_manager_balance_masters(
			sqlx_repository_get_elections_manager(repo),
			max, inactivity * G_TIME_SPAN_SECOND);

	gchar *out = g_strdup_printf("%u", count);
	reply->add_body(metautils_gba_from_string(out));
	reply->send_reply(CODE_FINAL_OK, "OK");
	g_free(out);
	return TRUE;
}

/* ------------------------------------------------------------------------- */

static GError*
_extract_params(MESSAGE msg, TableSequence_t **params)
{
	gsize bsize = 0;
	void *b = metautils_message_get_BODY(msg, &bsize);
	if (!b)
		return NEWERROR(CODE_BAD_REQUEST, "Bad body");

	asn_codec_ctx_t ctx = {0};
	ctx.max_stack_size = ASN1C_MAX_STACK;
	asn_dec_rval_t rv = ber_decode(&ctx, &asn_DEF_TableSequence,
			(void**)params, b, bsize);
	if (rv.code != RC_OK)
		return NEWERROR(CODE_BAD_REQUEST, "body decoding error");
	return NULL;
}

static gboolean
_handler_QUERY(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	GError *err;
	guint32 flags = 0;
	TableSequence_t *params = NULL, *result = NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	/* unpack the parameters */
	if (NULL != (err = _load_sqlx_name(reply, &name, &flags))) {
		reply->send_error(0, err);
		return TRUE;
	}

	if (!g_str_has_prefix(name.type, NAME_SRVTYPE_SQLX".") &&
			strcmp(name.type, NAME_SRVTYPE_SQLX)) {
		reply->send_error(0, NEWERROR(CODE_BAD_REQUEST,
					"Invalid schema name, not prefixed with 'sqlx.'"));
		return TRUE;
	}

	if (NULL != (err = _extract_params(reply->request, &params))) {
		reply->send_error(0, err);
		return TRUE;
	}
	if (!params) {
		reply->send_error(0, NEWERROR(CODE_BAD_REQUEST, "No BODY"));
		return TRUE;
	}

	/* execute the request now */
	result = ASN1C_CALLOC(1, sizeof(struct TableSequence));
	err = do_query(reply, repo, &n0, params, result);

	if (params)
		asn_DEF_TableSequence.free_struct(&asn_DEF_TableSequence, params, FALSE);

	if (result) {
		if (!err) {
			GByteArray *encoded = g_byte_array_new();
			asn_enc_rval_t rv = der_encode(&asn_DEF_TableSequence,
					result, metautils_asn1c_write_gba, encoded);
			if (0 < rv.encoded)
				reply->add_body(encoded);
			else {
				g_byte_array_free(encoded, TRUE);
				err = NEWERROR(CODE_INTERNAL_ERROR, "Table encoding error: %s",
						rv.failed_type->name);
			}
			encoded = NULL;
		}
		asn_DEF_TableSequence.free_struct(&asn_DEF_TableSequence, result, FALSE);
	}

	if (err)
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
_handler_DESTROY(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	GError *err = NULL;
	guint32 flags = 0;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	if (NULL != (err = _load_sqlx_name(reply, &name, &flags))) {
		reply->send_error(0, err);
		return TRUE;
	}

	if (NULL != (err = do_destroy(reply, repo, &n0, flags&FLAG_LOCAL)))
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

/* ------------------------------------------------------------------------- */

typedef gboolean (*hook) (struct gridd_reply_ctx_s *, gpointer, gpointer);

static gboolean
sqlx_dispatch_all(struct gridd_reply_ctx_s *reply,
		gpointer gdata, gpointer hdata)
{
	hook hk;
	gchar admin[16];
	GError *err = NULL;
	gboolean res = TRUE;

	hk = (hook)hdata;

	/* Extract admin */
	memset(admin, 0, sizeof(admin));
	err = metautils_message_extract_string(reply->request,
			NAME_MSGKEY_ADMIN_COMMAND, admin, sizeof(admin));
	if (err)
		g_clear_error(&err);
	oio_ext_set_admin(oio_str_parse_bool(admin, FALSE));

	if (!hk) {
		GRID_INFO("No hook defined for this request, consider not yet implemented");
		reply->send_reply(CODE_NOT_IMPLEMENTED, "NOT IMPLEMENTED");
	} else {
		res = hk(reply, gdata, NULL);
	}

	oio_ext_set_admin(FALSE);
	return res;
}

const struct gridd_request_descr_s *
sqlx_repli_gridd_get_requests(void)
{
	static struct gridd_request_descr_s descriptions[] = {
		{NAME_MSGNAME_SQLX_HAS,              (hook) sqlx_dispatch_all, _handler_HAS},
		{NAME_MSGNAME_SQLX_PROPSET,          (hook) sqlx_dispatch_all, _handler_PROPSET},
		{NAME_MSGNAME_SQLX_PROPGET,          (hook) sqlx_dispatch_all, _handler_PROPGET},
		{NAME_MSGNAME_SQLX_PROPDEL,          (hook) sqlx_dispatch_all, _handler_PROPDEL},
		{NAME_MSGNAME_SQLX_ENABLE,           (hook) sqlx_dispatch_all, _handler_ENABLE},
		{NAME_MSGNAME_SQLX_FREEZE,           (hook) sqlx_dispatch_all, _handler_FREEZE},
		{NAME_MSGNAME_SQLX_DISABLE,          (hook) sqlx_dispatch_all, _handler_DISABLE},
		{NAME_MSGNAME_SQLX_DISABLE_DISABLED, (hook) sqlx_dispatch_all, _handler_DISABLE2},

		{NAME_MSGNAME_SQLX_STATUS,       (hook) sqlx_dispatch_all, _handler_STATUS},
		{NAME_MSGNAME_SQLX_DESCR,        (hook) sqlx_dispatch_all, _handler_DESCR},
		{NAME_MSGNAME_SQLX_ISMASTER,     (hook) sqlx_dispatch_all, _handler_ISMASTER},
		{NAME_MSGNAME_SQLX_USE,          (hook) sqlx_dispatch_all, _handler_USE},
		{NAME_MSGNAME_SQLX_EXITELECTION, (hook) sqlx_dispatch_all, _handler_EXIT},
		{NAME_MSGNAME_SQLX_PIPETO,       (hook) sqlx_dispatch_all, _handler_PIPETO},
		{NAME_MSGNAME_SQLX_PIPEFROM,     (hook) sqlx_dispatch_all, _handler_PIPEFROM},
		{NAME_MSGNAME_SQLX_REMOVE,       (hook) sqlx_dispatch_all, _handler_REMOVE},
		{NAME_MSGNAME_SQLX_SNAPSHOT,     (hook) sqlx_dispatch_all, _handler_SNAPSHOT},
		{NAME_MSGNAME_SQLX_DUMP,         (hook) sqlx_dispatch_all, _handler_DUMP},
		{NAME_MSGNAME_SQLX_RESTORE,      (hook) sqlx_dispatch_all, _handler_RESTORE},
		{NAME_MSGNAME_SQLX_REPLICATE,    (hook) sqlx_dispatch_all, _handler_REPLICATE},
		{NAME_MSGNAME_SQLX_GETVERS,      (hook) sqlx_dispatch_all, _handler_GETVERS},
		{NAME_MSGNAME_SQLX_RESYNC,       (hook) sqlx_dispatch_all, _handler_RESYNC},
		{NAME_MSGNAME_SQLX_VACUUM,       (hook) sqlx_dispatch_all, _handler_VACUUM},

		{NAME_MSGNAME_SQLX_INFO,    (hook) sqlx_dispatch_all, _handler_INFO},
		{NAME_MSGNAME_SQLX_LEANIFY, (hook) sqlx_dispatch_all, _handler_LEANIFY},
		{NAME_MSGNAME_SQLX_BALM,    (hook) sqlx_dispatch_all, _handler_BALM},

		{NULL, NULL, NULL}
	};

	return descriptions;
}

const struct gridd_request_descr_s *
sqlx_sql_gridd_get_requests(void)
{
	static struct gridd_request_descr_s descriptions[] = {
		{NAME_MSGNAME_SQLX_QUERY,   (hook) sqlx_dispatch_all, _handler_QUERY},
		{NAME_MSGNAME_SQLX_DESTROY, (hook) sqlx_dispatch_all, _handler_DESTROY},
		{NULL, NULL, NULL}
	};

	return descriptions;
}
