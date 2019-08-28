/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

			metautils_asn_INTEGER_to_int64(&(row->rowid), &rowid);
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
							metautils_asn_INTEGER_to_int64(&(field->value.choice.i), &i64);
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

			metautils_asn_INTEGER_to_int64(&(row->rowid), &rowid);
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
		const gchar *path)
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
	GError *err = sqlx_repository_open_and_lock(repo, name,
			SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK|SQLX_OPEN_CREATE, &sq3, NULL);
	if (!err) {
		struct sqlx_repctx_s *repctx = NULL;
		if (sync_repli)
			err = sqlx_transaction_begin(sq3, &repctx);
		if (!err) {
			err = sqlx_repository_restore_from_file(sq3, path);
			if (!err) {
				sqlx_repository_call_change_callback(sq3);
				/* Reset the set of peers.
				 * It will be loaded from meta1 when needed.
				 * FIXME(FVE): the request should define the peer set. */
				sqlx_admin_del(sq3, SQLX_ADMIN_PEERS);
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
		GByteArray **result)
{
	GRID_TRACE2("%s(%p,%s,%s,%p)", __FUNCTION__, repo, name->base, name->type, result);

	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = sqlx_repository_open_and_lock(repo, name,
			SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK, &sq3, NULL);
	if (NULL != err)
		return err;

	GByteArray *dump = NULL;
	err = sqlx_repository_dump_base_gba(sq3, &dump);
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
			_dump_chunked_cb, NULL);

	sqlx_repository_unlock_and_close_noerror(sq3);
	return err;
}

static GError *
_pipe_base_from(const gchar *source, struct sqlx_repository_s *repo,
		struct sqlx_name_s *name, struct restore_ctx_s **ctx)
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

	return peer_dump(source, name, TRUE, _pipe_from_cb, NULL, oio_ext_get_deadline());
}

static GError *
_pipe_from(const gchar *source, struct sqlx_repository_s *repo,
		struct sqlx_name_s *name)
{
	GError *err;
	struct restore_ctx_s *ctx = NULL;
	err = _pipe_base_from(source, repo, name, &ctx);
	if (!err)
		err = _restore2(repo, name, ctx->path);

	restore_ctx_clear(&ctx);
	return err;
}

static GError *
_snapshot_from(const gchar *source, struct sqlx_repository_s *repo,
		struct sqlx_name_s *source_name, struct sqlx_name_s *dest_name)
{
	GError *err = NULL;
	struct restore_ctx_s *ctx = NULL;
	err = _pipe_base_from(source, repo, source_name, &ctx);
	if (!err)
		err = _restore_snapshot(repo, dest_name, ctx->path);

	restore_ctx_clear(&ctx);
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

	if (NULL != (err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}

	err = sqlx_repository_open_and_lock(repo, &n0,
			SQLX_OPEN_CREATE|SQLX_OPEN_LOCAL|SQLX_OPEN_URGENT, &sq3, NULL);
	if (NULL != err) {
		g_prefix_error(&err, "Open/lock: ");
		reply->send_error(0, err);
		return TRUE;
	}

	err = sqlx_repository_get_version(sq3, &version);
	sqlx_repository_unlock_and_close_noerror(sq3);

	if (NULL != err) {
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

	if (NULL != (err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}

	const gboolean master = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_MASTER, FALSE);

	if (NULL != (err = sqlx_repository_use_base(repo, &n0, master, TRUE, NULL)))
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");
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
	err = _dump(repo, &n0, &dump);
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
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	if (NULL != (err = _load_sqlx_name(reply, &name, &flags))) {
		reply->send_error(0, err);
		return TRUE;
	}

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
		err = _dump_chunked(repo, &n0, _send_part);
	} else {
		GByteArray *dump = NULL;
		/* Open and lock the base */
		err = _dump(repo, &n0, &dump);
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
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	if (NULL != (err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}
	EXTRACT_STRING("SRC", source);
	reply->subject("%s.%s|%s", name.base, name.type, source);

	if (NULL != (err = _pipe_from(source, repo, &n0)))
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
	full_base_name = g_strconcat(cid, seq_num, NULL);
	struct sqlx_name_s src = {name.ns, full_base_name ,name.type};
	if ((err = _snapshot_from(source, repo, &src, &no)))
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	g_free(full_base_name);
	return TRUE;
}

static gboolean
_handler_RESYNC(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	GError *err = NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	if (NULL != (err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}

	struct sqlx_sqlite3_s *sq3 = NULL;
	err = sqlx_repository_open_and_lock(repo, &n0,
			SQLX_OPEN_CREATE|SQLX_OPEN_SLAVEONLY, &sq3, NULL);
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
		g_prefix_error(&err, "Open/lock: ");
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
		g_ptr_array_add (tmp, NULL);
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

static const char*
_mode2str(enum election_mode_e mode)
{
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

static void
_info_replication(struct sqlx_repository_s *repo, GString *gstr)
{
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

typedef gboolean (*hook) (struct gridd_reply_ctx_s *, gpointer, gpointer);

const struct gridd_request_descr_s *
sqlx_repli_gridd_get_requests(void)
{
	static struct gridd_request_descr_s descriptions[] = {
		{NAME_MSGNAME_SQLX_HAS,              (hook) _handler_HAS,      NULL},
		{NAME_MSGNAME_SQLX_PROPSET,          (hook) _handler_PROPSET,  NULL},
		{NAME_MSGNAME_SQLX_PROPGET,          (hook) _handler_PROPGET,  NULL},
		{NAME_MSGNAME_SQLX_PROPDEL,          (hook) _handler_PROPDEL,  NULL},
		{NAME_MSGNAME_SQLX_ENABLE,           (hook) _handler_ENABLE,   NULL},
		{NAME_MSGNAME_SQLX_FREEZE,           (hook) _handler_FREEZE,   NULL},
		{NAME_MSGNAME_SQLX_DISABLE,          (hook) _handler_DISABLE,  NULL},
		{NAME_MSGNAME_SQLX_DISABLE_DISABLED, (hook) _handler_DISABLE2, NULL},

		{NAME_MSGNAME_SQLX_STATUS,       (hook) _handler_STATUS,    NULL},
		{NAME_MSGNAME_SQLX_DESCR,        (hook) _handler_DESCR,     NULL},
		{NAME_MSGNAME_SQLX_ISMASTER,     (hook) _handler_ISMASTER,  NULL},
		{NAME_MSGNAME_SQLX_USE,          (hook) _handler_USE,       NULL},
		{NAME_MSGNAME_SQLX_EXITELECTION, (hook) _handler_EXIT,      NULL},
		{NAME_MSGNAME_SQLX_PIPETO,       (hook) _handler_PIPETO,    NULL},
		{NAME_MSGNAME_SQLX_PIPEFROM,     (hook) _handler_PIPEFROM,  NULL},
		{NAME_MSGNAME_SQLX_REMOVE,       (hook) _handler_REMOVE,    NULL},
		{NAME_MSGNAME_SQLX_SNAPSHOT,     (hook) _handler_SNAPSHOT,  NULL},
		{NAME_MSGNAME_SQLX_DUMP,         (hook) _handler_DUMP,      NULL},
		{NAME_MSGNAME_SQLX_RESTORE,      (hook) _handler_RESTORE,   NULL},
		{NAME_MSGNAME_SQLX_REPLICATE,    (hook) _handler_REPLICATE, NULL},
		{NAME_MSGNAME_SQLX_GETVERS,      (hook) _handler_GETVERS,   NULL},
		{NAME_MSGNAME_SQLX_RESYNC,       (hook) _handler_RESYNC,    NULL},
		{NAME_MSGNAME_SQLX_VACUUM,       (hook) _handler_VACUUM,    NULL},

		{NAME_MSGNAME_SQLX_INFO,    (hook) _handler_INFO,      NULL},
		{NAME_MSGNAME_SQLX_LEANIFY, (hook) _handler_LEANIFY,   NULL},
		{NAME_MSGNAME_SQLX_BALM,    (hook) _handler_BALM,      NULL},

		{NULL, NULL, NULL}
	};

	return descriptions;
}
