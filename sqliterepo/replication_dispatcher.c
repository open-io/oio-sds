/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2023 OVH SAS

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

#include <events/oio_events_queue.h>

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
#include "replication_dispatcher.h"
#include "internals.h"
#include "restoration.h"

#define EXTRACT_STRING(Name,Dst) do { \
	err = metautils_message_extract_string(reply->request, Name, Dst, sizeof(Dst)); \
	if (err != NULL) { \
		reply->send_error(0, err); \
		return TRUE; \
	} \
} while (0)

#define EXTRACT_STRING2(Name,Dst,Opt) do { \
	err = metautils_message_extract_string(reply->request, Name, Dst, sizeof(Dst)); \
	if (err != NULL) { \
		if(!Opt) { \
			reply->send_error(0, err); \
			return TRUE; \
		} else { \
			g_clear_error(&err); \
			Dst[0] = '\0'; \
		} \
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
			GRID_WARN("Replication failed on table [%.*s] of [%s.%s]: (%d) %s",
					table->name.size, table->name.buf,
					sq3->name.base, sq3->name.type,
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
	if (err) {
		return err;
	}

	// Check the election without trigger an election
	if (election_is_master(repo->election_manager, name)) {
		err = NEWERROR(CODE_IS_MASTER,
				"Restore operation is not allowed on the master service");
	}

	if (!err) {
		err = sqlx_repository_restore_base(sq3, dump, dump_size);
	}

	if (!err) {
		GRID_TRACE("Restore done!");
		/* See the comment in replicate_body_manage */
		sqlx_admin_reload(sq3);
		sqlx_repository_call_change_callback(sq3);
	} else {
		GRID_TRACE("Restore failed!");
	}

	sqlx_repository_unlock_and_close_noerror(sq3);
	return err;
}

static GError *
_restore2(struct sqlx_repository_s *repo, struct sqlx_name_s *name,
		const gchar *path)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = sqlx_repository_open_and_lock(repo, name,
		SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK|SQLX_OPEN_CREATE, &sq3, NULL);
	if (err) {
		return err;
	}

	// Check the election without trigger an election
	if (election_is_master(repo->election_manager, name)) {
		err = NEWERROR(CODE_IS_MASTER,
				"Restore operation is not allowed on the master service");
	}

	if (!err) {
		err = sqlx_repository_restore_from_file(sq3, path);
	}

	if (!err) {
		GRID_TRACE("Restore done!");
		/* See the comment in replicate_body_manage */
		sqlx_admin_reload(sq3);
		sqlx_repository_call_change_callback(sq3);
	} else {
		GRID_TRACE("Restore failed!");
	}

	sqlx_repository_unlock_and_close_noerror(sq3);
	return err;
}

static GError *
_restore_snapshot(struct sqlx_repository_s *repo, struct sqlx_name_s *name,
		const gchar *path, const gchar *peers, gchar **properties)
{
	struct stat bstats;
	if (stat(path, &bstats) != 0) {
		return NEWERROR(errno, "Failed to read snapshot: %s", strerror(errno));
	}
	struct sqlx_sqlite3_s *sq3 = NULL;
	/* The database snapshot file is here, open the base locally to avoid
	 * a redirection, in case the local service does not become the master.
	 * TODO(FVE): find a way to force the local peer to be the master.
	 * This would allow synchronous replication of the snapshot (provided
	 * it is small enough). */
	GError *err = sqlx_repository_timed_open_and_lock(repo, name,
			SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK|SQLX_OPEN_CREATE, peers,
			&sq3, NULL, oio_ext_get_deadline());
	if (!err) {
		err = sqlx_repository_restore_from_file(sq3, path);
		if (!err) {
			/* Set the new set of peers, avoid a lookup from meta1. */
			sqlx_admin_set_str(sq3, SQLX_ADMIN_PEERS, peers);
			/* Update base name */
			sqlx_admin_set_str(sq3, SQLX_ADMIN_BASENAME, name->base);
			/* Update properties
			 * If a property is suffixed by ".", then all properties prefixed by
			 * this will be updated/deleted.
			 */
			for (gchar **p=properties; !err && *p && *(p+1); p+=2) {
				if (oio_str_is_set(*(p+1))) {
					if (g_str_has_suffix(*p, ".")) {
						sqlx_admin_set_str_all_keys_with_prefix(sq3, *p, *(p+1));
					} else {
						sqlx_admin_set_str(sq3, *p, *(p+1));
					}
				} else {
					if (g_str_has_suffix(*p, ".")) {
						sqlx_admin_del_all_keys_with_prefix(sq3, *p, NULL, NULL);
					} else {
						sqlx_admin_del(sq3, *p);
					}
				}
			}
			sqlx_admin_save_lazy(sq3);
			sqlx_repository_call_change_callback(sq3);
		}
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
_snapshot_from(const gchar *src_addr, struct sqlx_repository_s *repo,
		struct sqlx_name_s *src_name, struct sqlx_name_s *dest_name,
		const gchar *dest_peers, gchar **dest_properties)
{
	GError *err = NULL;
	struct restore_ctx_s *ctx = NULL;
	err = _pipe_base_from(src_addr, repo, src_name, -1, &ctx);
	if (!err)
		err = _restore_snapshot(repo, dest_name, ctx->path, dest_peers,
				dest_properties);

	/* The snapshot exists locally, but there is still no election.
	 * Trigger one, forcing the other peers to download the database.
	 * We use sqlx_repository_status_base rather than sqlx_repository_use_base
	 * to wait for the election to establish before returning. */
	if (!err) {
		NAME2CONST(n0, *dest_name);
		err = sqlx_repository_status_base(repo, &n0, dest_peers,
				oio_ext_get_deadline());
		if (err && CODE_IS_REDIRECT(err->code))
			g_clear_error(&err);
	}

	restore_ctx_clear(&ctx);
	return err;
}

/* ------------------------------------------------------------------------- */

#define FLAG_LOCAL                  0x02
#define FLAG_NOCHECK                0x08
#define FLAG_CHUNKED                0x10
#define FLAG_FLUSH                  0x20
#define FLAG_PROPAGATE_TO_SHARDS    0x40

static GError *
_load_sqlx_name (struct gridd_reply_ctx_s *ctx,
		struct sqlx_name_inline_s *n, guint32 *pflags)
{
	GError *err;
	gchar
		ns[LIMIT_LENGTH_NSNAME],
		base[LIMIT_LENGTH_BASENAME],
		type[LIMIT_LENGTH_BASETYPE],
		suffix[LIMIT_LENGTH_BASESUFFIX];
	gboolean flush, nocheck, local, chunked, propagate_to_shards;

	flush = local = nocheck = chunked = propagate_to_shards = FALSE;

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
	err = metautils_message_extract_string(ctx->request,
			NAME_MSGKEY_BASESUFFIX, suffix, sizeof(suffix));
	if (err != NULL) {
		g_clear_error(&err);
		suffix[0] = '\0';
	}

	local = metautils_message_extract_flag(ctx->request,
			NAME_MSGKEY_LOCAL, FALSE);
	nocheck = metautils_message_extract_flag(ctx->request,
			NAME_MSGKEY_NOCHECK, FALSE);
	chunked = metautils_message_extract_flag(ctx->request,
			NAME_MSGKEY_CHUNKED, FALSE);
	flush = metautils_message_extract_flag(ctx->request,
			NAME_MSGKEY_FLUSH, FALSE);
	propagate_to_shards = metautils_message_extract_flag(ctx->request,
			NAME_MSGKEY_PROPAGATE_SHARDS, FALSE);

	ctx->subject(
			"base:%s.%s\thexid:%.*s\top_type:%s",
			base, type,
			STRLEN_CONTAINERID - 1, base,
			local ? "local" : "replicated"
	);

	memset(n, 0, sizeof(*n));
	g_strlcpy(n->ns, ns, sizeof(n->ns));
	g_strlcpy(n->base, base, sizeof(n->base));
	g_strlcpy(n->type, type, sizeof(n->type));
	g_strlcpy(n->suffix, suffix, sizeof(n->suffix));

	if (pflags) {
		*pflags = 0;
		*pflags |= (local ? FLAG_LOCAL : 0);
		*pflags |= (nocheck ? FLAG_NOCHECK : 0);
		*pflags |= (chunked ? FLAG_CHUNKED : 0);
		*pflags |= (flush ? FLAG_FLUSH : 0);
		*pflags |= (propagate_to_shards ? FLAG_PROPAGATE_TO_SHARDS : 0);
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

	// Check the election without trigger an election
	if (election_is_master(repo->election_manager, &n0)) {
		err = NEWERROR(CODE_IS_MASTER,
				"Replicate operation is not allowed on the master service");
	}

	if (!err) {
		/* Unpack the body from the message, decode it */
		err = replicate_body_parse(sq3, b, bsize);
	}

	if (!err) {
		reply->send_reply(CODE_FINAL_OK, "OK");
	} else {
		reply->send_error(0, err);
	}

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

	if ((err = sqlx_repository_status_base(repo, &n0, NULL, reply->deadline)))
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

	err = sqlx_repository_status_base(repo, &n0, NULL, reply->deadline);
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
	reply->subject("base:%s.%s\ttarget:%s", name.base, name.type, target);

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
	EXTRACT_STRING(NAME_MSGKEY_SRC, source);
	_maybe_override_check_type(reply, &check_type);
	reply->subject("base:%s.%s\tcopy_source:%s", name.base, name.type, source);

	if ((err = _pipe_from(source, repo, &n0, check_type)))
		reply->send_error(0, err);
	else
		reply->send_reply(CODE_FINAL_OK, "OK");

	return TRUE;
}

static gboolean
_handler_LOCAL_COPY(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo UNUSED, gpointer ignored UNUSED)
{
	GError *err;
	gchar source[64];
	gchar suffix[LIMIT_LENGTH_BASESUFFIX]= {'\0'};
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	err = _load_sqlx_name(reply, &name, NULL);
	if (err != NULL) {
		reply->send_error(0, err);
		return TRUE;
	}

	EXTRACT_STRING2(NAME_MSGKEY_SUFFIX, suffix, TRUE);
	if (!*suffix) {
		reply->send_error(0, BADREQ("Missing suffix for local copy"));
		return TRUE;
	}
	struct sqlx_sqlite3_s *sq3 = NULL;
	err = sqlx_repository_open_and_lock(repo, &n0,
			SQLX_OPEN_LOCAL, &sq3, NULL);
	if (err != NULL) {
		reply->send_error(0, err);
		return TRUE;
	}
	gchar *copy_path = g_strdup_printf("%s.%s",sq3->path_inline, suffix);
	err = metautils_syscall_copy_file(sq3->path_inline, copy_path);
	if (err != NULL) {
		g_prefix_error(&err, "Failed to make local copy of %s to %s: ",
				sq3->path_inline, copy_path);
		g_free(copy_path);
		reply->send_error(0, err);
		return TRUE;
	}
	g_free(copy_path);
	sqlx_repository_unlock_and_close_noerror(sq3);

	EXTRACT_STRING(NAME_MSGKEY_SRC, source);
	reply->subject("base:%s.%s\tcopy_source:%s", name.base, name.type, source);

	reply->send_reply(CODE_FINAL_OK, "OK");

	return TRUE;
}

static gboolean
_handler_SNAPSHOT(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	GError *err;
	gchar src_addr[64];
	gchar src_base[LIMIT_LENGTH_BASENAME];
	gchar src_suffix[LIMIT_LENGTH_BASESUFFIX];
	gchar *dest_peers = NULL;
	gchar **dest_properties = NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);

	if ((err = _load_sqlx_name(reply, &name, NULL))) {
		reply->send_error(0, err);
		return TRUE;
	}

	gsize length = 0;
	void *body = metautils_message_get_BODY(reply->request, &length);
	if (body) {
		err = KV_decode_buffer(body, length, &dest_properties);
		if (err)
			goto cleanup;
	}

	EXTRACT_STRING(NAME_MSGKEY_SRC, src_addr);
	EXTRACT_STRING(NAME_MSGKEY_SRC_BASE, src_base);
	EXTRACT_STRING2(NAME_MSGKEY_SRC_SUFFIX, src_suffix, TRUE);

	reply->subject("base:%s.%s\tcopy_source:%s", name.base, name.type, src_addr);
	_load_sqlx_peers(reply, &dest_peers);

	struct sqlx_name_s src = {name.ns, src_base, name.type, src_suffix};
	err = _snapshot_from(src_addr, repo, &src, &n0, dest_peers,
			dest_properties);

cleanup:
	if (err) {
		reply->send_error(0, err);
	} else {
		reply->send_reply(CODE_FINAL_OK, "OK");
	}

	g_strfreev(dest_properties);
	g_free(dest_peers);
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
	GError *err = NULL;
	struct sqlx_name_inline_s name;
	NAME2CONST(n0, name);
	guint32 flags = 0;

	if (NULL != (err = _load_sqlx_name(reply, &name, &flags))) {
		reply->send_error(0, err);
		return TRUE;
	}

	const enum sqlx_open_type_e how = (flags & FLAG_LOCAL)
		? (SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK) : SQLX_OPEN_MASTERONLY;
	err = sqlx_repository_vacuum(repo, &n0, how);

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
				sq3, url, db_properties, FALSE);
		oio_url_clean(url);
	}

	sqlx_repository_unlock_and_close_noerror(sq3);

	if (!err) {
		// Tip for forcing property sharing with shards
		gchar **shared_properties = oio_ext_get_shared_properties();
		if (shared_properties) {
			err = NEWERROR(CODE_REDIRECT_SHARD, "null");
		}
	}

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
		/* The pointer array is no longer used,
		 * but the content (dynamically allocated) is still used. */
		g_free(keys);

		if (oio_ext_is_admin()) {
			GPtrArray *stats = sqlx_admin_get_usage(sq3);
			if (stats) {
				for(guint i=0; i < stats->len; i++) {
					g_ptr_array_add(tmp, g_ptr_array_index(stats, i));
				}
				/* The pointer array is no longer used,
				 * but the content (dynamically allocated) is still used. */
				g_ptr_array_free(stats, TRUE);
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
				sq3, url, db_properties, flags & FLAG_PROPAGATE_TO_SHARDS);
		oio_url_clean(url);
	}

	sqlx_repository_unlock_and_close_noerror(sq3);

	if (!err) {
		// Tip for forcing property sharing with shards
		gchar **shared_properties = oio_ext_get_shared_properties();
		if (shared_properties) {
			err = NEWERROR(CODE_REDIRECT_SHARD, "null");
		}
	}

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

	const enum sqlx_open_type_e how = ((flags&FLAG_LOCAL)
		? (SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK) : SQLX_OPEN_MASTERONLY)
		| SQLX_OPEN_URGENT;
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
	g_string_append_static(gstr, "\"VERSION_COMPILED=");
	g_string_append_static(gstr, SQLITE_VERSION);
	g_string_append_static(gstr, "\",\"VERSION_RUNTIME=");
	oio_str_gstring_append_json_string(gstr, sqlite3_libversion());
	g_string_append_c(gstr, '"');
	for (int i=0; NULL != (s = sqlite3_compileoption_get(i)); ++i) {
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
_info_elections(struct sqlx_repository_s *repo, GString *gstr,
		gboolean prometheus_format)
{
	struct election_counts_s count = election_manager_count(
			sqlx_repository_get_elections_manager(repo));
	if (prometheus_format) {
		g_string_append_printf(gstr,
				"meta_base_elections{status=\"none\"} %u\n"
				"meta_base_elections{status=\"pending\"} %u\n"
				"meta_base_elections{status=\"failed\"} %u\n"
				"meta_base_elections{status=\"slave\"} %u\n"
				"meta_base_elections{status=\"master\"} %u\n",
				count.none, count.pending, count.failed,
				count.slave, count.master);
	} else {
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
_info_cache(struct sqlx_repository_s *repo, GString *gstr,
		gboolean prometheus_format)
{
	struct cache_counts_s count = sqlx_cache_count(
			sqlx_repository_get_cache(repo));
	if (prometheus_format) {
		g_string_append_printf(gstr,
				"meta_base_cache{type=\"max\"} %u\n"
				"meta_base_cache{type=\"soft_max\"} %u\n"
				"meta_base_cache{type=\"hot\"} %u\n"
				"meta_base_cache{type=\"cold\"} %u\n"
				"meta_base_cache{type=\"used\"} %u\n",
				count.max, count.soft_max, count.hot, count.cold, count.used);
	} else {
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

static void
_append_request_stats(GByteArray *body)
{
	GArray *stats = network_server_stat_getall();
	network_server_stats_to_prometheus(stats, body);
	g_array_free(stats, TRUE);
}

static gboolean
_handler_INFO(struct gridd_reply_ctx_s *reply,
		struct sqlx_repository_s *repo, gpointer ignored UNUSED)
{
	reply->no_access();

	gchar format[64] = {0};
	metautils_message_extract_string_noerror(
			reply->request, NAME_MSGKEY_FORMAT, format, sizeof(format));

	GString *gstr = g_string_sized_new(2048);
	GByteArray *body = NULL;
	if (g_strcmp0(format, "prometheus") == 0) {
		_info_elections(repo, gstr, TRUE);
		_info_cache(repo, gstr, TRUE);
		oio_events_stats_to_prometheus(
				oio_server_service_id, oio_server_namespace, gstr);
		body = metautils_gba_from_string(gstr->str);
		_append_request_stats(body);
	} else {
		g_string_append_c(gstr, '{');
		_info_sqlite(gstr);
		g_string_append_c(gstr, ',');
		_info_repository(repo, gstr);
		g_string_append_c(gstr, ',');
		_info_replication(repo, gstr);
		g_string_append_c(gstr, ',');
		_info_elections(repo, gstr, FALSE);
		g_string_append_c(gstr, ',');
		_info_cache(repo, gstr, FALSE);
		g_string_append_c(gstr, ',');
		_info_server(reply, gstr);
		g_string_append_c(gstr, ',');
		oio_str_gstring_append_json_pair(gstr, "version", OIOSDS_PROJECT_VERSION);
		g_string_append_c(gstr, '}');
		body = metautils_gba_from_string(gstr->str);
	}
	reply->add_body(body);
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
	gboolean rejoin = TRUE;
	gchar rejoin_str[16] = {0};
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

	/* Shall we join as slave an election we were previously master on?
	 * If not, we will join the election only if needed. */
	EXTRACT_STRING2(NAME_MSGKEY_REJOIN, rejoin_str, TRUE);
	rejoin = oio_str_parse_bool(rejoin_str, rejoin);

	max = CLAMP(max, 1, 9999);
	inactivity = CLAMP(inactivity, 0, 86400);
	reply->subject("max_int:%u\tinactivity_int:%"G_GINT64_FORMAT, max, inactivity);

	guint count = election_manager_balance_masters(
			sqlx_repository_get_elections_manager(repo),
			max, inactivity * G_TIME_SPAN_SECOND, rejoin);

	gchar *out = g_strdup_printf("%u", count);
	reply->add_body(metautils_gba_from_string(out));
	reply->send_reply(CODE_FINAL_OK, "OK");
	g_free(out);
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
	gchar user_agent[1024];
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
	/* Extract user-agent */
	memset(user_agent, 0, sizeof(user_agent));
	err = metautils_message_extract_string(reply->request,
			NAME_MSGKEY_USER_AGENT, user_agent, sizeof(user_agent));
	if (err)
		g_clear_error(&err);
	oio_ext_set_user_agent(user_agent);
	oio_ext_set_shared_properties(NULL);
	oio_ext_allow_long_timeout(FALSE);

	if (!hk) {
		GRID_INFO("No hook defined for this request, consider not yet implemented");
		reply->send_reply(CODE_NOT_IMPLEMENTED, "NOT IMPLEMENTED");
	} else {
		res = hk(reply, gdata, NULL);
	}

	oio_ext_set_admin(FALSE);
	oio_ext_set_user_agent(NULL);
	oio_ext_set_shared_properties(NULL);
	oio_ext_allow_long_timeout(FALSE);
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

		{NAME_MSGNAME_SQLX_LOCAL_COPY,    (hook) sqlx_dispatch_all, _handler_LOCAL_COPY},

		{NULL, NULL, NULL}
	};

	return descriptions;
}
