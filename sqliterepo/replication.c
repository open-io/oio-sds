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
# define G_LOG_DOMAIN "grid.sqlx.repli"
#endif

#include <stddef.h>
#include <unistd.h>

#include <metatypes.h>
#include <metautils.h>
#include <metacomm.h>
#include "../metautils/lib/hashstr.h"
#include "../metautils/lib/loggers.h"

#include <glib.h>

#include "./internals.h"
#include "./election.h"
#include "./version.h"
#include "./sqliterepo.h"
#include "./sqlx_remote.h"
#include "./gridd_client.h"

#include <RowFieldSequence.h>
#include <RowFieldValue.h>
#include <RowField.h>
#include <Row.h>
#include <RowSet.h>
#include <RowName.h>
#include <TableHeader.h>
#include <Table.h>
#include <TableSequence.h>

#include <asn_codecs.h>

/* Collects the changes in a DB context */

struct sqlx_repctx_s
{
	gboolean huge;
	int changes; /**< explicit changes */
	struct sqlx_sqlite3_s *sq3;
	TableSequence_t sequence;
	GTree *pending;
};

static GQuark gquark_log = 0;

static guint
group_to_quorum(guint group_size)
{
	return 1+(group_size / 2);
}

/* ------------------------------------------------------------------------- */

static void
dump_request(const gchar *func, gchar **targets,
		const gchar *rn, struct sqlx_name_s *n)
{
	gchar *tmp = g_strjoinv("|", targets);
	GRID_DEBUG("%s [%s][%s] to %s (%s)", rn, n->base, n->type, tmp, func);
	g_free(tmp);
}

static GTree*
context_get_pending_table(GTree *tree, const hashstr_t *key)
{
	GTree *subtree;

	if (NULL != (subtree = g_tree_lookup(tree, key)))
		return subtree;

	subtree = g_tree_new_full(hashstr_quick_cmpdata, NULL, g_free, NULL);
	g_tree_insert(tree, hashstr_dup(key), subtree);
	return subtree;
}

static void
context_flush_pending(struct sqlx_repctx_s *ctx)
{
	void _clean_value(gpointer v) {
		if (v)
			g_tree_destroy(v);
	}

	if (!ctx)
		return;
	if (ctx->pending)
		g_tree_destroy(ctx->pending);
	ctx->pending = g_tree_new_full(hashstr_quick_cmpdata, NULL,
			g_free, _clean_value);
}

static void
context_flush_rowsets(struct sqlx_repctx_s *ctx)
{
	void _clean_value(gpointer v) {
		if (!v)
			return;
		asn_DEF_Table.free_struct(&asn_DEF_Table, v, FALSE);
	}

	if (!ctx)
		return;

	asn_DEF_TableSequence.free_struct(&asn_DEF_TableSequence,
			&(ctx->sequence), TRUE);
	memset(&(ctx->sequence), 0, sizeof(ctx->sequence));
}

/* Encoder ----------------------------------------------------------------- */

static void
load_table_header(sqlite3_stmt *stmt, Table_t *t)
{
	guint32 i, max;

	GRID_TRACE2("%s(%p,%p)", __FUNCTION__, stmt, t);

	for (i=0,max=sqlite3_data_count(stmt); i<max ;i++) {
		const gchar *cname;
		RowName_t *rname;

		cname = sqlite3_column_name(stmt, i);
		rname = g_malloc0(sizeof(*rname));
		asn_uint32_to_INTEGER(&(rname->pos), i);
		OCTET_STRING_fromBuf(&(rname->name), cname, strlen(cname));
		asn_sequence_add(&(t->header.list), rname);

		GRID_TRACE2(" > column (%u,%s)", i, cname);
	}
}

void
load_statement(sqlite3_stmt *stmt, Row_t *row, Table_t *table,
		gboolean noreal)
{
	guint32 i, max;

	if (table->header.list.count <= 0) /* Lazy header loading */
		load_table_header(stmt, table);

	if (!row->fields) /* Lazy memory allocation */
		row->fields = g_malloc0(sizeof(struct RowFieldSequence));

	for (i=0,max=sqlite3_data_count(stmt); i<max ;i++) {
		struct RowField *rf;

		rf = g_malloc0(sizeof(*rf));
		asn_uint32_to_INTEGER(&(rf->pos), i);
		/*rf->value.present = RowFieldValue_PR_NOTHING;*/
		rf->value.present = RowFieldValue_PR_n;

		switch (sqlite3_column_type(stmt, i)) {
			case SQLITE_NULL:
				GRID_TRACE2(" >> null   (%u)", i);
				rf->value.present = RowFieldValue_PR_n;
				break;
			case SQLITE_INTEGER:
				do {
					gint64 i64 = sqlite3_column_int64(stmt, i);
					asn_int64_to_INTEGER(&(rf->value.choice.i), i64);
					rf->value.present = RowFieldValue_PR_i;
					GRID_TRACE2(" >> int    (%u,%"G_GINT64_FORMAT")", i, i64);
				} while (0);
				break;
			case SQLITE_FLOAT:
				if (!noreal) {
					gdouble d = sqlite3_column_double(stmt, i);
					asn_double2REAL(&(rf->value.choice.f), d);
					rf->value.present = RowFieldValue_PR_f;
					GRID_TRACE2(" >> float  (%u,%f)", i, d);
				}
				else {
					const guint8 *t = sqlite3_column_text(stmt, i);
					OCTET_STRING_fromBuf(&(rf->value.choice.s), (char*)t, strlen((char*)t));
					rf->value.present = RowFieldValue_PR_s;
					GRID_TRACE2(" >> Sfloat (%u,%s)", i, t);
				}
				break;
			case SQLITE_TEXT:
				do {
					const guint8 *t = sqlite3_column_text(stmt, i);
					gsize tsize = sqlite3_column_bytes(stmt, i);
					OCTET_STRING_fromBuf(&(rf->value.choice.s), (char*)t, tsize);
					rf->value.present = RowFieldValue_PR_s;
					GRID_TRACE2(" >> char   (%u,%"G_GSIZE_FORMAT")", i, tsize);
				} while (0);
				break;
			case SQLITE_BLOB:
				do {
					const void *b = sqlite3_column_blob(stmt, i);
					gsize bsize = sqlite3_column_bytes(stmt, i);
					OCTET_STRING_fromBuf(&(rf->value.choice.b), (char*)b, bsize);
					rf->value.present = RowFieldValue_PR_b;
					GRID_TRACE2(" >> blob   (%u,%"G_GSIZE_FORMAT")", i, bsize);
				} while (0);
				break;
			default:
				GRID_TRACE2(" >> ?     (%u)", i);
				rf->value.present = RowFieldValue_PR_n;
				break;
		}
		asn_sequence_add(&(row->fields->list), rf);
	}
}

static void
load_table_row(sqlite3 *db, const hashstr_t *name, gint64 rowid, Row_t *row,
		Table_t *table)
{
	int rc;
	sqlite3_stmt *stmt = NULL;
	gchar *sql;

	GRID_TRACE2("%s(%p,%s,%"G_GINT64_FORMAT",%p,%p)", __FUNCTION__,
			db, hashstr_str(name), rowid, row, table);

	sql = g_strdup_printf("SELECT * FROM %s WHERE ROWID = ?", hashstr_str(name));
	sqlite3_prepare_debug(rc, db, sql, -1, &stmt, NULL);
	g_free(sql);

	sqlite3_bind_int64(stmt, 1, rowid);
	while (SQLITE_ROW == (rc = sqlite3_step(stmt)))
		load_statement(stmt, row, table, FALSE);

	sqlite3_finalize_debug(rc, stmt);
}

static void
context_pending_inc_versions(struct sqlx_repctx_s *ctx)
{
	gboolean _on_table(gpointer k, gpointer v, gpointer u0) {
		GTree *rows = v;
		(void) u0;

		GRID_TRACE2("%s(%s,%p,%p)", __FUNCTION__, hashstr_str(k), v, u0);
		if (g_tree_nnodes(rows) > 0) {
			if (0 != g_ascii_strcasecmp(hashstr_str(k), "main.admin"))
				version_increment(ctx->sq3->versions, hashstr_str(k));
		}
		return FALSE;
	}

	GRID_TRACE2("%s(%p)", __FUNCTION__, ctx);
	if (ctx->pending)
		g_tree_foreach(ctx->pending, _on_table, NULL);
}

static void
context_pending_to_rowset(sqlite3 *db, struct sqlx_repctx_s *ctx)
{
	gboolean _on_table(gpointer name, gpointer rows, gpointer u0) {
		Table_t *table;
		(void) u0;

		gboolean _on_row(gpointer k, gpointer v, gpointer u1) {
			Row_t *row;
			gint64 rowid = *((gint64*)k);
			guint deleted = GPOINTER_TO_UINT(v);
			(void) u1;

			GRID_TRACE2("%s(%s,%"G_GINT64_FORMAT",%d)", __FUNCTION__,
					hashstr_str(name), rowid, deleted);

			row = g_malloc0(sizeof(*row));
			asn_int64_to_INTEGER(&(row->rowid), rowid);
			if (!deleted)
				load_table_row(db, name, rowid, row, table);

			asn_sequence_add(&(table->rows.list), row);
			return FALSE;
		}

		GRID_TRACE2("%s(%s,%p)", __FUNCTION__, hashstr_str(name), rows);

		table = g_malloc0(sizeof(Table_t));
		OCTET_STRING_fromBuf(&(table->name),
				hashstr_str(name), hashstr_len(name));
		g_tree_foreach(rows, _on_row, NULL);
		asn_sequence_add(&(ctx->sequence.list), table);
		return FALSE;
	}

	GRID_TRACE2("%s(%p,%p)", __FUNCTION__, db, ctx);
	SQLX_ASSERT(db != NULL);
	SQLX_ASSERT(ctx != NULL);
	SQLX_ASSERT(ctx->pending != NULL);
	g_tree_foreach(ctx->pending, _on_table, NULL);
	context_flush_pending(ctx);
}

/* HOOKS ------------------------------------------------------------------- */

static GError*
_replicate_on_peers(gchar **peers, struct sqlx_repctx_s *ctx)
{
	GError *err = NULL;
	struct sqlx_name_s n;
	GByteArray *encoded;
	struct client_s **clients, **pc;
	guint count_errors = 0, count_success = 0;

	n.ns = "";
	n.base = ctx->sq3->logical_name;
	n.type =  ctx->sq3->logical_type;
	dump_request(__FUNCTION__, peers, "SQLX_REPLICATE", &n);

	encoded = sqlx_pack_REPLICATE(&n, &(ctx->sequence));
	clients = gridd_client_create_many(peers, encoded, NULL, NULL);
	g_byte_array_unref(encoded);

	gridd_clients_start(clients);
	err = gridd_clients_loop(clients);
	if (!err) {
		for (pc=clients; pc && *pc ;pc++) {
			GError *e = gridd_client_error(*pc);
			if (NULL != e) {
				if (e->code == CODE_PIPEFROM) {
					++ count_success;
					/* The concerned peer will trigger a RESYNC */
				}
				else
					++ count_errors;
				g_clear_error(&e);
			}
			else
				++ count_success;
		}

		++ count_success; /* JFS: local success! */
		guint groupsize = 1 + g_strv_length(peers);
		if (ctx->sq3->config->mode == ELECTION_MODE_GROUP) {
			if (count_success < groupsize)
				err = g_error_new(gquark_log, 500,
						"Not enough successes, no group");
		}
		else {
			if (count_success < group_to_quorum(groupsize))
				err = g_error_new(gquark_log, 500,
						"Not enough successes, no quorum");
		}
	}

	gridd_clients_free(clients);
	return err;
}

static int
hook_commit(gpointer d)
{
	struct sqlx_repctx_s *ctx = d;
	GError *err = NULL;
	gchar **peers = NULL;

	GRID_TRACE2("%s(%p)", __FUNCTION__, ctx);
	SQLX_ASSERT(ctx != NULL);
	SQLX_ASSERT(ctx->sq3 != NULL);
	SQLX_ASSERT(ctx->sq3->config != NULL);
	SQLX_ASSERT(ctx->sq3->config->get_peers != NULL);

	if (ctx->sequence.list.count <= 0) {
		GRID_DEBUG("Empty transaction!");
		return 0;
	}

	peers = ctx->sq3->config->get_peers(ctx->sq3->config->ctx,
			ctx->sq3->logical_name, ctx->sq3->logical_type);
	if (!peers || !*peers) {
		GRID_DEBUG("No peer located, no replication to do");
		err = NULL;
	}
	else {
		err = _replicate_on_peers(peers, ctx);
	}

	if (peers)
		g_strfreev(peers);
	context_flush_rowsets(ctx);

	if (err) {
		GRID_WARN("%s(%p) FAILED : (%d) %s", __FUNCTION__, ctx, err->code,
				err->message);
		g_error_free(err);
		return 1;
	}

	GRID_TRACE("%s(%p) OK : Replication requests succeded", __FUNCTION__, ctx);
	return 0;
}

static void
hook_rollback(void *d)
{
	GRID_TRACE2("%s(%p)", __FUNCTION__, d);
	context_flush_pending(d);
	context_flush_rowsets(d);
}

static void
hook_update(void *d, int op, char const *bn, char const *tn,
	sqlite3_int64 rowid)
{
	hashstr_t *key;
	struct sqlx_repctx_s *ctx;
	GTree *subtree;
	guint u;

	GRID_TRACE2("%s(%p,%d,%s,%s,%"G_GINT64_FORMAT")", __FUNCTION__,
			d, op, bn, tn, (gint64)rowid);

	do {
		gchar *n = g_strconcat(bn, ".", tn, NULL);
		HASHSTR_ALLOCA(key, n);
		g_free(n);
	} while (0);

	ctx = d;
	ctx->changes ++;
	subtree = context_get_pending_table(ctx->pending, key);
	u = (op == SQLITE_DELETE ? 1 : 0);
	g_tree_replace(subtree, g_memdup(&rowid, sizeof(rowid)),
			GUINT_TO_POINTER(u));
}

/* Public API -------------------------------------------------------------- */

static void
sqlx_replication_free_context(struct sqlx_repctx_s *ctx)
{
	if (!ctx)
		return;
	context_flush_rowsets(ctx);
	if (ctx->pending)
		g_tree_destroy(ctx->pending);
	memset(ctx, 0, sizeof(*ctx));
	g_free(ctx);
}

struct sqlx_repctx_s*
sqlx_transaction_prepare(struct sqlx_sqlite3_s *sq3)
{
	struct sqlx_repctx_s *repctx;

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	GRID_TRACE2("%s(%p)", __FUNCTION__, sq3);

	SQLX_ASSERT(sq3 != NULL);
	SQLX_ASSERT(sq3->repo != NULL);
	SQLX_ASSERT(sq3->db != NULL);

	repctx = g_malloc0(sizeof(*repctx));

	repctx->sq3 = sq3;
	repctx->changes = sqlite3_total_changes(sq3->db);
	context_flush_pending(repctx);
	context_flush_rowsets(repctx);

	if (sqlx_repository_replication_configured(sq3->repo) &&
				election_has_peers(sqlx_repository_get_elections_manager(sq3->repo), sq3->logical_name, sq3->logical_type))
	{
		sqlite3_commit_hook(sq3->db, hook_commit, repctx);
		sqlite3_rollback_hook(sq3->db, hook_rollback, repctx);
		sqlite3_update_hook(sq3->db, hook_update, repctx);
	}

	return repctx;
}

struct sqlx_repctx_s*
sqlx_transaction_begin(struct sqlx_sqlite3_s *sq3)
{
	struct sqlx_repctx_s *repctx = sqlx_transaction_prepare(sq3);
	sqlx_exec(sq3->db, "BEGIN");
	return repctx;
}

void
sqlx_transaction_changes(struct sqlx_repctx_s *ctx)
{
	SQLX_ASSERT(ctx != NULL);
	SQLX_ASSERT(ctx->sq3 != NULL);
	SQLX_ASSERT(ctx->sq3->db != NULL);

	version_reinit(ctx->sq3);

	if (sqlite3_total_changes(ctx->sq3->db) == ctx->changes
			&& !ctx->huge)
		context_pending_inc_versions(ctx);
	else {
		GRID_DEBUG("HUGE change detected");
		context_flush_pending(ctx);
		/* double increment to force a RESYNC on the slaves */
		version_increment_all(ctx->sq3->versions);
		version_increment_all(ctx->sq3->versions);
		version_save(ctx->sq3);
	}

	version_save(ctx->sq3);
	context_pending_to_rowset(ctx->sq3->db, ctx);
	version_debug("NEW:", ctx->sq3->versions);
}

void
sqlx_transaction_notify_huge_changes(struct sqlx_repctx_s *ctx)
{
	SQLX_ASSERT(ctx != NULL);
	ctx->huge = TRUE;
}

void
sqlx_transaction_detach(struct sqlx_repctx_s *ctx)
{
	SQLX_ASSERT(ctx != NULL);
	SQLX_ASSERT(ctx->sq3 != NULL);
	SQLX_ASSERT(ctx->sq3->db != NULL);

	sqlite3_commit_hook(ctx->sq3->db, NULL, NULL);
	sqlite3_rollback_hook(ctx->sq3->db, NULL, NULL);
	sqlite3_update_hook(ctx->sq3->db, NULL, NULL);
}

GError*
sqlx_transaction_end(struct sqlx_repctx_s *ctx, GError *err)
{
	int rc;

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	GRID_TRACE2("%s(%p)", __FUNCTION__, ctx);
	SQLX_ASSERT(ctx != NULL);
	SQLX_ASSERT(ctx->sq3 != NULL);
	SQLX_ASSERT(ctx->sq3->db != NULL);

	if (err) {
		rc = sqlx_exec(ctx->sq3->db, "ROLLBACK");
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			GRID_WARN("ROLLBACK failed! (%d/%s) %s", rc, sqlite_strerror(rc), sqlite3_errmsg(ctx->sq3->db));
		version_load(ctx->sq3, TRUE);
	}
	else {
		/* Manage the changes */
		sqlx_transaction_changes(ctx);

		/* apply them */
		rc = sqlx_exec(ctx->sq3->db, "COMMIT");
		if (rc != SQLITE_OK && rc != SQLITE_DONE) {
			err = SQLITE_GERROR(ctx->sq3->db, rc);
			g_prefix_error(&err, "COMMIT failed: ");
			version_load(ctx->sq3, FALSE);
		}
	}

	sqlx_transaction_detach(ctx);
	sqlx_replication_free_context(ctx);

	return err;
}

void
sqlx_transaction_destroy(struct sqlx_repctx_s *ctx)
{
	if (!ctx)
		return;

	if (ctx->sq3 && ctx->sq3->db) {
		sqlite3_commit_hook(ctx->sq3->db, NULL, NULL);
		sqlite3_rollback_hook(ctx->sq3->db, NULL, NULL);
		sqlite3_update_hook(ctx->sq3->db, NULL, NULL);
	}

	sqlx_replication_free_context(ctx);
}

struct sqlx_sqlite3_s*
sqlx_transaction_get_base(struct sqlx_repctx_s *ctx)
{
	SQLX_ASSERT(ctx != NULL);
	return ctx->sq3;
}

