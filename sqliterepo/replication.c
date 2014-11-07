#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "sqliterepo"
#endif

#include <stddef.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

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

#include "sqliterepo.h"
#include "election.h"
#include "version.h"
#include "sqlx_remote.h"
#include "internals.h"

struct sqlx_repctx_s
{
	// Explicit changes matched
	TableSequence_t sequence;

	struct sqlx_sqlite3_s *sq3;

	// Explicit changes matched but not yet resolved : this stores ROWID
	GTree *pending;

	// Some SLAVES maybe replied an error with code=471, telling their are out
	// of sync. Their URLs are stored here, because after the local commit we
	// will send them a whole dump.
	GPtrArray *resync_todo; // <gchar*>

	// Count the explicit changes, those matched
	gint32 changes;

	// if set, there is no replication configured, even if a replicated
	// transaction context had been initiated.
	char hollow : 1;

	// if set, some changes were not matched by the update hook and a resync
	// will be necessary. This is the case in the SQLX by "DELETE FROM <table>"
	// queries.
	char huge : 1;

	char any_change : 1;
};

static guint
group_to_quorum(guint group_size)
{
	return 1 + (group_size / 2);
}

// This typedef is absent from sqlite3.h
typedef void (*sqlite3_update_hook_f) (void *, int, char const *,
		char const *, sqlite3_int64);

/* ------------------------------------------------------------------------- */

static void
g_free0(gpointer p)
{
	if (p)
		g_free(p);
}

static void
dump_request(const gchar *func, gchar **targets,
		const gchar *rn, struct sqlx_name_s *n)
{
	if (!GRID_DEBUG_ENABLED())
		return;
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

	for (i=0,max=sqlite3_data_count(stmt); i<max ;i++) {
		const gchar *cname;
		RowName_t *rname;

		cname = sqlite3_column_name(stmt, i);
		rname = g_malloc0(sizeof(*rname));
		asn_uint32_to_INTEGER(&(rname->pos), i);
		OCTET_STRING_fromBuf(&(rname->name), cname, strlen(cname));
		asn_sequence_add(&(t->header.list), rname);
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
		rf->value.present = RowFieldValue_PR_n;

		switch (sqlite3_column_type(stmt, i)) {
			case SQLITE_NULL:
				rf->value.present = RowFieldValue_PR_n;
				break;
			case SQLITE_INTEGER:
				do {
					gint64 i64 = sqlite3_column_int64(stmt, i);
					asn_int64_to_INTEGER(&(rf->value.choice.i), i64);
					rf->value.present = RowFieldValue_PR_i;
				} while (0);
				break;
			case SQLITE_FLOAT:
				if (!noreal) {
					gdouble d = sqlite3_column_double(stmt, i);
					asn_double2REAL(&(rf->value.choice.f), d);
					rf->value.present = RowFieldValue_PR_f;
				}
				else {
					const guint8 *t = sqlite3_column_text(stmt, i);
					OCTET_STRING_fromBuf(&(rf->value.choice.s), (char*)t, strlen((char*)t));
					rf->value.present = RowFieldValue_PR_s;
				}
				break;
			case SQLITE_TEXT:
				do {
					const guint8 *t = sqlite3_column_text(stmt, i);
					gsize tsize = sqlite3_column_bytes(stmt, i);
					OCTET_STRING_fromBuf(&(rf->value.choice.s), (char*)t, tsize);
					rf->value.present = RowFieldValue_PR_s;
				} while (0);
				break;
			case SQLITE_BLOB:
				do {
					const void *b = sqlite3_column_blob(stmt, i);
					gsize bsize = sqlite3_column_bytes(stmt, i);
					OCTET_STRING_fromBuf(&(rf->value.choice.b), (char*)b, bsize);
					rf->value.present = RowFieldValue_PR_b;
				} while (0);
				break;
			default:
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
	gboolean _on_table(hashstr_t *k, GTree *rows, gpointer u0) {
		(void) u0;
		if (g_tree_nnodes(rows) > 0) {
			if (0 != g_ascii_strcasecmp(hashstr_str(k), "main.admin")) {
				gsize max = sizeof("version:")+hashstr_len(k);
				gchar buf[max];
				g_snprintf(buf, max, "version:%s", hashstr_str(k));
				sqlx_admin_inc_version(ctx->sq3, buf, 1);
			}
		}
		return FALSE;
	}

	if (ctx->pending)
		g_tree_foreach(ctx->pending, (GTraverseFunc)_on_table, NULL);
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
	EXTRA_ASSERT(db != NULL);
	EXTRA_ASSERT(ctx != NULL);
	EXTRA_ASSERT(ctx->pending != NULL);
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

	gridd_clients_set_timeout(clients, 5.0, 10.0);

	gridd_clients_start(clients);
	err = gridd_clients_loop(clients);
	if (!err) {
		for (pc=clients; pc && *pc ;pc++) {
			GError *e = gridd_client_error(*pc);
			if (!e)
				++ count_success;
			else {
				if (e->code == CODE_PIPEFROM || e->code == CODE_PIPETO
						|| e->code == CODE_CONCURRENT)
				{
					// XXX JFS Previously, the SLAVE triggered a RESYNC. Now
					// we immediately send the DUMP as soon as the COMMIT is
					// terminated. We Just store the SLAVE's address.
					// XXX Why do the resync in case of a PIPEFROM (understand
					// as 'pipe from the peer') ? The current host is MASTER
					// it is the refernce for several others bases, and
					// whatever the remote problem on *that* peer, the it
					// is MASTER because the election succeeded, and we won't
					// restart a whole election
					++ count_success;
					g_ptr_array_add(ctx->resync_todo, g_strdup(
							gridd_client_url(*pc)));
				}
				else
					++ count_errors;
				g_clear_error(&e);
			}
		}

		++ count_success; // XXX JFS: don't forget the local success!
		guint groupsize = 1 + g_strv_length(peers);
		if (ctx->sq3->config->mode == ELECTION_MODE_GROUP) {
			if (count_success < groupsize)
				err = NEWERROR(500, "Not enough successes, no group");
		}
		else {
			if (count_success < group_to_quorum(groupsize))
				err = NEWERROR(500, "Not enough successes, no quorum");
		}
	}

	gridd_clients_free(clients);
	return err;
}

static void
_defer_synchronous_RESYNC(struct sqlx_repctx_s *ctx)
{
	gchar **peers = NULL;

	GError *err = sqlx_config_get_peers(ctx->sq3->config,
			ctx->sq3->logical_name, ctx->sq3->logical_type, &peers);

	if (err != NULL) {
		GRID_WARN("Replicated transaction started but peers not found "
				"[%s][%s] : (%d) %s", ctx->sq3->logical_name,
				ctx->sq3->logical_type, err->code, err->message);
		g_clear_error(&err);
		return;
	}

	if (peers) {
		for (gchar **p=peers; *p ;++p)
			g_ptr_array_add(ctx->resync_todo, *p);
		g_free(peers);
	}
}

static int
_perform_REPLICATE(struct sqlx_repctx_s *ctx)
{
	GError *err;
	gchar **peers = NULL;

	err = sqlx_config_get_peers(ctx->sq3->config, ctx->sq3->logical_name,
			ctx->sq3->logical_type, &peers);

	if (err != NULL) {
		GRID_WARN("Replicated transaction started but peers not found "
				"[%s][%s] : (%d) %s", ctx->sq3->logical_name,
				ctx->sq3->logical_type, err->code, err->message);
		g_clear_error(&err);
		return 1;
	}

	if (!peers) {
		GRID_DEBUG("No peer located, no replication to do");
		return 0;
	}

	err = _replicate_on_peers(peers, ctx);
	g_strfreev(peers);
	context_flush_rowsets(ctx);

	if (!err)
		return 0;

	GRID_WARN("%s(%p) FAILED : (%d) %s", __FUNCTION__, ctx, err->code,
			err->message);
	g_error_free(err);
	ctx->any_change = 0;
	return 1;
}

static int
hook_commit(gpointer d)
{
	struct sqlx_repctx_s *ctx = d;

	GRID_TRACE2("%s(%p)", __FUNCTION__, ctx);
	EXTRA_ASSERT(ctx != NULL);
	EXTRA_ASSERT(ctx->sq3 != NULL);
	EXTRA_ASSERT(ctx->sq3->config != NULL);
	EXTRA_ASSERT(ctx->sq3->config->get_peers != NULL);

	ctx->any_change = 1;

	if (ctx->huge) {
		_defer_synchronous_RESYNC(ctx);
		return 0;
	}

	if (ctx->sequence.list.count <= 0) {
		GRID_DEBUG("Empty transaction!");
		ctx->any_change = 0;
		context_flush_rowsets(ctx);
		return 0;
	}

	return _perform_REPLICATE(ctx);
}

static void
hook_rollback(void *d)
{
	GRID_TRACE2("%s(%p)", __FUNCTION__, d);
	context_flush_pending(d);
	context_flush_rowsets(d);
}

static void
hook_update(struct sqlx_repctx_s *ctx, int op, char const *bn, char const *tn,
	sqlite3_int64 rowid)
{
	hashstr_t *key;

	if (ctx->hollow || ctx->huge)
		return ;

	GRID_TRACE2("%s(%p,%d,%s,%s,%"G_GINT64_FORMAT")", __FUNCTION__,
			ctx, op, bn, tn, (gint64)rowid);

	do {
		gchar *n = g_strconcat(bn, ".", tn, NULL);
		HASHSTR_ALLOCA(key, n);
		g_free(n);
	} while (0);

	ctx->changes ++;
	GTree *subtree = context_get_pending_table(ctx->pending, key);
	guint u = (op == SQLITE_DELETE);
	g_tree_replace(subtree, g_memdup(&rowid, sizeof(rowid)),
			GUINT_TO_POINTER(u));
}

static void
sqlx_synchronous_resync(struct sqlx_repctx_s *ctx, gchar **peers)
{
	GByteArray *dump;
	GError *err;

	// Generate the DUMP
	err = sqlx_repository_dump_base_gba(ctx->sq3, &dump);
	if (NULL != err) {
		GRID_WARN("[%s][%s] Synchronous COMMIT not possible : (%d) %s",
				ctx->sq3->logical_name, ctx->sq3->logical_type,
				err->code, err->message);
		g_clear_error(&err);
		return;
	}

	// Now send it to the SLAVES
	struct sqlx_name_s n;
	n.base = ctx->sq3->logical_name;
	n.type = ctx->sq3->logical_type;
	n.ns = "";
	peers_restore(peers, &n, dump);
	GRID_INFO("RESTORED on SLAVES [%s][%s]",
			ctx->sq3->logical_name, ctx->sq3->logical_type);
}

static void
sqlx_replication_free_context(struct sqlx_repctx_s *ctx)
{
	if (!ctx)
		return;
	context_flush_rowsets(ctx);
	if (ctx->pending)
		g_tree_destroy(ctx->pending);
	if (ctx->resync_todo)
		g_ptr_array_free(ctx->resync_todo, TRUE);
	memset(ctx, 0, sizeof(*ctx));
	g_free(ctx);
}

static void
sqlx_transaction_changes(struct sqlx_repctx_s *ctx)
{
	EXTRA_ASSERT(ctx != NULL);
	EXTRA_ASSERT(ctx->sq3 != NULL);
	EXTRA_ASSERT(ctx->sq3->db != NULL);

	if (sqlite3_total_changes(ctx->sq3->db) != ctx->changes) {
		GRID_DEBUG("HUGE change detected [%s][%s]", ctx->sq3->logical_name,
				ctx->sq3->logical_type);
		ctx->huge = 1;
	}

	if (!ctx->hollow && !ctx->huge) {
		context_pending_inc_versions(ctx);
		context_pending_to_rowset(ctx->sq3->db, ctx);
	}
	else {
		context_flush_pending(ctx);
		sqlx_admin_inc_all_versions(ctx->sq3, 2);
	}
}

// Public API -----------------------------------------------------------------

GError *
sqlx_transaction_prepare(struct sqlx_sqlite3_s *sq3,
		struct sqlx_repctx_s **result)
{
	gboolean has = FALSE;

	GRID_TRACE2("%s(%p)", __FUNCTION__, sq3);

	EXTRA_ASSERT(result != NULL);
	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(sq3->repo != NULL);
	EXTRA_ASSERT(sq3->db != NULL);
	*result = NULL;

	if (!sq3->no_peers &&
			sqlx_repository_replication_configured(sq3->repo)) {
		GError *err = election_has_peers(
				sqlx_repository_get_elections_manager(sq3->repo),
				sq3->logical_name, sq3->logical_type, &has);
		if (err != NULL) {
			g_prefix_error(&err, "Peer resolution: ");
			return err;
		}
	}

	struct sqlx_repctx_s *repctx = g_malloc0(sizeof(*repctx));
	repctx->hollow = !has;
	repctx->sq3 = sq3;
	repctx->changes = sqlite3_total_changes(sq3->db);

	if (has) {
		repctx->resync_todo = g_ptr_array_sized_new(4);
		g_ptr_array_set_free_func(repctx->resync_todo, g_free0);

		context_flush_pending(repctx);
		context_flush_rowsets(repctx);

		sqlite3_commit_hook(sq3->db, hook_commit, repctx);
		sqlite3_rollback_hook(sq3->db, hook_rollback, repctx);
		sqlite3_update_hook(sq3->db, (sqlite3_update_hook_f)hook_update, repctx);
	}

	*result = repctx;
	return NULL;
}

GError *
sqlx_transaction_begin(struct sqlx_sqlite3_s *sq3,
		struct sqlx_repctx_s **result)
{
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(result != NULL);
	*result = NULL;

	GError *err = sqlx_transaction_prepare(sq3, &repctx);
	if (err != NULL) {
		g_prefix_error(&err, "TNX error: ");
		return err;
	}

	if (repctx->resync_todo)
		g_ptr_array_set_size(repctx->resync_todo, 0);
	sqlx_exec(sq3->db, "BEGIN");
	sqlx_admin_reload(sq3);
	*result = repctx;
	return NULL;
}

void
sqlx_transaction_notify_huge_changes(struct sqlx_repctx_s *ctx)
{
	EXTRA_ASSERT(ctx != NULL);
	ctx->huge = 1;
}

GError*
sqlx_transaction_end(struct sqlx_repctx_s *ctx, GError *err)
{
	int rc;

	GRID_TRACE2("%s(%p)", __FUNCTION__, ctx);

	if (NULL == ctx) {
		if (!err)
			err = NEWERROR(500, "no tnx");
		g_prefix_error(&err, "transaction error: ");
		return err;
	}

	EXTRA_ASSERT(ctx != NULL);
	EXTRA_ASSERT(ctx->sq3 != NULL);
	EXTRA_ASSERT(ctx->sq3->db != NULL);

	if (err) {
		ctx->any_change = 0;
		rc = sqlx_exec(ctx->sq3->db, "ROLLBACK");
		if (rc != SQLITE_OK && rc != SQLITE_DONE) {
			GRID_WARN("ROLLBACK failed! (%d/%s) %s", rc,
					sqlite_strerror(rc), sqlite3_errmsg(ctx->sq3->db));
		}
		sqlx_admin_reload(ctx->sq3);
	}
	else {
		// Ensure that newly created tables have versions now referenced
		// in the admin table.
		sqlx_admin_reload(ctx->sq3);

		// Agregate the changes
		sqlx_transaction_changes(ctx);

		// Apply the changes on the slaves.
		rc = sqlx_exec(ctx->sq3->db, "COMMIT");
		if (rc != SQLITE_OK && rc != SQLITE_DONE) {
			err = SQLITE_GERROR(ctx->sq3->db, rc);
			g_prefix_error(&err, "COMMIT failed: ");
			// Restore the in-RAM cache
			sqlx_admin_reload(ctx->sq3);
		}
		else if (ctx->resync_todo && ctx->resync_todo->len) {
			// Detected the need of an explicit RESYNC on some SLAVES.
			g_ptr_array_add(ctx->resync_todo, NULL);
			sqlx_synchronous_resync(ctx, (gchar**)ctx->resync_todo->pdata);
		}
	}

	if (ctx->any_change) {
		sqlx_repository_call_change_callback(ctx->sq3);
		ctx->any_change = 0;
	}

	sqlite3_commit_hook(ctx->sq3->db, NULL, NULL);
	sqlite3_rollback_hook(ctx->sq3->db, NULL, NULL);
	sqlite3_update_hook(ctx->sq3->db, NULL, NULL);
	sqlx_replication_free_context(ctx);
	return err;
}

struct sqlx_sqlite3_s*
sqlx_transaction_get_base(struct sqlx_repctx_s *ctx)
{
	EXTRA_ASSERT(ctx != NULL);
	return ctx->sq3;
}

