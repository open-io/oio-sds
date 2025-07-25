/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2025 OVH SAS

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

#include <stddef.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/codec.h>
#include <sqliterepo/sqliterepo_remote_variables.h>
#include <sqliterepo/sqliterepo_variables.h>

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

	// Some SLAVES maybe replied an error with code=CODE_PIPEFROM, telling their are out
	// of sync. Their URLs are stored here, because after the local commit we
	// will send them a whole dump.
	GPtrArray *resync_todo; // <gchar*>

	GString *errors;

	// Count the explicit changes, those matched
	int changes;
	guint8 local_changes : 1;

	// if set, there is no replication configured, even if a replicated
	// transaction context had been initiated.
	guint8 hollow : 1;

	// if set, some changes were not matched by the update hook and a resync
	// will be necessary. This is the case in the SQLX by "DELETE FROM <table>"
	// queries.
	guint8 huge : 1;

	guint8 any_change : 1;
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
dump_request(const gchar *func, gchar **targets,
		const gchar *rn, struct sqlx_name_s *n)
{
	if (!GRID_DEBUG_ENABLED())
		return;
	gchar *tmp = g_strjoinv("|", targets);
	GRID_DEBUG("%s [%s][%s] to %s (%s)", rn, n->base, n->type, tmp, func);
	g_free(tmp);
}

static gint
_compare_rowid(gconstpointer a, gconstpointer b, gpointer unused)
{
	(void) unused;
	return CMP(*(sqlite3_int64*)a, *(sqlite3_int64*)b);
}

static GTree*
context_get_pending_table(GTree *tree, const hashstr_t *key)
{
	GTree *subtree;

	if (NULL != (subtree = g_tree_lookup(tree, key)))
		return subtree;

	subtree = g_tree_new_full(_compare_rowid, NULL, g_free, NULL);
	g_tree_insert(tree, hashstr_dup(key), subtree);
	return subtree;
}

static void _clean_value(gpointer v) { if (v) g_tree_destroy(v); }

static void
context_flush_pending(struct sqlx_repctx_s *ctx)
{
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
		const char *cname = sqlite3_column_name(stmt, i);
		struct RowName *rname = ASN1C_CALLOC(1, sizeof(*rname));
		metautils_asn_uint32_to_INTEGER(&(rname->pos), i);
		OCTET_STRING_fromBuf(&(rname->name), cname, strlen(cname));
		asn_sequence_add(&(t->header.list), rname);
	}
}

void
load_statement(sqlite3_stmt *stmt, Row_t *row, Table_t *table)
{
	guint32 i, max;

	if (table->header.list.count <= 0) /* Lazy header loading */
		load_table_header(stmt, table);

	if (!row->fields) /* Lazy memory allocation */
		row->fields = ASN1C_CALLOC(1, sizeof(struct RowFieldSequence));

	for (i=0,max=sqlite3_data_count(stmt); i<max ;i++) {
		struct RowField *rf = ASN1C_CALLOC(1, sizeof(*rf));
		metautils_asn_uint32_to_INTEGER(&(rf->pos), i);
		rf->value.present = RowFieldValue_PR_n;

		switch (sqlite3_column_type(stmt, i)) {
			case SQLITE_NULL:
				rf->value.present = RowFieldValue_PR_n;
				break;
			case SQLITE_INTEGER:
				do {
					gint64 i64 = sqlite3_column_int64(stmt, i);
					metautils_asn_int64_to_INTEGER(&(rf->value.choice.i), i64);
					rf->value.present = RowFieldValue_PR_i;
				} while (0);
				break;
			case SQLITE_FLOAT:
				do {
					gdouble d = sqlite3_column_double(stmt, i);
					asn_double2REAL(&(rf->value.choice.f), d);
					rf->value.present = RowFieldValue_PR_f;
				} while (0);
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
	gchar sql[128] = {0};

	GRID_TRACE2("%s(%p,%s,%"G_GINT64_FORMAT",%p,%p)", __FUNCTION__,
			db, hashstr_str(name), rowid, row, table);

	g_snprintf(sql, sizeof(sql), "SELECT * FROM %s WHERE ROWID = ?",
			hashstr_str(name));
	sqlite3_prepare_debug(rc, db, sql, -1, &stmt, NULL);

	sqlite3_bind_int64(stmt, 1, rowid);
	while (SQLITE_ROW == (rc = sqlite3_step(stmt)))
		load_statement(stmt, row, table);

	sqlite3_finalize_debug(rc, stmt);
}

static void
context_pending_inc_versions(struct sqlx_repctx_s *ctx)
{
	/* while we iterate on the tables about to be changed, we keep an eye
	 * on the 'admin' table. We need to increment its version number only
	 * once. Because that table will always receive a change (the version
	 * themselves alter the table) but the legit operations on the DB maybe
	 * already touched that table and cause an increment. */
	volatile gboolean admin_changed = FALSE;
	gboolean _on_table(hashstr_t *k, GTree *rows, gpointer u0 UNUSED) {
		if (g_tree_nnodes(rows) > 0) {
			if (0 == strcmp("main.admin", hashstr_str(k)))
				admin_changed = TRUE;
			gchar buf[256];
			g_snprintf(buf, sizeof(buf), "version:%s", hashstr_str(k));
			sqlx_admin_inc_version(ctx->sq3, buf, 1);
		}
		return FALSE;
	}

	EXTRA_ASSERT(NULL != ctx->pending);

	g_tree_foreach(ctx->pending, (GTraverseFunc)_on_table, NULL);

	/* ... so, if the admin table didn't receive an increment yet, we do it
	 * now */
	if (!admin_changed)
		sqlx_admin_inc_version(ctx->sq3, "version:main.admin", 1);
}

static void
context_pending_to_rowset(sqlite3 *db, struct sqlx_repctx_s *ctx)
{
	gboolean _on_table(gpointer name, gpointer rows, gpointer u0) {
		struct Table *table;
		(void) u0;

		gboolean _on_row(gpointer k, gpointer v, gpointer u1) {
			gint64 rowid = *((gint64*)k);
			guint deleted = GPOINTER_TO_UINT(v);
			(void) u1;

			GRID_TRACE2("%s(%s,%"G_GINT64_FORMAT",%d)", __FUNCTION__,
					hashstr_str(name), rowid, deleted);

			struct Row *row = ASN1C_CALLOC(1, sizeof(*row));
			metautils_asn_int64_to_INTEGER(&(row->rowid), rowid);
			if (!deleted)
				load_table_row(db, name, rowid, row, table);

			asn_sequence_add(&(table->rows.list), row);
			return FALSE;
		}

		GRID_TRACE2("%s(%s,%p)", __FUNCTION__, hashstr_str(name), rows);

		table = ASN1C_CALLOC(1, sizeof(struct Table));
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

static void
_leave_election(gchar **peers, struct sqlx_repctx_s *ctx, gboolean local,
		gint64 deadline)
{
	NAME2CONST(n, ctx->sq3->name);
	dump_request(__FUNCTION__, peers, "SQLX_EXITELECTION", &n);

	// Leave the election locally
	GError *err = election_exit(ctx->sq3->manager, &n);
	if (err) {
		GRID_WARN("Failed to leave election locally: %s", err->message);
		g_clear_error(&err);
	}

	if (local) {
		return;
	}

	GByteArray *encoded = sqlx_pack_EXITELECTION(&n, deadline);
	struct gridd_client_s **clients =
		gridd_client_create_many(peers, encoded, NULL, NULL);
	g_byte_array_unref(encoded);
	if (!clients) {
		GRID_WARN(
			"Failed to create leave election clients, "
			"see service logs for more information");
	}

	if (deadline > 0) {
		gridd_clients_set_timeout_cnx(clients,
				oio_clamp_timeout(oio_election_replicate_timeout_cnx, deadline));
		gridd_clients_set_timeout(clients,
				oio_clamp_timeout(oio_election_replicate_timeout_req, deadline));
	}

	// Ask others peers to leave the election
	gridd_clients_start(clients);
	err = gridd_clients_loop(clients);
	if (err != NULL) {
		for (struct gridd_client_s **pc = clients; clients && *pc; pc++) {
			GError *e = gridd_client_error(*pc);
			if (e != NULL) {
				GRID_WARN("Failed to leave the election [%s]: (%d) %s",
						gridd_client_url(*pc), e->code, e->message);
				g_error_free(e);
			}
		}
		g_error_free(err);
	}

	gridd_clients_free(clients);
}

static GError*
_replicate_on_peers(gchar **peers, struct sqlx_repctx_s *ctx, gint64 deadline)
{
	guint count_success = 0;
	guint other_master = 0;
	guint slave_ahead = 0;
	guint slave_behind = 0;

	NAME2CONST(n, ctx->sq3->name);
	dump_request(__FUNCTION__, peers, "SQLX_REPLICATE", &n);

	// Local address or service ID
	const gchar *local_addr = election_manager_get_local(ctx->sq3->manager);
	GByteArray *encoded = sqlx_pack_REPLICATE(
			&n, &(ctx->sequence), local_addr, deadline);
	struct gridd_client_s **clients =
		gridd_client_create_many(peers, encoded, NULL, NULL);
	g_byte_array_unref(encoded);
	if (!clients) {
		return SYSERR(
			"Failed to create replication clients, "
			"see service logs for more information.");
	}

	gridd_clients_set_timeout_cnx(clients,
			oio_clamp_timeout(oio_election_replicate_timeout_cnx, deadline));
	gridd_clients_set_timeout(clients,
			oio_clamp_timeout(oio_election_replicate_timeout_req, deadline));

	gridd_clients_start(clients);
	GError *err = gridd_clients_loop(clients);
	if (!err) {
		// 1st pass: analyze the response codes
		for (struct gridd_client_s **pc = clients; clients && *pc; pc++) {
			GError *e = gridd_client_error(*pc);
			if (!e) {
				++ count_success;
			} else {
				switch (e->code) {
				case CODE_IS_MASTER:
					other_master++;
					break;
				case CODE_PIPETO:
				case CODE_CONCURRENT:
					slave_ahead++;
					break;
				case CODE_PIPEFROM:
				case SQLITE_CORRUPT:
					slave_behind++;
					break;
				default:
					break;
				}
				g_string_append_printf(ctx->errors, " [%s/%d/%s]",
						gridd_client_url(*pc), e->code, e->message);
				g_clear_error(&e);
			}
		}

		// Count the successes (including the local update),
		// and decide if we commit or rollback.
		++ count_success;
		guint groupsize = 1 + g_strv_length(peers);
		if (election_manager_get_mode(ctx->sq3->manager) == ELECTION_MODE_GROUP) {
			if (count_success < groupsize) {
				err = NEWERROR(CODE_UNAVAILABLE,
						"Not enough successes, no group (%u/%u)",
						count_success, groupsize);
				g_string_append_printf(ctx->errors, " %s",
						err->message);
			}
		} else {
			if (count_success < group_to_quorum(groupsize)) {
				err = NEWERROR(CODE_UNAVAILABLE,
						"Not enough successes, no quorum (%u/%u)",
						count_success, groupsize);
				g_string_append_printf(ctx->errors, " %s",
						err->message);
			}
		}

		/* 2nd pass: trigger resyncs if we have quorum (and no other master)
		+------------------+------------------------+------------------------+
		|        \   Other | = 0                    | > 0 (another master)   |
		| Slaves  \ master |                        |                        |
		+------------------+------------------------+------------------------+
		| ahead > 0        | DB_RESTORE(ahead)      | Rollback               |
		|                  |                        | Leave election locally |
		|                  | -> Note 1              | -> Note 3              |
		+------------------+------------------------+------------------------+
		| behind > 0       | DB_RESTORE(behind)     | Commit                 |
		|                  |                        | Reset election         |
		|                  | -> Note 2              | -> Note 4              |
		+------------------+------------------------+------------------------+
		| ahead = 0        |                        | Commit                 |
		| behind = 0       |                        | Reset election         |
		|                  |                        | -> Note 4              |
		+------------------+------------------------+------------------------+

		Note 1: 1 (or more) slave successfully applied the last change, but
				was slow to do it, and the master timed out and rolled back
				the transaction. We can send a full copy of the database so
				the last change is rolled back and the current change applies.

		Note 2: 1 (or more) slave did not get the last change (connection
				failure or service down). Send a full copy so the slave gets
				the missed changes (including the current change).
		*/
		if (!err && !other_master && (slave_ahead || slave_behind)) {
			for (struct gridd_client_s **pc = clients; clients && *pc; pc++) {
				GError *e = gridd_client_error(*pc);
				if (!e) {
					continue;
				} else if (e->code == SQLITE_CORRUPT
						|| e->code == CODE_PIPETO
						|| e->code == CODE_PIPEFROM
						|| e->code == CODE_CONCURRENT) {
					/* Send a dump of the database to the out-of-sync slave. */
					g_ptr_array_add(
							ctx->resync_todo, g_strdup(gridd_client_url(*pc)));
				}
				g_clear_error(&e);
			}
		}
	}

	gridd_clients_free(clients);

	if (other_master > 0) {
		if (slave_ahead > 0) {
			/* Note 3: the remote peers agree that the local peer has missed
			 * some information. Leave the election locally (maybe we have
			 * already left while the current request was in progress). */
			GRID_WARN("Master changed? Leave the election locally [%s][%s] reqid=%s",
					ctx->sq3->name.base, ctx->sq3->name.type, oio_ext_get_reqid());
			_leave_election(peers, ctx, TRUE, 0);
		} else {
			/* Note 4: not sure who is right, make everyone leave. The new
			 * election process will compare all versions and decide.
			 * Notice that we may still validate the transaction (if enough
			 * slaves have agreed to replicate the changes). */
			GRID_WARN("Double master detected, try to leave the election "
					"on all peers [%s][%s] reqid=%s", ctx->sq3->name.base,
				ctx->sq3->name.type, oio_ext_get_reqid());
			_leave_election(peers, ctx, FALSE, 0);
		}
	}

	return err;
}

static void
_defer_synchronous_RESYNC(struct sqlx_repctx_s *ctx)
{
	NAME2CONST(n, ctx->sq3->name);

	gchar **peers = NULL;
	GError *err = election_get_peers (ctx->sq3->manager, &n, FALSE, &peers);
	EXTRA_ASSERT((err != NULL) ^ (peers != NULL));

	if (err != NULL) {
		GRID_WARN("Replicated transaction started but peers not found "
				"[%s][%s]: (%d) %s reqid=%s", ctx->sq3->name.base, ctx->sq3->name.type,
				err->code, err->message, oio_ext_get_reqid());
		g_clear_error(&err);
	} else if (peers) {
		for (gchar **p=peers; *p ;++p) {
			g_ptr_array_add(ctx->resync_todo, *p);
			*p = NULL;
		}
		g_free(peers);
	}
}

static int
_perform_REPLICATE(struct sqlx_repctx_s *ctx)
{
	NAME2CONST(n, ctx->sq3->name);

	gchar **peers = NULL;
	GError *err = election_get_peers (ctx->sq3->manager, &n, FALSE, &peers);
	EXTRA_ASSERT((err != NULL) ^ (peers != NULL));

	if (err != NULL) {
		GRID_WARN("Replicated transaction started but peers not found [%s.%s]"
				": (%d) %s reqid=%s", ctx->sq3->name.base, ctx->sq3->name.type,
				err->code, err->message, oio_ext_get_reqid());
		g_clear_error(&err);
		return 1;
	}

	if (!peers || !oio_str_is_set(*peers)) {
		GRID_WARN("Replication triggered but no peer found for [%s.%s] reqid=%s",
				 ctx->sq3->name.base, ctx->sq3->name.type, oio_ext_get_reqid());
		oio_str_cleanv(&peers);
		return 1;
	}

	enum election_status_e status =
		election_get_status_nowait(ctx->sq3->manager, &n);
	if (status != ELECTION_LEADER) {
		err = NEWERROR(
				CODE_CONCURRENT, "Election status changed during transaction");
	} else {
		err = _replicate_on_peers(peers, ctx, oio_ext_get_deadline());
	}
	g_strfreev(peers);
	context_flush_rowsets(ctx);

	if (likely(err == NULL))
		return 0;

	GRID_WARN("%s(%p, reqid=%s) FAILED: (%d) %s reqid=%s", __FUNCTION__, ctx,
			oio_ext_get_reqid(), err->code, err->message, oio_ext_get_reqid());
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
	EXTRA_ASSERT(ctx->sq3->manager != NULL);

	ctx->any_change = 1;

	gint64 start = oio_ext_monotonic_time();
	int rc = 0;
	if (ctx->huge) {
		_defer_synchronous_RESYNC(ctx);
	} else if (ctx->sequence.list.count <= 0) {
		GRID_DEBUG("Empty transaction!");
		ctx->any_change = 0;
		context_flush_rowsets(ctx);
	} else {
		rc = _perform_REPLICATE(ctx);
	}
	gint64 duration = oio_ext_monotonic_time() - start;
	oio_ext_add_perfdata("db_commit", duration);
	return rc;
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

	++ ctx->changes;
	ctx->local_changes = 1;

	GTree *subtree = context_get_pending_table(ctx->pending, key);
	guint u = (op == SQLITE_DELETE);
	g_tree_replace(subtree, oio_memdup(&rowid, sizeof(rowid)),
			GUINT_TO_POINTER(u));
}

static GError *
sqlx_synchronous_resync(struct sqlx_repctx_s *ctx, gchar **peers)
{
	GByteArray *dump;
	GError *err;

	// Generate the DUMP
	err = sqlx_repository_dump_base_gba(ctx->sq3, sqliterepo_dump_check_type,
			&dump);
	if (err) {
		GRID_WARN("[%s][%s] Synchronous COMMIT not possible: (%d) %s reqid=%s",
				ctx->sq3->name.base, ctx->sq3->name.type,
				err->code, err->message, oio_ext_get_reqid());
		// We did not do the operation, but we still have the quorum.
		g_clear_error(&err);
		return NULL;
	}

	// Now send it to the SLAVES
	NAME2CONST(n, ctx->sq3->name);
	const gchar *local_addr = election_manager_get_local(ctx->sq3->manager);
	err = peers_restore(peers, &n, dump, local_addr, oio_ext_get_deadline());
	if (err) {
		GRID_ERROR("%s reqid=%s", err->message, oio_ext_get_reqid());
		if (err->code == CODE_IS_MASTER) {
			// There was a change of master while we were performing the
			// operation, probably because we are exiting.
			g_clear_error(&err);
			err = NEWERROR(CODE_CONCURRENT,
					"Master changed during operation. Exiting?");
		} else {
			g_clear_error(&err);
		}
	} else {
		GRID_INFO("RESTORED on SLAVES [%s][%s] reqid=%s",
				ctx->sq3->name.base, ctx->sq3->name.type, oio_ext_get_reqid());
	}
	return err;
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
	if (ctx->errors)
		g_string_free (ctx->errors, TRUE);
	g_slice_free(struct sqlx_repctx_s, ctx);
}

static void
_sqlx_transaction_rollback(struct sqlx_repctx_s *ctx, GError *err)
{
	int rc;

	if (err) {
		if (g_strrstr(err->message, "SQLITE_NOTADB") != NULL
				|| g_strrstr(err->message, "SQLITE_CORRUPT") != NULL) {
			ctx->sq3->corrupted = TRUE;
		}
	}

	ctx->any_change = 0;
	rc = sqlx_exec(ctx->sq3->db, "ROLLBACK");
	if (rc != SQLITE_OK && rc != SQLITE_DONE) {
		GRID_WARN("ROLLBACK failed! (%d/%s) %s reqid=%s", rc,
				sqlite_strerror(rc), sqlite3_errmsg(ctx->sq3->db),
				oio_ext_get_reqid());
		if (rc == SQLITE_NOTADB || rc == SQLITE_CORRUPT) {
			ctx->sq3->corrupted = TRUE;
		}
	}
	sqlx_admin_reload(ctx->sq3);
}

static GError*
_sqlx_transaction_validate(struct sqlx_repctx_s *ctx)
{
	int rc;
	GError *err = NULL;

	/* Ensure that newly created tables have versions now referenced
	 * in the admin table. */
	sqlx_admin_ensure_versions (ctx->sq3);

	/* Ensure any operation happening during the request handler on the
	 * admin table, will be stored in the replication context and will
	 * trigger an increment in the version numbers. */
	sqlx_admin_save_lazy (ctx->sq3);

	/* Special management for the big changes (it is big when we could
	 * not capture each row change, so that we need to trigger a whole
	 * resync. */
	if (!ctx->hollow) {
		int changes = sqlite3_total_changes(ctx->sq3->db);
		if (changes != ctx->changes) {
			GRID_DEBUG("HUGE change detected [%s][%s] (%d vs %d)",
					ctx->sq3->name.base, ctx->sq3->name.type,
					changes, ctx->changes);
			ctx->huge = 1;
		}
	}

	if (!ctx->hollow) {
		if (ctx->huge) {
			sqlx_admin_inc_all_versions(ctx->sq3, 2);
		} else if (ctx->local_changes) {
			context_pending_inc_versions(ctx);
		}
	}

	/* If anything changed in the admin table, then save it */
	sqlx_admin_save_lazy (ctx->sq3);

	/* Prepare the changes to be sent to the slave peers */
	if (!ctx->hollow && !ctx->huge) {
		context_pending_to_rowset(ctx->sq3->db, ctx);
	} else {
		context_flush_pending(ctx);
	}

	/* Apply the changes on the slaves. */
	rc = sqlx_exec(ctx->sq3->db, "COMMIT");
	if (rc != SQLITE_OK && rc != SQLITE_DONE) {
		err = NEWERROR(CODE_UNAVAILABLE, "COMMIT failed: (%s) %s%s",
				sqlite_strerror(rc), sqlite3_errmsg(ctx->sq3->db),
				ctx->errors->str);
		if (rc == SQLITE_NOTADB || rc == SQLITE_CORRUPT) {
			ctx->sq3->corrupted = TRUE;
		}
		// Restore the in-RAM cache
		sqlx_admin_reload(ctx->sq3);
	}
	if (ctx->errors->len > 0) {
		GRID_WARN("COMMIT errors on [%s.%s]:%s reqid=%s",
				ctx->sq3->name.base, ctx->sq3->name.type,
				ctx->errors->str, oio_ext_get_reqid());
	}
	if (ctx->resync_todo && ctx->resync_todo->len) {
		// Detected the need of an explicit RESYNC on some SLAVES.
		g_ptr_array_add(ctx->resync_todo, NULL);
		GError *err2 = sqlx_synchronous_resync(
				ctx, (gchar**)ctx->resync_todo->pdata);
		if (err2) {
			GRID_WARN("Failed to synchronously resync peers: %s (reqid=%s)",
					err2->message, oio_ext_get_reqid());
			if (!err) {
				err = err2;
			} else {
				// Error was logged already.
				g_clear_error(&err2);
			}
		}
	}

	return err;
}

static GError*
_sqlx_transaction_end(struct sqlx_repctx_s *ctx, GError *err, gboolean force_rollback)
{
	GRID_TRACE2("%s (%p)", __FUNCTION__, ctx);

	if (NULL == ctx) {
		if (!err)
			err = SYSERR("no tnx");
		g_prefix_error(&err, "transaction error: ");
		return err;
	}

	EXTRA_ASSERT(ctx != NULL);
	EXTRA_ASSERT(ctx->sq3 != NULL);
	EXTRA_ASSERT(ctx->sq3->db != NULL);

	if (err || force_rollback) {
		_sqlx_transaction_rollback(ctx, err);
	} else {
		err = _sqlx_transaction_validate(ctx);
	}

	if (ctx->sq3->admin_dirty)
		sqlx_alert_dirty_base (ctx->sq3, "still dirty after transaction");

	if (ctx->any_change) {
		sqlx_repository_call_change_callback(ctx->sq3);
		ctx->any_change = 0;
	}

	sqlite3_commit_hook(ctx->sq3->db, NULL, NULL);
	sqlite3_rollback_hook(ctx->sq3->db, NULL, NULL);
	sqlite3_update_hook(ctx->sq3->db, NULL, NULL);
	ctx->sq3->transaction = 0;
	if (!err) {
		ctx->sq3->update_queries = g_list_concat(ctx->sq3->update_queries,
				ctx->sq3->transaction_update_queries);
	} else {
		g_list_free_full(ctx->sq3->transaction_update_queries, g_free);
	}
	ctx->sq3->transaction_update_queries = NULL;
	sqlx_replication_free_context(ctx);
	return err;
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

	if (sq3->admin_dirty)
		sqlx_alert_dirty_base (sq3, "new TNX on a dirty admin");

	if (!sq3->no_peers &&
			sqlx_repository_replication_configured(sq3->repo)) {
		NAME2CONST(n, sq3->name);
		GError *err = election_has_peers(
				sqlx_repository_get_elections_manager(sq3->repo), &n, FALSE, &has);
		if (err != NULL) {
			g_prefix_error(&err, "Peer resolution: ");
			return err;
		}
	}

	struct sqlx_repctx_s *repctx = g_slice_new0(struct sqlx_repctx_s);
	repctx->hollow = !has;
	repctx->sq3 = sq3;
	repctx->changes = sqlite3_total_changes(sq3->db);
	repctx->local_changes = 0;

	if (has) {
		repctx->resync_todo = g_ptr_array_sized_new(4);
		g_ptr_array_set_free_func(repctx->resync_todo, g_free0);

		context_flush_pending(repctx);
		context_flush_rowsets(repctx);

		sqlite3_commit_hook(sq3->db, hook_commit, repctx);
		sqlite3_rollback_hook(sq3->db, hook_rollback, repctx);
		sqlite3_update_hook(sq3->db, (sqlite3_update_hook_f)hook_update, repctx);
	}

	repctx->errors = g_string_sized_new (128);

	*result = repctx;
	return NULL;
}

GError *
sqlx_transaction_begin(struct sqlx_sqlite3_s *sq3,
		struct sqlx_repctx_s **result)
{
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(sq3 != NULL);
	SQLXNAME_CHECK(&sq3->name);
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
	/*sqlx_admin_reload(sq3);*/
	*result = repctx;
	sq3->transaction = 1;
	return NULL;
}

void
sqlx_transaction_notify_huge_changes(struct sqlx_repctx_s *ctx)
{
	EXTRA_ASSERT(ctx != NULL);
	ctx->huge = 1;
}

GError*
sqlx_transaction_rollback(struct sqlx_repctx_s *ctx, GError *err)
{
	return _sqlx_transaction_end(ctx, err, TRUE);
}

GError*
sqlx_transaction_end(struct sqlx_repctx_s *ctx, GError *err)
{
	return _sqlx_transaction_end(ctx, err, FALSE);
}
