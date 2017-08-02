/*
OpenIO SDS sqlx
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#include <glib.h>
#include <sqlite3.h>

#include <core/oiolog.h>
#include <core/oiostr.h>
#include <core/oiourl.h>
#include <core/internals.h>

#include <metautils/lib/metautils.h>

#include "sqlx_client.h"
#include "sqlx_client_internals.h"
#include "sqlx_client_local.h"

struct oio_sqlx_client_LOCAL_s
{
	struct oio_sqlx_client_vtable_s *vtable;
	sqlite3 *db;
};

struct oio_sqlx_client_factory_LOCAL_s
{
	struct oio_sqlx_client_factory_vtable_s *vtable;
	gchar *schema;
	gchar *ns;
};

static void _local_client_destroy (struct oio_sqlx_client_s *self);

static GError * _local_client_create_db (struct oio_sqlx_client_s *self);

static GError * _local_client_execute_batch (struct oio_sqlx_client_s *self,
		struct oio_sqlx_batch_s *batch,
		struct oio_sqlx_batch_result_s **out_result);

static void _local_factory_destroy (struct oio_sqlx_client_factory_s *self);

static GError * _local_factory_open (struct oio_sqlx_client_factory_s *self,
			const struct oio_url_s *u, struct oio_sqlx_client_s **out);

struct oio_sqlx_client_factory_vtable_s vtable_factory_LOCAL =
{
	_local_factory_destroy,
	_local_factory_open,
	NULL /* the default batch implementation fits */
};

struct oio_sqlx_client_vtable_s vtable_LOCAL =
{
	_local_client_destroy,
	_local_client_create_db,
	_local_client_execute_batch,
};

static void
_local_client_destroy (struct oio_sqlx_client_s *self)
{
	g_assert (self != NULL);
	struct oio_sqlx_client_LOCAL_s *s = (struct oio_sqlx_client_LOCAL_s*)self;
	g_assert (s->vtable == &vtable_LOCAL);
	if (s->db)
		sqlite3_close (s->db);
	s->db = NULL;
	s->vtable = NULL;
	SLICE_FREE (struct oio_sqlx_client_LOCAL_s, s);
}

static GError *
_local_client_create_db (struct oio_sqlx_client_s *self)
{
	g_assert (self != NULL);
	struct oio_sqlx_client_LOCAL_s *s = (struct oio_sqlx_client_LOCAL_s*)self;
	g_assert (s->vtable == &vtable_LOCAL);
	/* actually a No-OP since the DB is in-mem, and created at the opening */
	return NULL;
}

static gchar **
_pack_record (sqlite3_stmt *stmt)
{
	GPtrArray *tmp = g_ptr_array_new ();
	const int max=sqlite3_column_count(stmt);
	for (int i=0; i<max ;++i) {
		const char *v = (const char*)sqlite3_column_text(stmt, i);
		g_ptr_array_add (tmp, g_strdup(v?v:""));
	}
	g_ptr_array_add (tmp, NULL);
	return (gchar**) g_ptr_array_free (tmp, FALSE);
}

static void
_exec_statement (struct oio_sqlx_client_LOCAL_s *s,
		GPtrArray *in, struct oio_sqlx_statement_result_s *out)
{
	sqlite3_stmt *stmt = NULL;

	/* prepare the query and bind the parameters */
	int rc = sqlite3_prepare (s->db, in->pdata[0], -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		out->err = NEWERROR(CODE_INTERNAL_ERROR, "DB ERROR (prepare): (%d) %s",
				rc, sqlite3_errmsg(s->db));
		goto out;
	}

	const guint max = in->len;
	for (guint i=1; i<max; ++i) {
		rc = sqlite3_bind_text (stmt, i, in->pdata[i], -1, NULL);
		if (SQLITE_OK != rc) {
			out->err = NEWERROR(CODE_INTERNAL_ERROR, "DB ERROR (bind): (%d) %s",
					rc, sqlite3_errmsg(s->db));
			goto out;
		}
	}

	/* pack the output */
	do {
		rc = sqlite3_step (stmt);
		if (rc == SQLITE_ROW) {
			g_ptr_array_add (out->rows, _pack_record (stmt));
		}
	} while (rc == SQLITE_ROW);

	if (rc != SQLITE_OK && rc != SQLITE_DONE) {
		out->err = NEWERROR(CODE_INTERNAL_ERROR, "DB ERROR (step): (%d) %s",
				rc, sqlite3_errmsg(s->db));
		goto out;
	}

out:
	if (SQLITE_OK != (rc = sqlite3_finalize (stmt))) {
		if (!out->err) {
			out->err = NEWERROR(CODE_INTERNAL_ERROR, "DB ERROR (finalize): "
					"(%d) %s", rc, sqlite3_errmsg(s->db));
		}
	}

	/* fill the context */
	out->ctx.changes = sqlite3_changes (s->db);
	out->ctx.total_changes = sqlite3_total_changes (s->db);
	out->ctx.last_rowid = sqlite3_last_insert_rowid (s->db);

}

static GError *
_local_client_execute_batch (struct oio_sqlx_client_s *self,
		struct oio_sqlx_batch_s *batch,
		struct oio_sqlx_batch_result_s **out_result)
{
	/* sanity checks */
	if (!self || !batch || !out_result || !batch->statements)
		return BADREQ("Invalid parameter");
	const guint max = batch->statements->len;
	if (!max)
		return BADREQ("Empty batch");
	for (guint i=0; i<max ;++i) {
		GPtrArray *stmt = batch->statements->pdata[i];
		if (!stmt || stmt->len < 1)
			return BADREQ("Empty statement at %u", i);
	}

	struct oio_sqlx_client_LOCAL_s *s = (struct oio_sqlx_client_LOCAL_s*)self;
	g_assert (s->vtable == &vtable_LOCAL);
	g_assert (s->db != NULL);

	struct oio_sqlx_batch_result_s *result = oio_sqlx_batch_result__create ();

	for (guint i=0; i<max ;++i) {
		GPtrArray *stmt = batch->statements->pdata[i];
		struct oio_sqlx_statement_result_s *out = oio_sqlx_statement_result__create ();
		_exec_statement (s, stmt, out);
		g_ptr_array_add (result->results, out);
	}

	*out_result = result;
	return NULL;
}

static void
_local_factory_destroy (struct oio_sqlx_client_factory_s *self)
{
	g_assert (self != NULL);
	struct oio_sqlx_client_factory_LOCAL_s *s =
		(struct oio_sqlx_client_factory_LOCAL_s*) self;
	g_assert (s->vtable == &vtable_factory_LOCAL);
	oio_str_clean (&s->schema);
	oio_str_clean (&s->ns);
	s->vtable = NULL;
	SLICE_FREE (struct oio_sqlx_client_factory_LOCAL_s, s);
}

/* XXX JFS dupplicated from sqliterepo/sqlite_utils.c */
static int
_sqlx_exec(sqlite3 *handle, const char *sql)
{
	int rc, grc = SQLITE_OK;
	sqlite3_stmt *stmt = NULL;

	while ((grc == SQLITE_OK) && sql && *sql) {
		const char *next = NULL;
		rc = sqlite3_prepare(handle, sql, -1, &stmt, &next);
		GRID_DEBUG("sqlite3_prepare(%s) = %d", sql, rc);
		sql = next;
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			grc = rc;
		else {
			if (stmt) {
				do {
					rc = sqlite3_step(stmt);
					GRID_DEBUG("sqlite3_step() = %d", rc);
				} while (rc == SQLITE_ROW);
				if (rc != SQLITE_OK && rc != SQLITE_DONE)
					grc = rc;
			}
		}
		if (stmt) {
			rc = sqlite3_finalize(stmt);
			GRID_DEBUG("sqlite3_finalize() = %d", rc);
			stmt = NULL;
			if (rc != SQLITE_OK && rc != SQLITE_DONE)
				grc = rc;
		}
	}

	return grc;
}

static GError *
_local_factory_open (struct oio_sqlx_client_factory_s *self,
			const struct oio_url_s *u, struct oio_sqlx_client_s **out)
{
	g_assert (self != NULL);
	struct oio_sqlx_client_factory_LOCAL_s *factory =
		(struct oio_sqlx_client_factory_LOCAL_s*) self;
	g_assert (factory->vtable == &vtable_factory_LOCAL);
	g_assert (out != NULL);
	g_assert (u != NULL);

	sqlite3 *db = NULL;
	int flags = SQLITE_OPEN_NOMUTEX|SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE;
	int rc = sqlite3_open_v2(":memory:", &db, flags, NULL);
	if (rc != SQLITE_OK) {
		sqlite3_close (db);
		return NEWERROR(CODE_INTERNAL_ERROR, "DB ERROR (open): (%d) %s",
				rc, sqlite3_errmsg(db));
	}

	/* apply the schema */
	rc = _sqlx_exec (db, factory->schema);
	if (SQLITE_OK != rc && SQLITE_DONE != rc) {
		sqlite3_close (db);
		return NEWERROR(CODE_INTERNAL_ERROR, "DB ERROR (schema): (%d) %s",
				rc, sqlite3_errmsg(db));
	}

	struct oio_sqlx_client_LOCAL_s *s = SLICE_NEW0 (struct oio_sqlx_client_LOCAL_s);
	s->vtable = &vtable_LOCAL;
	s->db = db;
	*out = (struct oio_sqlx_client_s*) s;

	return NULL;
}

struct oio_sqlx_client_factory_s *
oio_sqlx_client_factory__create_local (const char *ns, const char *schema)
{
	g_assert (ns != NULL);
	g_assert (schema != NULL);
	struct oio_sqlx_client_factory_LOCAL_s *self = SLICE_NEW0 (struct oio_sqlx_client_factory_LOCAL_s);
	self->vtable = &vtable_factory_LOCAL;
	self->ns = g_strdup (ns);
	self->schema = g_strdup (schema);
	if (self->ns && self->schema)
		return (struct oio_sqlx_client_factory_s*) self;
	_local_factory_destroy ((struct oio_sqlx_client_factory_s*)self);
	return NULL;
}

