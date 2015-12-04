/*
OpenIO SDS sqlx
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

/* from oiocore */
#include <core/oiocfg.h>
#include <core/oiolog.h>
#include <core/oiostr.h>
#include <core/oiourl.h>

/* from oiosds */
#include <core/oiodir.h>
#include <core/internals.h>

#include "sqlx_client.h"

#define CLIENT_CALL(self,F) VTABLE_CALL(self,struct oio_sqlx_client_abstract_s*,F)
#define FACTORY_CALL(self,F) VTABLE_CALL(self,struct oio_sqlx_client_factory_abstract_s*,F)

void
oio_sqlx_client__destroy (struct oio_sqlx_client_s *self)
{
	CLIENT_CALL(self,destroy)(self);
}

GError *
oio_sqlx_client__execute_statement (struct oio_sqlx_client_s *self,
		const char *in_stmt, gchar **in_params,
		struct oio_sqlx_output_ctx_s *out_ctx, gchar ***out)
{
	CLIENT_CALL(self,execute_statement)(self, in_stmt, in_params, out_ctx, out);
}

void
oio_sqlx_client_factory__destroy
(struct oio_sqlx_client_factory_s *self)
{
	FACTORY_CALL(self,destroy)(self);
}

GError *
oio_sqlx_client_factory__open (struct oio_sqlx_client_factory_s *self,
			struct oio_url_s *u, struct oio_sqlx_client_s **out)
{
	FACTORY_CALL(self,open)(self, u, out);
}

/* SDS implementation ------------------------------------------------------- */

struct oio_sqlx_client_factory_SDS_s
{
	struct oio_sqlx_client_factory_vtable_s *vtable;
	struct oio_directory_s *dir;
	gchar *ns;
};

struct oio_sqlx_client_SDS_s
{
	struct oio_sqlx_client_vtable_s *vtable;
	struct oio_sqlx_client_factory_SDS_s *factory;
	struct oio_url_s *url;
};

static void _sds_factory_destroy (struct oio_sqlx_client_factory_s *self);

static GError * _sds_factory_open (struct oio_sqlx_client_factory_s *self,
			const struct oio_url_s *u, struct oio_sqlx_client_s **out);

static void _sds_client_destroy (struct oio_sqlx_client_s *self);

static GError * _sds_client_execute (struct oio_sqlx_client_s *self,
		const char *in_stmt, gchar **in_params,
		struct oio_sqlx_output_ctx_s *out_ctx, gchar ***out_lines);

struct oio_sqlx_client_factory_vtable_s vtable_factory_SDS = {
	_sds_factory_destroy, _sds_factory_open
};

struct oio_sqlx_client_vtable_s vtable_SDS = {
	_sds_client_destroy, _sds_client_execute
};

static void
_sds_factory_destroy (struct oio_sqlx_client_factory_s *self)
{
	g_assert (self != NULL);
	struct oio_sqlx_client_factory_SDS_s *s =
		(struct oio_sqlx_client_factory_SDS_s*) self;
	g_assert (s->vtable == &vtable_factory_SDS);
	oio_str_clean (&s->ns);
	s->dir = NULL;
	s->vtable = NULL;
	g_free (s);
}

static GError *
_sds_factory_open (struct oio_sqlx_client_factory_s *self,
			const struct oio_url_s *u, struct oio_sqlx_client_s **out)
{
	g_assert (self != NULL);
	struct oio_sqlx_client_factory_SDS_s *f =
		(struct oio_sqlx_client_factory_SDS_s*) self;
	g_assert (f->vtable == &vtable_factory_SDS);
	g_assert (out != NULL);
	g_assert (u != NULL);

	if (!oio_url_has_fq_container(u))
		return BADREQ("Partial URL");

	struct oio_sqlx_client_SDS_s * client = g_malloc0 (sizeof(
				struct oio_sqlx_client_SDS_s));
	client->vtable = &vtable_SDS;
	client->factory = f;
	client->url = oio_url_dup (u);

	*out = (struct oio_sqlx_client_s*) client;
	return NULL;
}

struct oio_sqlx_client_factory_s *
oio_sqlx_client_factory__create_sds (const char *ns,
		struct oio_directory_s *dir)
{
	struct oio_sqlx_client_factory_SDS_s *self = g_slice_new0(
			struct oio_sqlx_client_factory_SDS_s);
	self->vtable = &vtable_factory_SDS;
	self->ns = g_strdup (ns);
	self->dir = dir;
	if (self->ns && self->dir)
		return (struct oio_sqlx_client_factory_s*) self;
	_sds_factory_destroy ((struct oio_sqlx_client_factory_s*)self);
	return NULL;
}

static void
_sds_client_destroy (struct oio_sqlx_client_s *self)
{
	g_assert (self != NULL);
	struct oio_sqlx_client_SDS_s *c = (struct oio_sqlx_client_SDS_s*) self;
	g_assert (c->vtable == &vtable_SDS);
	c->vtable = NULL;
	c->factory = NULL;
	g_free (c);
}

static GError *
_sds_client_execute (struct oio_sqlx_client_s *self,
		const char *in_stmt, gchar **in_params,
		struct oio_sqlx_output_ctx_s *out_ctx, gchar ***out_lines)
{
	g_assert (self != NULL);
	struct oio_sqlx_client_SDS_s *c = (struct oio_sqlx_client_SDS_s*) self;
	g_assert (c->vtable == &vtable_SDS);
	g_assert (c->factory != NULL);

	/* locate the sqlx server via the directory object */
	GError *err = oio_directory__list (c->factory->dir, c->url, "sqlx",
			NULL, NULL);

	/* contact it */

	return NEWERROR(CODE_NOT_IMPLEMENTED, "NYI");
}

/* Local implementation ----------------------------------------------------- */

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

static GError * _local_client_execute_statement (struct oio_sqlx_client_s *self,
		const char *in_stmt, gchar **in_params,
		struct oio_sqlx_output_ctx_s *out_ctx, gchar ***out_lines);

static void _local_factory_destroy (struct oio_sqlx_client_factory_s *self);

static GError * _local_factory_open (struct oio_sqlx_client_factory_s *self,
			const struct oio_url_s *u, struct oio_sqlx_client_s **out);

struct oio_sqlx_client_factory_vtable_s vtable_factory_LOCAL =
{
	_local_factory_destroy, _local_factory_open
};

struct oio_sqlx_client_vtable_s vtable_LOCAL =
{
	_local_client_destroy, _local_client_execute_statement,
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
	g_free (s);
}

static gchar *
_pack_column_names (sqlite3_stmt *stmt)
{
	GString *gs = g_string_new("");
	for (int i=0,max=sqlite3_column_count(stmt); i<max ;++i) {
		if (gs->len > 0) g_string_append_c (gs, ',');
		g_string_append (gs, sqlite3_column_name(stmt, i));
	}
	return g_string_free (gs, FALSE);
}

static gchar *
_pack_record (sqlite3_stmt *stmt)
{
	GString *gs = g_string_new("");
	for (int i=0,max=sqlite3_column_count(stmt); i<max ;++i) {
		if (gs->len > 0)
			g_string_append_c (gs, ',');
		if (sqlite3_column_type(stmt, i) == SQLITE_INTEGER) {
			g_string_append_printf (gs, "%"G_GINT64_FORMAT,
					(gint64)sqlite3_column_int64(stmt, i));
		} else {
			const char *v = (const char*)sqlite3_column_text(stmt, i);
			if (v) g_string_append (gs, v);
		}
	}
	return g_string_free (gs, FALSE);
}

static GError *
_local_client_execute_statement (struct oio_sqlx_client_s *self,
		const char *in_stmt, gchar **in_params,
		struct oio_sqlx_output_ctx_s *out_ctx, gchar ***out_lines)
{
	g_assert (self != NULL);
	struct oio_sqlx_client_LOCAL_s *s = (struct oio_sqlx_client_LOCAL_s*)self;
	g_assert (s->vtable == &vtable_LOCAL);
	g_assert (s->db != NULL);

	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	GPtrArray *tmp = NULL;

	/* prepare the query and bind the parameters */
	int rc = sqlite3_prepare (s->db, in_stmt, -1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		err = NEWERROR(CODE_INTERNAL_ERROR, "DB ERROR (prepare): (%d) %s",
				rc, sqlite3_errmsg(s->db));
		goto out;
	}

	for (int i=0; in_params && in_params[i]; ++i) {
		rc = sqlite3_bind_text (stmt, i+1, in_params[i], -1, NULL);
		if (SQLITE_OK != rc) {
			err = NEWERROR(CODE_INTERNAL_ERROR, "DB ERROR (bind): (%d) %s",
					rc, sqlite3_errmsg(s->db));
			goto out;
		}
	}

	/* pack the output */
	tmp = g_ptr_array_new ();
	if (out_lines)
		g_ptr_array_add (tmp, _pack_column_names(stmt));
	do {
		rc = sqlite3_step (stmt);
		if (rc == SQLITE_ROW && out_lines)
			g_ptr_array_add (tmp, _pack_record (stmt));
	} while (rc == SQLITE_ROW);

	if (rc != SQLITE_OK && rc != SQLITE_DONE) {
		err = NEWERROR(CODE_INTERNAL_ERROR, "DB ERROR (step): (%d) %s",
				rc, sqlite3_errmsg(s->db));
		goto out;
	}

	/* fill the context */
	if (out_ctx) {
		out_ctx->changes = sqlite3_changes (s->db);
		out_ctx->total_changes = sqlite3_total_changes (s->db);
		out_ctx->last_rowid = sqlite3_last_insert_rowid (s->db);
	}

out:
	if (SQLITE_OK != (rc = sqlite3_finalize (stmt))) {
		if (!err)
			err = NEWERROR(CODE_INTERNAL_ERROR, "DB ERROR (finalize): "
					"(%d) %s", rc, sqlite3_errmsg(s->db));
	}
	if (tmp)
		g_ptr_array_add (tmp, NULL);
	if (!err && out_lines) {
		*out_lines = (gchar**)g_ptr_array_free (tmp, FALSE);
		tmp = NULL;
	}
	if (tmp)
		g_strfreev ((gchar**)g_ptr_array_free (tmp, FALSE));
	return err;
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
	g_free (s);
}

/* XXX JFS dupplicated from sqliterepo/sqlite_utils.c */
static int
_sqlx_exec(sqlite3 *handle, const gchar *sql)
{
	int rc, grc = SQLITE_OK;
	const gchar *next;
	sqlite3_stmt *stmt = NULL;

	while ((grc == SQLITE_OK) && sql && *sql) {
		next = NULL;
		rc = sqlite3_prepare(handle, sql, -1, &stmt, &next);
		sql = next;
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			grc = rc;
		else if (stmt) {
			do {
				rc = sqlite3_step(stmt);
			} while (rc == SQLITE_ROW);
			if (rc != SQLITE_OK && rc != SQLITE_DONE)
				grc = rc;
			rc = sqlite3_finalize(stmt);
		}

		stmt = NULL;
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

	struct oio_sqlx_client_LOCAL_s *s = g_slice_new0 (struct oio_sqlx_client_LOCAL_s);
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
	struct oio_sqlx_client_factory_LOCAL_s *self = g_slice_new0(
			struct oio_sqlx_client_factory_LOCAL_s);
	self->vtable = &vtable_factory_LOCAL;
	self->ns = g_strdup (ns);
	self->schema = g_strdup (schema);
	if (self->ns && self->schema)
		return (struct oio_sqlx_client_factory_s*) self;
	_local_factory_destroy ((struct oio_sqlx_client_factory_s*)self);
	return NULL;
}

