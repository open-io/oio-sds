/*
OpenIO SDS sqlx
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#include <core/oiolog.h>
#include <core/oiostr.h>
#include <core/oiourl.h>

#include <core/internals.h>

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqlx_remote.h>

#include "sqlx_client.h"
#include "sqlx_client_internals.h"

#define CLIENT_CALL(self,F) VTABLE_CALL(self,struct oio_sqlx_client_abstract_s*,F)
#define FACTORY_CALL(self,F) VTABLE_CALL(self,struct oio_sqlx_client_factory_abstract_s*,F)

gboolean oio_sqlx_debug_requests = FALSE;

void
oio_sqlx_client__destroy (struct oio_sqlx_client_s *self)
{
	CLIENT_CALL(self,destroy)(self);
}

GError *
oio_sqlx_client__create_db (struct oio_sqlx_client_s *self)
{
	CLIENT_CALL(self,create_db)(self);
}

#ifdef HAVE_EXTRA_DEBUG
static void
_debug_statement(guint index,
		GPtrArray *stmt,
		struct oio_sqlx_statement_result_s *result)
{
	do {
		const guint max = stmt->len;
		GRID_DEBUG("#%u SQL %s", index, (gchar*) stmt->pdata[0]);
		GString *gstr = g_string_new("");
		for (guint i=1; i<max; ++i)
			g_string_append_printf(gstr, ",%s", (gchar*)stmt->pdata[i]);
		GRID_DEBUG(" Params: %s", gstr->str);
		g_string_free(gstr, TRUE);
	} while (0);
	do {
		const guint max = result->rows->len;
		for (guint irow=0; irow<max ;++irow) {
			gchar *sfields = g_strjoinv(",", result->rows->pdata[irow]);
			GRID_DEBUG(" row=%u/%u %s", irow, max, sfields);
			g_free (sfields);
		}
	} while (0);
}
#endif

GError *
oio_sqlx_client__execute_batch (struct oio_sqlx_client_s *self,
		struct oio_sqlx_batch_s *batch,
		struct oio_sqlx_batch_result_s **out_result)
{
	VTABLE_CHECK(self,struct oio_sqlx_client_abstract_s*,execute_batch);
	GError *err =
		VTABLE_CALL_NOCHECK(self,struct oio_sqlx_client_abstract_s*,execute_batch)
		(self,batch,out_result);
	if (oio_sqlx_debug_requests) {
#ifdef HAVE_EXTRA_DEBUG
		const guint max = batch->statements->len;
		for (guint i=0; i<max; ++i)
			_debug_statement (i,
					batch->statements->pdata[i],
					(*out_result)->results->pdata[i]);
#endif /*HAVE_EXTRA_DEBUG*/
	}
	return err;
}

GError *
oio_sqlx_client__execute_statement (struct oio_sqlx_client_s *self,
		const char *in_stmt, gchar **in_params,
		struct oio_sqlx_output_ctx_s *out_ctx, gchar ***out_lines)
{
	GError *err = NULL;
	struct oio_sqlx_batch_s *batch = NULL;
	struct oio_sqlx_batch_result_s *result = NULL;

	GRID_TRACE("%s (%p, %s)", __FUNCTION__, self, in_stmt);

	(void) oio_sqlx_client_factory__batch (NULL, &batch);
	oio_sqlx_batch__add (batch, in_stmt, in_params);
	err = oio_sqlx_client__execute_batch (self, batch, &result);
	oio_sqlx_batch__destroy (batch);

	if (err) {
		g_assert (result == NULL);
		return err;
	}

	g_assert (result != NULL);
	guint count = oio_sqlx_batch_result__count_statements (result);
	g_assert (count == 1);
	guint count_lines = 0;
	err = oio_sqlx_batch_result__get_statement (result, 0, &count_lines, out_ctx);
	if (!err && out_lines) {
		GPtrArray *tmp = g_ptr_array_new ();
		for (guint i=0; i<count_lines ;++i) {
			gchar **fields = oio_sqlx_batch_result__get_row (result, 0, i);
			g_ptr_array_add (tmp, g_strjoinv (",", fields));
			g_strfreev (fields);
		}
		g_ptr_array_add (tmp, NULL);
		*out_lines = (gchar**) g_ptr_array_free (tmp, FALSE);
	}
	oio_sqlx_batch_result__destroy (result);

	return err;
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

GError *
oio_sqlx_client_factory__batch (struct oio_sqlx_client_factory_s *self,
		struct oio_sqlx_batch_s **out)
{
	(void) self;
	EXTRA_ASSERT(out != NULL);
	*out = SLICE_NEW0(struct oio_sqlx_batch_s);
	(*out)->statements = g_ptr_array_new_with_free_func((GDestroyNotify)g_ptr_array_unref);
	return NULL;
}

void
oio_sqlx_batch__destroy (struct oio_sqlx_batch_s *self)
{
	if (!self)
		return;
	if (self->statements)
		g_ptr_array_free (self->statements, TRUE);
	self->statements = NULL;
	SLICE_FREE(struct oio_sqlx_batch_s, self);
}

void
oio_sqlx_batch__add (struct oio_sqlx_batch_s *self,
		const char *stmt, gchar **params)
{
	EXTRA_ASSERT(self != NULL);
	EXTRA_ASSERT(self->statements != NULL);

	GPtrArray *tab = g_ptr_array_new_with_free_func (g_free);
	g_ptr_array_add (tab, g_strdup(stmt));
	if (params) {
		for (gchar **p=params; *p ;++p)
			g_ptr_array_add (tab, g_strdup(*p));
	}

	g_ptr_array_add (self->statements, tab);
}

gboolean
oio_sqlx_batch__is_empty (struct oio_sqlx_batch_s *self)
{
	EXTRA_ASSERT (self != NULL);
	EXTRA_ASSERT(self->statements != NULL);
	return self->statements->len <= 0;
}

guint
oio_sqlx_batch_result__count_errors (struct oio_sqlx_batch_result_s *self)
{
	EXTRA_ASSERT(self != NULL);
	EXTRA_ASSERT(self->results != NULL);
	guint count = 0;
	const guint max = self->results->len;
	for (guint i=0; i<max ;++i) {
		struct oio_sqlx_statement_result_s *res = self->results->pdata[i];
		if (NULL != res->err)
			++ count;
	}
	return count;
}

guint
oio_sqlx_batch_result__count_statements (struct oio_sqlx_batch_result_s *self)
{
	EXTRA_ASSERT(self != NULL);
	EXTRA_ASSERT(self->results != NULL);
	return self->results->len;
}

GError*
oio_sqlx_batch_result__get_statement (
		struct oio_sqlx_batch_result_s *self, guint i_stmt,
		guint *out_count, struct oio_sqlx_output_ctx_s *out_ctx)
{
	EXTRA_ASSERT(self != NULL);
	EXTRA_ASSERT(self->results != NULL);
	EXTRA_ASSERT(i_stmt < self->results->len);

	struct oio_sqlx_statement_result_s *stmt = self->results->pdata[i_stmt];
	EXTRA_ASSERT (stmt != NULL);
	EXTRA_ASSERT (stmt->rows != NULL);

	if (out_ctx)
		*out_ctx = stmt->ctx;
	if (out_count)
		*out_count = stmt->rows->len;
	if (!stmt->err)
		return NULL;
	return NEWERROR(stmt->err->code, "%s", stmt->err->message);
}

gchar **
oio_sqlx_batch_result__get_row (struct oio_sqlx_batch_result_s *self,
		guint i_stmt, guint i_row)
{
	EXTRA_ASSERT(self != NULL);
	EXTRA_ASSERT(self->results != NULL);
	EXTRA_ASSERT(i_stmt < self->results->len);

	struct oio_sqlx_statement_result_s *stmt = self->results->pdata[i_stmt];
	EXTRA_ASSERT (stmt != NULL);
	EXTRA_ASSERT (stmt->rows != NULL);
	EXTRA_ASSERT (i_row < stmt->rows->len);

	gchar **fields = stmt->rows->pdata[i_row];
	EXTRA_ASSERT(fields != NULL);

	return g_strdupv (fields);
}

void
oio_sqlx_batch_result__destroy (struct oio_sqlx_batch_result_s *self)
{
	if (!self)
		return;
	if (self->results)
		g_ptr_array_free (self->results, TRUE);
	SLICE_FREE (struct oio_sqlx_batch_result_s, self);
}

static void
_free_statement_result (struct oio_sqlx_statement_result_s *p)
{
	if (!p)
		return;
	if (p->err)
		g_clear_error (&p->err);
	if (p->rows) {
		g_ptr_array_free (p->rows, TRUE);
		p->rows = NULL;
	}
	SLICE_FREE(struct oio_sqlx_statement_result_s, p);
}

struct oio_sqlx_batch_result_s *
oio_sqlx_batch_result__create (void)
{
	struct oio_sqlx_batch_result_s *self = SLICE_NEW0(struct oio_sqlx_batch_result_s);
	self->results = g_ptr_array_new_with_free_func (
			(GDestroyNotify)_free_statement_result);
	return self;
}

struct oio_sqlx_statement_result_s *
oio_sqlx_statement_result__create (void)
{
	struct oio_sqlx_statement_result_s *self = SLICE_NEW0(
			struct oio_sqlx_statement_result_s);
	self->rows = g_ptr_array_new_with_free_func ((GDestroyNotify)g_strfreev);
	return self;
}

