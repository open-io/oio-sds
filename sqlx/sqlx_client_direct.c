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

#include <string.h>

#include <glib.h>

#include <core/oiolog.h>
#include <core/oiostr.h>
#include <core/oiourl.h>
#include <core/oiodir.h>
#include <core/internals.h>

#include <core/client_variables.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/codec.h>

#include <sqliterepo/sqlx_remote.h>

#include "sqlx_client.h"
#include "sqlx_client_internals.h"
#include "sqlx_client_direct.h"

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

static GError * _sds_client_create_db (struct oio_sqlx_client_s *self);

static void _sds_client_destroy (struct oio_sqlx_client_s *self);

static GError * _sds_client_batch (struct oio_sqlx_client_s *self,
		struct oio_sqlx_batch_s *in,
		struct oio_sqlx_batch_result_s **out);

struct oio_sqlx_client_factory_vtable_s vtable_factory_SDS = {
	_sds_factory_destroy,
	_sds_factory_open,
	NULL /* the default batch implementation fits */
};

struct oio_sqlx_client_vtable_s vtable_SDS = {
	_sds_client_destroy,
	_sds_client_create_db,
	_sds_client_batch
};

/* -------------------------------------------------------------------------- */

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
	SLICE_FREE (struct oio_sqlx_client_factory_SDS_s, s);
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

	struct oio_sqlx_client_SDS_s * client = SLICE_NEW0 (struct oio_sqlx_client_SDS_s);
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
	struct oio_sqlx_client_factory_SDS_s *self = SLICE_NEW0 (struct oio_sqlx_client_factory_SDS_s);
	self->vtable = &vtable_factory_SDS;
	self->ns = g_strdup (ns);
	self->dir = dir;
	if (self->ns && self->dir)
		return (struct oio_sqlx_client_factory_s*) self;
	_sds_factory_destroy ((struct oio_sqlx_client_factory_s*)self);
	return NULL;
}

/* -------------------------------------------------------------------------- */

static void
_sds_client_get_srvtype (struct oio_sqlx_client_SDS_s *self, gchar *d, gsize dlen)
{
	g_strlcpy (d, NAME_SRVTYPE_SQLX, dlen);
	const char *subtype = oio_url_get (self->url, OIOURL_TYPE);
	if (subtype && *subtype) {
		g_strlcat (d, ".", dlen);
		g_strlcat (d, subtype, dlen);
	}
}

static void
_sds_client_destroy (struct oio_sqlx_client_s *self)
{
	g_assert (self != NULL);
	struct oio_sqlx_client_SDS_s *c = (struct oio_sqlx_client_SDS_s*) self;
	g_assert (c->vtable == &vtable_SDS);
	c->vtable = NULL;
	c->factory = NULL;
	oio_url_pclean (&c->url);
	SLICE_FREE (struct oio_sqlx_client_SDS_s, c);
}

/* With SQLX, creating a DB is mainly a call to the directory to ensure a
 * service is linked, then a query to reach the service a autocreate the
 * DB file. */
static GError *
_sds_client_create_db (struct oio_sqlx_client_s *self)
{
	g_assert (self != NULL);
	struct oio_sqlx_client_SDS_s *c = (struct oio_sqlx_client_SDS_s*) self;
	g_assert (c->vtable == &vtable_SDS);

	/* Link with the directory */
	gchar srvtype[64] = "";
	_sds_client_get_srvtype (c, srvtype, sizeof(srvtype));

	gchar **allsrv = NULL;
	GError *err = oio_directory__link (c->factory->dir,
			c->url, srvtype, TRUE/*autocreate*/, &allsrv);
	if (err) {
		g_prefix_error (&err, "Directory error: ");
		EXTRA_ASSERT (allsrv == NULL);
		return err;
	} else {
		EXTRA_ASSERT (allsrv != NULL);
		g_strfreev (allsrv);
	}

	/* then hit the service to autocreate the base */
	err = oio_sqlx_client__execute_statement (self,
			"SELECT COUNT(*) from sqlite_master", NULL,
			NULL, NULL);
	if (err) {
		g_prefix_error (&err, "sqlx error: ");
		return err;
	}

	return NULL;
}

static GByteArray *
_pack_request (struct sqlx_name_inline_s *n0, struct oio_sqlx_batch_s *batch, gint64 deadline)
{
	GByteArray *req = NULL;
	struct TableSequence in_table_sequence = {{0}};

	for (guint i=0; i<batch->statements->len ;++i) {
		GPtrArray *stmt = batch->statements->pdata[i];
		if (!stmt || !stmt->len) {
			GRID_WARN("Empty statement at position %u", i);
			continue;
		}

		const gchar *query = (gchar*)(stmt->pdata[0]);

		struct Table *table = ASN1C_CALLOC(1, sizeof(struct Table));
		OCTET_STRING_fromBuf(&(table->name), query, strlen(query));
		asn_sequence_add (&in_table_sequence.list, table);

		if (stmt->len > 1) {
			struct Row *row = ASN1C_CALLOC(1, sizeof(struct Row));
			asn_int64_to_INTEGER(&row->rowid, 0);
			struct RowFieldSequence *rfs = ASN1C_CALLOC(1, sizeof(struct RowFieldSequence));
			row->fields = rfs;
			for (guint fi=1; fi < stmt->len ;++fi) {
				const char *param = stmt->pdata[fi];
				struct RowField *rf = ASN1C_CALLOC(1, sizeof(struct RowField));
				/* XXX JFS: index must conform the sqlite3_bind_*() norm,
				 * where the leftmost parameter has an index of 1 */
				asn_uint32_to_INTEGER (&rf->pos, fi);
				OCTET_STRING_fromBuf(&rf->value.choice.s, param, strlen(param));
				rf->value.present = RowFieldValue_PR_s;
				asn_sequence_add(&(rfs->list), rf);
			}
			asn_sequence_add (&table->rows.list, row);
		}
	}

	NAME2CONST(n, *n0);
	req = sqlx_pack_QUERY(&n, "QUERY", &in_table_sequence, TRUE/*autocreate*/, deadline);

	asn_DEF_TableSequence.free_struct(&asn_DEF_TableSequence,
			&in_table_sequence, TRUE);
	return req;
}

static GError *
_unpack_asn1_to_api (struct TableSequence *ts, struct oio_sqlx_batch_result_s *batch)
{
	GError *err = NULL;

	for (int ti=0; !err && ti < ts->list.count ;++ti) {
		struct Table *t = ts->list.array[ti];
		if (!t)
			continue;

		if (!t->status) {
			err = NEWERROR(CODE_PLATFORM_ERROR, "SQLX reply failure");
			break;
		}

		struct oio_sqlx_statement_result_s *stmt = oio_sqlx_statement_result__create ();

		gint64 s64 = -1;
		asn_INTEGER_to_int64 (t->status, &s64);
		if (s64 != 0) {
			stmt->err = NEWERROR(CODE_INTERNAL_ERROR,
					"Query failure: (%"G_GINT64_FORMAT") %.*s", s64,
					t->statusString ? t->statusString->size : 64,
					t->statusString ? (char*)t->statusString->buf : "Unknown error");
		}

		if (t->localChanges)
			asn_INTEGER_to_int64 (t->localChanges, &stmt->ctx.changes);
		if (t->totalChanges)
			asn_INTEGER_to_int64 (t->localChanges, &stmt->ctx.total_changes);
		if (t->lastRowId)
			asn_INTEGER_to_int64 (t->lastRowId, &stmt->ctx.last_rowid);

		/* append each row */
		for (int ri=0; !err && ri < t->rows.list.count ;++ri) {
			struct Row *r = t->rows.list.array[ri];
			if (!r || !r->fields)
				continue;
			GPtrArray *tokens = g_ptr_array_new ();

			/* append one token per field */
			for (int fi=0; !err && fi < r->fields->list.count ;++fi) {
				struct RowField *f = r->fields->list.array[fi];
				if (!f)
					continue;
				gint64 i64;
				gdouble d;
				gchar *s;
				switch (f->value.present) {
					case RowFieldValue_PR_NOTHING:
					case RowFieldValue_PR_n:
						g_ptr_array_add (tokens, g_strdup("null"));
						break;
					case RowFieldValue_PR_i:
						asn_INTEGER_to_int64(&(f->value.choice.i), &i64);
						g_ptr_array_add (tokens, g_strdup_printf("%"G_GINT64_FORMAT, i64));
						break;
					case RowFieldValue_PR_f:
						asn_REAL2double(&(f->value.choice.f), &d);
						g_ptr_array_add (tokens, g_strdup_printf("%f", d));
						break;
					case RowFieldValue_PR_b:
						s = g_strndup((gchar*)f->value.choice.b.buf, f->value.choice.b.size);
						g_ptr_array_add (tokens, s);
						break;
					case RowFieldValue_PR_s:
						s = g_strndup((gchar*)f->value.choice.s.buf, f->value.choice.s.size);
						g_ptr_array_add (tokens, s);
						break;
					default:
						g_ptr_array_add (tokens, g_strdup("?"));
						break;
				}
			}

			if (!err) {
				g_ptr_array_add (tokens, NULL);
				g_ptr_array_add (stmt->rows, (gchar**)g_ptr_array_free (tokens, FALSE));
			} else {
				g_ptr_array_set_free_func (tokens, g_free);
				g_ptr_array_free (tokens, TRUE);
			}
			tokens = NULL;
		}

		g_ptr_array_add (batch->results, stmt);
	}

	return err;
}

static GError *
_unpack_reply (GByteArray *packed, struct oio_sqlx_batch_result_s **result)
{
	/* asn1 unpacking */
	struct TableSequence *ts = NULL;
	asn_codec_ctx_t ctx = {0};
	ctx.max_stack_size = ASN1C_MAX_STACK;
	asn_dec_rval_t rv = ber_decode(&ctx, &asn_DEF_TableSequence,
			(void**)&ts, packed->data, packed->len);

	if (rv.code != RC_OK)
		return NEWERROR(CODE_PLATFORM_ERROR, "Invalid body from the sqlx (decode)");
	if (!ts)
		return NEWERROR(CODE_PLATFORM_ERROR, "Invalid body from the sqlx (content)");

	if (!ts->list.count || !ts->list.array) {
		asn_DEF_TableSequence.free_struct(&asn_DEF_TableSequence, ts, FALSE);
		return NEWERROR(CODE_PLATFORM_ERROR, "Invalid body from the sqlx (content)");
	}

	struct oio_sqlx_batch_result_s *batch = oio_sqlx_batch_result__create ();
	GError *err = _unpack_asn1_to_api (ts, batch);

	if (err)
		oio_sqlx_batch_result__destroy (batch);
	else
		*result = batch;

	asn_DEF_TableSequence.free_struct(&asn_DEF_TableSequence, ts, FALSE);
	return err;
}

static GError *
_sds_client_batch (struct oio_sqlx_client_s *self,
		struct oio_sqlx_batch_s *batch,
		struct oio_sqlx_batch_result_s **out_result)
{
	GRID_TRACE2("%s (%p)", __FUNCTION__, self);

	g_assert (self != NULL);
	struct oio_sqlx_client_SDS_s *c = (struct oio_sqlx_client_SDS_s*) self;
	g_assert (c->vtable == &vtable_SDS);
	g_assert (c->factory != NULL);

	/* locate the sqlx server via the directory object */
	gchar srvtype[64] = "";
	_sds_client_get_srvtype (c, srvtype, sizeof(srvtype));

	gchar **allsrv = NULL;
	GError *err = oio_directory__list (c->factory->dir,
			c->url, srvtype, NULL, &allsrv);
	if (NULL != err) {
		g_prefix_error (&err, "Directory error: ");
		g_assert (allsrv == NULL);
		return err;
	}
	if (!allsrv || !*allsrv) {
		if (allsrv)
			g_strfreev (allsrv);
		return NEWERROR(CODE_CONTAINER_NOTFOUND, "Base not found");
	}

	/* Pack the query parameters */
	struct sqlx_name_inline_s name;
	sqlx_inline_name_fill (&name, c->url, NAME_SRVTYPE_SQLX, atoi(allsrv[0]));

	const gdouble timeout = oio_sqlx_timeout_req;
	const gint64 deadline = oio_ext_monotonic_time() + (timeout * G_TIME_SPAN_SECOND);

	/* Query each service until a reply is acceptable */
	gboolean done = FALSE;
	for (gchar **psrv=allsrv; !err && *psrv ;++psrv) {
		gchar *p = *psrv;
		if (!(p = strchr (p, ','))) continue;
		if (!(p = strchr (p+1, ','))) continue;
		done = TRUE;
		++p;

		/* send the request and concat all the replies */
		GByteArray *out = NULL;
		GByteArray *req = _pack_request (&name, batch, deadline);
		GRID_DEBUG("Encoded query: %u bytes", req ? req->len : 0);

		/* TODO(jfs): here are memory copies. big result sets can cause OOM.
		 * Manage to avoid big resultsets. */
		err = gridd_client_exec_and_concat(
				p, oio_clamp_timeout(timeout, deadline), req, &out);
		if (err) {
			if (err->code == CODE_NETWORK_ERROR) {
				g_clear_error (&err);
				continue;
			}
			break;
		}

		/* Decode the reply */
		GRID_DEBUG("Got %u bytes", out ? out->len : 0);
		struct oio_sqlx_batch_result_s *result = NULL;
		if (NULL != (err = _unpack_reply (out, &result))) {
			oio_sqlx_batch_result__destroy (result); /* to be sure */
		} else {
			*out_result = result;
		}

		g_byte_array_free (out, TRUE);
	}

	if (!err && !done)
		err = NEWERROR(CODE_PLATFORM_ERROR, "Invalid SQLX URL: none matched");

	g_strfreev (allsrv);
	return err;
}

