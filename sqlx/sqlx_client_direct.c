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

#include <string.h>

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

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqlx_remote.h>

#include "sqlx_client.h"
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
	oio_url_pclean (&c->url);
	g_free (c);
}

static GByteArray *
_pack_request (struct sqlx_name_mutable_s *n, const char *in_stmt,
		gchar **in_params)
{
	GByteArray *req = NULL;

	struct Row *row = calloc(1, sizeof(struct Row));
	asn_int64_to_INTEGER(&row->rowid, 0);
	if (in_params) {
		for (gchar **pparam=in_params; *pparam ;++pparam) {
			struct RowField *rf = calloc(1, sizeof(struct RowField));
			asn_uint32_to_INTEGER (&rf->pos, (guint32)(pparam - in_params));
			OCTET_STRING_fromBuf(&rf->value.choice.s, *pparam, strlen(*pparam));
			rf->value.present = RowFieldValue_PR_s;
			asn_sequence_add(&(row->fields->list), rf);
		}
	}

	struct Table *table = calloc(1, sizeof(struct Table));
	OCTET_STRING_fromBuf(&(table->name), in_stmt, strlen(in_stmt));
	asn_sequence_add (&table->rows.list, row);

	struct TableSequence in_table_sequence;
	memset (&in_table_sequence, 0, sizeof(in_table_sequence));
	asn_sequence_add (&in_table_sequence.list, table);

	req = sqlx_pack_QUERY(sqlx_name_mutable_to_const(n),
			in_stmt, &in_table_sequence, TRUE/*autocreate*/);

	asn_DEF_TableSequence.free_struct(&asn_DEF_TableSequence,
			&in_table_sequence, TRUE);
	return req;
}

static GError *
_unpack_reply (struct TableSequence *ts, GPtrArray *lines)
{
	if (!ts->list.count || !ts->list.array)
		return NEWERROR(CODE_PLATFORM_ERROR, "Invalid body from the sqlx (content)");

	GError *err = NULL;

	for (int ti=0; !err && ti < ts->list.count ;++ti) {
		struct Table *t = ts->list.array[ti];
		if (!t)
			continue;

		if (!t->status) {
			err = NEWERROR(CODE_PLATFORM_ERROR, "SQLX reply failure");
			break;
		}

		gint64 s64 = -1;
		asn_INTEGER_to_int64 (t->status, &s64);
		if (s64 != 0) {
			err = NEWERROR(CODE_INTERNAL_ERROR,
					"Query failure: (%"G_GINT64_FORMAT") %.*s", s64,
					t->statusString ? t->statusString->size : 64,
					t->statusString ? (char*)t->statusString->buf : "Unknown error");
			continue;
		}

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

			/* pack the ROW for the line */
			g_ptr_array_add (tokens, NULL);
			if (!err) {
				gchar *csv = g_strjoinv (",", (gchar**) tokens->pdata);
				g_ptr_array_add (lines, csv);
			}
			g_strfreev ((gchar**)g_ptr_array_free (tokens, FALSE));
		}
	}

	return NULL;
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
	gchar srvtype[64] = "sqlx";
	const char *subtype = oio_url_get (c->url, OIOURL_TYPE);
	if (subtype && *subtype) {
		g_strlcat (srvtype, ".", sizeof(srvtype));
		g_strlcat (srvtype, subtype, sizeof(srvtype));
	}

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
	struct sqlx_name_mutable_s name;
	sqlx_name_fill (&name, c->url, srvtype, atoi(allsrv[0]));
	GByteArray *req = _pack_request (&name, in_stmt, in_params);
	sqlx_name_clean (&name);
	GRID_DEBUG("Encoded query: %u bytes", req ? req->len : 0);

	/* Query each service until a reply is acceptable */
	gboolean done = FALSE;
	for (gchar **psrv=allsrv; !err && *psrv ;++psrv) {
		gchar *p = *psrv;
		if (!(p = strchr (p, ','))) continue;
		if (!(p = strchr (p+1, ','))) continue;
		done = TRUE;
		++p;

		/* send the request */
		GByteArray *out = NULL;
		GRID_DEBUG("SQLX trying with %s", p);
		/* TODO JFS: macro for the timeout */
		/* TODO JFS: here are memory copies. big result sets can can cause OOM */
		err = gridd_client_exec_and_concat (p, 60.0, req, &out);
		if (err) {
			if (err->code == CODE_NETWORK_ERROR) {
				g_clear_error (&err);
				continue;
			}
			break;
		}

		/* Decode the reply */
		GRID_DEBUG("Got %u bytes", out ? out->len : 0);
		struct TableSequence *ts = NULL;
		asn_codec_ctx_t ctx;
		memset(&ctx, 0, sizeof(ctx));
		ctx.max_stack_size = ASN1C_MAX_STACK;
		asn_dec_rval_t rv = ber_decode(&ctx, &asn_DEF_TableSequence,
				(void**)&ts, out->data, out->len);
		g_byte_array_unref (out);
		out = NULL;

		if (rv.code != RC_OK) {
			err = NEWERROR(CODE_PLATFORM_ERROR, "Invalid body from the sqlx (decode)");
			break;
		}
		if (!ts) {
			err = NEWERROR(CODE_PLATFORM_ERROR, "Invalid body from the sqlx (content)");
			break;
		}

		GPtrArray *lines = g_ptr_array_new ();
		err = _unpack_reply (ts, lines);
		g_ptr_array_add (lines, NULL);

		if (err) {
			g_strfreev ((gchar**) g_ptr_array_free (lines, FALSE));
		} else {
			*out_lines = (gchar**) g_ptr_array_free (lines, FALSE);
		}

		asn_DEF_TableSequence.free_struct(&asn_DEF_TableSequence, ts, FALSE);
	}

	if (!err && !done)
		err = NEWERROR(CODE_PLATFORM_ERROR, "Invalid SQLX URL: none matched");

	g_strfreev (allsrv);
	return err;
}

