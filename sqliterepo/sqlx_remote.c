/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "sqliterepo"
#endif
#include <stddef.h>
#include <unistd.h>

#include <metautils/lib/metatypes.h>
#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <RowName.h>
#include <RowField.h>
#include <Row.h>
#include <RowSet.h>
#include <Table.h>
#include <TableSequence.h>
#include <asn_codecs.h>
#include <der_encoder.h>

#include "sqliterepo.h"
#include "sqlx_remote.h"
#include "version.h"
#include "internals.h"

struct asn_TYPE_descriptor_s;

static MESSAGE
make_request(const gchar *rn, struct sqlx_name_s *name)
{
	MESSAGE req = message_create_request(NULL, NULL, rn, NULL, NULL);
	message_add_fields_str(req,
				"BASE_NAME", name->base,
				"BASE_TYPE", name->type,
				"NAMESPACE", name->ns,
				"VIRTUAL_NAMESPACE", name->ns,
				NULL);
	return req;
}

/* ------------------------------------------------------------------------- */

static GByteArray*
sqlx_encode_ASN1(struct asn_TYPE_descriptor_s *descr, void *s, GError **err)
{
	asn_enc_rval_t rv;
	GByteArray *encoded = g_byte_array_new();
	rv = der_encode(descr, s, write_to_gba, encoded);
	if (0 >= rv.encoded) {
		g_byte_array_free(encoded, TRUE);
		GSETERROR(err, "TableSequence encoding error : %s",
			rv.failed_type->name);
		return NULL;
	}

	return encoded;
}

GByteArray*
sqlx_encode_Table(struct Table *table, GError **err)
{
	return sqlx_encode_ASN1(&asn_DEF_Table, table, err);
}

GByteArray*
sqlx_encode_TableSequence(struct TableSequence *tabseq, GError **err)
{
	return sqlx_encode_ASN1(&asn_DEF_TableSequence, tabseq, err);
}

GByteArray*
sqlx_encode_Row(struct Row *row, GError **err)
{
	return sqlx_encode_ASN1(&asn_DEF_Row, row, err);
}

GByteArray*
sqlx_encode_RowSet(struct RowSet *rows, GError **err)
{
	return sqlx_encode_ASN1(&asn_DEF_RowSet, rows, err);
}

/* ------------------------------------------------------------------------- */

GByteArray*
sqlx_pack_USE(struct sqlx_name_s *name)
{
	MESSAGE req = make_request("SQLX_USE", name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_DESCR(struct sqlx_name_s *name)
{
	MESSAGE req = make_request("SQLX_DESCR", name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_INFO(struct sqlx_name_s *name)
{
	MESSAGE req = make_request("SQLX_INFO", name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_LEANIFY(struct sqlx_name_s *name)
{
	MESSAGE req = make_request("SQLX_LEANIFY", name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_RESYNC(struct sqlx_name_s *name)
{
	MESSAGE req = make_request("SQLX_RESYNC", name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_STATUS(struct sqlx_name_s *name)
{
    MESSAGE req = make_request("SQLX_STATUS", name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_EXITELECTION(struct sqlx_name_s *name)
{
    MESSAGE req = make_request("SQLX_EXITELECTION", name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_ISMASTER(struct sqlx_name_s *name)
{
	MESSAGE req = make_request("SQLX_ISMASTER", name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_PIPEFROM(struct sqlx_name_s *name, const gchar *source)
{
	MESSAGE req = make_request("SQLX_PIPEFROM", name);
	message_add_fields_str(req, "SRC", source, NULL);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_PIPETO(struct sqlx_name_s *name, const gchar *target)
{
	MESSAGE req = make_request("SQLX_PIPETO", name);
	message_add_fields_str(req, "DST", target, NULL);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_DUMP(struct sqlx_name_s *name, gboolean chunked)
{
	MESSAGE req = make_request("SQLX_DUMP", name);
	message_add_field(req, "CHUNKED", &chunked, 1);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_RESTORE(struct sqlx_name_s *name, const guint8 *raw, gsize rawsize)
{
	MESSAGE req = make_request("SQLX_RESTORE", name);
	message_set_BODY(req, raw, rawsize, NULL);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_REPLICATE(struct sqlx_name_s *name, struct TableSequence *tabseq)
{
	GError *err = NULL;
	GByteArray *body, *encoded;

	EXTRA_ASSERT(name != NULL);
	EXTRA_ASSERT(tabseq != NULL);

	body = sqlx_encode_TableSequence(tabseq, &err);
	if (!body) {
		GRID_WARN("Transaction encoding error : (%d) %s",
				err->code, err->message);
		return NULL;
	}

	MESSAGE req = make_request("SQLX_REPLICATE", name);
	message_set_BODY(req, body->data, body->len, NULL);
	encoded = message_marshall_gba(req, NULL);
	g_byte_array_free(body, TRUE);
	message_destroy(req);

	return encoded;
}

GByteArray*
sqlx_pack_GETVERS(struct sqlx_name_s *name)
{
	EXTRA_ASSERT(name != NULL);
	MESSAGE req = make_request("SQLX_GETVERS", name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_QUERY(struct sqlx_name_s *name, const gchar *query,
		struct TableSequence *params, gboolean autocreate)
{
	EXTRA_ASSERT(name != NULL);
	EXTRA_ASSERT(query != NULL);

	guint8 ac = (guint8) autocreate;
	MESSAGE req = make_request("SQLX_QUERY", name);
	message_add_field(req, "AUTOCREATE", &ac, 1);
	message_add_fields_str(req, "QUERY", query, NULL);

	if (!params) {
		GByteArray *body = sqlx_encode_TableSequence(params, NULL);
		message_set_BODY(req, body->data, body->len, NULL);
		g_byte_array_free(body, TRUE);
	}

	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_QUERY_single(struct sqlx_name_s *name, const gchar *query,
		gboolean autocreate)
{
	EXTRA_ASSERT(name != NULL);
	EXTRA_ASSERT(query != NULL);

	MESSAGE req = make_request("SQLX_QUERY", name);
	guint8 ac = (guint8) autocreate;
	do {
		Table_t *t;
		TableSequence_t *ts;
		GByteArray *body;

		t = g_malloc0(sizeof(Table_t));
		g_assert(t != NULL);
		ts = g_malloc0(sizeof(TableSequence_t));
		g_assert(ts != NULL);

		OCTET_STRING_fromBuf(&(t->name), query, strlen(query));
		asn_sequence_add(&(ts->list), t);
		body = sqlx_encode_TableSequence(ts, NULL);
		g_assert(body != NULL);
		message_set_BODY(req, body->data, body->len, NULL);
		message_add_field(req, "AUTOCREATE", &ac, 1);

		asn_DEF_TableSequence.free_struct(&asn_DEF_TableSequence, ts, FALSE);
		g_byte_array_free(body, TRUE);
	} while (0);

	return message_marshall_gba_and_clean(req);
}

GByteArray *
sqlx_pack_DESTROY(struct sqlx_name_s *name, gboolean local)
{
	gint8 local2 = BOOL(local);
	MESSAGE req = make_request("SQLX_DESTROY", name);
	if (local)
		message_add_field(req, "LOCAL", &local2, 1);
	return message_marshall_gba_and_clean(req);
}

GByteArray *
sqlx_pack_LOAD(struct sqlx_name_s *name, GByteArray *dump)
{
	MESSAGE req = make_request("SQLX_LOAD", name);
	message_set_BODY(req, dump->data, dump->len, NULL);
	return message_marshall_gba_and_clean(req);
}

GByteArray *
sqlx_pack_ENABLE(struct sqlx_name_s *name)
{
	return message_marshall_gba_and_clean(make_request("SQLX_ENABLE", name));
}

GByteArray *
sqlx_pack_DISABLE(struct sqlx_name_s *name)
{
	return message_marshall_gba_and_clean(make_request("SQLX_DISABLE", name));
}

GByteArray *
sqlx_pack_FREEZE(struct sqlx_name_s *name)
{
	return message_marshall_gba_and_clean(make_request("SQLX_FREEZE", name));
}

GByteArray *
sqlx_pack_DISABLE_DISABLED(struct sqlx_name_s *name)
{
	return message_marshall_gba_and_clean(make_request("SQLX_DISABLE_DISABLED", name));
}

GByteArray *
sqlx_pack_PROPGET(struct sqlx_name_s *name, gchar **keys)
{
	GSList *names = metautils_array_to_list((void**)keys);
	GByteArray *body = strings_marshall_gba(names, NULL);
	g_slist_free(names);
	if (!body)
		return NULL;

	MESSAGE req = make_request("SQLX_PROPGET", name);
	message_set_BODY(req, body->data, body->len, NULL);
	g_byte_array_free (body, TRUE);
	return message_marshall_gba_and_clean(req);
}

GByteArray *
sqlx_pack_PROPDEL(struct sqlx_name_s *name, gchar **keys)
{
	GSList *names = metautils_array_to_list((void**)keys);
	GByteArray *body = strings_marshall_gba(names, NULL);
	g_slist_free(names);
	if (!body)
		return NULL;

	MESSAGE req = make_request("SQLX_PROPDEL", name);
	message_set_BODY(req, body->data, body->len, NULL);
	g_byte_array_free (body, TRUE);
	return message_marshall_gba_and_clean(req);
}

GByteArray *
sqlx_pack_PROPSET_pairs(struct sqlx_name_s *name, GSList *pairs)
{
	GByteArray *body = key_value_pairs_marshall_gba (pairs, NULL);
	MESSAGE req = make_request("SQLX_PROPSET", name);
	message_set_BODY(req, body->data, body->len, NULL);
	g_byte_array_free (body, TRUE);
	return message_marshall_gba_and_clean(req);
}

GByteArray *
sqlx_pack_PROPSET_tab(struct sqlx_name_s *name, gchar **kv)
{
	GSList  *pairs = NULL;
	for (gchar **p=kv; p && *p && *(p+1) ;p+=2) {
		struct key_value_pair_s *tmp = key_value_pair_create (
				*p, (guint8*)*(p+1), strlen(*(p+1)));
		pairs = g_slist_prepend (pairs, tmp);
	}
	GByteArray *body = sqlx_pack_PROPSET_pairs (name, pairs);
	g_slist_free_full (pairs, (GDestroyNotify)key_value_pair_clean);
	return body;
}

void
sqlx_name_clean (struct sqlx_name_mutable_s *n)
{
	if (!n) return;
	metautils_str_clean(&n->ns);
	metautils_str_clean(&n->base);
	metautils_str_clean(&n->type);
}

void
sqlx_name_free (struct sqlx_name_mutable_s *n)
{
	sqlx_name_clean(n);
	g_free0 (n);
}

