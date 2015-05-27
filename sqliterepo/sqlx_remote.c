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
#include "sqlx_macros.h"
#include "sqlx_remote.h"
#include "version.h"
#include "internals.h"

struct asn_TYPE_descriptor_s;

static MESSAGE
make_request(const gchar *rn, struct sqlx_name_s *name)
{
	MESSAGE req = message_create_named(rn);
	message_add_fields_str(req,
				NAME_MSGKEY_BASENAME, name->base,
				NAME_MSGKEY_BASETYPE, name->type,
				NAME_MSGKEY_NAMESPACE, name->ns,
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
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_USE, name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_DESCR(struct sqlx_name_s *name)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_DESCR, name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_INFO(struct sqlx_name_s *name)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_INFO, name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_LEANIFY(struct sqlx_name_s *name)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_LEANIFY, name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_RESYNC(struct sqlx_name_s *name)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_RESYNC, name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_STATUS(struct sqlx_name_s *name)
{
    MESSAGE req = make_request(NAME_MSGNAME_SQLX_STATUS, name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_EXITELECTION(struct sqlx_name_s *name)
{
    MESSAGE req = make_request(NAME_MSGNAME_SQLX_EXITELECTION, name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_ISMASTER(struct sqlx_name_s *name)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_ISMASTER, name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_PIPEFROM(struct sqlx_name_s *name, const gchar *source)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_PIPEFROM, name);
	message_add_fields_str(req, NAME_MSGKEY_SRC, source, NULL);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_PIPETO(struct sqlx_name_s *name, const gchar *target)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_PIPETO, name);
	message_add_fields_str(req, NAME_MSGKEY_DST, target, NULL);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_DUMP(struct sqlx_name_s *name, gboolean chunked)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_DUMP, name);
	message_add_field(req, NAME_MSGKEY_CHUNKED, &chunked, 1);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_RESTORE(struct sqlx_name_s *name, const guint8 *raw, gsize rawsize)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_RESTORE, name);
	message_set_BODY(req, raw, rawsize);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_REPLICATE(struct sqlx_name_s *name, struct TableSequence *tabseq)
{
	EXTRA_ASSERT(name != NULL);
	EXTRA_ASSERT(tabseq != NULL);

	MESSAGE req = make_request(NAME_MSGNAME_SQLX_REPLICATE, name);
	message_add_body_unref(req, sqlx_encode_TableSequence(tabseq, NULL));
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_GETVERS(struct sqlx_name_s *name)
{
	EXTRA_ASSERT(name != NULL);
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_GETVERS, name);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_QUERY(struct sqlx_name_s *name, const gchar *query,
		struct TableSequence *params, gboolean autocreate)
{
	EXTRA_ASSERT(name != NULL);
	EXTRA_ASSERT(query != NULL);

	guint8 ac = (guint8) autocreate;
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_QUERY, name);
	message_add_field(req, NAME_MSGKEY_AUTOCREATE, &ac, 1);
	message_add_fields_str(req, NAME_MSGKEY_QUERY, query, NULL);
	if (!params)
		message_add_body_unref (req, sqlx_encode_TableSequence(params, NULL));
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_QUERY_single(struct sqlx_name_s *name, const gchar *query,
		gboolean autocreate)
{
	EXTRA_ASSERT(name != NULL);
	EXTRA_ASSERT(query != NULL);

	MESSAGE req = make_request(NAME_MSGNAME_SQLX_QUERY, name);
	guint8 ac = (guint8) autocreate;
	do {
		Table_t *t = g_malloc0(sizeof(Table_t));
		OCTET_STRING_fromBuf(&(t->name), query, strlen(query));

		TableSequence_t *ts = g_malloc0(sizeof(TableSequence_t));
		asn_sequence_add(&(ts->list), t);

		message_add_body_unref(req, sqlx_encode_TableSequence(ts, NULL));
		message_add_field(req, NAME_MSGKEY_AUTOCREATE, &ac, 1);

		asn_DEF_TableSequence.free_struct(&asn_DEF_TableSequence, ts, FALSE);
	} while (0);

	return message_marshall_gba_and_clean(req);
}

GByteArray *
sqlx_pack_DESTROY(struct sqlx_name_s *name, gboolean local)
{
	gint8 local2 = BOOL(local);
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_DESTROY, name);
	if (local)
		message_add_field(req, NAME_MSGKEY_LOCAL, &local2, 1);
	return message_marshall_gba_and_clean(req);
}

GByteArray *
sqlx_pack_ENABLE(struct sqlx_name_s *name)
{
	return message_marshall_gba_and_clean(make_request(NAME_MSGNAME_SQLX_ENABLE, name));
}

GByteArray *
sqlx_pack_DISABLE(struct sqlx_name_s *name)
{
	return message_marshall_gba_and_clean(make_request(NAME_MSGNAME_SQLX_DISABLE, name));
}

GByteArray *
sqlx_pack_FREEZE(struct sqlx_name_s *name)
{
	return message_marshall_gba_and_clean(make_request(NAME_MSGNAME_SQLX_FREEZE, name));
}

GByteArray *
sqlx_pack_DISABLE_DISABLED(struct sqlx_name_s *name)
{
	return message_marshall_gba_and_clean(make_request(NAME_MSGNAME_SQLX_DISABLE_DISABLED, name));
}

GByteArray *
sqlx_pack_PROPGET(struct sqlx_name_s *name, const gchar * const *keys)
{
	GSList *names = metautils_array_to_list((void**)keys);
	GByteArray *body = strings_marshall_gba(names, NULL);
	g_slist_free(names);

	MESSAGE req = make_request(NAME_MSGNAME_SQLX_PROPGET, name);
	message_add_body_unref(req, body);
	return message_marshall_gba_and_clean(req);
}

GByteArray *
sqlx_pack_PROPDEL(struct sqlx_name_s *name, const gchar * const *keys)
{
	GSList *names = metautils_array_to_list((void**)keys);
	GByteArray *body = strings_marshall_gba(names, NULL);
	g_slist_free(names);

	MESSAGE req = make_request(NAME_MSGNAME_SQLX_PROPDEL, name);
	message_add_body_unref(req, body);
	return message_marshall_gba_and_clean(req);
}

GByteArray *
sqlx_pack_PROPSET_pairs(struct sqlx_name_s *name, gboolean flush, GSList *pairs)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_PROPSET, name);
	if (flush)
		message_add_field_strint (req, NAME_MSGKEY_FLUSH, 1);
	message_add_body_unref (req, key_value_pairs_marshall_gba (pairs, NULL));
	return message_marshall_gba_and_clean(req);
}

GByteArray *
sqlx_pack_PROPSET_tab(struct sqlx_name_s *name, gboolean flush, gchar const * const *kv)
{
	GSList  *pairs = NULL;
	for (const gchar * const *p=kv; p && *p && *(p+1) ;p+=2) {
		struct key_value_pair_s *tmp = key_value_pair_create (
				*p, (guint8*)*(p+1), strlen(*(p+1)));
		pairs = g_slist_prepend (pairs, tmp);
	}
	GByteArray *body = sqlx_pack_PROPSET_pairs (name, flush, pairs);
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

void
sqlx_name_fill  (struct sqlx_name_mutable_s *n, struct hc_url_s *url,
		const char *srvtype, gint64 seq)
{
	EXTRA_ASSERT (n != NULL);
	EXTRA_ASSERT (url != NULL);
	EXTRA_ASSERT (srvtype != NULL);
	const gchar *subtype = hc_url_get (url, HCURL_TYPE);

	n->ns = g_strdup(hc_url_get (url, HCURL_NS));
	n->base = g_strdup_printf ("%s.%"G_GINT64_FORMAT, hc_url_get (url, HCURL_HEXID), seq);
	if (subtype && 0 != strcmp(subtype, HCURL_DEFAULT_TYPE))
		n->type = g_strdup_printf ("%s.%s", srvtype, subtype);
	else
		n->type = g_strdup (srvtype);
}

gboolean
sqlx_name_extract (struct sqlx_name_s *n, struct hc_url_s *url,
		const char *srvtype, gint64 *pseq)
{
	SQLXNAME_CHECK(n);
	EXTRA_ASSERT (url != NULL);
	EXTRA_ASSERT (srvtype != NULL);
	EXTRA_ASSERT (pseq != NULL);

	gboolean rc;
	gchar **tokens;

	tokens = g_strsplit (n->type, ".", 2);
	rc = BOOL(!strcmp(tokens[0], srvtype));
	if (tokens[1])
		hc_url_set (url, HCURL_TYPE, tokens[1]);
	else
		hc_url_set (url, HCURL_TYPE, HCURL_DEFAULT_TYPE);
	g_strfreev (tokens);

	tokens = g_strsplit (n->base, ".", 2);
	hc_url_set (url, HCURL_HEXID, tokens[0]);
	*pseq = g_ascii_strtoll (tokens[1], NULL, 10);
	g_strfreev (tokens);

	return rc;
}

