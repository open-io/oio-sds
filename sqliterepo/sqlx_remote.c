/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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
#include <metautils/lib/metacomm.h>
#include <metautils/lib/codec.h>
#include <sqliterepo/sqliterepo_remote_variables.h>

#include "sqliterepo.h"
#include "sqlx_macros.h"
#include "sqlx_remote.h"
#include "version.h"
#include "internals.h"

struct asn_TYPE_descriptor_s;

static MESSAGE
make_request(const gchar *rn, const struct sqlx_name_s *name, gint64 deadline)
{
	MESSAGE req = metautils_message_create_named(rn, deadline);
	metautils_message_add_field_str(req, NAME_MSGKEY_BASENAME, name->base);
	metautils_message_add_field_str(req, NAME_MSGKEY_BASETYPE, name->type);
	metautils_message_add_field_str(req, NAME_MSGKEY_NAMESPACE, name->ns);
	return req;
}

/* ------------------------------------------------------------------------- */

static GByteArray*
sqlx_encode_ASN1(struct asn_TYPE_descriptor_s *descr, void *s, GError **err)
{
	asn_enc_rval_t rv;
	GByteArray *encoded = g_byte_array_sized_new(2048);
	rv = der_encode(descr, s, metautils_asn1c_write_gba, encoded);
	if (0 >= rv.encoded) {
		g_byte_array_free(encoded, TRUE);
		GSETERROR(err, "TableSequence encoding error : %s",
			rv.failed_type->name);
		return NULL;
	}

	return encoded;
}

GByteArray*
sqlx_encode_TableSequence(struct TableSequence *tabseq, GError **err)
{
	return sqlx_encode_ASN1(&asn_DEF_TableSequence, tabseq, err);
}

/* ------------------------------------------------------------------------- */

GByteArray*
sqlx_pack_USE(const struct sqlx_name_s *name, gint64 deadline)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_USE, name, deadline);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_DESCR(const struct sqlx_name_s *name, gint64 deadline)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_DESCR, name, deadline);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_INFO(gint64 deadline)
{
	MESSAGE req = metautils_message_create_named (NAME_MSGNAME_SQLX_INFO, deadline);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_LEANIFY(gint64 deadline)
{
	MESSAGE req = metautils_message_create_named (NAME_MSGNAME_SQLX_LEANIFY, deadline);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_RESYNC(const struct sqlx_name_s *name, gint64 deadline)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_RESYNC, name, deadline);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_STATUS(const struct sqlx_name_s *name, gint64 deadline)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_STATUS, name, deadline);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_EXITELECTION(const struct sqlx_name_s *name, gint64 deadline)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_EXITELECTION, name, deadline);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_SNAPSHOT(const struct sqlx_name_s *name, const gchar *source,
		const gchar *cid, const gchar *seq_num, gint64 deadline)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_SNAPSHOT, name, deadline);
	metautils_message_add_field_str(req, NAME_MSGKEY_SRC, source);
	metautils_message_add_field_str(req, NAME_MSGKEY_CONTAINERID, cid);
	metautils_message_add_field_str(req, NAME_MSGKEY_SEQNUM, seq_num);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_PIPEFROM(const struct sqlx_name_s *name, const gchar *source, gint64 deadline)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_PIPEFROM, name, deadline);
	metautils_message_add_field_str(req, NAME_MSGKEY_SRC, source);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_PIPETO(const struct sqlx_name_s *name, const gchar *target, gint64 deadline)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_PIPETO, name, deadline);
	metautils_message_add_field_str(req, NAME_MSGKEY_DST, target);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_DUMP(const struct sqlx_name_s *name, gboolean chunked, gint64 deadline)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_DUMP, name, deadline);
	metautils_message_add_field(req, NAME_MSGKEY_CHUNKED, &chunked, 1);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_RESTORE(const struct sqlx_name_s *name, const guint8 *raw, gsize rawsize, gint64 deadline)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_RESTORE, name, deadline);
	metautils_message_set_BODY(req, raw, rawsize);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_REPLICATE(const struct sqlx_name_s *name, struct TableSequence *tabseq, gint64 deadline)
{
	EXTRA_ASSERT(name != NULL);
	EXTRA_ASSERT(tabseq != NULL);

	MESSAGE req = make_request(NAME_MSGNAME_SQLX_REPLICATE, name, deadline);
	metautils_message_add_body_unref(req, sqlx_encode_TableSequence(tabseq, NULL));
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_GETVERS(const struct sqlx_name_s *name, gint64 deadline)
{
	EXTRA_ASSERT(name != NULL);
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_GETVERS, name, deadline);
	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_QUERY(const struct sqlx_name_s *name, const gchar *query,
		struct TableSequence *params, gboolean autocreate, gint64 deadline)
{
	EXTRA_ASSERT(name != NULL);
	EXTRA_ASSERT(query != NULL);

	guint8 ac = (guint8) autocreate;
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_QUERY, name, deadline);
	metautils_message_add_field(req, NAME_MSGKEY_AUTOCREATE, &ac, 1);
	metautils_message_add_field_str(req, NAME_MSGKEY_QUERY, query);
	if (params)
		metautils_message_add_body_unref (req, sqlx_encode_TableSequence(
					params, NULL));
	return message_marshall_gba_and_clean(req);
}

GByteArray *
sqlx_pack_DESTROY(const struct sqlx_name_s *name, gboolean local, gint64 deadline)
{
	gint8 local2 = BOOL(local);
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_DESTROY, name, deadline);
	if (local)
		metautils_message_add_field(req, NAME_MSGKEY_LOCAL, &local2, 1);
	return message_marshall_gba_and_clean(req);
}

GByteArray *
sqlx_pack_ENABLE(const struct sqlx_name_s *name, gint64 deadline)
{
	return message_marshall_gba_and_clean(make_request(NAME_MSGNAME_SQLX_ENABLE, name, deadline));
}

GByteArray *
sqlx_pack_DISABLE(const struct sqlx_name_s *name, gint64 deadline)
{
	return message_marshall_gba_and_clean(make_request(NAME_MSGNAME_SQLX_DISABLE, name, deadline));
}

GByteArray *
sqlx_pack_FREEZE(const struct sqlx_name_s *name, gint64 deadline)
{
	return message_marshall_gba_and_clean(make_request(NAME_MSGNAME_SQLX_FREEZE, name, deadline));
}

GByteArray *
sqlx_pack_DISABLE_DISABLED(const struct sqlx_name_s *name, gint64 deadline)
{
	return message_marshall_gba_and_clean(make_request(NAME_MSGNAME_SQLX_DISABLE_DISABLED, name, deadline));
}

GByteArray *
sqlx_pack_PROPGET(const struct sqlx_name_s *name, gint64 deadline)
{
	return message_marshall_gba_and_clean(make_request(NAME_MSGNAME_SQLX_PROPGET, name, deadline));
}

GByteArray *
sqlx_pack_PROPDEL(const struct sqlx_name_s *name, const gchar * const *keys, gint64 deadline)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_PROPDEL, name, deadline);
	metautils_message_add_body_unref(req, STRV_encode_gba((gchar**)keys));
	return message_marshall_gba_and_clean(req);
}

GByteArray *
sqlx_pack_PROPSET_tab(const struct sqlx_name_s *name, gboolean flush, gchar **kv, gint64 deadline)
{
	MESSAGE req = make_request(NAME_MSGNAME_SQLX_PROPSET, name, deadline);
	if (flush)
		metautils_message_add_field_strint (req, NAME_MSGKEY_FLUSH, 1);
	metautils_message_add_body_unref (req, KV_encode_gba((gchar**)kv));
	return message_marshall_gba_and_clean(req);
}

void
sqlx_inline_name_fill_type_asis  (struct sqlx_name_inline_s *n,
		struct oio_url_s *url, const char *srvtype, gint64 seq)
{
	EXTRA_ASSERT (n != NULL);
	EXTRA_ASSERT (url != NULL);
	EXTRA_ASSERT (srvtype != NULL);

	g_strlcpy(n->ns, oio_url_get (url, OIOURL_NS), sizeof(n->ns));
	g_strlcpy(n->type, srvtype, sizeof(n->type));

	if (!strcmp(srvtype, NAME_SRVTYPE_META0)) {
		g_strlcpy(n->base, oio_url_get (url, OIOURL_NS), sizeof(n->base));
	} else if (!strcmp(srvtype, NAME_SRVTYPE_META1)) {
		g_strlcpy(n->base, oio_url_get(url, OIOURL_HEXID), 4+1);
	} else {
		g_snprintf (n->base, sizeof(n->base), "%s.%"G_GINT64_FORMAT,
				oio_url_get (url, OIOURL_HEXID), seq);
	}
}

void
sqlx_inline_name_fill (struct sqlx_name_inline_s *n, struct oio_url_s *url,
		const char *srvtype, gint64 seq)
{
	gchar tmp[LIMIT_LENGTH_BASETYPE];
	const gchar *subtype = oio_url_get (url, OIOURL_TYPE);

	if (subtype && 0 != strcmp(subtype, OIOURL_DEFAULT_TYPE))
		g_snprintf(tmp, sizeof(tmp), "%s.%s", srvtype, subtype);
	else
		g_strlcpy(tmp, srvtype, sizeof(tmp));

	return sqlx_inline_name_fill_type_asis(n, url, tmp, seq);
}

gboolean
sqlx_name_extract (const struct sqlx_name_s *n, struct oio_url_s *url,
		const char *srvtype, gint64 *pseq)
{
	SQLXNAME_CHECK(n);
	EXTRA_ASSERT (url != NULL);
	EXTRA_ASSERT (srvtype != NULL);
	EXTRA_ASSERT (pseq != NULL);

	int rc = 0;
	gchar **tokens;

	if (NULL != (tokens = g_strsplit (n->type, ".", 2))) {
		if (tokens[0])
			rc = !strcmp(tokens[0], srvtype);
		oio_url_set (url, OIOURL_TYPE, tokens[1] ? tokens[1] : OIOURL_DEFAULT_TYPE);
		g_strfreev (tokens);
	}

	if (NULL != (tokens = g_strsplit (n->base, ".", 2))) {
		if (tokens[0]) {
			if (strlen(tokens[0]) >= 64) {
				oio_url_set(url, OIOURL_HEXID, tokens[0]);
			} else {
				// Special case of meta1 databases
				EXTRA_ASSERT(!strcmp(srvtype, NAME_SRVTYPE_META1));
				gchar hexid[STRLEN_CONTAINERID];
				gchar *cur = g_stpcpy(hexid, tokens[0]);
				for (; cur < hexid + STRLEN_CONTAINERID - 1; cur++)
					*cur = '0';
				*cur = '\0';
				oio_url_set(url, OIOURL_HEXID, hexid);
			}
		}
		*pseq = tokens[1] ? g_ascii_strtoll (tokens[1], NULL, 10) : 1;
		g_strfreev (tokens);
	}

	return BOOL(rc);
}
