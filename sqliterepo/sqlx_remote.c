/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.sqlx.remote"
#endif
#include <stddef.h>
#include <unistd.h>

#include <glib.h>

#include <RowName.h>
#include <RowField.h>
#include <Row.h>
#include <RowSet.h>
#include <Table.h>
#include <TableSequence.h>
#include <asn_codecs.h>
#include <der_encoder.h>

#include "../metautils/lib/metatypes.h"
#include "../metautils/lib/metautils.h"
#include "../metautils/lib/metacomm.h"

#include "./internals.h"
#include "./sqliterepo.h"
#include "./sqlx_remote.h"
#include "./version.h"

struct asn_TYPE_descriptor_s;

static MESSAGE
make_request(const gchar *rn, struct sqlx_name_s *name)
{
	MESSAGE req = NULL;

	req = message_create_request(NULL, NULL, rn, NULL, NULL);
	message_add_fields_str(req,
				"BASE_NAME", name->base,
				"BASE_TYPE", name->type,
				"NAMESPACE", name->ns,
				"VIRTUAL_NAMESPACE", name->ns,
				NULL);

	return req;
}

static MESSAGE
make_srv_request(const gchar *rn, struct sqlxsrv_name_s *name)
{
	MESSAGE req = NULL;
	gchar strcid[65], strseq[32];
	GByteArray *gba_cid;

	gba_cid = metautils_gba_from_cid(*(name->cid));
	memset(strcid, 0, sizeof(strcid));
	buffer2str(name->cid, sizeof(container_id_t), strcid, sizeof(strcid));
	g_snprintf(strseq, sizeof(strseq), "%"G_GINT64_FORMAT, name->seq);

	req = message_create_request(NULL, NULL, rn, NULL, NULL);

	message_add_fields_str(req,
				"BASE_SEQ", strseq,
				"BASE_NAME", strcid,
				"BASE_TYPE", name->schema,
				"SCHEMA", name->schema,
				"NAMESPACE", name->ns,
				"VIRTUAL_NAMESPACE", name->ns,
				NULL);

	message_add_fields_gba(req,
				"CONTAINER_ID", gba_cid,
				NULL);

	g_byte_array_free(gba_cid, TRUE);
	return req;
}


/* ------------------------------------------------------------------------- */

GByteArray*
sqlx_pack_USE(struct sqlx_name_s *name)
{
	MESSAGE req;
	GByteArray *gba;

	req = make_request("SQLX_USE", name);
	gba = message_marshall_gba(req, NULL);
	(void) message_destroy(req, NULL);
	return gba;
}

GByteArray*
sqlx_pack_PIPEFROM(struct sqlx_name_s *name, const gchar *source)
{
	MESSAGE req;
	GByteArray *gba;

	req = make_request("SQLX_PIPEFROM", name);
	message_add_fields_str(req, "SRC", source, NULL);
	gba = message_marshall_gba(req, NULL);
	(void) message_destroy(req, NULL);
	return gba;
}

GByteArray*
sqlx_pack_PIPETO(struct sqlx_name_s *name, const gchar *target)
{
	MESSAGE req;
	GByteArray *gba;

	req = make_request("SQLX_PIPETO", name);
	message_add_fields_str(req, "DST", target, NULL);
	gba = message_marshall_gba(req, NULL);
	(void) message_destroy(req, NULL);
	return gba;
}

GByteArray*
sqlx_pack_DUMP(struct sqlx_name_s *name)
{
	MESSAGE req;
	GByteArray *gba;

	req = make_request("SQLX_DUMP", name);
	gba = message_marshall_gba(req, NULL);
	(void) message_destroy(req, NULL);
	return gba;
}

GByteArray*
sqlx_pack_RESTORE(struct sqlx_name_s *name, const guint8 *raw, gsize rawsize)
{
	MESSAGE req;
	GByteArray *gba;

	req = make_request("SQLX_RESTORE", name);
	(void) message_set_BODY(req, raw, rawsize, NULL);
	gba = message_marshall_gba(req, NULL);
	(void) message_destroy(req, NULL);
	return gba;
}

GByteArray*
sqlx_pack_REPLICATE(struct sqlx_name_s *name, struct TableSequence *tabseq)
{
	GError *err = NULL;
	GByteArray *body, *encoded;
	MESSAGE req;

	SQLX_ASSERT(name != NULL);
	SQLX_ASSERT(tabseq != NULL);

	body = sqlx_encode_TableSequence(tabseq, &err);
	if (!body) {
		GRID_WARN("Transaction encoding error : (%d) %s",
				err->code, err->message);
		return NULL;
	}

	req = make_request("SQLX_REPLICATE", name);
	(void) message_set_BODY(req, body->data, body->len, NULL);
	encoded = message_marshall_gba(req, NULL);
	g_byte_array_free(body, TRUE);
	(void) message_destroy(req, NULL);

	return encoded;
}

GByteArray*
sqlx_pack_GETVERS(struct sqlx_name_s *name)
{
	GByteArray *encoded;
	MESSAGE req;

	SQLX_ASSERT(name != NULL);

	req = make_request("SQLX_GETVERS", name);
	encoded = message_marshall_gba(req, NULL);
	(void) message_destroy(req, NULL);

	return encoded;
}

static GByteArray*
sqlx_encode_ASN1(struct asn_TYPE_descriptor_s *descr, void *s, GError **err)
{
	asn_enc_rval_t rv;
	GByteArray *encoded;

	encoded = g_byte_array_new();
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

GByteArray*
sqlx_pack_QUERY(struct sqlxsrv_name_s *name, const gchar *query,
		struct TableSequence *params)
{
	MESSAGE req;
	
	SQLX_ASSERT(name != NULL);
	SQLX_ASSERT(query != NULL);
	
	req = make_srv_request("SQLX_QUERY", name);
	message_add_fields_str(req, "QUERY", query, NULL);

	if (!params) {
		GByteArray *body;
		body = sqlx_encode_TableSequence(params, NULL);
		message_set_BODY(req, body->data, body->len, NULL);
		g_byte_array_free(body, TRUE);
	}

	return message_marshall_gba_and_clean(req);
}

GByteArray*
sqlx_pack_QUERY_single(struct sqlxsrv_name_s *name, const gchar *query)
{
	MESSAGE req = NULL;

	SQLX_ASSERT(name != NULL);
	SQLX_ASSERT(query != NULL);
	
	req = make_srv_request("SQLX_QUERY", name);
	g_assert(req != NULL);

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

		asn_DEF_TableSequence.free_struct(&asn_DEF_TableSequence, ts, FALSE);
		g_byte_array_free(body, TRUE);
	} while (0);

	return message_marshall_gba_and_clean(req);
}

