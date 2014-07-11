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
sqlx_pack_STATUS(struct sqlx_name_s *name)
{
    MESSAGE req;
    GByteArray *gba;

    req = make_request("SQLX_STATUS", name);
    gba = message_marshall_gba(req, NULL);
    (void) message_destroy(req, NULL);
    return gba;
}


GByteArray*
sqlx_pack_ISMASTER(struct sqlx_name_s *name)
{
    MESSAGE req;
    GByteArray *gba;

    req = make_request("SQLX_ISMASTER", name);
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

	EXTRA_ASSERT(name != NULL);
	EXTRA_ASSERT(tabseq != NULL);

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

	EXTRA_ASSERT(name != NULL);

	req = make_request("SQLX_GETVERS", name);
	encoded = message_marshall_gba(req, NULL);
	(void) message_destroy(req, NULL);

	return encoded;
}

GByteArray*
sqlx_pack_QUERY(struct sqlxsrv_name_s *name, const gchar *query,
		struct TableSequence *params, gboolean autocreate)
{
	MESSAGE req;
	guint8 ac = (guint8) autocreate;

	EXTRA_ASSERT(name != NULL);
	EXTRA_ASSERT(query != NULL);

	req = make_srv_request("SQLX_QUERY", name);
	message_add_field(req, "AUTOCREATE", 10, &ac, 1, NULL);
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
sqlx_pack_QUERY_single(struct sqlxsrv_name_s *name, const gchar *query,
		gboolean autocreate)
{
	struct message_s *req = NULL;
	guint8 ac = (guint8) autocreate;

	EXTRA_ASSERT(name != NULL);
	EXTRA_ASSERT(query != NULL);

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
		message_add_field(req, "AUTOCREATE", 10, &ac, 1, NULL);

		asn_DEF_TableSequence.free_struct(&asn_DEF_TableSequence, ts, FALSE);
		g_byte_array_free(body, TRUE);
	} while (0);

	return message_marshall_gba_and_clean(req);
}

GByteArray *
sqlx_pack_DESTROY(struct sqlxsrv_name_s *name, gboolean local)
{
	gint8 local2 = BOOL(local);
	GByteArray *encoded;
	MESSAGE req;

	EXTRA_ASSERT(name != NULL);

	req = make_srv_request("SQLX_DESTROY", name);
	if (local)
		message_add_field(req, "LOCAL", 5, &local2, 1, NULL);
	g_assert(req != NULL);
	encoded = message_marshall_gba(req, NULL);
	(void) message_destroy(req, NULL);

	return encoded;
}

GByteArray *
sqlx_pack_LOAD(struct sqlx_name_s *name, GByteArray *dump)
{
	struct message_s *req;

	req = make_request("SQLX_LOAD", name);
	g_assert(req != NULL);

	message_set_BODY(req, dump->data, dump->len, NULL);
	return message_marshall_gba_and_clean(req);
}

GByteArray *
sqlx_pack_ADMGET(struct sqlx_name_s *name, const gchar *k)
{
	GByteArray *encoded;
	MESSAGE req;

	EXTRA_ASSERT(name != NULL);

	req = make_request("SQLX_GETADM", name);
	message_add_fields_str(req, "K", k, NULL);
	encoded = message_marshall_gba(req, NULL);
	(void) message_destroy(req, NULL);

	return encoded;
}

GByteArray *
sqlx_pack_ADMSET(struct sqlx_name_s *name, const gchar *k, const gchar *v)
{
	GByteArray *encoded;
	MESSAGE req;

	EXTRA_ASSERT(name != NULL);

	req = make_request("SQLX_GETADM", name);
	message_add_fields_str(req, "K", k, "V", v, NULL);
	encoded = message_marshall_gba(req, NULL);
	(void) message_destroy(req, NULL);

	return encoded;
}
