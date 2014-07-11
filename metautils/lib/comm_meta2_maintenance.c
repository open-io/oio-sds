#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metacomm.meta2_maintenance"
#endif

#include <string.h>
#include <glib.h>
#include "./metatypes.h"
#include "./metautils.h"
#include "./metacomm.h"

#include "./metautils_internals.h"

#include "./ArrayList.h"
#include "./ContentList.h"

#include "./asn_ChunkInfo.h"
#include "./asn_Meta2Raw.h"

static struct abstract_sequence_handler_s meta2_property_descr = {
	sizeof(Meta2Property_t),
	sizeof(meta2_property_t),
	&asn_DEF_Meta2PropertySequence,
	(abstract_converter_f) meta2_property_ASN2API,
	(abstract_converter_f) meta2_property_API2ASN,
	(abstract_asn_cleaner_f) meta2_property_cleanASN,
	(abstract_api_cleaner_f) meta2_property_clean,
	"meta2_property"
};

DEFINE_SEQUENCE_MARSHALLER_GBA( &meta2_property_descr,  meta2_property_marshall_gba);
DEFINE_SEQUENCE_MARSHALLER(     &meta2_property_descr,  meta2_property_marshall);
DEFINE_SEQUENCE_UNMARSHALLER(   &meta2_property_descr,  meta2_property_unmarshall);
DEFINE_BODY_MANAGER(             meta2_property_concat, meta2_property_unmarshall);

/* ------------------------------------------------------------------------- */

static struct abstract_sequence_handler_s meta2_raw_content_header_descr = {
	sizeof(Meta2RawContentHeader_t),
	sizeof(meta2_raw_content_header_t),
	&asn_DEF_Meta2RawContentHeaderSequence,
	(abstract_converter_f) meta2_raw_content_header_ASN2API,
	(abstract_converter_f) meta2_raw_content_header_API2ASN,
	(abstract_asn_cleaner_f) meta2_raw_content_header_cleanASN,
	(abstract_api_cleaner_f) meta2_raw_content_header_clean,
	"meta2_raw_content_header"
};

DEFINE_SEQUENCE_MARSHALLER_GBA( &meta2_raw_content_header_descr,  meta2_raw_content_header_marshall_gba);
DEFINE_SEQUENCE_MARSHALLER(     &meta2_raw_content_header_descr,  meta2_raw_content_header_marshall);
DEFINE_SEQUENCE_UNMARSHALLER(   &meta2_raw_content_header_descr,  meta2_raw_content_header_unmarshall);
DEFINE_BODY_MANAGER(             meta2_raw_content_header_concat, meta2_raw_content_header_unmarshall);

/* ------------------------------------------------------------------------- */

#ifdef HAVE_UNUSED_CODE
static struct abstract_sequence_handler_s meta2_raw_content_descr = {
	sizeof(Meta2RawContent_t),
	sizeof(meta2_raw_content_t),
	&asn_DEF_Meta2RawContentSequence,
	(abstract_converter_f) meta2_raw_content_ASN2API,
	(abstract_converter_f) meta2_raw_content_API2ASN,
	(abstract_asn_cleaner_f) meta2_raw_content_cleanASN,
	(abstract_api_cleaner_f) meta2_raw_content_clean,
	"meta2_raw_content"
};

DEFINE_SEQUENCE_MARSHALLER_GBA( &meta2_raw_content_descr,  meta2_raw_content_marshall_gba);
DEFINE_SEQUENCE_MARSHALLER(     &meta2_raw_content_descr,  meta2_raw_content_marshall);
DEFINE_SEQUENCE_UNMARSHALLER(   &meta2_raw_content_descr,  meta2_raw_content_unmarshall);
DEFINE_BODY_MANAGER(             meta2_raw_content_concat, meta2_raw_content_unmarshall);
#endif /* HAVE_UNUSED_CODE */

/* ------------------------------------------------------------------------- */

static struct abstract_sequence_handler_s meta2_raw_chunk_descr = {
	sizeof(Meta2RawChunk_t),
	sizeof(meta2_raw_chunk_t),
	&asn_DEF_Meta2RawChunkSequence,
	(abstract_converter_f) meta2_raw_chunk_ASN2API,
	(abstract_converter_f) meta2_raw_chunk_API2ASN,
	(abstract_asn_cleaner_f) meta2_raw_chunk_cleanASN,
	(abstract_api_cleaner_f) meta2_raw_chunk_clean,
	"meta2_raw_chunk"
};

DEFINE_SEQUENCE_MARSHALLER_GBA( &meta2_raw_chunk_descr,  meta2_raw_chunk_marshall_gba);
DEFINE_SEQUENCE_MARSHALLER(     &meta2_raw_chunk_descr,  meta2_raw_chunk_marshall);
DEFINE_SEQUENCE_UNMARSHALLER(   &meta2_raw_chunk_descr,  meta2_raw_chunk_unmarshall);
DEFINE_BODY_MANAGER(             meta2_raw_chunk_concat, meta2_raw_chunk_unmarshall);

/* ------------------------------------------------------------------------- */

static struct abstract_sequence_handler_s meta2_raw_content_v2_descr = {
	sizeof(Meta2RawContentV2_t),
	sizeof(meta2_raw_content_v2_t),
	&asn_DEF_Meta2RawContentV2Sequence,
	(abstract_converter_f) meta2_raw_content_v2_ASN2API,
	(abstract_converter_f) meta2_raw_content_v2_API2ASN,
	(abstract_asn_cleaner_f) meta2_raw_content_v2_cleanASN,
	(abstract_api_cleaner_f) meta2_raw_content_v2_clean,
	"meta2_raw_content_v2"
};

DEFINE_SEQUENCE_MARSHALLER_GBA( &meta2_raw_content_v2_descr,     meta2_raw_content_v2_marshall_gba);
DEFINE_SEQUENCE_MARSHALLER(     &meta2_raw_content_v2_descr,     meta2_raw_content_v2_marshall);
DEFINE_SEQUENCE_UNMARSHALLER(   &meta2_raw_content_v2_descr,     meta2_raw_content_v2_unmarshall);
DEFINE_BODY_MANAGER(             meta2_raw_content_v2_concat,    meta2_raw_content_v2_unmarshall);

/* ------------------------------------------------------------------------- */

static void
free_OCTET_STRING(OCTET_STRING_t * os)
{
	if (!os)
		return;
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, os, 0);
}

/* ------------------------------------------------------------------------- */

GSList *
meta2_maintenance_sized_arrays_unmarshall_buffer(guint8 * buf, gsize buf_len, gsize array_size, GError ** err)
{
	int i;
	asn_dec_rval_t decRet;
	asn_codec_ctx_t codecCtx;
	GSList *result = NULL;
	ArrayList_t *result_asn = NULL;

	/*sanity checks */
	if (!buf || buf_len <= 0)
		goto error_params;

	/*decode the sequence */
	codecCtx.max_stack_size = 0;
	decRet = ber_decode(&codecCtx, &asn_DEF_ArrayList, (void *) &result_asn, buf, buf_len);
	switch (decRet.code) {
	case RC_OK:
		break;
	case RC_FAIL:
		GSETERROR(err, "Cannot deserialize: %s", "invalid content");
		goto error_decode;
	case RC_WMORE:
		GSETERROR(err, "Cannot deserialize: %s", "uncomplete content");
		goto error_decode;
	}
	if (!result_asn)
		goto error_decode;

	/*fills the result list */
	for (i = result_asn->list.count - 1; i >= 0; i--) {
		guint8 *new_buf = NULL;
		OCTET_STRING_t *osCursor = result_asn->list.array[i];

		if (!osCursor) {
			WARN("NULL ASN.1 name");
			continue;
		}

		if ((gsize) osCursor->size != array_size) {
			GSETERROR(err, "Invalid size received");
			goto error_size;
		}

		new_buf = g_try_malloc(array_size);
		g_memmove(new_buf, osCursor->buf, osCursor->size);
		result = g_slist_prepend(result, new_buf);
	}

	/*free the ASN.1 sequence of strings */
	result_asn->list.free = free_OCTET_STRING;
	ASN_STRUCT_FREE(asn_DEF_ArrayList, result_asn);
	return result;
      error_size:
	if (result) {
		GSList *pL;

		for (pL = result; pL; pL = g_slist_next(pL))
			g_free(pL->data);
		g_slist_free(result);
	}
      error_decode:
      error_params:
	return NULL;
}


GSList *
meta2_maintenance_sized_arrays_unmarshall_bytearray(GByteArray * encoded, gsize array_size, GError ** err)
{
	if (!encoded) {
		GSETERROR(err, "Invalid parameter");
		return NULL;
	}
	return meta2_maintenance_sized_arrays_unmarshall_buffer(encoded->data, encoded->len, array_size, err);
}


GByteArray *
meta2_maintenance_sized_arrays_marshall(GSList * arrays, gsize array_size, GError ** err)
{
	GSList *lCursor;
	ArrayList_t list_asn;
	asn_enc_rval_t encRet;
	GByteArray *result = NULL;

	int write_f(const void *b, gsize bSize, void *key) {
		(void) key;
		g_byte_array_append(result, b, bSize);
		return 0;
	}

	memset(&list_asn, 0x00, sizeof(list_asn));

	result = g_byte_array_sized_new(4096);
	if (!result) {
		GSETERROR(err, "Failed to alloc byte array");
		return NULL;
	}

	/*fills the ASN.1 list */
	for (lCursor = arrays; lCursor; lCursor = lCursor->next) {
		OCTET_STRING_t *os;

		os = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, lCursor->data, array_size);
		if (!os)
			continue;
		asn_set_add(&(list_asn.list), os);
	}

	/*serializes the list */
	encRet = der_encode(&asn_DEF_ArrayList, &list_asn, write_f, 0);
	if (encRet.encoded == -1)
		goto error_encode;

	/*free the list */
	list_asn.list.free = free_OCTET_STRING;
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ArrayList, &list_asn);
	return result;

      error_encode:
	GSETERROR(err, "Failed to encode arrays");
	return NULL;
}


/* ------------------------------------------------------------------------- */


GSList *
meta2_maintenance_arrays_unmarshall_bytearray(GByteArray * encoded, GError ** err)
{
	if (!encoded) {
		GSETERROR(err, "Invalid parameter");
		return NULL;
	}
	return meta2_maintenance_arrays_unmarshall_buffer(encoded->data, encoded->len, err);
}


GSList *
meta2_maintenance_arrays_unmarshall_buffer(guint8 * buf, gsize buf_len, GError ** err)
{
	int i;
	asn_dec_rval_t decRet;
	asn_codec_ctx_t codecCtx;
	GSList *result = NULL;
	ArrayList_t *result_asn = NULL;

	/*sanity checks */
	if (!buf || buf_len <= 0)
		goto error_params;

	/*decode the sequence */
	codecCtx.max_stack_size = 0;
	decRet = ber_decode(&codecCtx, &asn_DEF_ArrayList, (void *) &result_asn, buf, buf_len);
	switch (decRet.code) {
	case RC_OK:
		break;
	case RC_FAIL:
		GSETERROR(err, "Cannot deserialize: %s", "invalid content");
		goto error_decode;
	case RC_WMORE:
		GSETERROR(err, "Cannot deserialize: %s", "uncomplete content");
		goto error_decode;
	}
	if (!result_asn)
		goto error_decode;

	/*fills the result list */
	for (i = result_asn->list.count - 1; i >= 0; i--) {
		GByteArray *gba;
		OCTET_STRING_t *osCursor = result_asn->list.array[i];

		if (!osCursor) {
			WARN("NULL ASN.1 name");
			continue;
		}

		gba = g_byte_array_sized_new(osCursor->size);
		g_byte_array_append(gba, osCursor->buf, osCursor->size);
		result = g_slist_prepend(result, gba);
	}

	/*free the ASN.1 sequence of strings */
	result_asn->list.free = free_OCTET_STRING;
	ASN_STRUCT_FREE(asn_DEF_ArrayList, result_asn);
	return result;
      error_decode:
      error_params:
	return NULL;
}


GByteArray *
meta2_maintenance_arrays_marshall(GSList * arrays, GError ** err)
{
	GSList *lCursor;
	ArrayList_t list_asn;
	asn_enc_rval_t encRet;
	GByteArray *result = NULL;

	int write_f(const void *b, gsize bSize, void *key) {
		(void) key;
		g_byte_array_append(result, b, bSize);
		return 0;
	}

	memset(&list_asn, 0x00, sizeof(list_asn));

	result = g_byte_array_sized_new(4096);
	if (!result) {
		GSETERROR(err, "Failed to alloc byte array");
		return NULL;
	}

	/*fills the ASN.1 list */
	for (lCursor = arrays; lCursor; lCursor = lCursor->next) {
		OCTET_STRING_t *os;
		GByteArray *gba = lCursor->data;

		if (!gba)
			continue;
		os = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, (const char*)gba->data, gba->len);
		if (!os)
			continue;
		asn_set_add(&(list_asn.list), os);
	}

	/*serializes the list */
	encRet = der_encode(&asn_DEF_ArrayList, &list_asn, write_f, 0);
	if (encRet.encoded == -1)
		goto error_encode;

	/*free the list */
	list_asn.list.free = free_OCTET_STRING;
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ArrayList, &list_asn);
	return result;

      error_encode:
	GSETERROR(err, "Failed to encode arrays");
	return NULL;
}


/* ------------------------------------------------------------------------- */


GSList *
meta2_maintenance_names_unmarshall_bytearray(GByteArray * encoded, GError ** err)
{
	if (!encoded)
		return NULL;
	return meta2_maintenance_names_unmarshall_buffer(encoded->data, encoded->len, err);
}


GSList *
meta2_maintenance_names_unmarshall_buffer(const guint8 * buf, gsize buf_len, GError ** err)
{
	int i;
	asn_dec_rval_t decRet;
	asn_codec_ctx_t codecCtx;
	GSList *result = NULL;
	ContentList_t *result_asn = NULL;

	/*sanity checks */
	if (!buf || buf_len <= 0)
		goto error_params;

	/*decode the sequence */
	codecCtx.max_stack_size = 0;
	decRet = ber_decode(&codecCtx, &asn_DEF_ContentList, (void *) &result_asn, buf, buf_len);
	switch (decRet.code) {
	case RC_OK:
		break;
	case RC_FAIL:
		GSETERROR(err, "Cannot deserialize: %s", "invalid content");
		goto error_decode;
	case RC_WMORE:
		GSETERROR(err, "Cannot deserialize: %s", "uncomplete content");
		goto error_decode;
	}
	if (!result_asn)
		goto error_decode;

	/*fills the result list */
	for (i = result_asn->list.count - 1; i >= 0; i--) {
		char *str;
		OCTET_STRING_t *osCursor = result_asn->list.array[i];

		if (!osCursor) {
			WARN("NULL ASN.1 name");
			continue;
		}

		str = g_try_malloc(osCursor->size + 1);
		if (!str) {
			ALERT("Memory allocation failure");
			continue;
		}
		else
			memset(str, 0x00, osCursor->size + 1);

		g_memmove(str, osCursor->buf, osCursor->size);
		result = g_slist_prepend(result, str);
	}

	/*free the ASN.1 sequence of strings */
	result_asn->list.free = free_OCTET_STRING;
	ASN_STRUCT_FREE(asn_DEF_ContentList, result_asn);
	return result;
      error_decode:
      error_params:
	return NULL;
}

GByteArray *
strings_marshall_gba(GSList * list, GError ** err)
{
	return meta2_maintenance_names_marshall(list, err);
}

gint
strings_unmarshall(GSList ** l, const void *s, gsize * sSize, GError ** err)
{
	if (!l || !s || !sSize || !*sSize) {
		GSETERROR(err, "Invalid parameter (l=%p s=%p sSize=%p)", l, s, sSize);
		return 0;
	}
	*l = meta2_maintenance_names_unmarshall_buffer(s, *sSize, err);
	if (!*l) {
		if (err && *err) {
			GSETERROR(err, "Wrapper failed");
			return 0;
		}
	}
	return 1;
}

GByteArray *
meta2_maintenance_names_marshall(GSList * contents, GError ** err)
{
	GSList *lCursor;
	ContentList_t list_asn;
	asn_enc_rval_t encRet;
	GByteArray *result = NULL;

	int write_f(const void *b, gsize bSize, void *key) {
		(void) key;
		g_byte_array_append(result, b, bSize);
		return 0;
	}

	memset(&list_asn, 0x00, sizeof(list_asn));

	result = g_byte_array_sized_new(4096);
	if (!result) {
		GSETERROR(err, "Failed to alloc byte array");
		return NULL;
	}

	/*fills the ASN.1 list */
	for (lCursor = contents; lCursor; lCursor = lCursor->next) {
		OCTET_STRING_t *os;
		char *s = lCursor->data;

		if (!s)
			continue;
		os = OCTET_STRING_new_fromBuf(&asn_DEF_PrintableString, s, strlen(s));
		if (!os)
			continue;
		asn_set_add(&(list_asn.list), os);
	}

	/*serializes the list */
	encRet = der_encode(&asn_DEF_ContentList, &list_asn, write_f, 0);
	if (encRet.encoded == -1)
		goto error_encode;

	/*free the list */
	list_asn.list.free = free_OCTET_STRING;
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ContentList, &list_asn);
	return result;

      error_encode:
	GSETERROR(err, "Failed to encode arrays");
	return NULL;
}


/* ------------------------------------------------------------------------- */


GByteArray *
meta2_maintenance_marshall_content(struct meta2_raw_content_s * content, GError ** err)
{
	asn_enc_rval_t encRet;
	GByteArray *result = NULL;
	Meta2RawContent_t asn1_content;

	int write_f(const void *b, gsize bSize, void *key)
	{
		(void) key;

		GByteArray *a = g_byte_array_append(result, b, bSize);

		return a ? 0 : -1;
	}

	/*sanity checks */
	if (!content) {
		GSETERROR(err, "Invalid parameter");
		goto error_params;
	}

	/*prepare the structures */
	memset(&asn1_content, 0x00, sizeof(Meta2RawContent_t));
	if (!(result = g_byte_array_sized_new(4096))) {
		GSETERROR(err, "memory allocation failure");
		goto error_byte_array;
	}

	/*fills an ASN.1 structure */
	if (!meta2_raw_content_API2ASN(content, &asn1_content)) {
		GSETERROR(err, "API to ASN.1 mapping error");
		goto error_mapping;
	}

	/*serialize the ASN.1 structure */
	encRet = der_encode(&asn_DEF_Meta2RawContent, &asn1_content, write_f, 0);
	if (encRet.encoded == -1) {
		GSETERROR(err, "ASN.1 encoding error");
		goto error_encode;
	}

	/*free the ASN.1 structure */
	meta2_raw_content_cleanASN(&asn1_content, TRUE);
	return result;

      error_mapping:
      error_encode:
	g_byte_array_free(result, 1);
      error_byte_array:
	meta2_raw_content_cleanASN(&asn1_content, TRUE);
      error_params:
	return NULL;
}


struct meta2_raw_content_s *
meta2_maintenance_content_unmarshall_buffer(guint8 * buf, gsize buf_size, GError ** err)
{
	asn_dec_rval_t decRet;
	asn_codec_ctx_t codecCtx;
	struct meta2_raw_content_s *result = NULL;
	Meta2RawContent_t *asn1_content = NULL;

	/*sanity checks */
	if (!buf || buf_size <= 0)
		goto error_params;

	/*prepare the working structures */
	result = g_try_malloc0(sizeof(struct meta2_raw_content_s));
	if (!result)
		goto error_content;

	/*deserialize the encoded form */
	codecCtx.max_stack_size = 0;
	decRet = ber_decode(&codecCtx, &asn_DEF_Meta2RawContent, (void *) &asn1_content, buf, buf_size);
	switch (decRet.code) {
	case RC_OK:
		break;
	case RC_FAIL:
		GSETERROR(err, "Cannot deserialize: %s", "invalid content");
		goto error_decode;
	case RC_WMORE:
		GSETERROR(err, "Cannot deserialize: %s", "uncomplete content");
		goto error_decode;
	}

	/*map the ASN.1 in a common structure */
	if (!meta2_raw_content_ASN2API(asn1_content, result)) {
		GSETERROR(err, "ASN.1 to API mapping failure");
		goto error_mapping;
	}

	/*clean the working structures and return the success */
	meta2_raw_content_cleanASN(asn1_content, FALSE);
	return result;

      error_mapping:
      error_decode:
	meta2_raw_content_cleanASN(asn1_content, FALSE);
      error_content:
      error_params:
	return NULL;
}

struct meta2_raw_content_s *
meta2_maintenance_content_unmarshall_bytearray(GByteArray * encoded_content, GError ** err)
{
	if (!encoded_content || !encoded_content->data || encoded_content->len <= 0) {
		return NULL;
	}

	return meta2_maintenance_content_unmarshall_buffer(encoded_content->data, encoded_content->len, err);
}


/* ------------------------------------------------------------------------- */

gboolean
strings_concat(GError ** err, gpointer udata, gint code, guint8 * body, gsize bodySize)
{
	(void) code;
	GSList **resL, *list;

	resL = (GSList **) udata;

	if (!udata || !body || bodySize <= 0) {
		GSETERROR(err, "Invalid parameter (%p %p %u)", udata, body, bodySize);
		return FALSE;
	}
	list = NULL;
	list = meta2_maintenance_names_unmarshall_buffer(body, bodySize, err);
	if (!list && err && *err) {
		GSETERROR(err, "Cannot unserialize the content of the reply");
		return FALSE;
	}
	DEBUG("Received [%d] elements", g_slist_length(list));
	*resL = g_slist_concat(*resL, list);
	return TRUE;
}

