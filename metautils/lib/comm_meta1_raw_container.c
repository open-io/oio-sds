#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metacomm.meta1_raw_container"
#endif

#include <errno.h>
#include <glib.h>

#include "./metacomm.h"
#include "./Meta1RawContainer.h"
#include "./asn_AddrInfo.h"

static void
free_asn1_container(Meta1RawContainer_t * asn1_container, gboolean content_only)
{
	void cleaner(AddrInfo_t *asn_addr) {
		addr_info_cleanASN(asn_addr, FALSE);
	}

	if (!asn1_container) {
		errno = EINVAL;
		return;
	}

	asn1_container->meta2.list.free = cleaner;

	if (content_only)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Meta1RawContainer, asn1_container);
	else
		ASN_STRUCT_FREE(asn_DEF_Meta1RawContainer, asn1_container);

	errno = 0;
}


static gboolean
container_asn1_to_api(Meta1RawContainer_t * src, struct meta1_raw_container_s *dst)
{
	int i;

	if (!src || !dst)
		return FALSE;

	memset(dst, 0x00, sizeof(struct meta1_raw_container_s));

	/*map the fields */
	g_memmove(dst->id, src->id.buf, src->id.size);
	g_memmove(dst->name, src->name.buf, src->name.size);
	g_memmove(&(dst->flags), src->flags.buf, src->flags.size);

	/* map meta2 addr list */
	for (i = src->meta2.list.count - 1; i >= 0; i--) {
		addr_info_t *addr_api = NULL;
		AddrInfo_t *addr_asn;

		addr_asn = src->meta2.list.array[i];
		if (!addr_asn) {
			WARN("NULL ASN.1 addr");
			continue;
		}

		addr_api = g_try_malloc0(sizeof(addr_info_t));
		if (!addr_api) {
			ALERT("memory allocation failure");
			abort();
		}

		if (!addr_info_ASN2API(addr_asn, addr_api)) {
			WARN("ASN.1 to ASN.1 mapping failure");
			g_free(addr_api);
			continue;
		}

		dst->meta2 = g_slist_prepend(dst->meta2, addr_api);
	}

	return TRUE;
}


static gboolean
container_api_to_asn1(struct meta1_raw_container_s *src, Meta1RawContainer_t * dst)
{
	GSList *meta2;

	if (!src || !dst)
		return FALSE;

	memset(dst, 0x00, sizeof(Meta1RawContainer_t));

	/* map simple fields */
	OCTET_STRING_fromBuf(&(dst->id), (char *) src->id, sizeof(container_id_t));
	OCTET_STRING_fromBuf(&(dst->name), src->name, strnlen(src->name, sizeof(src->name)));
	OCTET_STRING_fromBuf(&(dst->flags), (char *) &(src->flags), sizeof(src->flags));

	/* map meta2 addr list */
	for (meta2 = src->meta2; meta2; meta2 = meta2->next) {
		AddrInfo_t *addr_asn;
		addr_info_t *addr_api;

		if (!meta2->data) {
			WARN("NULL ASN.1 chunk");
			continue;
		}
		else
			addr_api = (addr_info_t *) (meta2->data);

		addr_asn = g_try_malloc0(sizeof(AddrInfo_t));
		if (addr_asn == NULL) {
			ALERT("memory allocation failure");
			continue;
		}

		if (!addr_info_API2ASN(addr_api, addr_asn)) {
			WARN("API to ASN.1 mapping failure");
			g_free(addr_asn);
			continue;
		}

		asn_set_add(&(dst->meta2.list), addr_asn);
	}

	return TRUE;
}

static int
write_in_gba(const void *b, gsize bSize, void *key)
{
	GByteArray *a = g_byte_array_append((GByteArray *) key, b, bSize);

	return a ? 0 : -1;
}


GByteArray *
meta1_raw_container_marshall(struct meta1_raw_container_s * container, GError ** err)
{
	asn_enc_rval_t encRet;
	GByteArray *result = NULL;
	Meta1RawContainer_t asn1_container;

	/*sanity checks */
	if (!container) {
		GSETERROR(err, "Invalid parameter");
		goto error_params;
	}

	memset(&asn1_container, 0x00, sizeof(Meta1RawContainer_t));

	/*fills an ASN.1 structure */
	if (!container_api_to_asn1(container, &asn1_container)) {
		GSETERROR(err, "API to ASN.1 mapping error");
		goto error_mapping;
	}

	/*serialize the ASN.1 structure */
	if (!(result = g_byte_array_sized_new(4096))) {
		GSETERROR(err, "memory allocation failure");
		goto error_alloc_gba;
	}
	encRet = der_encode(&asn_DEF_Meta1RawContainer, &asn1_container, write_in_gba, result);
	if (encRet.encoded == -1) {
		GSETERROR(err, "ASN.1 encoding error");
		goto error_encode;
	}

	/*free the ASN.1 structure */
	free_asn1_container(&asn1_container, TRUE);
	return result;

      error_encode:
	g_byte_array_free(result, TRUE);
      error_alloc_gba:
      error_mapping:
	free_asn1_container(&asn1_container, TRUE);
      error_params:
	return NULL;
}

struct meta1_raw_container_s *
meta1_raw_container_unmarshall(guint8 * buf, gsize buf_len, GError ** err)
{
	asn_dec_rval_t decRet;
	asn_codec_ctx_t codecCtx;
	struct meta1_raw_container_s *result = NULL;
	Meta1RawContainer_t *asn1_container = NULL;

	/*sanity checks */
	if (!buf)
		goto error_params;

	/*prepare the working structures */
	result = g_try_malloc0(sizeof(struct meta1_raw_container_s));
	if (!result)
		goto error_container;

	/*deserialize the encoded form */
	codecCtx.max_stack_size = 0;
	decRet = ber_decode(&codecCtx, &asn_DEF_Meta1RawContainer, (void *) &asn1_container, buf, buf_len);
	switch (decRet.code) {
	case RC_OK:
		break;
	case RC_FAIL:
		GSETERROR(err, "Cannot deserialize: %s", "invalid container");
		goto error_decode;
	case RC_WMORE:
		GSETERROR(err, "Cannot deserialize: %s", "uncomplete container");
		goto error_decode;
	}

	/*map the ASN.1 in a common structure */
	if (!container_asn1_to_api(asn1_container, result)) {
		GSETERROR(err, "ASN.1 to API mapping failure");
		goto error_mapping;
	}

	/*clean the working structures and return the success */
	free_asn1_container(asn1_container, FALSE);
	return result;

      error_mapping:
      error_decode:
	free_asn1_container(asn1_container, FALSE);
      error_container:
      error_params:
	return NULL;
}
