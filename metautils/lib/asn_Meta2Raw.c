#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metacomm.meta2_raw.asn"
#endif

#include <errno.h>

#include <glib.h>

#include "./metatypes.h"
#include "./metautils.h"
#include "./metacomm.h"

#include "./Meta2Property.h"
#include "./Meta2PropertySequence.h"
#include "./Meta2RawContentHeader.h"
#include "./Meta2RawContentHeaderSequence.h"
#include "./Meta2RawContent.h"
#include "./Meta2RawContentV2.h"
#include "./Meta2RawChunk.h"
#include "./Meta2Property.h"
#include "./Meta2PropertySequence.h"
#include "./ServiceInfo.h"
#include "./ServiceInfoSequence.h"

#include "./asn_AddrInfo.h"
#include "./asn_ServiceInfo.h"
#include "./asn_ChunkInfo.h"
#include "./asn_Meta2Raw.h"

/* RAW Contents V1 --------------------------------------------------------- */

void
meta2_raw_content_cleanASN(Meta2RawContent_t * asn, gboolean only_content)
{
	void free_asn1_chunk(Meta2RawChunk_t * chunk) {
		meta2_raw_chunk_cleanASN(chunk, FALSE);
	}

	if (!asn) {
		errno = EINVAL;
		return;
	}

	asn->chunks.list.free = free_asn1_chunk;

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Meta2RawContent, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_Meta2RawContent, asn);

	errno = 0;
}

gboolean
meta2_raw_content_ASN2API(const Meta2RawContent_t * src, struct meta2_raw_content_s *dst)
{
	int i;

	if (!src || !dst) {
		errno = EINVAL;
		return FALSE;
	}

	bzero(dst, sizeof(*dst));

	/* Poorly, sadly, the C API-side structure does not have an
	 * explicit 'header' substructure field but has all the fields
	 * directly inlined. Thus we cannot reuse the meta2_raw_content_header
	 * function */

	asn_INTEGER_to_uint32(&(src->header.nbChunks), &(dst->nb_chunks));
	asn_INTEGER_to_int64(&(src->header.size), &(dst->size));
	/* asn_INTEGER_to_int64(&(src->header.version), &(dst->version)); */
	if(NULL != src->header.version) {
		asn_INTEGER_to_int64(src->header.version, &(dst->version));
	} else {
		dst->version = 0;
	}
	g_memmove(dst->path, src->header.path.buf, src->header.path.size);
	g_memmove(&(dst->flags), src->header.flags.buf, src->header.flags.size);
	g_memmove(dst->container_id, src->header.cID.buf, src->header.cID.size);

	if (src->header.metadata) {
		dst->metadata = g_byte_array_sized_new(src->header.metadata->size);
		if (!dst->metadata) {
			errno = 0;
			return FALSE;
		}
		g_byte_array_append(dst->metadata, src->header.metadata->buf, src->header.metadata->size);
	}

	if (src->header.systemMetadata) {
		dst->system_metadata = g_byte_array_sized_new(src->header.systemMetadata->size);
		if (!dst->system_metadata) {
			errno = 0;
			return FALSE;
		}
		g_byte_array_append(dst->system_metadata, src->header.systemMetadata->buf, src->header.systemMetadata->size);
	}

	/*map the chunks */
	for (i = src->chunks.list.count - 1; i >= 0; i--) {
		struct meta2_raw_chunk_s *chunk_api = NULL;
		Meta2RawChunk_t *chunk_asn;

		chunk_asn = src->chunks.list.array[i];
		if (!chunk_asn) /* Skip NULL chunks */
			continue;

		chunk_api = g_try_malloc0(sizeof(struct meta2_raw_chunk_s));
		if (!chunk_api) {
			errno = ENOMEM;
			return FALSE;
		}

		if (!meta2_raw_chunk_ASN2API(chunk_asn, chunk_api)) {
			WARN("ASN.1 to ASN.1 mapping failure");
			g_free(chunk_api);
			errno = EINVAL;
			return FALSE;
		}

		dst->raw_chunks = g_slist_prepend(dst->raw_chunks, chunk_api);
	}

	errno = 0;
	return TRUE;
}

gboolean
meta2_raw_content_API2ASN(const struct meta2_raw_content_s * src, Meta2RawContent_t * dst)
{
	GSList *c;

	if (!src || !dst) {
		errno = EINVAL;
		return FALSE;
	}

	bzero(dst, sizeof(*dst));

	OCTET_STRING_fromBuf(&(dst->header.path), src->path, strlen(src->path));
	OCTET_STRING_fromBuf(&(dst->header.cID), (char *) src->container_id, sizeof(container_id_t));
	OCTET_STRING_fromBuf(&(dst->header.flags), (char *) &(src->flags), sizeof(src->flags));
	asn_int64_to_INTEGER(&(dst->header.size), src->size);
	asn_uint32_to_INTEGER(&(dst->header.nbChunks), src->nb_chunks);

	/* OPTIONAL FIELDS : since 1.8 */
	
	if(src->version > 0)
		dst->header.version = g_malloc0(sizeof(INTEGER_t));
		asn_int64_to_INTEGER(dst->header.version, src->version);

	if (src->metadata && src->metadata->len > 0 && src->metadata->data) {
		dst->header.metadata = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING,
				(const char*)src->metadata->data, src->metadata->len);
		if (!dst->header.metadata) {
			errno = 0;
			return FALSE;
		}
	}

	if (src->system_metadata && src->system_metadata->len > 0 && src->system_metadata->data) {
		dst->header.systemMetadata = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING,
				(const char*)src->system_metadata->data, src->system_metadata->len);
		if (!dst->header.systemMetadata) {
			errno = 0;
			return FALSE;
		}
	}

	/*chunks */
	for (c = src->raw_chunks; c; c = g_slist_next(c)) {
		Meta2RawChunk_t *chunk_asn;
		struct meta2_raw_chunk_s *chunk_api;

		if (!c->data) /* skip NULL chunks */
			continue;

		chunk_api = (struct meta2_raw_chunk_s *) (c->data);

		chunk_asn = g_try_malloc0(sizeof(Meta2RawChunk_t));
		if (!chunk_asn) {
			errno = ENOMEM;
			return FALSE;
		}

		if (!meta2_raw_chunk_API2ASN(chunk_api, chunk_asn)) {
			g_free(chunk_asn);
			errno = EINVAL;
			return FALSE;
		}
		asn_set_add(&(dst->chunks.list), chunk_asn);
	}

	errno = 0;
	return TRUE;
}

/* RAW Chunks -------------------------------------------------------------- */

gboolean
meta2_raw_chunk_API2ASN(const struct meta2_raw_chunk_s * src, Meta2RawChunk_t * dst)
{
	if (!src || !dst) {
		errno = EINVAL;
		return FALSE;
	}

	bzero(dst, sizeof(*dst));

	chunk_id_API2ASN(&(src->id), &(dst->id));
	asn_uint32_to_INTEGER(&(dst->position), src->position);
	asn_int64_to_INTEGER(&(dst->size), src->size);
	OCTET_STRING_fromBuf(&(dst->flags), (char *) (&(src->flags)), sizeof(src->flags));
	OCTET_STRING_fromBuf(&(dst->hash), (char *) (&(src->hash)), sizeof(src->hash));

	if (src->metadata && src->metadata->data && src->metadata->len > 0) {
		dst->metadata = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING,
		    (const char*)src->metadata->data, src->metadata->len);
		if (!dst->metadata) {
			errno = ENOMEM;
			return FALSE;
		}
	}

	errno = 0;
	return TRUE;
}

gboolean
meta2_raw_chunk_ASN2API(const Meta2RawChunk_t * src, struct meta2_raw_chunk_s * dst)
{
	if (!src || !dst) {
		errno = EINVAL;
		return FALSE;
	}

	bzero(dst, sizeof(*dst));

	chunk_id_ASN2API(&(src->id), &(dst->id));
	asn_INTEGER_to_uint32(&(src->position), &(dst->position));
	asn_INTEGER_to_int64(&(src->size), &(dst->size));
	g_memmove(&(dst->flags), src->flags.buf, src->flags.size);
	g_memmove(&(dst->hash), src->hash.buf, src->hash.size);

	if (src->metadata && src->metadata->buf && src->metadata->size > 0) {
		dst->metadata = g_byte_array_sized_new(src->metadata->size);
		if (!dst->metadata) {
			errno = ENOMEM;
			return FALSE;
		}
		g_byte_array_append(dst->metadata, src->metadata->buf, src->metadata->size);
	}

	errno = 0;
	return TRUE;
}

void
meta2_raw_chunk_cleanASN(Meta2RawChunk_t *asn, gboolean only_content)
{
	if (!asn) {
		errno = EINVAL;
		return;
	}

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Meta2RawChunk, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_Meta2RawChunk, asn);

	errno = 0;
}

/* RAW Content header ------------------------------------------------------ */

gboolean
meta2_raw_content_header_ASN2API(const Meta2RawContentHeader_t *asn,
		meta2_raw_content_header_t *api)
{
	if (!asn || !api) {
		errno = EINVAL;
		return FALSE;
	}

	bzero(api, sizeof(*api));

	asn_INTEGER_to_uint32(&(asn->nbChunks), &(api->nb_chunks));
	asn_INTEGER_to_int64(&(asn->size), &(api->size));
	g_memmove(api->path, asn->path.buf, asn->path.size);
	g_memmove(&(api->flags), asn->flags.buf, asn->flags.size);
	g_memmove(api->container_id, asn->cID.buf, asn->cID.size);

	if (asn->metadata) {
		api->metadata = g_byte_array_sized_new(asn->metadata->size);
		if (!api->metadata) {
			errno = ENOMEM;
			return FALSE;
		}
		g_byte_array_append(api->metadata, asn->metadata->buf, asn->metadata->size);
	}

	if (asn->systemMetadata) {
		api->system_metadata = g_byte_array_sized_new(asn->systemMetadata->size);
		if (!api->system_metadata) {
			errno = ENOMEM;
			return FALSE;
		}
		g_byte_array_append(api->system_metadata, asn->systemMetadata->buf, asn->systemMetadata->size);
	}

	errno = 0;
	return TRUE;
}

gboolean
meta2_raw_content_header_API2ASN(const meta2_raw_content_header_t *api,
	Meta2RawContentHeader_t *asn)
{
	if (!asn || !api) {
		errno = EINVAL;
		return FALSE;
	}

	bzero(asn, sizeof(*asn));

	OCTET_STRING_fromBuf( &(asn->path), api->path, strlen(api->path));
	OCTET_STRING_fromBuf( &(asn->cID), (char *) api->container_id, sizeof(container_id_t));
	OCTET_STRING_fromBuf( &(asn->flags), (char *) &(api->flags), sizeof(api->flags));
	asn_int64_to_INTEGER( &(asn->size), api->size);
	asn_uint32_to_INTEGER(&(asn->nbChunks), api->nb_chunks);

	/*user metadata */
	if (api->metadata && api->metadata->len > 0 && api->metadata->data) {
		asn->metadata = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING,
		    (const char*)api->metadata->data, api->metadata->len);
		if (!asn->metadata) {
			errno = ENOMEM;
			return FALSE;
		}
	}

	/*system metadata */
	if (api->system_metadata && api->system_metadata->len > 0 && api->system_metadata->data) {
		asn->systemMetadata = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING,
		    (const char*)api->system_metadata->data, api->system_metadata->len);
		if (!asn->systemMetadata) {
			errno = ENOMEM;
			return FALSE;
		}
	}

	errno = 0;
	return TRUE;
}

void
meta2_raw_content_header_cleanASN(Meta2RawContentHeader_t *asn, gboolean only_content)
{
	if (!asn) {
		errno = EINVAL;
		return;
	}

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Meta2RawContent, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_Meta2RawContentHeader, asn);

	errno = 0;
}

/* RAW Content V2 ---------------------------------------------------------- */

gboolean
meta2_raw_content_v2_ASN2API(const Meta2RawContentV2_t *asn, meta2_raw_content_v2_t *api)
{
	int i;

	if (!asn || !api) {
		errno = EINVAL;
		return FALSE;
	}

	bzero(api, sizeof(*api));

	/* header */
	if (!meta2_raw_content_header_ASN2API(&(asn->header), &(api->header)))
		return FALSE;

	/* chunks */
	for (i = asn->chunks.list.count - 1; i >= 0; i--) {
		struct meta2_raw_chunk_s *c_api = NULL;
		Meta2RawChunk_t *c_asn = NULL;

		if (!(c_asn = asn->chunks.list.array[i])) /* Skip NULL's */
			continue;
		if (!(c_api = g_try_malloc0(sizeof(*c_api)))) {
			errno = ENOMEM;
			goto label_error;
		}
		if (!meta2_raw_chunk_ASN2API(c_asn, c_api)) {
			g_free(c_api);
			WARN("chunk ASN.1 to ASN.1 mapping failure");
			errno = EINVAL;
			goto label_error;
		}

		api->raw_chunks = g_slist_prepend(api->raw_chunks, c_api);
	}

	/* services */
	for (i = asn->services.list.count - 1; i >= 0; i--) {
		service_info_t *c_api = NULL;
		ServiceInfo_t *c_asn = NULL;

		if (!(c_asn = asn->services.list.array[i])) /* Skip NULL's */
			continue;
		if (!(c_api = g_try_malloc0(sizeof(*c_api)))) {
			errno = ENOMEM;
			goto label_error;
		}
		if (!service_info_ASN2API(c_asn, c_api)) {
			g_free(c_api);
			WARN("service_info ASN.1 to ASN.1 mapping failure");
			errno = EINVAL;
			goto label_error;
		}

		api->raw_services = g_slist_prepend(api->raw_services, c_api);
	}

	/* properties */
	for (i = asn->properties.list.count - 1; i >= 0; i--) {
		meta2_property_t *c_api = NULL;
		Meta2Property_t *c_asn = NULL;

		if (!(c_asn = asn->properties.list.array[i])) /* Skip NULL's */
			continue;
		if (!(c_api = g_try_malloc0(sizeof(*c_api)))) {
			errno = ENOMEM;
			goto label_error;
		}
		if (!meta2_property_ASN2API(c_asn, c_api)) {
			g_free(c_api);
			WARN("service_info ASN.1 to ASN.1 mapping failure");
			errno = EINVAL;
			goto label_error;
		}

		api->properties = g_slist_prepend(api->properties, c_api);
	}

	errno = 0;
	return TRUE;

label_error:
	return FALSE;
}

gboolean
meta2_raw_content_v2_API2ASN(const meta2_raw_content_v2_t *api, Meta2RawContentV2_t *asn)
{
	GSList *l;

	if (!asn || !api) {
		errno = EINVAL;
		return FALSE;
	}

	bzero(asn, sizeof(*asn));

	/* header */
	if (!meta2_raw_content_header_API2ASN(&(api->header), &(asn->header)))
		return FALSE;

	/* chunks */
	for (l=api->raw_chunks; l ;l=l->next) {
		Meta2RawChunk_t *chunk_asn;
		struct meta2_raw_chunk_s *chunk_api;

		if (!(chunk_api = l->data))
			continue;
		if (!(chunk_asn = g_try_malloc0(sizeof(Meta2RawChunk_t)))) {
			errno = ENOMEM;
			goto label_error;
		}
		if (!meta2_raw_chunk_API2ASN(chunk_api, chunk_asn)) {
			g_free(chunk_asn);
			errno = EINVAL;
			goto label_error;
		}
		asn_set_add(&(asn->chunks.list), chunk_asn);
	}

	/* Services */
	for (l=api->raw_services; l ;l=l->next) {
		ServiceInfo_t *si_asn;
		service_info_t *si;

		if (!(si = l->data))
			continue;
		if (!(si_asn = g_try_malloc0(sizeof(*si_asn)))) {
			errno = ENOMEM;
			goto label_error;
		}
		if (!service_info_API2ASN(si, si_asn)) {
			g_free(si_asn);
			errno = EINVAL;
			goto label_error;
		}
		asn_set_add(&(asn->services.list), si_asn);
	}

	/* Properties */
	for (l=api->properties; l ;l=l->next) {
		Meta2Property_t *prop_asn;
		meta2_property_t *prop_api;

		if (!(prop_api = l->data))
			continue;
		if (!(prop_asn = g_try_malloc0(sizeof(*prop_asn)))) {
			errno = ENOMEM;
			goto label_error;
		}
		if (!meta2_property_API2ASN(prop_api, prop_asn)) {
			g_free(prop_asn);
			errno = EINVAL;
			goto label_error;
		}
		asn_set_add(&(asn->properties.list), prop_asn);
	}

	errno = 0;
	return TRUE;

label_error:
	return FALSE;
}

void
meta2_raw_content_v2_cleanASN(Meta2RawContentV2_t *asn, gboolean only_content)
{
	void free_asn1_property(Meta2Property_t * prop) {
		meta2_property_cleanASN(prop, FALSE);
	}
	void free_asn1_service(ServiceInfo_t * si) {
		service_info_cleanASN(si, FALSE);
	}
	void free_asn1_chunk(Meta2RawChunk_t * chunk) {
		meta2_raw_chunk_cleanASN(chunk, FALSE);
	}
	if (!asn) {
		errno = EINVAL;
		return;
	}

	asn->chunks.list.free = free_asn1_chunk;
	asn->services.list.free = free_asn1_service;
	asn->properties.list.free = free_asn1_property;

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Meta2RawContentV2, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_Meta2RawContentV2, asn);

	errno = 0;
}

/* META2 properties -------------------------------------------------------- */

void
meta2_property_cleanASN(Meta2Property_t *asn, gboolean only_content)
{
	if (!asn) {
		errno = EINVAL;
		return;
	}

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Meta2Property, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_Meta2Property, asn);

	errno = 0;
}

gboolean
meta2_property_ASN2API(const Meta2Property_t *asn, meta2_property_t *api)
{
	if (!asn || !api) {
		errno = EINVAL;
		return FALSE;
	}
	if (!asn->name.buf || asn->name.size <= 0) {
		errno = EINVAL;
		return FALSE;
	}

	bzero(api, sizeof(*api));
	
	api->name = g_strndup((gchar*)asn->name.buf, asn->name.size);
	asn_INTEGER_to_int64(&(asn->version), &(api->version));
	api->value = g_byte_array_new();

	if (asn->value.size > 0 && asn->value.buf != NULL)
		g_byte_array_append(api->value, asn->value.buf, asn->value.size);
	
	errno = 0;
	return TRUE;
}

gboolean
meta2_property_API2ASN(const meta2_property_t *api, Meta2Property_t *asn)
{
	if (!api || !asn) {
		errno = EINVAL;
		return FALSE;
	}
	if (!api->name) {
		errno = EINVAL;
		return FALSE;
	}

	bzero(asn, sizeof(*asn));

	OCTET_STRING_fromBuf(&(asn->name), api->name, strlen(api->name));
	asn_int64_to_INTEGER(&(asn->version), api->version);

	if (api->value && api->value->data && api->value->len) {
		OCTET_STRING_fromBuf(&(asn->value), (gchar*)api->value->data, api->value->len);
	}
	else {
		OCTET_STRING_fromBuf(&(asn->value), "", 0);
	}

	errno = 0;
	return TRUE;
}

