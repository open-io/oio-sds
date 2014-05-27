#include <errno.h>

#include <meta2v2/meta2_bean.h>
#include <meta2v2/autogen.h>
#include <meta2v2/generic.h>

#include <metautils/lib/M2V2Bean.h>
#include <metautils/lib/M2V2Alias.h>
#include <metautils/lib/M2V2Content.h>
#include <metautils/lib/M2V2ContentHeader.h>
#include <metautils/lib/M2V2Property.h>

#include <glib.h>

/* ---------------------------------------------------------------- */

static gpointer
_generate_api_alias(const M2V2Bean_t * asn)
{
	gpointer result = NULL;
	gint64 version, container_version, ct;

	result = _bean_create(&descr_struct_ALIASES);

	ALIASES_set2_alias(result, (const char *)asn->alias->name.buf);

	asn_INTEGER_to_int64(&(asn->alias->version), &version);
	asn_INTEGER_to_int64(&(asn->alias->containerVersion), &container_version);
	asn_INTEGER_to_int64(&(asn->alias->ctime), &ct);
		
	ALIASES_set_version(result, version);
	ALIASES_set_container_version(result, container_version);
	ALIASES_set2_content_id(result, asn->alias->contentId.buf, asn->alias->contentId.size);
	ALIASES_set2_mdsys(result, (const char *)asn->alias->mdsys.buf);
	ALIASES_set_ctime(result, ct);

	/* deleted */
	ALIASES_set_deleted(result, asn->alias->deleted);

	return result;
}

static gpointer
_generate_api_header(const M2V2Bean_t * asn)
{
	gpointer result = NULL;
	result = _bean_create(&descr_struct_CONTENTS_HEADERS);

	CONTENTS_HEADERS_set2_id(result, asn->header->id.buf, asn->header->id.size);

	if(asn->header->policy && asn->header->policy->buf && asn->header->policy->size > 0)
		CONTENTS_HEADERS_set2_policy(result, (const char *)asn->header->policy->buf);

	/* hash */
	if (asn->header->hash && asn->header->hash->buf && asn->header->hash->size > 0)
		CONTENTS_HEADERS_set2_hash(result, asn->header->hash->buf, asn->header->hash->size);
	
	gint64 size = 0;
	asn_INTEGER_to_int64(&(asn->header->size), &size);
	CONTENTS_HEADERS_set_size(result, size);

	return result;
}

static gpointer
_generate_api_content(const M2V2Bean_t * asn)
{
	gpointer result = NULL;
	result = _bean_create(&descr_struct_CONTENTS);

	CONTENTS_set2_content_id(result, asn->content->contentId.buf, asn->content->contentId.size);
	CONTENTS_set2_chunk_id(result, (const char *)asn->content->chunkId.buf);
	CONTENTS_set2_position(result, (const char *)asn->content->position.buf);

	return result;
}

static gpointer
_generate_api_chunk(const M2V2Bean_t * asn)
{
	gpointer result = NULL;
	gint64 size, c;
	result = _bean_create(&descr_struct_CHUNKS);

	CHUNKS_set2_hash(result, asn->chunk->hash.buf, asn->chunk->hash.size);
	CHUNKS_set2_id(result, (const char *)asn->chunk->id.buf);

	asn_INTEGER_to_int64(&(asn->chunk->size), &size);
	asn_INTEGER_to_int64(&(asn->chunk->ctime), &c);

	CHUNKS_set_size(result, size);
	CHUNKS_set_ctime(result, c);

	return result;
}

static gpointer
_generate_api_prop(const M2V2Bean_t * asn)
{
	gpointer result = NULL;
	gint64 av;
	result = _bean_create(&descr_struct_PROPERTIES);

	asn_INTEGER_to_int64(&(asn->prop->aliasVersion), &av);

	PROPERTIES_set2_alias(result, (const char *)asn->prop->aliasName.buf);
	PROPERTIES_set_alias_version(result, av);
	PROPERTIES_set2_key(result, (const char *)asn->prop->key.buf);
	PROPERTIES_set2_value(result, asn->prop->value.buf, asn->prop->value.size);
	PROPERTIES_set_deleted(result, asn->prop->deleted);

	return result;
}

static gpointer
_generate_api_snapshot(const M2V2Bean_t * asn)
{
	gpointer result = NULL;
	gint64 version;
	result = _bean_create(&descr_struct_SNAPSHOTS);

	asn_INTEGER_to_int64(&(asn->snapshot->version), &version);

	SNAPSHOTS_set_version(result, version);
	SNAPSHOTS_set2_name(result, (const char *)asn->snapshot->name.buf);

	return result;
}

static gboolean
_header_to_asn(gpointer api, M2V2Bean_t *asn)
{
	struct bean_CONTENTS_HEADERS_s *header = (struct bean_CONTENTS_HEADERS_s*) api;
	asn->header = g_malloc0(sizeof(M2V2ContentHeader_t));

	GByteArray *id = CONTENTS_HEADERS_get_id(header);
	OCTET_STRING_fromBuf(&(asn->header->id), (const char *)id->data, id->len);

	GByteArray *hash = CONTENTS_HEADERS_get_hash(header);
	if(NULL != hash)
		asn->header->hash = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING,
			(const char *)hash->data, hash->len);

	GString *pol = CONTENTS_HEADERS_get_policy(header);
	if(NULL != pol)
		asn->header->policy = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING,
			(const char *)pol->str, pol->len);

	asn_int64_to_INTEGER(&(asn->header->size), CONTENTS_HEADERS_get_size(header));

	return TRUE;
}

static gboolean
_content_to_asn(gpointer api, M2V2Bean_t *asn)
{
	struct bean_CONTENTS_s *content = (struct bean_CONTENTS_s*) api;
	asn->content = g_malloc0(sizeof(M2V2Content_t));
	GByteArray *content_id = CONTENTS_get_content_id(content);
	GString *chunk_id = CONTENTS_get_chunk_id(content);
	GString *position = CONTENTS_get_position(content);

	OCTET_STRING_fromBuf(&(asn->content->contentId), (const char *)content_id->data, content_id->len);
	OCTET_STRING_fromBuf(&(asn->content->chunkId), chunk_id->str, chunk_id->len); 
	OCTET_STRING_fromBuf(&(asn->content->position), position->str, position->len); 

	return TRUE;
}

static gboolean
_chunk_to_asn(gpointer api, M2V2Bean_t *asn)
{
	struct bean_CHUNKS_s *chunk = (struct bean_CHUNKS_s *) api;
	asn->chunk = g_malloc0(sizeof(M2V2Chunk_t));

	GByteArray *hash = CHUNKS_get_hash(chunk);
	GString *chunk_id = CHUNKS_get_id(chunk);

	OCTET_STRING_fromBuf(&(asn->chunk->hash), (const char *)hash->data, hash->len);
	OCTET_STRING_fromBuf(&(asn->chunk->id), chunk_id->str, chunk_id->len);

	asn_int64_to_INTEGER(&(asn->chunk->size), CHUNKS_get_size(chunk));
	asn_int64_to_INTEGER(&(asn->chunk->ctime), CHUNKS_get_ctime(chunk));

	return TRUE;
}

static gboolean
_property_to_asn(gpointer api, M2V2Bean_t *asn)
{
	struct bean_PROPERTIES_s *prop = (struct bean_PROPERTIES_s *) api;
	asn->prop = g_malloc0(sizeof(M2V2Property_t));

	GString *alias_name = PROPERTIES_get_alias(prop);
	OCTET_STRING_fromBuf(&(asn->prop->aliasName), alias_name->str, alias_name->len);

	asn_int64_to_INTEGER(&(asn->prop->aliasVersion), PROPERTIES_get_alias_version(prop));

	GString *key = PROPERTIES_get_key(prop);
	OCTET_STRING_fromBuf(&(asn->prop->key), key->str, key->len);

	GByteArray *val = PROPERTIES_get_value(prop);
	OCTET_STRING_fromBuf(&(asn->prop->value), (const char *)val->data, val->len);

	asn->prop->deleted = PROPERTIES_get_deleted(prop);

	return TRUE;
}

static gboolean
_alias_to_asn(gpointer api, M2V2Bean_t *asn)
{
	struct bean_ALIASES_s *alias = (struct bean_ALIASES_s *) api;
	asn->alias = g_malloc0(sizeof(M2V2Alias_t));

	GString *name = ALIASES_get_alias(alias);
	OCTET_STRING_fromBuf(&(asn->alias->name), name->str, name->len);

	asn_int64_to_INTEGER(&(asn->alias->version), ALIASES_get_version(alias));
	asn_int64_to_INTEGER(&(asn->alias->containerVersion), ALIASES_get_container_version(alias));

	GByteArray *id = ALIASES_get_content_id(alias);
	OCTET_STRING_fromBuf(&(asn->alias->contentId), (const char *)id->data, id->len);

	GString *mdsys = ALIASES_get_mdsys(alias);
	OCTET_STRING_fromBuf(&(asn->alias->mdsys), mdsys->str, mdsys->len);

	asn_int64_to_INTEGER(&(asn->alias->ctime), ALIASES_get_ctime(alias));

	asn->alias->deleted = ALIASES_get_deleted(alias);

	return TRUE;
}

static gboolean
_snapshot_to_asn(gpointer api, M2V2Bean_t *asn)
{
	struct bean_SNAPSHOTS_s *snap = (struct bean_SNAPSHOTS_s *) api;
	asn->snapshot = g_malloc0(sizeof(M2V2Snapshot_t));

	GString *name = SNAPSHOTS_get_name(snap);
	OCTET_STRING_fromBuf(&(asn->snapshot->name), name->str, name->len);

	asn_int64_to_INTEGER(&(asn->snapshot->version), SNAPSHOTS_get_version(snap));

	return TRUE;
}

/* ---------------------------------------------------------------- */

gpointer
bean_ASN2API(const M2V2Bean_t * asn)
{
	if (!asn)
		return NULL;

	if (asn->alias)
		return _generate_api_alias(asn);

	if (asn->header)
		return _generate_api_header(asn);

	if (asn->content)
		return _generate_api_content(asn);

	if (asn->chunk)
		return _generate_api_chunk(asn);

	if (asn->prop)
		return _generate_api_prop(asn);

	if (asn->snapshot)
		return _generate_api_snapshot(asn);

	return NULL;
}

gboolean
bean_API2ASN(gpointer * api, M2V2Bean_t * asn)
{
	/* find bean type and fill matching item in M2V2Bean */
	if (!api || !asn)
		return FALSE;

	if (DESCR(api) == &descr_struct_ALIASES)
		return _alias_to_asn(api, asn);
	if (DESCR(api) == &descr_struct_CONTENTS_HEADERS)
		return _header_to_asn(api, asn);
	if (DESCR(api) == &descr_struct_CHUNKS)
		return _chunk_to_asn(api, asn);
	if (DESCR(api) == &descr_struct_CONTENTS)
		return _content_to_asn(api, asn);
	if (DESCR(api) == &descr_struct_PROPERTIES)
		return _property_to_asn(api, asn);
	if (DESCR(api) == &descr_struct_SNAPSHOTS)
		return _snapshot_to_asn(api, asn);

	return FALSE;
}

void
bean_cleanASN(M2V2Bean_t * asn, gboolean only_content)
{
	if (!asn) {
		errno = EINVAL;
		return;
	}

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_M2V2Bean, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_M2V2Bean, asn);

	errno = 0;
}
