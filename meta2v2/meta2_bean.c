/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015-2016 OpenIO, modified as part of OpenIO SDS

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

#include <errno.h>

#include <meta2v2/meta2_bean.h>
#include <meta2v2/autogen.h>
#include <meta2v2/generic.h>

#include <metautils/lib/codec.h>

#include <glib.h>

/* ---------------------------------------------------------------- */

static gpointer
_generate_api_alias(const M2V2Bean_t * asn)
{
	gint64 i64;

	gpointer result = _bean_create(&descr_struct_ALIASES);
	ALIASES_set2_alias(result, (const char *)asn->alias->name.buf);

	asn_INTEGER_to_int64(&(asn->alias->version), &i64);
	ALIASES_set_version(result, i64);

	ALIASES_set2_content(result, asn->alias->content.buf, asn->alias->content.size);

	ALIASES_set_deleted(result, asn->alias->deleted);

	asn_INTEGER_to_int64(&(asn->alias->ctime), &i64);
	ALIASES_set_ctime(result, i64);

	asn_INTEGER_to_int64(&(asn->alias->mtime), &i64);
	ALIASES_set_mtime(result, i64);

	return result;
}

static gpointer
_generate_api_header(const M2V2Bean_t * asn)
{
	gint64 i64;

	gpointer result = _bean_create(&descr_struct_CONTENTS_HEADERS);

	CONTENTS_HEADERS_set2_id(result, asn->header->id.buf, asn->header->id.size);

	if (asn->header->hash && asn->header->hash->buf && asn->header->hash->size > 0)
		CONTENTS_HEADERS_set2_hash(result, asn->header->hash->buf, asn->header->hash->size);

	asn_INTEGER_to_int64(&(asn->header->size), &i64);
	CONTENTS_HEADERS_set_size(result, i64);

	asn_INTEGER_to_int64(&(asn->header->ctime), &i64);
	CONTENTS_HEADERS_set_ctime(result, i64);

	asn_INTEGER_to_int64(&(asn->header->mtime), &i64);
	CONTENTS_HEADERS_set_mtime(result, i64);

	CONTENTS_HEADERS_set2_chunk_method (result, (const char*)asn->header->chunkMethod.buf);
	CONTENTS_HEADERS_set2_mime_type (result, (const char*)asn->header->mimeType.buf);

	if (asn->header->policy && asn->header->policy->buf && asn->header->policy->size > 0)
		CONTENTS_HEADERS_set2_policy(result, (const char *)asn->header->policy->buf);

	return result;
}

static gpointer
_generate_api_chunk(const M2V2Bean_t * asn)
{
	gint64 i64;

	gpointer result = _bean_create(&descr_struct_CHUNKS);

	CHUNKS_set2_id(result, (const char *)asn->chunk->id.buf);

	CHUNKS_set2_hash(result, asn->chunk->hash.buf, asn->chunk->hash.size);

	asn_INTEGER_to_int64(&(asn->chunk->size), &i64);
	CHUNKS_set_size(result, i64);

	asn_INTEGER_to_int64(&(asn->chunk->ctime), &i64);
	CHUNKS_set_ctime(result, i64);

	CHUNKS_set2_content(result, asn->chunk->content.buf, asn->chunk->content.size);

	CHUNKS_set2_position(result, (const char *)asn->chunk->position.buf);

	return result;
}

static gpointer
_generate_api_prop(const M2V2Bean_t * asn)
{
	gpointer result = NULL;
	gint64 av;
	result = _bean_create(&descr_struct_PROPERTIES);

	asn_INTEGER_to_int64(&(asn->prop->version), &av);

	PROPERTIES_set2_alias(result, (const char *)asn->prop->alias.buf);
	PROPERTIES_set_version(result, av);
	PROPERTIES_set2_key(result, (const char *)asn->prop->key.buf);
	PROPERTIES_set2_value(result, asn->prop->value.buf, asn->prop->value.size);

	return result;
}

static gboolean
_header_to_asn(gpointer api, M2V2Bean_t *asn)
{
	struct bean_CONTENTS_HEADERS_s *header = (struct bean_CONTENTS_HEADERS_s*) api;
	asn->header = ASN1C_CALLOC(1, sizeof(M2V2ContentHeader_t));

	GByteArray *id = CONTENTS_HEADERS_get_id(header);
	GByteArray *hash = CONTENTS_HEADERS_get_hash(header);
	GString *pol = CONTENTS_HEADERS_get_policy(header);
	GString *type = CONTENTS_HEADERS_get_mime_type(header);
	GString *method = CONTENTS_HEADERS_get_chunk_method(header);

	OCTET_STRING_fromBuf(&(asn->header->id), (const char *)id->data, id->len);

	if (NULL != hash)
		asn->header->hash = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING,
				(const char *)hash->data, hash->len);

	asn_int64_to_INTEGER(&(asn->header->size), CONTENTS_HEADERS_get_size(header));
	asn_int64_to_INTEGER(&(asn->header->ctime), CONTENTS_HEADERS_get_ctime(header));
	asn_int64_to_INTEGER(&(asn->header->mtime), CONTENTS_HEADERS_get_mtime(header));

	OCTET_STRING_fromBuf(&(asn->header->chunkMethod), method->str, method->len);
	OCTET_STRING_fromBuf(&(asn->header->mimeType), type->str, type->len);

	if(NULL != pol)
		asn->header->policy = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING,
				(const char *)pol->str, pol->len);

	return TRUE;
}

static gboolean
_chunk_to_asn(gpointer api, M2V2Bean_t *asn)
{
	struct bean_CHUNKS_s *chunk = (struct bean_CHUNKS_s *) api;
	asn->chunk = ASN1C_CALLOC(1, sizeof(M2V2Chunk_t));

	GByteArray *hash = CHUNKS_get_hash(chunk);
	GString *chunk_id = CHUNKS_get_id(chunk);
	GByteArray *content = CHUNKS_get_content(chunk);
	GString *position = CHUNKS_get_position(chunk);

	OCTET_STRING_fromBuf(&(asn->chunk->hash), (const char *)hash->data, hash->len);
	OCTET_STRING_fromBuf(&(asn->chunk->id), chunk_id->str, chunk_id->len);
	OCTET_STRING_fromBuf(&(asn->chunk->position), position->str, position->len);
	OCTET_STRING_fromBuf(&(asn->chunk->content), (const char *)content->data, content->len);
	asn_int64_to_INTEGER(&(asn->chunk->size), CHUNKS_get_size(chunk));
	asn_int64_to_INTEGER(&(asn->chunk->ctime), CHUNKS_get_ctime(chunk));

	return TRUE;
}

static gboolean
_property_to_asn(gpointer api, M2V2Bean_t *asn)
{
	struct bean_PROPERTIES_s *prop = (struct bean_PROPERTIES_s *) api;
	asn->prop = ASN1C_CALLOC(1, sizeof(M2V2Property_t));

	GString *alias_name = PROPERTIES_get_alias(prop);
	OCTET_STRING_fromBuf(&(asn->prop->alias), alias_name->str, alias_name->len);

	asn_int64_to_INTEGER(&(asn->prop->version), PROPERTIES_get_version(prop));

	GString *key = PROPERTIES_get_key(prop);
	OCTET_STRING_fromBuf(&(asn->prop->key), key->str, key->len);

	GByteArray *val = PROPERTIES_get_value(prop);
	OCTET_STRING_fromBuf(&(asn->prop->value), (const char *)val->data, val->len);

	return TRUE;
}

static gboolean
_alias_to_asn(gpointer api, M2V2Bean_t *asn)
{
	struct bean_ALIASES_s *alias = (struct bean_ALIASES_s *) api;
	asn->alias = ASN1C_CALLOC(1, sizeof(M2V2Alias_t));

	GString *name = ALIASES_get_alias(alias);
	OCTET_STRING_fromBuf(&(asn->alias->name), name->str, name->len);

	asn_int64_to_INTEGER(&(asn->alias->version), ALIASES_get_version(alias));

	GByteArray *id = ALIASES_get_content(alias);
	OCTET_STRING_fromBuf(&(asn->alias->content), (const char *)id->data, id->len);

	asn->alias->deleted = ALIASES_get_deleted(alias);

	asn_int64_to_INTEGER(&(asn->alias->ctime), ALIASES_get_ctime(alias));

	asn_int64_to_INTEGER(&(asn->alias->mtime), ALIASES_get_mtime(alias));

	return TRUE;
}

/* -------------------------------------------------------------------------- */

gpointer
bean_ASN2API(const M2V2Bean_t * asn)
{
	if (!asn)
		return NULL;
	if (asn->alias)
		return _generate_api_alias(asn);
	if (asn->header)
		return _generate_api_header(asn);
	if (asn->chunk)
		return _generate_api_chunk(asn);
	if (asn->prop)
		return _generate_api_prop(asn);
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
	if (DESCR(api) == &descr_struct_PROPERTIES)
		return _property_to_asn(api, asn);
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
