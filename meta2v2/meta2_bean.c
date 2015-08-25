/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#include <metautils/lib/metautils.h>
#include <metautils/lib/M2V2Bean.h>
#include <metautils/lib/M2V2Alias.h>
#include <metautils/lib/M2V2Content.h>
#include <metautils/lib/M2V2Property.h>

#include <meta2v2/meta2_bean.h>
#include <meta2v2/autogen.h>
#include <meta2v2/generic.h>

/* ---------------------------------------------------------------- */

static gpointer
_generate_api_alias(const M2V2Bean_t * asn)
{

	gpointer result = _bean_create(&descr_struct_ALIAS);

	ALIAS_set2_alias(result, (const char *)asn->alias->name.buf);

	gint64 version = 0;
	asn_INTEGER_to_int64(&(asn->alias->version), &version);
	ALIAS_set_version(result, version);

	ALIAS_set2_content(result, asn->alias->content.buf, asn->alias->content.size);

	gint64 ct = 0;
	asn_INTEGER_to_int64(&(asn->alias->ctime), &ct);
	ALIAS_set_ctime(result, ct);

	ALIAS_set_deleted(result, asn->alias->deleted);

	return result;
}

static gpointer
_generate_api_content(const M2V2Bean_t * asn)
{
	gpointer result = _bean_create(&descr_struct_CONTENT);

	CONTENT_set2_id(result, asn->content->id.buf, asn->content->id.size);

	if (asn->content->hash && asn->content->hash->buf && asn->content->hash->size > 0)
		CONTENT_set2_hash(result, asn->content->hash->buf, asn->content->hash->size);
	else
		CONTENT_nullify_hash(result);

	gint64 size = 0;
	asn_INTEGER_to_int64(&(asn->content->size), &size);
	CONTENT_set_size(result, size);

	CONTENT_set2_mime_type(result, OIO_DEFAULT_MIME_TYPE);
	CONTENT_set2_chunk_method(result, OIO_DEFAULT_CHUNK_METHOD);
	CONTENT_set2_policy(result, (const char *)asn->content->policy.buf);

	return result;
}

static gpointer
_generate_api_chunk(const M2V2Bean_t * asn)
{
	gpointer result = _bean_create(&descr_struct_CHUNK);

	CHUNK_set2_id(result, (const char *)asn->chunk->id.buf);
	CHUNK_set2_content(result, asn->chunk->content.buf, asn->chunk->content.size);
	CHUNK_set2_hash(result, asn->chunk->hash.buf, asn->chunk->hash.size);
	CHUNK_set2_position(result, (const char *)asn->chunk->position.buf);

	gint64 size;
	asn_INTEGER_to_int64(&(asn->chunk->size), &size);
	CHUNK_set_size(result, size);

	gint64 c;
	asn_INTEGER_to_int64(&(asn->chunk->ctime), &c);
	CHUNK_set_ctime(result, c);

	return result;
}

static gpointer
_generate_api_prop(const M2V2Bean_t * asn)
{
	gpointer result = _bean_create(&descr_struct_PROPERTY);

	PROPERTY_set2_alias(result, (const char *)asn->prop->alias.buf);

	gint64 av;
	asn_INTEGER_to_int64(&(asn->prop->version), &av);
	PROPERTY_set_version(result, av);

	PROPERTY_set2_key(result, (const char *)asn->prop->key.buf);
	PROPERTY_set2_value(result, asn->prop->value.buf, asn->prop->value.size);

	return result;
}

static gboolean
_content_to_asn(gpointer api, M2V2Bean_t *asn)
{
	struct bean_CONTENT_s *content = (struct bean_CONTENT_s*) api;
	asn->content = g_malloc0(sizeof(M2V2Content_t));

	GByteArray *id = CONTENT_get_id(content);
	OCTET_STRING_fromBuf(&(asn->content->id), (const char *)id->data, id->len);

	GByteArray *hash = CONTENT_get_hash(content);
	if (NULL != hash)
		asn->content->hash = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING,
			(const char *)hash->data, hash->len);

	asn_int64_to_INTEGER(&(asn->content->size), CONTENT_get_size(content));

	asn_int64_to_INTEGER(&(asn->content->ctime), CONTENT_get_ctime(content));

	GString *s;
	s = CONTENT_get_policy(content);
	OCTET_STRING_fromBuf(&(asn->content->policy), (const char *)s->str, s->len);

	s = CONTENT_get_mime_type(content);
	OCTET_STRING_fromBuf(&(asn->content->mimetype), (const char *)s->str, s->len);

	s = CONTENT_get_chunk_method(content);
	OCTET_STRING_fromBuf(&(asn->content->chunkmethod), (const char *)s->str, s->len);

	return TRUE;
}

static gboolean
_chunk_to_asn(gpointer api, M2V2Bean_t *asn)
{
	struct bean_CHUNK_s *chunk = (struct bean_CHUNK_s *) api;
	asn->chunk = g_malloc0(sizeof(M2V2Chunk_t));

	GString *id = CHUNK_get_id(chunk);
	OCTET_STRING_fromBuf(&(asn->chunk->id), id->str, id->len);

	GByteArray *content = CHUNK_get_content(chunk);
	OCTET_STRING_fromBuf(&(asn->chunk->content), (const char *)content->data, content->len);

	GString *pos = CHUNK_get_position(chunk);
	OCTET_STRING_fromBuf(&(asn->chunk->position), pos->str, pos->len);

	GByteArray *hash = CHUNK_get_hash(chunk);
	OCTET_STRING_fromBuf(&(asn->chunk->hash), (const char *)hash->data, hash->len);

	asn_int64_to_INTEGER(&(asn->chunk->size), CHUNK_get_size(chunk));
	asn_int64_to_INTEGER(&(asn->chunk->ctime), CHUNK_get_ctime(chunk));

	return TRUE;
}

static gboolean
_property_to_asn(gpointer api, M2V2Bean_t *asn)
{
	struct bean_PROPERTY_s *prop = (struct bean_PROPERTY_s *) api;
	asn->prop = g_malloc0(sizeof(M2V2Property_t));

	GString *alias = PROPERTY_get_alias(prop);
	OCTET_STRING_fromBuf(&(asn->prop->alias), alias->str, alias->len);

	asn_int64_to_INTEGER(&(asn->prop->version), PROPERTY_get_version(prop));

	GString *key = PROPERTY_get_key(prop);
	OCTET_STRING_fromBuf(&(asn->prop->key), key->str, key->len);

	GByteArray *val = PROPERTY_get_value(prop);
	OCTET_STRING_fromBuf(&(asn->prop->value), (const char *)val->data, val->len);

	return TRUE;
}

static gboolean
_alias_to_asn(gpointer api, M2V2Bean_t *asn)
{
	struct bean_ALIAS_s *alias = (struct bean_ALIAS_s *) api;
	asn->alias = g_malloc0(sizeof(M2V2Alias_t));

	GString *name = ALIAS_get_alias(alias);
	OCTET_STRING_fromBuf(&(asn->alias->name), name->str, name->len);

	asn_int64_to_INTEGER(&(asn->alias->version), ALIAS_get_version(alias));

	GByteArray *id = ALIAS_get_content(alias);
	OCTET_STRING_fromBuf(&(asn->alias->content), (const char *)id->data, id->len);

	asn_int64_to_INTEGER(&(asn->alias->ctime), ALIAS_get_ctime(alias));

	asn->alias->deleted = ALIAS_get_deleted(alias);

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

	if (asn->content)
		return _generate_api_content(asn);

	if (asn->chunk)
		return _generate_api_chunk(asn);

	if (asn->prop)
		return _generate_api_prop(asn);

	return NULL;
}

gboolean
bean_API2ASN(gpointer * api, M2V2Bean_t * asn)
{
	EXTRA_ASSERT (api != NULL);
	EXTRA_ASSERT (asn != NULL);

	if (DESCR(api) == &descr_struct_ALIAS)
		return _alias_to_asn(api, asn);
	if (DESCR(api) == &descr_struct_CONTENT)
		return _content_to_asn(api, asn);
	if (DESCR(api) == &descr_struct_CHUNK)
		return _chunk_to_asn(api, asn);
	if (DESCR(api) == &descr_struct_PROPERTY)
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
