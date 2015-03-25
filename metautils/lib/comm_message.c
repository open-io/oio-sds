/*
OpenIO SDS metautils
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
# define G_LOG_DOMAIN "metacomm.message"
#endif

#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#include "./metautils.h"
#include "./metacomm.h"
#include "./Parameter.h"
#include "./Message.h"

struct message_s
{
	Message_t *asnMsg;
};

static void
__octetString_array_free(Parameter_t * p)
{
	if (!p)
		return;
	OCTET_STRING_free(&asn_DEF_OCTET_STRING, &(p->name), 1);
	p->name.buf = NULL;
	p->name.size = 0;

	OCTET_STRING_free(&asn_DEF_OCTET_STRING, &(p->value), 1);
	p->value.buf = NULL;
	p->value.size = 0;

	g_free(p);
}

static void
_clean_asn_message(MESSAGE m)
{
	if (!m || !m->asnMsg)
		return ;

	/*quick parameters */
	if (m->asnMsg->id != NULL) {
		ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, m->asnMsg->id);
		m->asnMsg->id = NULL;
	}

	if (m->asnMsg->body != NULL) {
		ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, m->asnMsg->body);
		m->asnMsg->body = NULL;
	}

	if (m->asnMsg->version != NULL) {
		ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, m->asnMsg->version);
		m->asnMsg->version = NULL;
	}

	if (m->asnMsg->name != NULL) {
		ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, m->asnMsg->name);
		m->asnMsg->name = NULL;
	}

	m->asnMsg->content.list.free = __octetString_array_free;
	asn_set_empty(&(m->asnMsg->content.list));

	memset(m->asnMsg, 0x00, sizeof(Message_t));
	g_free(m->asnMsg);

	m->asnMsg = NULL;
}

static gint
_alloc_asn_message(MESSAGE m, GError ** err)
{
	if (!m) {
		GSETERROR(err, "Invalid parameter");
		return 0;
	}
	m->asnMsg = g_malloc0(sizeof(Message_t));
	return 1;
}

static gint
__getParameter(MESSAGE m, enum message_param_e mp, OCTET_STRING_t ** os)
{
	if (!m || !m->asnMsg || !os)
		return 0;

	*os = NULL;

	switch (mp) {
	case MP_ID:
		*os = m->asnMsg->id;
		return 1;
	case MP_NAME:
		*os = m->asnMsg->name;
		return 1;
	case MP_VERSION:
		*os = m->asnMsg->version;
		return 1;
	case MP_BODY:
		*os = m->asnMsg->body;
		return 1;
	}

	return 0;
}

MESSAGE
message_create(void)
{
	const char *id = gridd_get_reqid ();
	MESSAGE result = g_malloc0(sizeof(struct message_s));
	if (id)
		message_set_ID (result, id, strlen(id), NULL);
	return result;
}

MESSAGE
message_create_named (const char *name)
{
	MESSAGE result = message_create ();
	if (name)
		message_set_NAME (result, name, strlen(name), NULL);
	return result;
}

void
message_destroy(MESSAGE m)
{
	if (unlikely(NULL == m))
		return;
	_clean_asn_message(m);
	m->asnMsg = NULL;
	g_free(m);
}

static int
write_gba(const void *b, gsize bSize, void *key)
{
	if (b && bSize > 0)
		g_byte_array_append((GByteArray*)key, b, bSize);
	return 0;
}

GByteArray*
message_marshall_gba(MESSAGE m, GError **err)
{
	GByteArray *result = NULL;
	asn_enc_rval_t encRet;

	/*sanity check */
	if (!m) {
		GSETERROR(err, "Invalid parameter");
		return NULL;
	}

	if (!m->asnMsg)
		_alloc_asn_message(m, err);

	/*set an ID if it is not present */
	if (0 == message_has_ID(m, NULL)) {
		const char *reqid = gridd_get_reqid ();
		if (!reqid)
			gridd_set_random_reqid ();
		reqid = gridd_get_reqid ();
		message_set_ID(m, (guint8*)reqid, strlen(reqid), NULL);
	}

	/*try to encode */
	guint32 u32 = 0;
	result = g_byte_array_sized_new(256);
	g_byte_array_append(result, (guint8*)&u32, sizeof(u32));
	encRet = der_encode(&asn_DEF_Message, m->asnMsg, write_gba, result);

	if (encRet.encoded < 0) {
		g_byte_array_free(result, TRUE);
		GSETERROR(err, "Encoding error (Message)");
		return NULL;
	}

	l4v_prepend_size(result->data, result->len);
	return result;
}

GByteArray*
message_marshall_gba_and_clean(MESSAGE m)
{
	GByteArray *result;

	EXTRA_ASSERT(m != NULL);
	result = message_marshall_gba(m, NULL);
	message_destroy(m);
	return result;
}

gint
message_marshall(MESSAGE m, void **s, gsize * sSize, GError ** error)
{
	if (!s || !sSize) {
		GSETERROR(error, "Invalid parameter");
		return 0;
	}

	GByteArray *encoded = message_marshall_gba(m, error);
	if (!encoded)
		return 0;
	*sSize = encoded->len;
	*s = g_byte_array_free(encoded, FALSE);
	return 1;
}

gint
message_unmarshall(MESSAGE m, void *s, gsize * sSize, GError ** error)
{
	asn_dec_rval_t decRet;
	asn_codec_ctx_t codecCtx;

	guint8 *rawS = NULL;
	gsize rawSSize = 0;

	if (!m || !s || !sSize || *sSize < 4) {
		GSETERROR(error, "Invalid parameter (m=%p s=%p sSize=%p/%i)", m, s, sSize, sSize ? *sSize : ~0U);
		return 0;
	}

	_clean_asn_message(m);

	/*extract the real buffer from the L4V capsule */
	if (!l4v_extract(s, *sSize, (void *) &rawS, &rawSSize)) {
		GSETERROR(error, "Cannot extract the L4V encapsulated data");
		return 0;
	}

	/*tries the real unmarshalling work */
	codecCtx.max_stack_size = 0;

	do {/*appease gcc with its ugly strict aliasing rules*/
		void *ptr = NULL;
		decRet = ber_decode(&codecCtx, &asn_DEF_Message, &ptr, rawS, rawSSize);
		m->asnMsg = ptr;
	} while (0);

	switch (decRet.code) {
	case RC_OK:
		break;

	case RC_FAIL:
		GSETERROR(error, "Cannot deserialize: %s (%d bytes consumed)",
				"invalid content", decRet.consumed);
		goto errorLABEL;

	case RC_WMORE:
		GSETERROR(error, "Cannot deserialize: %s (%d bytes consumed)",
				"uncomplete content", decRet.consumed);
		goto errorLABEL;
	}

	*sSize = decRet.consumed + 4;

	return 1;
      errorLABEL:
	_clean_asn_message(m);
	return 0;
}

gint
message_has_param(MESSAGE m, enum message_param_e mp, GError ** error)
{
	OCTET_STRING_t *os;

	if (!m) {
		GSETERROR(error, "Invalid parameter");
		return -1;
	}

	if (!m->asnMsg)
		return 0;

	return (__getParameter(m, mp, &os) && os && os->buf) ? 1 : 0;
}

gint
message_get_param(MESSAGE m, enum message_param_e mp, void **s, gsize * sSize, GError ** error)
{
	const char *name_mp;
	OCTET_STRING_t *os;

	if (!m || !s || !sSize) {
		GSETERROR(error, "Invalid parameter");
		return -1;
	}

	if (!m->asnMsg)
		_alloc_asn_message(m, error);

	switch (mp) {
		case MP_ID : name_mp = "MP_ID"; break;
		case MP_NAME : name_mp = "MP_NAME"; break;
		case MP_VERSION : name_mp = "MP_VERSION"; break;
		case MP_BODY : name_mp = "MP_BODY"; break;
		default : name_mp = "***invalid***"; break;
	}

	switch (message_has_param(m, mp, error)) {
		case -1:
			/*error is set */
			return -1;
		case 0:
			GSETERROR(error, "Type not set (%d/%s)", mp, name_mp);
			return 0;
	}

	if (__getParameter(m, mp, &os) && os) {
		*sSize = os->size;
		*s = os->buf;
		return 1;
	}

	return 0;
}

gint
message_set_param(MESSAGE m, enum message_param_e mp, const void *s, gsize sSize, GError ** error)
{
	OCTET_STRING_t *os;

	if (!m || !s || sSize < 1) {
		GSETERROR(error, "Invalid parameter (%p %p %d)", m, s, sSize);
		return 0;
	}

	if (!m->asnMsg)
		_alloc_asn_message(m, error);

	if (!__getParameter(m, mp, &os)) {
		GSETERROR(error, "Invalid message parameter type");
		return 0;
	}

	if (os != NULL) {
		OCTET_STRING_fromBuf(os, s, sSize);
		return 1;
	}

	switch (mp) {
		case MP_ID:
			m->asnMsg->id = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, s, sSize);
			return 1;
		case MP_NAME:
			m->asnMsg->name = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, s, sSize);
			return 1;
		case MP_VERSION:
			m->asnMsg->version = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, s, sSize);
			return 1;
		case MP_BODY:
			m->asnMsg->body = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, s, sSize);
			return 1;
		default:
			return 1;
	}
}

void
message_add_field(MESSAGE m, const char *name, const void *value, gsize valueSize)
{
	if (!m || !name || !value) {
		GRID_DEBUG("Invalid parameter (%p %s %p)", m, name, value);
		return ;
	}

	if (!m->asnMsg)
		_alloc_asn_message(m, NULL);

	void *pList = &(m->asnMsg->content.list);
	Parameter_t *pMember = g_malloc0(sizeof(Parameter_t));

	if (0 != OCTET_STRING_fromBuf(&(pMember->name), name, strlen(name))) {
		GRID_WARN("Cannot copy the parameter name");
		goto errorLABEL;
	}
	if (0 != OCTET_STRING_fromBuf(&(pMember->value), value, valueSize)) {
		GRID_WARN("Cannot copy the parameter value");
		goto errorLABEL;
	}
	if (0 != asn_set_add(pList, pMember)) {
		GRID_WARN("Cannot add the parameter to the message");
		goto errorLABEL;
	}

	return ;

errorLABEL:
	ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, &(pMember->name));
	ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, &(pMember->value));
	g_free(pMember);
}

gint
message_get_field(MESSAGE m, const void *name, gsize name_size, void **value, gsize * valueSize, GError ** error)
{
	int i, max, name_real_size;

	/*sanity checks */
	if (!m || !name || name_size < 1 || !value || !valueSize) {
		GSETERROR(error, "Invalid parameter");
		return -1;
	}

	if (!m->asnMsg)
		_alloc_asn_message(m, error);

	if (!m->asnMsg->content.list.array || m->asnMsg->content.list.count<=0) {
		return 0;
	}

	name_real_size = strlen_len(name, name_size);

	/*run the list and find a matching field */
	max = m->asnMsg->content.list.count;
	for (i = 0; i < max ; i++) {
		Parameter_t *p;

		p = m->asnMsg->content.list.array[i];
		if (!p)
			continue;
		if (p->name.size != name_real_size)
			continue;

		if (!memcmp(p->name.buf, name, name_real_size)) {
			*value = p->value.buf;
			*valueSize = p->value.size;
			return 1;
		}
	}

	return 0;
}

gchar **
message_get_field_names(MESSAGE m, GError ** error)
{
	gchar **array;
	gint max, nb, i;

	if (!m || !m->asnMsg) {
		GSETERROR(error, "invalid message parameter");
		return NULL;
	}

	max = m->asnMsg->content.list.count;
	if (max < 0) {
		GSETERROR(error, "invalid message field count : %d", max);
		return NULL;
	}

	array = g_malloc0(sizeof(gchar *) * (max + 1));

	TRACE("found %d fields", max);

	for (nb = 0, i = 0; i < max; i++) {
		Parameter_t *p = m->asnMsg->content.list.array[i];

		if (p && p->name.buf) {
			array[nb] = g_strndup((const gchar*)p->name.buf, p->name.size);
			nb++;
		}
	}

	return array;
}

gint
message_get_fields(MESSAGE m, GHashTable ** hash, GError ** error)
{
	gchar **field_names, **fn_ptr;
	GByteArray *field_value = NULL;

	if (!m || !m->asnMsg) {
		GSETERROR(error, "invalid message parameter");
		return (0);
	}

	field_names = message_get_field_names(m, error);
	if (field_names == NULL) {
		GSETERROR(error, "Failed to get fiels names");
		return (0);
	}

	*hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_clean);

	for (fn_ptr = field_names; *fn_ptr; fn_ptr++) {
		void *value;
		gsize value_size;

		if (message_get_field(m, *fn_ptr, strlen(*fn_ptr), &value, &value_size, error) > 0) {
			field_value = g_byte_array_new();
			field_value = g_byte_array_append(field_value, value, value_size);
			g_hash_table_insert(*hash, *fn_ptr, field_value);
		}
	}

	g_free(field_names);

	return (1);
}

void
message_add_field_strint64(MESSAGE m, const char *name, gint64 v)
{
	gchar tmp[64];
	g_snprintf(tmp, sizeof(tmp), "%"G_GINT64_FORMAT, v);
	return message_add_fields_str(m, name, tmp, NULL);
}

void
message_add_fieldv_str(MESSAGE m, va_list args)
{
	if (!m)
		return;

	for (;;) {
		char *k, *v;

		k = va_arg(args, char *);
		if (!k)
			break;

		v = va_arg(args, char *);
		if (!v)
			break;
		message_add_field(m, k, v, strlen(v));
	}
}

void
message_add_fields_str(MESSAGE m, ...)
{
	if (!m)
		return;

	va_list args;
	va_start(args, m);
	message_add_fieldv_str(m, args);
	va_end(args);
}

void
message_add_fieldv_gba(MESSAGE m, va_list args)
{
	if (!m)
		return;

	for (;;) {
		char *k;
		GByteArray *v;
		k = va_arg(args, char *);

		if (!k)
			break;
		v = va_arg(args, GByteArray *);
		if (!v)
			break;
		message_add_field(m, k, v->data, v->len);
	}
}

void
message_add_fields_gba(MESSAGE m, ...)
{
	if (!m)
		return;

	va_list args;
	va_start(args, m);
	message_add_fieldv_gba(m, args);
	va_end(args);
}

MESSAGE
message_create_request(GError ** err, GByteArray * id, const char *name,
		GByteArray * body, ...)
{
	MESSAGE msg = message_create();
	if (name != NULL)
		message_set_NAME(msg, name, strlen(name), err);
	if (id != NULL)
		message_set_ID(msg, id->data, id->len, NULL);
	if (body != NULL)
		message_set_BODY(msg, body->data, body->len, NULL);

	va_list args;
	va_start(args, body);
	message_add_fieldv_gba(msg, args);
	va_end(args);

	return msg;
}

GError *
message_extract_body_strv(struct message_s *msg, gchar ***result)
{
	int rc;
	void *b = NULL;
	gsize bsize = 0;

	if (0 >= (rc = message_get_BODY(msg, &b, &bsize, NULL))) {
		*result = g_malloc0(sizeof(gchar*));
		return NULL;
	}

	*result = metautils_decode_lines(b, ((gchar*)b)+bsize);
	return NULL;
}

GError *
message_extract_prefix(struct message_s *msg, const gchar *n,
		guint8 *d, gsize *dsize)
{
	void *f;
	gsize fsize;

	if (0 >= message_get_field(msg, n, strlen(n), &f, &fsize, NULL))
		return NEWERROR(CODE_BAD_REQUEST, "Missing ID prefix at '%s'", n);
	if (fsize > *dsize)
		return NEWERROR(CODE_BAD_REQUEST, "Invalid ID prefix at '%s'", n);

	memset(d, 0, *dsize);
	memcpy(d, f, fsize);
	*dsize = fsize;
	return NULL;
}

GError *
message_extract_cid(struct message_s *msg, const gchar *n, container_id_t *cid)
{
	void *f;
	gsize f_size;

	if (0 >= message_get_field(msg, n, strlen(n), &f, &f_size, NULL))
		return NEWERROR(CODE_BAD_REQUEST, "Missing container ID at '%s'", n);
	if (f_size != sizeof(container_id_t))
		return NEWERROR(CODE_BAD_REQUEST, "Invalid container ID at '%s'", n);
	memcpy(cid, f, sizeof(container_id_t));
	return NULL;
}

GError *
message_extract_string(struct message_s *msg, const gchar *n, gchar *dst,
		gsize dst_size)
{
	int rc;
	void *f;
	gsize f_size;

	rc = message_get_field(msg, n, strlen(n), &f, &f_size, NULL);
	if (0 >= rc)
		return NEWERROR(CODE_BAD_REQUEST, "Missing field '%s'", n);
	if (f_size >= dst_size)
		return NEWERROR(CODE_BAD_REQUEST,
				"Invalid field '%s': value too long (%"G_GSIZE_FORMAT")",
				n, f_size);

	memcpy(dst, f, f_size);
	memset(dst+f_size, 0, dst_size-f_size);
	return NULL;
}

GError *
message_extract_string_copy(struct message_s *msg, const gchar *n, gchar **dst)
{
	void *f;
	gsize f_size;

	int rc = message_get_field(msg, n, strlen(n), &f, &f_size, NULL);
	if (0 >= rc)
		return NEWERROR(CODE_BAD_REQUEST, "Missing field '%s'", n);

	*dst = g_strndup(f, f_size);
	return NULL;
}

GError *
message_extract_flag(struct message_s *msg, const gchar *n,
		gboolean mandatory, gboolean *flag)
{
	gsize f_size;
	void *f;
	int rc;

	rc = message_get_field(msg, n, strlen(n), &f, &f_size, NULL);
	if (0 >= rc) {
		if (mandatory)
			return NEWERROR(CODE_BAD_REQUEST, "Missing field '%s'", n);
		return NULL;
	}

	guint8 *b, _flag = 0;
	for (b=(guint8*)f + f_size; b > (guint8*)f;)
		_flag |= *(--b);

	*flag = _flag;
	return NULL;
}

GError*
message_extract_flags32(struct message_s *msg, const gchar *n,
		gboolean mandatory, guint32 *flags)
{
	void *f = NULL;
	gsize f_size = 0;

	EXTRA_ASSERT(flags != NULL);
	*flags = 0;

	if (0 >= message_get_field(msg, n, strlen(n), &f, &f_size, NULL)) {
		if (mandatory)
			return NEWERROR(CODE_BAD_REQUEST, "Missing field '%s'", n);
		return NULL;
	}

	if (f_size != 4)
		return NEWERROR(CODE_BAD_REQUEST, "Invalid 32bit flag set");

	*flags = g_ntohl(*((guint32*)f));
	return NULL;
}

GError *
message_extract_body_gba(struct message_s *msg, GByteArray **result)
{
	int rc;
	void *b = NULL;
	gsize bsize = 0;

	EXTRA_ASSERT(result != NULL);

	rc = message_get_BODY(msg, &b, &bsize, NULL);
	if (0 >= rc)
		return NEWERROR(CODE_BAD_REQUEST, "Missing body");

	*result = g_byte_array_append(g_byte_array_new(), b, bsize);
	return NULL;
}

GError *
message_extract_body_string(struct message_s *msg, gchar **result)
{
	int rc;
	void *b = NULL;
	gsize bsize = 0;

	rc = message_get_BODY(msg, &b, &bsize, NULL);
	if (0 >= rc)
		return NEWERROR(CODE_BAD_REQUEST, "Missing body");

	register gchar *c, *last;
	for (c=b,last=b+bsize; c < last ;c++) {
		if (!g_ascii_isprint(*c))
			return NEWERROR(CODE_BAD_REQUEST,
					"Body contains non printable characters");
	}

	*result = g_strndup((gchar*)b, bsize);
	return NULL;
}

GError *
metautils_unpack_bodyv (GByteArray **bodyv, GSList **result,
		body_decoder_f decoder)
{
	GError *err = NULL;
	GSList *items = NULL;
	for (GByteArray **p=bodyv; *p && !err ;++p) {
		GSList *l = NULL;
		gsize s = (*p)->len;
		if (!decoder (&l, (*p)->data, &s, NULL))
			err = NEWERROR (CODE_PROXY_ERROR, "Bad payload from service");
		else
			items = g_slist_concat (items, l);
	}
	*result = items;
	return err;
}

GError *
message_extract_body_encoded(struct message_s *msg, gboolean mandatory,
		GSList **result, body_decoder_f decoder)
{
	int rc;
	void *b = NULL;
	gsize bsize = 0;
	GError *err = NULL;

	EXTRA_ASSERT(result != NULL);
	EXTRA_ASSERT(decoder != NULL);

	rc = message_get_BODY(msg, &b, &bsize, NULL);
	if (0 >= rc) {
		if (mandatory)
			return NEWERROR(CODE_BAD_REQUEST, "Missing body");	
		*result = NULL;
		return NULL;
	}

	rc = decoder(result, b, &bsize, &err);
	if (rc <= 0) {
		EXTRA_ASSERT(err != NULL);
		err->code = CODE_BAD_REQUEST;
		g_prefix_error(&err, "Invalid body: ");
		return err;
	}

	return NULL;
}

GError*
message_extract_header_encoded(struct message_s *msg,
		const gchar *n, gboolean mandatory,
		GSList **result, body_decoder_f decoder)
{
	int rc;
	void *b = NULL;
	gsize bsize = 0;
	GError *err = NULL;

	EXTRA_ASSERT(result != NULL);
	EXTRA_ASSERT(decoder != NULL);

	rc = message_get_field(msg, n, strlen(n), &b, &bsize, NULL);
	if (0 >= rc) {
		*result = NULL;
		if (mandatory)
			return NEWERROR(CODE_BAD_REQUEST, "Missing header [%s]", n);
		return NULL;
	} 

	rc = decoder(result, b, &bsize, &err);
	if (rc <= 0) {
		EXTRA_ASSERT(err != NULL);
		err->code = CODE_BAD_REQUEST;
		g_prefix_error(&err, "Invalid header: ");
		return err;
	}

	return NULL;
}

GError *
message_extract_strint64(struct message_s *msg, const gchar *n, gint64 *i64)
{
	gchar *end, dst[32];
	GError *err;

	err = message_extract_string(msg, n, dst, sizeof(dst));
	if (err != NULL)
		return err;
	end = NULL;
	*i64 = g_ascii_strtoll(dst, &end, 10);

	switch (*i64) {
		case G_MININT64:
		case G_MAXINT64:
			return (errno == ERANGE)
				? NEWERROR(CODE_BAD_REQUEST, "Invalid number") : NULL;
		case 0:
			return (end == dst)
				? NEWERROR(CODE_BAD_REQUEST, "Invalid number") : NULL;
		default:
			return NULL;
	}
}

GError*
message_extract_struint(struct message_s *msg, const gchar *n, guint *u)
{
	gint64 i64;
	GError *err;

	err = message_extract_strint64(msg, n, &i64);
	if (err != NULL)
		return err;
	*u = i64;
	return NULL;
}

GError*
message_extract_boolean(struct message_s *msg, const gchar *n,
		gboolean mandatory, gboolean *v)
{
	gchar tmp[32];
	GError *err = message_extract_string(msg, n, tmp, sizeof(tmp));
	if (err)
		return err;
	if (v)
		*v = metautils_cfg_get_bool (tmp, *v);
	return NULL;
}

GError*
message_extract_header_gba(struct message_s *msg, const gchar *n,
		gboolean mandatory, GByteArray **result)
{
	int rc;
	void *f;
	gsize fsize;

	g_assert(msg != NULL);
	g_assert(n != NULL);
	g_assert(result != NULL);

	rc = message_get_field(msg, n, strlen(n), &f, &fsize, NULL);

	if (rc < 0)
		return NEWERROR(CODE_BAD_REQUEST, "Missing ID prefix at '%s'", n);
	if (!rc) {
		if (mandatory)
			return NEWERROR(CODE_BAD_REQUEST, "Missing ID prefix at '%s'", n);
		*result = NULL;
		return NULL;
	}

	*result = g_byte_array_append(g_byte_array_new(), f, fsize);
	return NULL;
}

