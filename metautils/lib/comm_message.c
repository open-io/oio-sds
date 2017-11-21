/*
OpenIO SDS metautils
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
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#include "metautils.h"
#include "codec.h"

enum message_param_e { MP_ID, MP_NAME, MP_VERSION, MP_BODY };

static void
_free_Parameter(Parameter_t * p)
{
	if (!p)
		return;
	ASN_STRUCT_FREE(asn_DEF_Parameter, p);
}

static OCTET_STRING_t *
__getParameter(MESSAGE m, enum message_param_e mp)
{
	switch (mp) {
		case MP_ID:
			return m->id;
		case MP_NAME:
			return m->name;
		case MP_VERSION:
			return m->version;
		case MP_BODY:
			return m->body;
		default:
			g_assert_not_reached();
			return NULL;
	}
}

MESSAGE
metautils_message_create_named (const char *name, gint64 deadline)
{
	EXTRA_ASSERT(name != NULL);

	MESSAGE result = ASN1C_CALLOC(1, sizeof(Message_t));
	metautils_message_set_NAME (result, name, strlen(name));

	const char *id = oio_ext_get_reqid ();
	if (id)
		metautils_message_set_ID (result, id, strlen(id));

	if (deadline > 0) {
		const gint64 now = oio_ext_monotonic_time();
		metautils_message_add_field_strint64(result, NAME_MSGKEY_TIMEOUT,
				(now < deadline) ? (deadline - now) : 1);
	}

	return result;
}

void
metautils_message_destroy(MESSAGE m)
{
	if (!m)
		return ;

	if (m->id != NULL)
		ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, m->id);
	if (m->body != NULL)
		ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, m->body);
	if (m->version != NULL)
		ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, m->version);
	if (m->name != NULL)
		ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, m->name);

	m->content.list.free = _free_Parameter;
	asn_set_empty(&(m->content.list));
	ASN1C_FREE(m);
}

int
metautils_asn1c_write_gba (const void *b, gsize bSize, void *key)
{
	if (b && bSize > 0)
		g_byte_array_append((GByteArray*)key, b, bSize);
	return 0;
}


static GByteArray*
message_marshall_gba(MESSAGE m)
{
	EXTRA_ASSERT(m != NULL);

	/*set an ID if it is not present */
	if (!metautils_message_has_ID(m)) {
		const char *reqid = oio_ext_get_reqid ();
		if (!reqid)
			oio_ext_set_random_reqid ();
		reqid = oio_ext_get_reqid ();
		metautils_message_set_ID(m, (guint8*)reqid, strlen(reqid));
	}

	if (oio_ext_is_admin())
		metautils_message_add_field_strint(m, NAME_MSGKEY_ADMIN_COMMAND, 1);

	/*try to encode */
	guint32 u32 = 0;
	GByteArray *result = g_byte_array_sized_new(256);
	g_byte_array_append(result, (guint8*)&u32, sizeof(u32));
	asn_enc_rval_t encRet = der_encode(&asn_DEF_Message, m, metautils_asn1c_write_gba, result);

	if (encRet.encoded < 0) {
		g_byte_array_free(result, TRUE);
		return NULL;
	}

	guint32 s32 = result->len - 4;
	*((guint32*)(result->data)) = g_htonl(s32);
	return result;
}

GByteArray*
message_marshall_gba_and_clean(MESSAGE m)
{
	GByteArray *result;

	EXTRA_ASSERT(m != NULL);
	result = message_marshall_gba(m);
	metautils_message_destroy(m);
	return result;
}

MESSAGE
message_unmarshall(const guint8 *buf, gsize len, GError ** error)
{
	if (!buf || len < 4) {
		GSETERROR(error, "Invalid parameter");
		return NULL;
	}

	guint32 l0 = *((guint32*)buf);
	l0 = g_ntohl(l0);

	if (l0 > len-4) {
		GSETERROR(error, "l4v: uncomplete");
		return NULL;
	}

	MESSAGE m = NULL;
	asn_codec_ctx_t codec_ctx;
	codec_ctx.max_stack_size = ASN1C_MAX_STACK;
	size_t s = l0;
	asn_dec_rval_t rc = ber_decode(&codec_ctx, &asn_DEF_Message, (void**)&m, buf+4, s);

	if (rc.code == RC_OK)
		return m;

	if (rc.code == RC_WMORE)
		GSETERROR(error, "%s (%"G_GSIZE_FORMAT" bytes consumed)", "uncomplete content", rc.consumed);
	else
		GSETERROR(error, "%s (%"G_GSIZE_FORMAT" bytes consumed)", "invalid content", rc.consumed);

	metautils_message_destroy (m);
	return NULL;
}

static void*
message_get_param(MESSAGE m, enum message_param_e mp, gsize *sSize)
{
	EXTRA_ASSERT (m != NULL);

	OCTET_STRING_t *os = __getParameter(m, mp);
	if (!os || !os->buf) {
		if (sSize) *sSize = 0;
		return NULL;
	} else {
		if (sSize) *sSize = os->size;
		return os->buf;
	}
}

static void
_os_set (OCTET_STRING_t **pos, const void *s, gsize sSize)
{
	if (*pos)
		OCTET_STRING_fromBuf(*pos, s, sSize);
	else
		*pos = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, s, sSize);
}

static void
message_set_param(MESSAGE m, enum message_param_e mp, const void *s, gsize sSize)
{
	EXTRA_ASSERT(m != NULL);
	EXTRA_ASSERT(s != NULL);
	EXTRA_ASSERT(sSize > 0);

	switch (mp) {
		case MP_ID:
			_os_set(&m->id, s, sSize);
			return;
		case MP_NAME:
			_os_set(&m->name, s, sSize);
			return;
		case MP_VERSION:
			_os_set(&m->version, s, sSize);
			return;
		case MP_BODY:
			_os_set(&m->body, s, sSize);
			return;
		default:
			g_assert_not_reached();
			return;
	}
}

void*
metautils_message_get_ID (MESSAGE m, gsize *l)
{ return message_get_param(m, MP_ID, l); }

void*
metautils_message_get_NAME (MESSAGE m, gsize *l)
{ return message_get_param(m, MP_NAME, l); }

void*
metautils_message_get_BODY (MESSAGE m, gsize *l)
{ return message_get_param(m, MP_BODY, l); }

void
metautils_message_set_ID (MESSAGE m, const void *b, gsize l)
{ return message_set_param(m, MP_ID, b, l); }

void
metautils_message_set_NAME (MESSAGE m, const void *b, gsize l)
{ return message_set_param(m, MP_NAME, b, l); }

void
metautils_message_set_BODY (MESSAGE m, const void *b, gsize l)
{ return message_set_param(m, MP_BODY, b, l); }

gboolean
metautils_message_has_ID (MESSAGE m)
{ return NULL != metautils_message_get_ID(m,NULL); }

gboolean
metautils_message_has_BODY (MESSAGE m)
{ return NULL != metautils_message_get_BODY(m,NULL); }

void*
metautils_message_get_field(MESSAGE m, const char *name, gsize *vsize)
{
	EXTRA_ASSERT (m != NULL);
	EXTRA_ASSERT (name != NULL);
	EXTRA_ASSERT (vsize != NULL);

	*vsize = 0;

	if (!m->content.list.array) {
		return NULL;
	}

	const gssize nlen = strlen(name);

	for (int i = 0; i < m->content.list.count ;i++) {
		Parameter_t *p = m->content.list.array[i];
		if (p->name.size != nlen)
			continue;
		if (!memcmp(p->name.buf, name, nlen)) {
			*vsize = p->value.size;
			return p->value.buf;
		}
	}

	return NULL;
}

gchar **
metautils_message_get_field_names(MESSAGE m)
{
	EXTRA_ASSERT(m != NULL);

	const int max = m->content.list.count;
	EXTRA_ASSERT(max >= 0);

	gchar **array = g_malloc0(sizeof(gchar *) * (max + 1));
	for (int nb=0,i=0; i<max; ) {
		Parameter_t *p = m->content.list.array[i++];
		if (p && p->name.buf)
			array[nb++] = g_strndup((const gchar*)p->name.buf, p->name.size);
	}

	return array;
}

void
metautils_message_add_field(MESSAGE m, const char *n, const void *v, gsize vs)
{
	EXTRA_ASSERT (m!=NULL);
	EXTRA_ASSERT (n!=NULL);
	if (!v || !vs)
		return ;
	Parameter_t *pMember = ASN1C_CALLOC(1, sizeof(Parameter_t));
	OCTET_STRING_fromBuf(&(pMember->name), n, strlen(n));
	OCTET_STRING_fromBuf(&(pMember->value), v, vs);
	asn_set_add(&(m->content.list), pMember);
}

void
metautils_message_add_field_str(MESSAGE m, const char *name, const char *value)
{
	if (value)
		metautils_message_add_field (m, name, value, strlen(value));
}

void
metautils_message_add_field_gba(MESSAGE m, const char *name, GByteArray *gba)
{
	if (gba)
		metautils_message_add_field (m, name, gba->data, gba->len);
}

void
metautils_message_add_field_strint64(MESSAGE m, const char *name, gint64 v)
{
	gchar tmp[24];
	g_snprintf(tmp, 24, "%"G_GINT64_FORMAT, v);
	return metautils_message_add_field_str(m, name, tmp);
}

static struct map_s
{
	const char *f;
	int u;
	const char *avoid;
	int max_length;
} url2msg_map[] = {
	{NAME_MSGKEY_NAMESPACE,   OIOURL_NS,        NULL, LIMIT_LENGTH_NSNAME},
	{NAME_MSGKEY_ACCOUNT,     OIOURL_ACCOUNT,   NULL, LIMIT_LENGTH_ACCOUNTNAME},
	{NAME_MSGKEY_USER,        OIOURL_USER,      NULL, LIMIT_LENGTH_BASENAME},
	{NAME_MSGKEY_TYPENAME,    OIOURL_TYPE,      OIOURL_DEFAULT_TYPE, LIMIT_LENGTH_SRVTYPE},
	{NAME_MSGKEY_CONTENTPATH, OIOURL_PATH,      NULL, LIMIT_LENGTH_CONTENTPATH},
	{NAME_MSGKEY_CONTENTID,   OIOURL_CONTENTID, NULL, STRLEN_CONTAINERID},
	{NAME_MSGKEY_VERSION,     OIOURL_VERSION,   NULL, LIMIT_LENGTH_VERSION},
	{NULL, 0, NULL, 0},
};

void
metautils_message_add_url (MESSAGE m, struct oio_url_s *url)
{
	if (!m)
		return;
	for (struct map_s *p = url2msg_map; p->f ;++p) {
		if (oio_url_has (url, p->u)) {
			const char *s = oio_url_get (url, p->u);
			if (!p->avoid || strcmp(p->avoid, s))
				metautils_message_add_field_str(m, p->f, s);
		}
	}

	const guint8 *id = oio_url_get_id (url);
	if (id)
		metautils_message_add_field (m, NAME_MSGKEY_CONTAINERID, id, oio_url_get_id_size (url));
}

void
metautils_message_add_url_no_type (MESSAGE m, struct oio_url_s *url)
{
	if (!m)
		return;
	for (struct map_s *p = url2msg_map; p->f ;++p) {
		if (p->u != OIOURL_TYPE && oio_url_has (url, p->u)) {
			const char *s = oio_url_get (url, p->u);
			if (!p->avoid || strcmp(p->avoid, s))
				metautils_message_add_field_str(m, p->f, s);
		}
	}

	const guint8 *id = oio_url_get_id (url);
	if (id)
		metautils_message_add_field (m, NAME_MSGKEY_CONTAINERID, id, oio_url_get_id_size (url));
}

struct oio_url_s *
metautils_message_extract_url (MESSAGE m)
{
	GError *err = NULL;
	struct oio_url_s *url = oio_url_empty ();
	for (struct map_s *p = url2msg_map; p->f; ++p) {
		gchar field[p->max_length];
		memset(field, 0, sizeof(field));
		if (metautils_message_extract_string_noerror(
				m, p->f, field, sizeof(field))) {
			if (!p->avoid || strcmp(p->avoid, field))
				oio_url_set(url, p->u, field);
		}
	}

	container_id_t cid;
	err = metautils_message_extract_cid(m, NAME_MSGKEY_CONTAINERID, &cid);
	if (err)
		g_clear_error(&err);
	else
		oio_url_set_id(url, cid);

	return url;
}

void
metautils_message_add_cid (MESSAGE m, const char *f, const container_id_t cid)
{
	if (cid)
		metautils_message_add_field (m, f, cid, sizeof(container_id_t));
}

void
metautils_message_add_body_unref (MESSAGE m, GByteArray *body)
{
	if (!body)
		return;
	if (body->len && body->data)
		metautils_message_set_BODY (m, body->data, body->len);
	g_byte_array_unref (body);
}

GError *
metautils_message_extract_cid(MESSAGE msg, const gchar *n, container_id_t *cid)
{
	gsize fsize = 0;
	void *f = metautils_message_get_field(msg, n, &fsize);
	if (!f || !fsize)
		return NEWERROR(CODE_BAD_REQUEST, "Missing container ID at '%s'", n);
	if (fsize != sizeof(container_id_t))
		return NEWERROR(CODE_BAD_REQUEST, "Invalid container ID at '%s'", n);
	memcpy(cid, f, sizeof(container_id_t));
	return NULL;
}

gboolean
metautils_message_extract_string_noerror(MESSAGE msg, const gchar *n,
		gchar *dst, gsize dst_size)
{
	gsize fsize = 0;
	void *f = metautils_message_get_field(msg, n, &fsize);
	if (!f || !fsize || (gssize)fsize < 0 || fsize >= dst_size)
		return FALSE;
	if (fsize)
		memcpy(dst, f, fsize);
	dst[fsize] = '\0';
	return TRUE;
}

GError *
metautils_message_extract_string(MESSAGE msg, const gchar *n,
		gchar *dst, gsize dst_size)
{
	if (!metautils_message_extract_string_noerror(msg, n, dst, dst_size))
		return BADREQ("Missing/Bad field %s", n);
	return NULL;
}

gchar *
metautils_message_extract_string_copy(MESSAGE msg, const gchar *n)
{
	gsize fsize = 0;
	void *f = metautils_message_get_field(msg, n, &fsize);
	if (!f || !fsize)
		return NULL;
	return g_strndup(f, fsize);
}

gboolean
metautils_message_extract_flag(MESSAGE msg, const gchar *n, gboolean def)
{
	gsize fsize = 0;
	void *f = metautils_message_get_field(msg, n, &fsize);
	if (!f || !fsize)
		return def;

	guint8 *b, _flag = 0;
	for (b=(guint8*)f + fsize; b > (guint8*)f;)
		_flag |= *(--b);
	return _flag;
}

void
metautils_message_extract_flags32(MESSAGE msg, const gchar *n, guint32 *flags)
{
	EXTRA_ASSERT(flags != NULL);
	*flags = 0;

	gsize fsize = 0;
	void *f = metautils_message_get_field(msg, n, &fsize);
	if (!f || fsize != 4)
		return;
	*flags = g_ntohl(*((guint32*)f));
}

GError *
metautils_message_extract_body_gba(MESSAGE msg, GByteArray **result)
{
	EXTRA_ASSERT(result != NULL);

	gsize bsize = 0;
	*result = NULL;
	void *b = metautils_message_get_BODY(msg, &bsize);
	if (!b)
		return NEWERROR(CODE_BAD_REQUEST, "No body");

	if (bsize > 0) {
		*result = g_byte_array_sized_new(bsize);
		g_byte_array_append(*result, b, bsize);
	} else {
		*result = g_byte_array_sized_new(8);
	}
	return NULL;
}

GError *
metautils_message_extract_body_string(MESSAGE msg, gchar **result)
{
	gsize bsize = 0;
	void *b = metautils_message_get_BODY(msg, &bsize);
	if (!b)
		return NEWERROR(CODE_BAD_REQUEST, "No body");

	if (!bsize) {
		*result = g_malloc0(sizeof(void*));
		return NULL;
	}

	register gchar *c, *last;
	for (c = b, last = b + bsize; c < last; c++) {
		if (!g_ascii_isprint(*c))
			return NEWERROR(CODE_BAD_REQUEST,
					"Body contains non printable characters at offset %td",
					((void*)c - b));
	}

	*result = g_strndup((gchar*)b, bsize);
	return NULL;
}

GError *
metautils_message_extract_body_encoded(MESSAGE msg, gboolean mandatory,
		GSList **result, body_decoder_f decoder)
{
	EXTRA_ASSERT(result != NULL);
	EXTRA_ASSERT(decoder != NULL);

	gsize bsize = 0;
	void *b = metautils_message_get_BODY(msg, &bsize);
	if (!b) {
		if (mandatory)
			return NEWERROR(CODE_BAD_REQUEST, "Missing body");
		return NULL;
    }

	GError *err = NULL;
	int rc = decoder(result, b, bsize, &err);
	if (rc <= 0) {
		EXTRA_ASSERT(err != NULL);
		err->code = CODE_BAD_REQUEST;
		g_prefix_error(&err, "Invalid body: ");
		return err;
	}

	return NULL;
}

GError*
metautils_message_extract_header_encoded(MESSAGE msg, const gchar *n, gboolean mandatory,
		GSList **result, body_decoder_f decoder)
{
	EXTRA_ASSERT(result != NULL);
	EXTRA_ASSERT(decoder != NULL);

	gsize bsize = 0;
	void *b = metautils_message_get_field(msg, n, &bsize);
	if (!b || !bsize) {
		*result = NULL;
		if (mandatory)
			return NEWERROR(CODE_BAD_REQUEST, "Missing header [%s]", n);
		return NULL;
	}

	GError *err = NULL;
	int rc = decoder(result, b, bsize, &err);
	if (rc <= 0) {
		EXTRA_ASSERT(err != NULL);
		err->code = CODE_BAD_REQUEST;
		g_prefix_error(&err, "Invalid header: ");
		return err;
	}

	return NULL;
}

GError *
metautils_message_extract_strint64(MESSAGE msg, const gchar *n, gint64 *i64)
{
	gchar dst[24] = "";
	*i64 = 0;

	if (!metautils_message_extract_string_noerror(msg, n, dst, sizeof(dst)))
		return BADREQ("Missing field %s", n);
	if (!oio_str_is_number(dst, i64))
		return BADREQ("Invalid number for %s", n);
	return NULL;
}

GError*
metautils_message_extract_struint(MESSAGE msg, const gchar *n, guint *u)
{
	EXTRA_ASSERT (u != NULL);
	*u = 0;
	gint64 i64 = 0;
	GError *err = metautils_message_extract_strint64(msg, n, &i64);
	if (err) return err;
	if (i64<0) return BADREQ("[%s] is negative", n);
	if (i64 > G_MAXUINT) return BADREQ("[%s] is too big", n);
	*u = i64;
	return NULL;
}

GError*
metautils_message_extract_boolean(MESSAGE msg, const gchar *n,
		gboolean mandatory, gboolean *v)
{
	gchar tmp[16];
	if (!metautils_message_extract_string_noerror(msg, n, tmp, sizeof(tmp))) {
		if (mandatory)
			return BADREQ("Missing field %s", n);
		return NULL;
	} else {
		if (v)
			*v = oio_str_parse_bool (tmp, *v);
		return NULL;
	}
}

