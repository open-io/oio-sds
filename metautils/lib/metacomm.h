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

#ifndef OIO_SDS__metautils__lib__metacomm_h
# define OIO_SDS__metautils__lib__metacomm_h 1

#include <core/oiourl.h>
#include <metautils/lib/metatypes.h>

#define DECLARE_MARSHALLER_GBA(Name) \
GByteArray* Name (GSList *l, GError **err)

#define DECLARE_UNMARSHALLER(Name) \
gint Name (GSList **l, const void *buf, gsize len, GError **err)

typedef struct Message Message_t;
typedef Message_t* MESSAGE;

/** Builds a simple reply for the given request. This function automates the
 * copy of the required fields from the request, and sets the appropriated
 * fields with the given status and message.
 *
 * The reply pointer wust be freed with metautils_message_destroy(). */
MESSAGE metaXServer_reply_simple(MESSAGE request, gint status, const gchar *msg);

/** Performs the opposite operation : retrieves the core elements of the
 * message (supposed to be a reply).
 * The message returned in the msg pointer is a copy of the original.
 * It is allocated with the g_lib and must be freed with g_free(). */
GError* metaXClient_reply_simple(MESSAGE reply, guint * status, gchar ** msg);

void* metautils_message_get_ID (MESSAGE m, gsize *l);
void* metautils_message_get_NAME (MESSAGE m, gsize *l);
void* metautils_message_get_BODY (MESSAGE m, gsize *l);

void metautils_message_set_ID (MESSAGE m, const void *b, gsize l);
void metautils_message_set_NAME (MESSAGE m, const void *b, gsize l);
void metautils_message_set_BODY (MESSAGE m, const void *b, gsize l);

gboolean metautils_message_has_ID (MESSAGE m);
gboolean metautils_message_has_BODY (MESSAGE m);

MESSAGE metautils_message_create_named (const char *name, gint64 deadline);

/** Frees all the internal structures of the pointed message. */
void metautils_message_destroy(MESSAGE m);

/** Allocates a new message and Unserializes the given buffer. */
MESSAGE message_unmarshall(const guint8 *buf, gsize len, GError ** error);

/** Calls message_marshall_gba() then metautils_message_destroy() on 'm'. */
GByteArray* message_marshall_gba_and_clean(MESSAGE m);

typedef gint (*body_decoder_f)(GSList **r, const void *b, gsize l, GError **e);

/** Adds a new custom field in the list of the message. Now check is made to
 * know whether the given field is already present or not. The given new value
 * will be copied. */
void metautils_message_add_field(MESSAGE m, const char *name, const void *value, gsize valueSize);

void metautils_message_add_cid (MESSAGE m, const char *f, const container_id_t cid);

void metautils_message_add_url (MESSAGE m, struct oio_url_s *url);

/* As for metautils_message_add_url() but skip the type mentionned */
void metautils_message_add_url_no_type (MESSAGE m, struct oio_url_s *url);

/* wraps message_set_BODY() and g_bytes_array_unref() */
void metautils_message_add_body_unref (MESSAGE m, GByteArray *body);

void metautils_message_add_field_gba(MESSAGE m, const char *name, GByteArray *gba);

void metautils_message_add_field_str(MESSAGE m, const char *name, const char *value);

void metautils_message_add_field_strint64(MESSAGE m, const char *n, gint64 v);

static inline void metautils_message_add_field_strint(MESSAGE m, const char *n, gint v) { return metautils_message_add_field_strint64(m,n,v); }
static inline void metautils_message_add_field_struint(MESSAGE m, const char *n, guint v) { return metautils_message_add_field_strint64(m,n,v); }

void* metautils_message_get_field(MESSAGE m, const char *name, gsize *vsize);

gchar ** metautils_message_get_field_names(MESSAGE m);

GError* metautils_message_extract_cid(MESSAGE msg, const gchar *n,
		container_id_t *cid);

gboolean metautils_message_extract_flag(MESSAGE m, const gchar *n, gboolean d);

void metautils_message_extract_flags32(MESSAGE msg, const gchar *n,
		guint32 *flags);

GError* metautils_message_extract_string(MESSAGE msg, const gchar *n,
		gchar *dst, gsize dst_size);

/** Returns TRUE on success, FALSE otherwise */
gboolean metautils_message_extract_string_noerror(MESSAGE msg, const gchar *n,
		gchar *dst, gsize dst_size);

gchar* metautils_message_extract_string_copy(MESSAGE msg, const gchar *n);

GError* metautils_message_extract_strint64(MESSAGE msg, const gchar *n,
		gint64 *i64);

GError* metautils_message_extract_struint(MESSAGE msg, const gchar *n,
		guint *u);

GError* metautils_message_extract_boolean(MESSAGE msg,
		const gchar *n, gboolean mandatory, gboolean *v);

GError* metautils_message_extract_header_encoded(MESSAGE msg,
		const gchar *n, gboolean mandatory,
		GSList **result, body_decoder_f decoder);

GError* metautils_message_extract_body_gba(MESSAGE msg, GByteArray **result);

/** Upon success, ensures result will be a printable string with a trailing \0 */
GError* metautils_message_extract_body_string(MESSAGE msg, gchar **result);

GError* metautils_message_extract_body_encoded(MESSAGE msg, gboolean mandatory,
		GSList **result, body_decoder_f decoder);

struct oio_url_s * metautils_message_extract_url (MESSAGE m);

/* Destined to the ASN.1 encoders, <key> is expected to be a GByteArray */
int metautils_asn1c_write_gba(const void *b, gsize bSize, void *key);

/* ------------------------------------------------------------------------- */

DECLARE_MARSHALLER_GBA(meta0_info_marshall_gba);
DECLARE_UNMARSHALLER(meta0_info_unmarshall);

DECLARE_UNMARSHALLER(service_info_unmarshall);
DECLARE_MARSHALLER_GBA(service_info_marshall_gba);

GByteArray* service_info_marshall_1(service_info_t *si, GError **err);

GByteArray* namespace_info_marshall(struct namespace_info_s *ni,
		GError ** err);

namespace_info_t* namespace_info_unmarshall(const guint8 *b, gsize blen,
		GError ** err);

#endif /*OIO_SDS__metautils__lib__metacomm_h*/
