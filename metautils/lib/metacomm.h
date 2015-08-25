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

#ifndef OIO_SDS__metautils__lib__metacomm_h
# define OIO_SDS__metautils__lib__metacomm_h 1

/**
 * @file metacomm.h
 * Global communication library
 */

/**
 * @defgroup metautils_comm Metacomm
 * @ingroup metautils
 * @{
 */

#include <metautils/lib/metatypes.h>

#define DECLARE_MARSHALLER(Name) \
gint Name (GSList *l, void **d, gsize *dSize, GError **err)

#define DECLARE_MARSHALLER_GBA(Name) \
GByteArray* Name (GSList *l, GError **err)

#define DECLARE_UNMARSHALLER(Name) \
gint Name (GSList **l, const void *buf, gsize len, GError **err)

#define DECLARE_BODY_MANAGER(Name) \
gint Name (GError **err, gpointer udata, gint code, guint8 *buf, gsize len)

typedef struct Message Message_t;
typedef Message_t* MESSAGE;
struct oio_url_s;

/** Builds a simple reply for the given request. This function automates the
 * copy of the required fields from the request, and sets the appropriated
 * fields with the given status and message.
 *
 * The reply pointer wust be freed with metautils_message_destroy(). */
MESSAGE metaXServer_reply_simple(MESSAGE request, gint status, const char *msg);

/** Performs the opposite operation : retrieves the core elements of the
 * message (supposed to be a reply). 
 * The message returned in the msg pointer is a copy of the original.
 * It is allocated with the g_lib and must be freed with g_free(). */
GError* metaXClient_reply_simple(MESSAGE reply, guint * status, gchar ** msg);

void* metautils_message_get_ID (MESSAGE m, gsize *l);
void* metautils_message_get_NAME (MESSAGE m, gsize *l);
void* metautils_message_get_VERSION (MESSAGE m, gsize *l);
void* metautils_message_get_BODY (MESSAGE m, gsize *l);

void metautils_message_set_ID (MESSAGE m, const void *b, gsize l);
void metautils_message_set_NAME (MESSAGE m, const void *b, gsize l);
void metautils_message_set_VERSION (MESSAGE m, const void *b, gsize l);
void metautils_message_set_BODY (MESSAGE m, const void *b, gsize l);

gboolean metautils_message_has_ID (MESSAGE m);
gboolean metautils_message_has_NAME (MESSAGE m);
gboolean metautils_message_has_VERSION (MESSAGE m);
gboolean metautils_message_has_BODY (MESSAGE m);

/** Allocates all the internal structures of a hidden message. */
MESSAGE metautils_message_create(void);

MESSAGE metautils_message_create_named (const char *name);

/** Frees all the internal structures of the pointed message. */
void metautils_message_destroy(MESSAGE m);

/** Perform the serialization of the message. */
GByteArray* message_marshall_gba(MESSAGE m, GError **err);

/** Allocates a new message and Unserializes the given buffer. */
MESSAGE message_unmarshall(const guint8 *buf, gsize len, GError ** error);

/** Calls message_marshall_gba() then metautils_message_destroy() on 'm'. */
GByteArray* message_marshall_gba_and_clean(MESSAGE m);

typedef gint (body_decoder_f)(GSList **r, const void *b, gsize l, GError **e);

/* wraps message_set_BODY() and g_bytes_array_unref() */
void metautils_message_add_body_unref (MESSAGE m, GByteArray *body);

/** Adds a new custom field in the list of the message. Now check is made to
 * know whether the given field is already present or not. The given new value
 * will be copied. */
void metautils_message_add_field(MESSAGE m, const char *name, const void *value, gsize valueSize);
void metautils_message_add_cid (MESSAGE m, const char *f, const container_id_t cid);
void metautils_message_add_url (MESSAGE m, struct oio_url_s *url);
void metautils_message_add_field_str(MESSAGE m, const char *name, const char *value);
void metautils_message_add_field_strint64(MESSAGE m, const char *n, gint64 v);

static inline void metautils_message_add_field_strint(MESSAGE m, const char *n, gint v) { return metautils_message_add_field_strint64(m,n,v); }
static inline void metautils_message_add_field_struint(MESSAGE m, const char *n, guint v) { return metautils_message_add_field_strint64(m,n,v); }

void metautils_message_add_field_gba_and_unref(MESSAGE m, const char *n, GByteArray *gba);

void* metautils_message_get_field(MESSAGE m, const char *name, gsize *vsize);

gchar ** metautils_message_get_field_names(MESSAGE m);

GHashTable* metautils_message_get_fields(MESSAGE m);

GError* metautils_message_extract_cid(MESSAGE msg, const char *n,
		container_id_t *cid);

GError* metautils_message_extract_prefix(MESSAGE msg, const char *n,
		guint8 *d, gsize *dsize);

gboolean metautils_message_extract_flag(MESSAGE m, const char *n, gboolean d);

GError* metautils_message_extract_flags32(MESSAGE msg, const char *n,
		gboolean mandatory, guint32 *flags);

GError* metautils_message_extract_string(MESSAGE msg, const char *n, gchar *dst,
		gsize dst_size);

gchar* metautils_message_extract_string_copy(MESSAGE msg, const char *n);

GError* metautils_message_extract_strint64(MESSAGE msg, const char *n,
		gint64 *i64);

GError* metautils_message_extract_struint(MESSAGE msg, const char *n,
		guint *u);

GError* metautils_message_extract_boolean(MESSAGE msg,
		const char *n, gboolean mandatory, gboolean *v);

GError* metautils_message_extract_header_encoded(MESSAGE msg,
		const char *n, gboolean mandatory,
		GSList **result, body_decoder_f decoder);

GError* metautils_message_extract_header_gba(MESSAGE msg, const char *n,
		gboolean mandatory, GByteArray **result);

GError* metautils_message_extract_body_gba(MESSAGE msg, GByteArray **result);

/** Upon success, ensures result will be a printable string with a trailing \0 */
GError* metautils_message_extract_body_string(MESSAGE msg, gchar **result);

GError* metautils_message_extract_body_strv(MESSAGE msg, gchar ***result);

GError* metautils_unpack_bodyv (GByteArray **bodyv, GSList **result,
		body_decoder_f decoder);

GError* metautils_message_extract_body_encoded(MESSAGE msg, gboolean mandatory,
		GSList **result, body_decoder_f decoder);

struct oio_url_s * metautils_message_extract_url (MESSAGE m);

/* ------------------------------------------------------------------------- */

DECLARE_MARSHALLER_GBA(addr_info_marshall_gba);
DECLARE_UNMARSHALLER(addr_info_unmarshall);

DECLARE_MARSHALLER_GBA(meta0_info_marshall_gba);
DECLARE_UNMARSHALLER(meta0_info_unmarshall);

DECLARE_MARSHALLER_GBA(key_value_pairs_marshall_gba);
DECLARE_UNMARSHALLER(key_value_pairs_unmarshall);

DECLARE_MARSHALLER_GBA(strings_marshall_gba);
DECLARE_UNMARSHALLER(strings_unmarshall);

DECLARE_UNMARSHALLER(service_info_unmarshall);
DECLARE_MARSHALLER_GBA(service_info_marshall_gba);

DECLARE_MARSHALLER_GBA( meta2_property_marshall_gba);
DECLARE_UNMARSHALLER(   meta2_property_unmarshall);

/**
 * @param si the structure to be serialized. NULL is an error
 * @param err a pointer to the error structure being returned
 * @return NULL in case of error or a valid ASN.1 form of the given servccie_info
 */
GByteArray* service_info_marshall_1(service_info_t *si, GError **err);

/** Serialize a namespace_info to ASN1 */
GByteArray* namespace_info_marshall(struct namespace_info_s * namespace_info, GError ** err);

/** Unserialize a namespace_info from ASN1 */
namespace_info_t* namespace_info_unmarshall(const guint8 * buf, gsize buf_len, GError ** err);

#endif /*OIO_SDS__metautils__lib__metacomm_h*/
