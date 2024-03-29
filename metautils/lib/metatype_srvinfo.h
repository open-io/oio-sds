/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2020-2021 OVH SAS

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

#ifndef OIO_SDS__metautils__lib__metatype_srvinfo_h
# define OIO_SDS__metautils__lib__metatype_srvinfo_h 1

#include <glib/gtypes.h>

void service_info_clean(struct service_info_s *si);

void service_info_cleanv(struct service_info_s **siv, gboolean content_only);

/* Clean the tags array from the service_info_s object. */
void service_info_clean_tags(struct service_info_s *si);

struct service_info_s *service_info_dup(const struct service_info_s *si);


GPtrArray *service_info_copy_tags(GPtrArray * original);

struct service_tag_s *service_info_get_tag(GPtrArray * a, const gchar * n);

struct service_tag_s *service_info_ensure_tag(GPtrArray * a, const gchar * name);

void service_tag_copy(struct service_tag_s *dst, struct service_tag_s *src);

struct service_tag_s *service_tag_dup(struct service_tag_s *src);

void service_tag_destroy(struct service_tag_s *tag);

void service_tag_set_value_string(struct service_tag_s *tag, const gchar *s);

gboolean service_tag_get_value_string(struct service_tag_s *tag, gchar * s,
		gsize s_size, GError **error);

void service_tag_set_value_boolean(struct service_tag_s *tag, gboolean b);

gboolean service_tag_get_value_boolean(struct service_tag_s *tag, gboolean *b,
		GError **error);

void service_tag_set_value_i64(struct service_tag_s *tag, gint64 i);

void service_tag_set_value_float(struct service_tag_s *tag, gdouble r);

gsize service_tag_to_string(const struct service_tag_s *tag, gchar * dst,
		gsize dst_size);

const gchar * service_info_get_tag_value(const struct service_info_s *si,
		const gchar *name, const gchar *def);

struct json_object;

GError* service_info_load_json_object(struct json_object *obj,
		struct service_info_s **out, gboolean permissive);

GError* service_info_load_json(const gchar *encoded,
		struct service_info_s **out, gboolean permissive);

void service_info_encode_json(GString *out, const struct service_info_s *si,
		gboolean full);

void service_info_encode_prometheus(GString *gstr,
		const struct service_info_s *si);

void oio_parse_chunk_url(const gchar *url,
		gchar **type, gchar **netloc, gchar **id);

/** Build a key for a service from its type and ID */
gchar * oio_make_service_key(const char *ns_name, const char *type, const char *id);

/** Extract namespace, type and ID from a service key */
void oio_parse_service_key(const char *key, gchar **ns, gchar **type, gchar **id);

gchar * service_info_key (const struct service_info_s *si);

/** Fill a preallocated LB item from a service description */
void service_info_to_lb_item(const struct service_info_s *si,
		struct oio_lb_item_s *item);

gchar ** metautils_service_list_to_urlv(GSList *l);

/* Build a serialized representation of meta1_url that correspond
 * to the given service. */
gchar * metautils_service_to_m1url(const struct service_info_s *si, gint64 seq);
/* -------------------------------------------------------------------------- */

struct service_info_dated_s *service_info_dated_new(
		struct service_info_s *si, time_t lock_mtime);

void service_info_dated_free(struct service_info_dated_s *sid);

void service_info_dated_encode_json(GString *gstr,
		const struct service_info_dated_s *sid, gboolean full);

GError* service_info_dated_load_json(const gchar *encoded,
		struct service_info_dated_s **out, gboolean permissive);

#endif /*OIO_SDS__metautils__lib__metatype_srvinfo_h*/
