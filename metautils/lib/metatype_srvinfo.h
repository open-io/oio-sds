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

#ifndef OIO_SDS__metautils__lib__metatype_srvinfo_h
# define OIO_SDS__metautils__lib__metatype_srvinfo_h 1

#include <glib/gtypes.h>

void service_info_clean(struct service_info_s *si);
void service_info_cleanv(struct service_info_s **siv, gboolean content_only);
void service_info_gclean(gpointer si, gpointer unused);

gboolean service_info_equal(const struct service_info_s * si1, const struct service_info_s * si2);
/* only consider the PNS */
gboolean service_info_equal_v2(const struct service_info_s * si1, const struct service_info_s * si2);
void service_info_swap(struct service_info_s *si0, struct service_info_s *si1);
gint service_info_sort_by_score(gconstpointer a, gconstpointer b);

struct service_info_s *service_info_dup(const struct service_info_s *si);
struct service_tag_s *service_tag_dup(struct service_tag_s *src);

GPtrArray *service_info_copy_tags(GPtrArray * original);
void service_tag_copy(struct service_tag_s *dst, struct service_tag_s *src);

void service_tag_destroy(struct service_tag_s *tag);
void service_tag_set_value_string(struct service_tag_s *tag, const gchar *s);
gboolean service_tag_get_value_string(struct service_tag_s *tag, gchar * s,
		gsize s_size, GError **error);

void service_tag_set_value_boolean(struct service_tag_s *tag, gboolean b);
gboolean service_tag_get_value_boolean(struct service_tag_s *tag, gboolean *b,
		GError **error);

void service_tag_set_value_i64(struct service_tag_s *tag, gint64 i);
gboolean service_tag_get_value_i64(struct service_tag_s *tag, gint64* i,
		GError** error);

void service_tag_set_value_float(struct service_tag_s *tag, gdouble r);
gboolean service_tag_get_value_float(struct service_tag_s *tag, gdouble *r,
		GError** error);

void service_tag_set_value_macro(struct service_tag_s *tag, const gchar * type,
		const gchar * param);
gboolean service_tag_get_value_macro(struct service_tag_s *tag, gchar * type,
		gsize type_size, gchar* param, gsize param_size, GError** error);

gsize service_tag_to_string(const struct service_tag_s *tag, gchar * dst, gsize dst_size);
gchar* service_info_to_string(const service_info_t *si);

struct service_tag_s *service_info_get_tag(GPtrArray * a, const gchar * n);
struct service_tag_s *service_info_ensure_tag(GPtrArray * a, const gchar * name);

void service_info_remove_tag(GPtrArray * a, const gchar * name);

const gchar * service_info_get_tag_value(const struct service_info_s *si,
		const gchar *name, const gchar *def);

/* Calls service_info_get_tag_value() with NAME_TAGNAME_RAWX_LOC as 2nd parameter. */
const gchar * service_info_get_rawx_location(const struct service_info_s *si,
		const gchar *def);

/* Calls service_info_get_tag_value() with NAME_TAGNAME_RAWX_VOL as 2nd parameter. */
const gchar * service_info_get_rawx_volume(const struct service_info_s *si,
		const gchar *def);

/* Calls service_info_get_tag_value() with NAME_TAGNAME_RAWX_STGCLASS as 2nd parameter. */
const gchar * service_info_get_stgclass(const struct service_info_s *si,
		const gchar *def);

/* Tests if the storage class of a service complies with
 * a specific storage class.
 *
 * @param wanted_class The class we want to match to
 * @param si The service description
 * @param strict If false, accept equivalent storage classes
 * @return TRUE if storage class match, FALSE otherwise
 */
gboolean service_info_check_storage_class(const struct service_info_s *si,
		const gchar *wanted_class);

/* Check if a service_info is specified as internal (i.e. if it has a tag
 * "tag.internal" with a string value not equals to "false" */
gboolean service_info_is_internal(const struct service_info_s *si);

/* Extract the rawx location from service info tag */
gchar* get_rawx_location(service_info_t* rawx);

#define metautils_rawx_get_location(si) \
	g_strdup(service_info_get_rawx_location((si), ""))

#define metautils_rawx_get_volume(si) \
	g_strdup(service_info_get_rawx_volume((si), "/"))

struct json_object;

GError* service_info_load_json_object(struct json_object *obj,
		struct service_info_s **out);

GError* service_info_load_json(const gchar *encoded, struct service_info_s **out);

/* Appends to 'out' a json representation of 'si' */
void service_info_encode_json(GString *out, struct service_info_s *si);

/* Returns a unique key identifying the service */
gchar * service_info_key (const struct service_info_s *si);

#endif /*OIO_SDS__metautils__lib__metatype_srvinfo_h*/
