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

#ifndef OIO_SDS__metautils__lib__metatype_nsinfo_h
# define OIO_SDS__metautils__lib__metatype_nsinfo_h 1

struct namespace_info_s;

/* Get a parameter from the namespace info "options" hash table.
 * This intelligently looks for VNS overridden parameters.
 * If a service type is provided by the type-specific parameter
 * cannot be found, the generic parameter is tried. */
GByteArray *namespace_info_get_srv_param_gba(const namespace_info_t *ni,
		const gchar *ns_name, const gchar *srv_type, const gchar *param_name);

/* Same as namespace_info_get_srv_param_gba but converts the result
 * to int64. */
gint64 namespace_info_get_srv_param_i64(const namespace_info_t *ni,
		const gchar *ns_name, const gchar *srv_type, const gchar *param_name,
		gint64 def);

/* Copy a namespace_info into another namespace_info
 * The option hashtable is not copied. The old table's reference
 * count is decremented (then the table will e destroyed if it falls
 * to zero), and the table of the new struct namespace_info_s will be
 * referenced in the destination structure. */
void namespace_info_copy(struct namespace_info_s* src,
		struct namespace_info_s* dst);

/* Makes a deep copy of the input struct namespace_info_s.
 * Contrary to namespace_info_copy(), the options table will be
 * newly allocated and filled with newly allocated values. */
struct namespace_info_s* namespace_info_dup(struct namespace_info_s* src);

/* Clear a namespace_info content */
void namespace_info_clear(struct namespace_info_s* ns_info);
void namespace_info_free(struct namespace_info_s* ns_info);

void namespace_info_reset(namespace_info_t *ni);
void namespace_info_init(namespace_info_t *ni);

/* Calls namespace_info_free() on p1 and ignores p2.
 * Mainly used with g*list_foreach() functions of the GLib2
 * to clean at once whole lists of namespace_info_s structures. */
void namespace_info_gclean(gpointer p1, gpointer p2);

/* Get the data_security definition from the specified key */
gchar * namespace_info_get_data_security(struct namespace_info_s *ni,
		const gchar *data_sec_key);

/* Get the data_treatments definition from the specified key */
gchar * namespace_info_get_data_treatments(struct namespace_info_s *ni,
		const gchar *data_treat_key);

/* Get the storage_class definition from the specified key */
gchar * namespace_info_get_storage_class(struct namespace_info_s *ni,
		const gchar *stgclass_key);

struct json_object;

GError * namespace_info_init_json_object(struct json_object *obj,
		struct namespace_info_s *ni);

GError * namespace_info_init_json(const gchar *encoded,
		struct namespace_info_s *ni);

/* Appends to 'out' a json representation of 'ni' */
void namespace_info_encode_json(GString *out, struct namespace_info_s *ni);

#endif /*OIO_SDS__metautils__lib__metatype_nsinfo_h*/
