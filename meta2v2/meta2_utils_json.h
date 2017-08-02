/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__meta2v2__meta2_utils_json_h
# define OIO_SDS__meta2v2__meta2_utils_json_h 1

#include <glib.h>
#include <json-c/json.h>

GError* m2v2_json_load_single_alias (struct json_object *j, gpointer *pbean);
GError* m2v2_json_load_single_header (struct json_object *j, gpointer *pbean);
GError* m2v2_json_load_single_chunk (struct json_object *j, gpointer *pbean);

/* the type is discovered in the json object */
GError *m2v2_json_load_single_xbean (struct json_object *j, gpointer *pbean);

/** Extract a list of beans from a JSON object.
 * @param j The JSON object to extract beans from
 * @param out The output list of beans */
GError * meta2_json_load_setof_beans(struct json_object *j, GSList **out);

/**  */
GError * m2v2_json_load_setof_xbean (struct json_object *j, GSList **out);

/** Convert alias beans to their JSON representation.
 * Ignores beans of other types. */
void meta2_json_alias_only(GString *gstr, GSList *l, gboolean extend);

/** Convert header beans to their JSON representation.
 * Ignores beans os other types. */
void meta2_json_headers_only(GString *gstr, GSList *l, gboolean extend);

/** Convert chunk beans to their JSON representation.
 * Ignores beans os other types. */
void meta2_json_chunks_only(GString *gstr, GSList *l, gboolean extend);

/** Serialize beans to JSON.
 * The output has the form:
 *   "chunks":[],"aliases":[],"headers":[]
 * The output does not contain the outer curly brackets, to allow easier
 * inclusion in an existing dictionary. */
void meta2_json_dump_all_beans(GString *gstr, GSList *beans);

/** Serialize beans to JSON.
 * The output has the form:
 *   {"type":"chunk":,...},
 *   {"type":"alias",...},
 *   {"type":"header",...}
 * The output does not contain the outer square brackets, to allow easier
 * inclusion in an existing array. */
void meta2_json_dump_all_xbeans(GString *gstr, GSList *beans);

#endif /*OIO_SDS__meta2v2__meta2_utils_json_h*/
