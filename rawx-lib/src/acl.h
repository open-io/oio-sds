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

#ifndef OIO_SDS__metautils__lib__metatype_acl_h
# define OIO_SDS__metautils__lib__metatype_acl_h 1

#include <glib/gtypes.h>

/**
 * @defgroup metautils_utils_acl ACL 
 * @ingroup metautils_utils
 * @brief ACL utils
 * @details Handles access control lists got from the conscience.
 * @{
 */

gboolean authorized_personal_only(const gchar* addr, GSList* acl);

GSList* parse_acl(const GByteArray* acl_byte, gboolean authorize);

GSList* parse_acl_conf_file(const gchar* file_path, GError **error);

gchar* access_rule_to_string(const addr_rule_t* addr_rule);

void addr_rule_g_free(gpointer data);

#endif /*OIO_SDS__metautils__lib__metatype_acl_h*/
