/*
OpenIO SDS meta0v2
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

#ifndef OIO_SDS__meta0v2__meta0_remote_h
# define OIO_SDS__meta0v2__meta0_remote_h 1

#include <glib.h>

GError * meta0_remote_get_meta1_all(const char *m0, GSList **out);
GError * meta0_remote_get_meta1_one(const char *m0, const guint8 *prefix, GSList **out);
GError * meta0_remote_cache_refresh(const char *m0);
GError * meta0_remote_fill(const char *m0, gchar **urls, guint nbreplicas);
GError * meta0_remote_fill_v2(const char *m0, guint nbreplicas, gboolean nodist);
GError * meta0_remote_assign(const char *m0, gboolean nocheck);
GError * meta0_remote_disable_meta1(const char *m0, gchar **urls, gboolean nocheck);
GError * meta0_remote_get_meta1_info(const char *m0, gchar ***out);
GError * meta0_remote_destroy_meta1ref(const char *m0, const char *urls);
GError * meta0_remote_destroy_meta0zknode(const char *m0, const char *urls);

#endif /*OIO_SDS__meta0v2__meta0_remote_h*/
