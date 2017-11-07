/*
OpenIO SDS meta0v2
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

#ifndef OIO_SDS__meta0v2__meta0_remote_h
# define OIO_SDS__meta0v2__meta0_remote_h 1

#include <glib.h>

GError * meta0_remote_get_meta1_all(const char *m0, GSList **out, gint64 deadline);
GError * meta0_remote_get_meta1_one(const char *m0, const guint8 *prefix, GSList **out, gint64 deadline);
GError * meta0_remote_cache_refresh(const char *m0, gint64 deadline);
GError * meta0_remote_cache_reset(const char *m0, gboolean local, gint64 deadline);
GError * meta0_remote_force(const char *m0, const guint8 *mapping, gsize mapping_len, gint64 deadline);

#endif /*OIO_SDS__meta0v2__meta0_remote_h*/
