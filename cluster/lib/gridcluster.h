/*
OpenIO SDS cluster
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

#ifndef OIO_SDS__cluster__lib__gridcluster_h
# define OIO_SDS__cluster__lib__gridcluster_h 1

#include <metautils/lib/metatypes.h>

struct service_info_s;

GError* conscience_get_namespace (const char *ns, struct namespace_info_s **out);

GError* conscience_get_services (const char *ns, const char *type,
		gboolean full, GSList **out, gint64 deadline);

GError* conscience_get_types (const char *ns, GSList **out);

/* Variant of conscience_get_services() dedicated to meta0 and suitable
 * as a "meta0 location lookup hook" required at the construction of a
 * hc_resolver_s */
GError* conscience_locate_meta0(const char *ns, gchar ***result, gint64 dl);

#endif /*OIO_SDS__cluster__lib__gridcluster_h*/
