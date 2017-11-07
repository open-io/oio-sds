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
void metautils_srvinfo_ensure_tags (struct service_info_s *si);

/* Requests the the best target (conscience, agent proxy) ------------------- */

GError* conscience_get_namespace (const char *ns, struct namespace_info_s **out);
GError* conscience_get_services (const char *ns, const char *type,
		gboolean full, GSList **out, gint64 deadline);
GError* conscience_get_types (const char *ns, GSList **out);
GError* conscience_push_service (const char *ns, struct service_info_s *si);
GError* conscience_remove_services (const char *ns, const char *type);

GError* register_namespace_service (const struct service_info_s *si);

/* -------------------------------------------------------------------------- */

gboolean namespace_is_storage_policy_valid(const namespace_info_t* ns_info, const gchar *storage_policy);

gchar* namespace_data_security_value(const namespace_info_t *ns_info, const gchar *wanted_policy);

gchar* namespace_storage_policy_value(const namespace_info_t *ns_info, const gchar *wanted_policy);

#endif /*OIO_SDS__cluster__lib__gridcluster_h*/
