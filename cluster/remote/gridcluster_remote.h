/*
OpenIO SDS cluster
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__cluster__remote__gridcluster_remote_h
# define OIO_SDS__cluster__remote__gridcluster_remote_h 1

#include <metautils/lib/metacomm.h>

GError * gcluster_get_namespace (const char *cs, struct namespace_info_s **out);

GError * gcluster_get_services (const char *cs, const gchar *type, gboolean full,
		GSList **out);

GError * gcluster_get_service_types (const char *cs, GSList **out);

GError * gcluster_push_services (const char *cs, GSList *ls);

GError * gcluster_remove_services(const char *cs, const char *type, GSList *ls);

#endif /*OIO_SDS__cluster__remote__gridcluster_remote_h*/
