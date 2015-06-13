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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.remote"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>
#include <cluster/module/module.h>

#include "gridcluster_remote.h"

namespace_info_t *
gcluster_get_namespace_info_full(addr_info_t * addr, long timeout, GError ** error)
{
	EXTRA_ASSERT (addr != NULL);
	gchar str[STRLEN_ADDRINFO];
	addr_info_to_string(addr, str, sizeof(str));

	GByteArray *out = NULL;
	GError *err = gridd_client_exec_and_concat (str, ((gdouble)timeout)/1000.0,
			message_marshall_gba_and_clean(metautils_message_create_named(
					NAME_MSGNAME_CS_GET_NSINFO)), &out);
	if (err) {
		g_prefix_error(&err, "request: ");
		g_error_transmit(error, err);
		return NULL;
	}
	
	namespace_info_t *ns_info = namespace_info_unmarshall(out->data, out->len, error);
	if (!ns_info)
		GSETERROR(error, "Decoding error");
	return ns_info;
}

GSList *
gcluster_get_services(const char *target, gdouble timeout,
		const gchar *type, gboolean full, GError ** error)
{
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_CS_GET_SRV);
	metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, type);
	if (full)
		metautils_message_add_field_str(req, NAME_MSGKEY_FULL, "1");

	GSList *out = NULL;	
	GError *err = gridd_client_exec_and_decode (target, ((gdouble)timeout)/1000.0,
			message_marshall_gba_and_clean(req),
			&out, service_info_unmarshall);

	if (err) {
		g_error_transmit(error, err);
		g_slist_free_full (out, (GDestroyNotify)service_info_clean);
	}
	return out;
}

GSList *
gcluster_get_service_types(addr_info_t *addr, long timeout, GError ** error)
{
	EXTRA_ASSERT (addr != NULL);
	gchar target[STRLEN_ADDRINFO];
	grid_addrinfo_to_string (addr, target, sizeof(target));

	GSList *out = NULL;
	MESSAGE req = metautils_message_create_named (NAME_MSGNAME_CS_GET_SRVNAMES);
	GError *err = gridd_client_exec_and_decode (target, ((gdouble)timeout)/1000.0,
			message_marshall_gba_and_clean(req), &out, strings_unmarshall);
	if (err) {
		g_prefix_error (&err, "Remote: ");
		g_error_transmit(error, err);
	}
	return out;
}

GError *
gcluster_push_services(addr_info_t * addr, long timeout, GSList *ls)
{
	EXTRA_ASSERT (addr != NULL);
	gchar target[STRLEN_ADDRINFO];
	grid_addrinfo_to_string (addr, target, sizeof(target));

	MESSAGE req = metautils_message_create_named (NAME_MSGNAME_CS_PUSH_SRV);
	metautils_message_add_body_unref (req, service_info_marshall_gba (ls, NULL));
	return gridd_client_exec (target, ((gdouble)timeout)/1000.0,
			message_marshall_gba_and_clean(req));
}

