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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>
#include <cluster/module/module.h>

#include "gridcluster_remote.h"

GError *
gcluster_get_namespace (const char *cs, namespace_info_t **out)
{
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_CS_GET_NSINFO);
	GByteArray *gba = NULL;
	GError *err = gridd_client_exec_and_concat (cs, CS_CLIENT_TIMEOUT,
			message_marshall_gba_and_clean(req), &gba);
	if (err) {
		g_prefix_error(&err, "request: ");
		return err;
	}

	*out = namespace_info_unmarshall(gba->data, gba->len, &err);
	if (*out) return NULL;
	GSETERROR(&err, "Decoding error");
	return err;
}

GError *
gcluster_get_services(const char *cs, const char *type, gboolean full,
		GSList **out)
{
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_CS_GET_SRV);
	metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, type);
	if (full)
		metautils_message_add_field_str(req, NAME_MSGKEY_FULL, "1");
	return gridd_client_exec_and_decode (cs, CS_CLIENT_TIMEOUT,
			message_marshall_gba_and_clean(req), out, service_info_unmarshall);
}

GError *
gcluster_get_service_types(const char *cs, GSList **out)
{
	MESSAGE req = metautils_message_create_named (NAME_MSGNAME_CS_GET_SRVNAMES);
	return gridd_client_exec_and_decode (cs, CS_CLIENT_TIMEOUT,
			message_marshall_gba_and_clean(req), out, strings_unmarshall);
}

GError *
gcluster_push_services(const char *cs, GSList *ls)
{
	MESSAGE req = metautils_message_create_named (NAME_MSGNAME_CS_PUSH_SRV);
	metautils_message_add_body_unref (req, service_info_marshall_gba (ls, NULL));
	return gridd_client_exec (cs, CS_CLIENT_TIMEOUT,
			message_marshall_gba_and_clean(req));
}

GError*
gcluster_remove_services(const char *cs, const char *type, GSList *ls)
{
	MESSAGE req = metautils_message_create_named (NAME_MSGNAME_CS_RM_SRV);
	if (ls)
		metautils_message_add_body_unref (req, service_info_marshall_gba (ls, NULL));
	if (type) metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, type);
	return gridd_client_exec (cs, CS_CLIENT_TIMEOUT,
			message_marshall_gba_and_clean(req));
}

