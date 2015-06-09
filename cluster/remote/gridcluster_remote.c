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
#include <metautils/lib/metacomm.h>
#include <cluster/module/module.h>

#include "gridcluster_remote.h"

static MESSAGE
build_request(const gchar * req_name, void *body, gsize body_size)
{
	MESSAGE req = metautils_message_create_named(req_name);
	if (body)
		metautils_message_set_BODY(req, body, body_size);
	return req;
}


static gboolean
container_list_content_handler(GError ** error, gpointer udata, gint code, guint8 * body, gsize bodySize)
{
	(void) code;
	GSList **the_list = (GSList **) udata;
	GSList *list_from_body = meta2_maintenance_names_unmarshall_buffer(body, bodySize, error);
	if (!list_from_body) {
		GSETERROR(error, "Cannot unmarshall body of message as broken containers");
		return (FALSE);
	}

	*the_list = g_slist_concat(*the_list, list_from_body);
	return (TRUE);
}

namespace_info_t *
gcluster_get_namespace_info_full(addr_info_t * addr, long timeout, GError ** error)
{
	EXTRA_ASSERT (addr != NULL);
	gchar str[STRLEN_ADDRINFO];
	addr_info_to_string(addr, str, sizeof(str));

	GByteArray *out = NULL;
	GError *err = gridd_client_exec_and_concat (str, 60.0, message_marshall_gba_and_clean(
				metautils_message_create_named(NAME_MSGNAME_CS_GET_NSINFO)), &out);
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
	GByteArray *gba = message_marshall_gba_and_clean(req);

	GSList *out = NULL;	
	GError *err = gridd_client_exec_and_decode (target, timeout,
			gba, &out, service_info_unmarshall);
	g_byte_array_unref(gba);

	if (err) {
		if (error)
			g_error_transmit(error, err);
		else
			g_clear_error(&err);
		g_slist_free_full (out, (GDestroyNotify)service_info_clean);
		return NULL;
	} else {
		return out;
	}
}

GSList *
gcluster_get_service_types(addr_info_t *addr, long timeout, GError ** error)
{
	struct code_handler_s codes[] = {
		{CODE_PARTIAL_CONTENT, REPSEQ_BODYMANDATORY, &container_list_content_handler, NULL},
		{CODE_FINAL_OK, REPSEQ_FINAL, &container_list_content_handler, NULL},
		{0, 0, NULL, NULL}};
	GSList *srvtypes = NULL;
	struct reply_sequence_data_s data = { &srvtypes, 0, codes };

	MESSAGE req = build_request(NAME_MSGNAME_CS_GET_SRVNAMES, NULL, 0);
	if (!metaXClient_reply_sequence_run_from_addrinfo(error, req, addr, timeout, &data)) {
		GSETERROR(error, "Cannot execute the query %s and receive all the responses", NAME_MSGNAME_CS_GET_SRVNAMES);
		goto error_reply;
	}

	metautils_message_destroy(req);
	return (srvtypes);

error_reply:
	metautils_message_destroy(req);
	return (NULL);
}

gint
gcluster_push_services(addr_info_t * addr, long timeout, GSList * services_list, gboolean lock_action, GError ** error)
{
	struct code_handler_s codes[] = {
		{CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL},
		{0, 0, NULL, NULL}
	};
	struct reply_sequence_data_s data = { NULL, 0, codes };

	GByteArray *buf = service_info_marshall_gba(services_list, error);
	if (!buf) {
		GSETERROR(error, "Failed to marshall services list");
		return 0;
	}

	MESSAGE req = build_request(NAME_MSGNAME_CS_PUSH_SRV, buf->data, buf->len);
	if (lock_action)
		metautils_message_add_field_str(req, NAME_MSGKEY_LOCK, "true");

	if (!metaXClient_reply_sequence_run_from_addrinfo(error, req, addr, timeout, &data)) {
		GSETERROR(error, "Cannot execute the query %s and receive all the responses", NAME_MSGNAME_CS_PUSH_SRV);
		goto error_reply;
	}

	metautils_message_destroy(req);
	g_byte_array_free(buf, TRUE);
	return (1);

error_reply:
	metautils_message_destroy(req);
	g_byte_array_free(buf, TRUE);
	return (0);
}

