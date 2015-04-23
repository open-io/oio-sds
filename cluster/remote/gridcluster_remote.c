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

static MESSAGE
build_request(gchar * req_name, void *body, gsize body_size)
{
	MESSAGE req = message_create();
	if (body)
		message_set_BODY(req, body, body_size, NULL);
	message_set_NAME(req, req_name, strlen(req_name), NULL);
	return (req);
}

static gboolean
namespace_info_full_handler(GError ** error, gpointer udata, gint code, guint8 * body, gsize bodySize)
{
	(void) error, (void) code, (void) bodySize;
	namespace_info_t **ns_info = (namespace_info_t **) udata;
	*ns_info = namespace_info_unmarshall(body, bodySize, error);
	return (TRUE);
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
	static struct code_handler_s codes[] = {
		{CODE_FINAL_OK, REPSEQ_FINAL, &namespace_info_full_handler, NULL},
		{0, 0, NULL, NULL}
	};
	namespace_info_t *ns_info = NULL;
	struct reply_sequence_data_s data = { &ns_info, 0, codes };
	MESSAGE req = build_request(NAME_MSGNAME_CS_GET_NSINFO, NULL, 0);

	if (!metaXClient_reply_sequence_run_from_addrinfo(error, req, addr, timeout, &data)) {
		GSETERROR(error, "Cannot execute the query %s and receive all the responses", NAME_MSGNAME_CS_GET_NSINFO);
		goto error_reply;
	}

	message_destroy(req);
	return (ns_info);

error_reply:
	message_destroy(req);
	return (NULL);
}

gint
gcluster_push_broken_container(addr_info_t * addr, long timeout, GSList * container_list, GError ** error)
{
	static struct code_handler_s codes[] = {
		{CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL},
		{0, 0, NULL, NULL}
	};
	struct reply_sequence_data_s data = { NULL, 0, codes };

	GByteArray *buf = meta2_maintenance_names_marshall(container_list, error);
	if (!buf) {
		GSETERROR(error, "Failed to marshall container list");
		return 0;
	}

	MESSAGE req = build_request(NAME_MSGNAME_CS_PUSH_BROKEN_CONT, buf->data, buf->len);
	if (!metaXClient_reply_sequence_run_from_addrinfo(error, req, addr, timeout, &data)) {
		GSETERROR(error, "Cannot execute the query %s and receive all the responses",
				NAME_MSGNAME_CS_PUSH_BROKEN_CONT);
		goto error_reply;
	}

	message_destroy(req);
	g_byte_array_free(buf, TRUE);
	return (1);

error_reply:
	message_destroy(req);
	g_byte_array_free(buf, TRUE);
	return (0);
}

gint
gcluster_fix_broken_container(addr_info_t * addr, long timeout, GSList * container_list, GError ** error)
{
	static struct code_handler_s codes[] = {
		{CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL},
		{0, 0, NULL, NULL}
	};
	struct reply_sequence_data_s data = { NULL, 0, codes };

	GByteArray *buf = meta2_maintenance_names_marshall(container_list, error);
	if (!buf) {
		GSETERROR(error, "Failed to marshall container list");
		return 0;
	}

	MESSAGE req = build_request(NAME_MSGNAME_CS_FIX_BROKEN_CONT, buf->data, buf->len);
	if (!metaXClient_reply_sequence_run_from_addrinfo(error, req, addr, timeout, &data)) {
		GSETERROR(error, "Cannot execute the query %s and receive all the responses",
				NAME_MSGNAME_CS_FIX_BROKEN_CONT);
		goto error_reply;
	}

	message_destroy(req);
	g_byte_array_free(buf, TRUE);
	return (1);

error_reply:
	message_destroy(req);
	g_byte_array_free(buf, TRUE);
	return (0);
}

gint
gcluster_rm_broken_container(addr_info_t * addr, long timeout, GSList * container_list, GError ** error)
{
	static struct code_handler_s codes[] = {
		{CODE_FINAL_OK, REPSEQ_FINAL, NULL, NULL},
		{0, 0, NULL, NULL}
	};
	struct reply_sequence_data_s data = { NULL, 0, codes };

	GByteArray *buf = meta2_maintenance_names_marshall(container_list, error);
	if (!buf) {
		GSETERROR(error, "Failed to marshall container list");
		return 0;
	}

	MESSAGE req = build_request(NAME_MSGNAME_CS_RM_BROKEN_CONT, buf->data, buf->len);
	if (!metaXClient_reply_sequence_run_from_addrinfo(error, req, addr, timeout, &data)) {
		GSETERROR(error, "Cannot execute the query %s and receive all the responses",
				NAME_MSGNAME_CS_RM_BROKEN_CONT);
		goto error_reply;
	}

	message_destroy(req);
	g_byte_array_free(buf, TRUE);
	return (1);

error_reply:
	message_destroy(req);
	g_byte_array_free(buf, TRUE);
	return (0);
}

GSList *
gcluster_get_broken_container(addr_info_t * addr, long timeout, GError ** error)
{
	static struct code_handler_s codes[] = {
		{CODE_PARTIAL_CONTENT, REPSEQ_BODYMANDATORY, &container_list_content_handler, NULL},
		{CODE_FINAL_OK, REPSEQ_FINAL, &container_list_content_handler, NULL},
		{0, 0, NULL, NULL}
	};
	GSList *containers = NULL;
	struct reply_sequence_data_s data = { &containers, 0, codes };

	MESSAGE req = build_request(NAME_MSGNAME_CS_GET_BROKEN_CONT, NULL, 0);
	if (!metaXClient_reply_sequence_run_from_addrinfo(error, req, addr, timeout, &data)) {
		GSETERROR(error, "Cannot execute the query %s and receive all the responses",
				NAME_MSGNAME_CS_GET_BROKEN_CONT);
		goto error_reply;
	}

	message_destroy(req);
	return (containers);

error_reply:
	message_destroy(req);
	return (NULL);
}

GSList *
gcluster_get_services(const char *target, gdouble timeout,
		const gchar *type, gboolean full, GError ** error)
{
	struct message_s *req = message_create_named(NAME_MSGNAME_CS_GET_SRV);
	message_add_fields_str (req,
			NAME_MSGKEY_TYPENAME, type,
			NAME_MSGKEY_FULL, full?"1":NULL,
			NULL);

	GSList *out = NULL;	
	GError *err = gridd_client_exec_and_decode (target, timeout,
			message_marshall_gba_and_clean(req), &out, service_info_unmarshall);
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
	static struct code_handler_s codes[] = {
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

	message_destroy(req);
	return (srvtypes);

error_reply:
	message_destroy(req);
	return (NULL);
}

gint
gcluster_push_services(addr_info_t * addr, long timeout, GSList * services_list, gboolean lock_action, GError ** error)
{
	static struct code_handler_s codes[] = {
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
		message_add_field(req, "LOCK", "true", sizeof("true") - 1);

	if (!metaXClient_reply_sequence_run_from_addrinfo(error, req, addr, timeout, &data)) {
		GSETERROR(error, "Cannot execute the query %s and receive all the responses", NAME_MSGNAME_CS_PUSH_SRV);
		goto error_reply;
	}

	message_destroy(req);
	g_byte_array_free(buf, TRUE);
	return (1);

error_reply:
	message_destroy(req);
	g_byte_array_free(buf, TRUE);
	return (0);
}

