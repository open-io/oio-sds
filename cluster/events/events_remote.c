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
# define G_LOG_DOMAIN "gridcluster.events"
#endif

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <metautils/lib/metautils.h>

#include <cluster/events/gridcluster_events.h>
#include <cluster/events/gridcluster_eventsremote.h>

static gboolean
__status_reply_handler(GError ** err, gpointer udata, gint code, MESSAGE rep)
{
	GError **soft_error = udata;
	gint64 status64;
	void *header_value;
	gsize header_size;

	(void) code;

	if (0 >= message_get_field(rep, MSG_HEADER_EVENT_STATUS, sizeof(MSG_HEADER_EVENT_STATUS)-1, &header_value, &header_size, err)) {
		GSETERROR(err,"No status in the message");
		return FALSE;
	}
	else {
		gchar buf[32];
		g_strlcpy(buf, header_value, MIN(sizeof(buf),header_size+1));
		status64 = g_ascii_strtoll(buf, NULL, 10);
	}

	if (0 < message_get_field(rep, MSG_HEADER_EVENT_MESSAGE, sizeof(MSG_HEADER_EVENT_MESSAGE)-1, &header_value, &header_size, err))
		GSETCODE(soft_error,status64,"%.*s", header_size, header_value);
	else
		GSETCODE(soft_error,status64,"no message");
	
	return TRUE;
}

static gboolean
__event_request(struct metacnx_ctx_s *cnx, MESSAGE request, GError **event_error, GError **error)
{
	static struct code_handler_s handlers[] = {
		{CODE_FINAL_OK, REPSEQ_FINAL, NULL, __status_reply_handler},
		{0,0,0,0}
	};
	GError *current_error = NULL; 
	struct reply_sequence_data_s data = { &current_error, -1, handlers };

	if (!metaXClient_reply_sequence_run_context(error, cnx, request, &data)) {
		GSETERROR(error,"Request failed");
		return FALSE;
	}

	*event_error = current_error;
	return TRUE;
}

gboolean
gridcluster_push_event(struct metacnx_ctx_s *cnx, const gchar *ueid, gridcluster_event_t *event, GError **event_error, GError **error)
{
	gboolean rc = FALSE;

	if (!cnx || !ueid || !event || !event_error) {
		GSETERROR(error,"Invalid parameter (%p %p %p %p)", cnx, ueid, event, event_error);
		return FALSE;
	}

	MESSAGE request = message_create();
	GByteArray *gba_event = gridcluster_encode_event(event, error);
	if (!gba_event) {
		GSETERROR(error,"Event serialization error");
		goto error_encode;
	}
	message_set_NAME(request, REQ_EVT_PUSH, sizeof(REQ_EVT_PUSH)-1, NULL);
	message_set_BODY(request, gba_event->data, gba_event->len, NULL);
	message_add_field(request, MSG_HEADER_UEID, ueid, strlen(ueid));
	if (!__event_request(cnx, request, event_error, error)) {
		GSETERROR(error,"Request failed");
		goto error_request;
	}
	rc = TRUE;
error_request:
	g_byte_array_free(gba_event, TRUE);
error_encode:
	message_destroy(request);
	return rc;
}

gboolean
gridcluster_status_event(struct metacnx_ctx_s *cnx, const gchar *ueid, GError **event_error, GError **error)
{
	gboolean rc = FALSE;

	if (!cnx || !ueid || !event_error) {
		GSETERROR(error,"Invalid parameter (%p %p %p)", cnx, ueid, event_error);
		return FALSE;
	}

	MESSAGE request = message_create();
	message_set_NAME(request, REQ_EVT_PUSH, sizeof(REQ_EVT_PUSH)-1, NULL);
	message_add_field(request, MSG_HEADER_UEID, ueid, strlen(ueid));

	if (!__event_request(cnx, request, event_error, error)) {
		GSETERROR(error,"Request failed");
		goto error_request;
	}
	rc = TRUE;
error_request:
	message_destroy(request);
	return rc;
}

