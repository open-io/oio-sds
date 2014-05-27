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
		{200, REPSEQ_FINAL, NULL, __status_reply_handler},
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
	GByteArray *gba_event;
	MESSAGE request = NULL;
	gboolean rc = FALSE;

	if (!cnx || !ueid || !event || !event_error) {
		GSETERROR(error,"Invalid parameter (%p %p %p %p)", cnx, ueid, event, event_error);
		return FALSE;
	}

	if (!message_create(&request, error)) {
		GSETERROR(error, "Failed to create a new message");
		goto error_create;
	}
	if (!message_set_NAME(request, REQ_EVT_PUSH, sizeof(REQ_EVT_PUSH)-1, error)) {
		GSETERROR(error, "Failed to set message name");
		goto error_set_name;
	}

	gba_event = gridcluster_encode_event(event, error);
	if (!gba_event) {
		GSETERROR(error,"Event serialization error");
		goto error_encode;
	}
	if (!message_set_BODY(request, gba_event->data, gba_event->len, error)) {
		GSETERROR(error, "Failed to set message body");
		goto error_set_body;
	}
	if (!message_add_field(request, MSG_HEADER_UEID, sizeof(MSG_HEADER_UEID)-1, ueid, strlen(ueid), error)) {
		GSETERROR(error,"Failed to add UEID");
		goto error_set_ueid;
	}

	if (!__event_request(cnx, request, event_error, error)) {
		GSETERROR(error,"Request failed");
		goto error_request;
	}
	rc = TRUE;
error_request:
error_set_ueid:
error_set_body:
	g_byte_array_free(gba_event, TRUE);
error_encode:
error_set_name:
	message_destroy(request, NULL);
error_create:
	return rc;
}

gboolean
gridcluster_status_event(struct metacnx_ctx_s *cnx, const gchar *ueid, GError **event_error, GError **error)
{
	MESSAGE request = NULL;
	gboolean rc = FALSE;

	if (!cnx || !ueid || !event_error) {
		GSETERROR(error,"Invalid parameter (%p %p %p)", cnx, ueid, event_error);
		return FALSE;
	}

	if (!message_create(&request, error)) {
		GSETERROR(error, "Failed to create a new message");
		goto error_create;
	}
	if (!message_set_NAME(request, REQ_EVT_PUSH, sizeof(REQ_EVT_PUSH)-1, error)) {
		GSETERROR(error, "Failed to set message name");
		goto error_set_name;
	}

	if (!message_add_field(request, MSG_HEADER_UEID, sizeof(MSG_HEADER_UEID)-1, ueid, strlen(ueid), error)) {
		GSETERROR(error,"Failed to add UEID");
		goto error_set_ueid;
	}

	if (!__event_request(cnx, request, event_error, error)) {
		GSETERROR(error,"Request failed");
		goto error_request;
	}
	rc = TRUE;

error_request:
error_set_ueid:
error_set_name:
	message_destroy(request, NULL);
error_create:
	return rc;
	return TRUE;
}

