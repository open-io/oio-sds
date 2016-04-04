#include <stdlib.h>
#include <assert.h>

#include <glib.h>

#include <events/oio_events_queue.h>
#include <mod_dav.h>
#include "mod_dav_rawx.h"
#include "rawx_event.h"

static struct oio_events_queue_s *q = NULL;

int
rawx_event_init (server_rec *s, const char *addr)
{
	if (addr == NULL)
		return 1;

	GError *err = oio_events_queue_factory__create (addr, &q);
	if (err) {
		ap_log_error (__FILE__, __LINE__, 0, APLOG_WARNING, 0, s,
				"Event queue creation failed: (%d) %s", err->code, err->message);
		g_clear_error (&err);
	}
	return q != NULL;
}

void
rawx_event_destroy (void)
{
	if (q != NULL)
		oio_events_queue__destroy (q);
	q = NULL;
}

static gboolean _running (gboolean pending) { return pending; }

int
rawx_event_send (const char *event_type, GString *data_json)
{
	if (q == NULL)
		return 1;

	GString *json = g_string_sized_new(256);

	g_string_append_printf(json,
			"{"
			"\"event\":\"%s\","
			"\"when\":%"G_GINT64_FORMAT","
			"\"data\":%s"
			"}",
			event_type,
			oio_ext_real_time() / G_TIME_SPAN_SECOND,
			data_json->str);

	g_string_free(data_json, TRUE);

	oio_events_queue__send (q, g_string_free (json, FALSE));
	oio_events_queue__run (q, _running);
	return 1;
}
