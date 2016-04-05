#include <stdlib.h>
#include <assert.h>

#include <glib.h>

#include <events/oio_events_queue.h>
#include <mod_dav.h>
#include "mod_dav_rawx.h"
#include "rawx_event.h"

static char s_queue_address[1024];

GError *
rawx_event_init (const char *addr)
{
	if (!addr)
		return NULL;
	GError *err = oio_events_queue_factory__check_config (addr);
	if (err) {
		g_prefix_error (&err, "Configuration error: ");
		return err;
	}
	s_queue_address[0] = 0;
	g_strlcpy (s_queue_address, addr, sizeof(s_queue_address));
	return NULL;
}

void
rawx_event_destroy (void)
{
	s_queue_address[0] = 0;
}

static gboolean _running (gboolean pending) { return pending; }

GError *
rawx_event_send (const char *event_type, GString *data_json)
{
	if (!s_queue_address[0])
		return NULL;

	struct oio_events_queue_s *q = NULL;

	GError *err = oio_events_queue_factory__create (s_queue_address, &q);
	if (err) {
		g_prefix_error (&err, "Event queue creation failed: ");
		return err;
	}

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

	err = oio_events_queue__run (q, _running);
	oio_events_queue__destroy (q);
	q = NULL;
	return err;
}
