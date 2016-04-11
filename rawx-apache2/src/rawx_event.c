#include <stdlib.h>
#include <assert.h>

#include <glib.h>

#include <events/oio_events_queue.h>
#include <mod_dav.h>
#include "mod_dav_rawx.h"
#include "rawx_event.h"

struct oio_events_queue_s *q = NULL;
static GThread *th_queue = NULL;
static volatile gboolean running = FALSE;
static GError *s_err = NULL;

static gboolean
_running (gboolean pending)
{
	(void) pending; return running;
}

static gpointer
_worker (gpointer p)
{
	EXTRA_ASSERT(running != FALSE);
	EXTRA_ASSERT(q != NULL);
	s_err = oio_events_queue__run (q, _running);
	return p;
}

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

	err = oio_events_queue_factory__create (addr, &q);
	if (err) {
		g_prefix_error (&err, "Event queue creation failed: ");
		return err;
	}

	th_queue = g_thread_try_new ("oio-events-queue", _worker, NULL, &err);
	if (err) {
		g_prefix_error (&err, "Thread creation failed: ");
		return err;
	}

	running = TRUE;
	return NULL;
}

void
rawx_event_destroy (void)
{
	running = FALSE;
	g_thread_join (th_queue);
	th_queue = NULL;
	if (s_err)
		g_clear_error(&s_err);
	oio_events_queue__destroy (q);
	q = NULL;
}

GError *
rawx_event_send (const char *event_type, GString *data_json)
{
	EXTRA_ASSERT(q != NULL);

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

	return NULL;
}
