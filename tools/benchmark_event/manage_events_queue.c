#include <glib.h>

#include <events/oio_events_queue.h>
#include <core/internals.h>
#include "manage_events_queue.h"

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
	if (q)
		s_err = oio_events_queue__run (q, _running);
	return p;
}

GError *
manage_events_queue_init (const char *addr)
{
	if (!addr) {
		q = NULL;
		th_queue = NULL;
		return NULL;
	}

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
manage_events_queue_destroy (void)
{
	running = FALSE;
	if (th_queue) {
		g_thread_join (th_queue);
		th_queue = NULL;
	}
	if (s_err)
		g_clear_error(&s_err);
	if (q) {
		oio_events_queue__destroy (q);
		q = NULL;
	}
}

GError *
manage_events_queue_send (const char *event_type, struct oio_url_s *url, GString *data_json)
{
	if (q != NULL && th_queue != NULL) {
		GString *json = oio_event__create (event_type, url);
		
		if (data_json) {
			g_string_append_printf(json, ",\"data\":%.*s}",
					(int) data_json->len, data_json->str);
		} else {
			g_string_append(json, ",\"data\":null}");
		}
		
		oio_events_queue__send (q, g_string_free (json, FALSE));
	}

	if (data_json) {
		g_string_free (data_json, TRUE);
	}
	
	return NULL;
}

