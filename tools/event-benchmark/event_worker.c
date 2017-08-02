/*
OpenIO SDS oio-event-benchmark
Copyright (C) 2017 OpenIO, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <events/oio_events_queue.h>
#include <core/internals.h>
#include "event_worker.h"

struct oio_events_queue_s *q = NULL;
static GThread *th_queue = NULL;
static volatile gboolean running = FALSE;
static GError *s_err = NULL;

static gboolean
_running(gboolean pending)
{
	(void) pending; return running;
}

static gpointer
_worker(gpointer p)
{
	EXTRA_ASSERT(running != FALSE);
	if (q)
		s_err = oio_events_queue__run(q, _running);
	return p;
}

GError *
event_worker_init(const char *addr)
{
	if (!addr) {
		q = NULL;
		th_queue = NULL;
		return NULL;
	}

	GError *err = oio_events_queue_factory__check_config(addr);
	if (err) {
		g_prefix_error(&err, "Configuration error: ");
		return err;
	}

	err = oio_events_queue_factory__create(addr, &q);
	if (err) {
		g_prefix_error(&err, "Event queue creation failed: ");
		return err;
	}

	th_queue = g_thread_try_new("oio-events-queue", _worker, NULL, &err);
	if (err) {
		g_prefix_error(&err, "Thread creation failed: ");
		return err;
	}

	running = TRUE;
	return NULL;
}

void
event_worker_destroy(void)
{
	running = FALSE;
	if (th_queue) {
		g_thread_join(th_queue);
		th_queue = NULL;
	}
	if (s_err)
		g_clear_error(&s_err);
	if (q) {
		oio_events_queue__destroy(q);
		q = NULL;
	}
}

GError *
event_worker_send(const char *event_type, struct oio_url_s *url,
		GString *data_json)
{
	if (q != NULL && th_queue != NULL) {
		GString *json = oio_event__create(event_type, url);

		if (data_json) {
			g_string_append_printf(json, ",\"data\":%.*s}",
					(int) data_json->len, data_json->str);
		} else {
			g_string_append(json, ",\"data\":null}");
		}

		oio_events_queue__send(q, g_string_free(json, FALSE));
	}

	if (url) {
		oio_url_clean(url);
	}

	if (data_json) {
		g_string_free(data_json, TRUE);
	}

	return NULL;
}
