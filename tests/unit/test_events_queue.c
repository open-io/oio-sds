/*
OpenIO SDS unit tests
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include <glib.h>
#include <zmq.h>

#include <core/oio_core.h>
#include <events/events_variables.h>
#include <events/oio_events_queue.h>

static gboolean immediately_done (gboolean p) { (void) p; return FALSE; }

static void
test_queue_stalled (void)
{
	struct oio_events_queue_s *q = NULL;
	GError *err = oio_events_queue_factory__create ("inproc://X", &q);
	g_assert_no_error (err);
	g_assert_nonnull (q);

	oio_events_common_max_pending = 100;

	g_assert_false (oio_events_queue__is_stalled (q));
	for (guint i=0; i<oio_events_common_max_pending ;++i)
		oio_events_queue__send (q, g_strdup ("x"));

	g_assert_true (oio_events_queue__is_stalled (q));
	for (guint i=0; i<oio_events_common_max_pending ;++i)
		oio_events_queue__send (q, g_strdup ("x"));
	g_assert_true (oio_events_queue__is_stalled (q));

	oio_events_queue__run (q, immediately_done);
	oio_events_queue__destroy (q);
}

static void
test_queue_init (void)
{
	GSList *l = NULL;
	for (guint i=0; i<16 ;i++) {
		gchar url[64];
		g_snprintf(url, sizeof(url), "inproc://%u", i);
		struct oio_events_queue_s *q = NULL;
		GError *err = oio_events_queue_factory__create (url, &q);
		g_assert_no_error (err);
		g_assert_nonnull (q);
		l = g_slist_prepend (l, q);
	}
	g_slist_free_full (l, (GDestroyNotify)oio_events_queue__destroy);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/events/queue/init", test_queue_init);
	g_test_add_func("/events/queue/clogged", test_queue_stalled);
	return g_test_run();
}
