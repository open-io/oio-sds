/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#include <stdlib.h>
#include <unistd.h>

#include "metautils.h"

static void
trigger_sigfpe(void)
{
	static gulong zero = 0LU;
	int local = 0;

	GRID_WARN("COIN!");
	GRID_WARN("%lu", ((gulong)(&local)) % zero);
}

static gpointer
_worker(gpointer data)
{
	gulong i = (gulong)data;
	metautils_ignore_signals();
	sleep(i);
	while (grid_main_is_running()) {
		if (!i)
			trigger_sigfpe();
		sleep(1);
	}
	GRID_NOTICE("Exiting");
	return data;
}

static void
main_action(void)
{
	GSList *threads = NULL;

	for (gulong i=0; i<5 ;++i) {
		GError *err = NULL;
		GThread *th = g_thread_try_new("worker", _worker, (gpointer)i, &err);
		if (NULL != err) {
			GRID_WARN("Thread creation failure : (%s:%d) %s",
					g_quark_to_string(err->domain), err->code, err->message);
			g_clear_error(&err);
		}
		if (NULL != th) {
			threads = g_slist_prepend(threads, th);
			GRID_NOTICE("Thread started : %p", th);
		}
	}

	GRID_NOTICE("All threads started!");

	for (GSList *l=threads; l ;l=l->next) {
		GThread *th;
		if (NULL == (th = l->data))
			continue;
		GRID_INFO("Joining thread : %p", th);
		g_thread_join(th);
		GRID_NOTICE("Thread joined : %p", th);
	}

	g_slist_free(threads);
}

static void
main_set_defaults(void)
{
}

static gboolean
main_configure(int argc, char **argv)
{
	(void) argc, (void) argv;
	return TRUE;
}

static void
main_specific_fini(void)
{
}

static void
main_specific_stop(void)
{
}

static const char *
main_usage(void)
{
	return "No extra arg";
}

static struct grid_main_option_s *
main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{NULL, 0, {.i=0}, NULL}
	};
	return options;
}

static struct grid_main_callbacks cb =
{
	.options = main_get_options,
	.action = main_action,
	.set_defaults = main_set_defaults,
	.specific_fini = main_specific_fini,
	.configure = main_configure,
	.usage = main_usage,
	.specific_stop = main_specific_stop,
};

int
main(int argc, char **argv)
{
	return grid_main_cli(argc, argv, &cb);
}

