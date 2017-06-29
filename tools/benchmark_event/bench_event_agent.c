#include <glib.h>

#include <metautils/lib/metautils.h>

#include "fake_service.h"
#include "send_events.h"

static void grid_main_specific_stop (void);

// send_events.c
extern gint n_events_per_round;
extern gint rounds;
extern gint increment;

GThread *fake_service_thread = NULL;

static gpointer
_fake_service_run(gpointer p)
{
	(void) p;
	
	if (!fake_service_run()) {
		grid_main_specific_stop();
		
		return NULL;
	}
	
	return NULL;
}

// Main callbacks

static struct grid_main_option_s *
grid_main_get_options (void)
{
    static struct grid_main_option_s cli_options[] = {
		{
			"Rounds", OT_UINT, {.i = &rounds},
			"Number of rounds for a test"
		},
		{
			"NEventsPerRound", OT_UINT, {.i = &n_events_per_round},
			"Number of events per round for the beginning"
		},
		{
			"Increment", OT_UINT, {.i = &increment},
			"Increment of the number of events between tests"
		},
		{NULL, 0, {.i=0}, NULL}
	};

	return cli_options;
}

static const char *
grid_main_get_usage (void)
{
	return "CHUNK_NEW/CHUNK_DELETE/CONTAINER_NEW/CONTAINER_STATE/CONTENT_DELETED";
}

static void
grid_main_set_defaults (void)
{
    send_events_defaults();
}

static gboolean
grid_main_configure (int argc, char **argv)
{
    return fake_service_configure() && send_events_configure(argc, argv);
}

static void
grid_main_action (void)
{
	GError *err;
	fake_service_thread = g_thread_try_new("fake_service", _fake_service_run, NULL, 
													&err);
	if (fake_service_thread == NULL) {
		GRID_INFO("Failed to start the fake_service thread: (%d) %s", err->code,
		          err->message);
	}
	
	g_usleep(G_TIME_SPAN_SECOND);
	
	send_events_run();
	
	fake_service_stop();
	
	g_thread_join(fake_service_thread);
}

static void
grid_main_specific_stop (void)
{
	fake_service_stop();
}

static void
grid_main_specific_fini (void)
{
	send_events_fini();
	fake_service_fini();
}

struct grid_main_callbacks main_callbacks = {
	.options = grid_main_get_options,
	.action = grid_main_action,
	.set_defaults = grid_main_set_defaults,
	.specific_fini = grid_main_specific_fini,
	.configure = grid_main_configure,
	.usage = grid_main_get_usage,
	.specific_stop = grid_main_specific_stop,
};

int
main (int argc, char **argv)
{
    return grid_main (argc, argv, &main_callbacks);
}
