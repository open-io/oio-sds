#include <glib.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#include "bench_conf.h"
#include "fake_service.h"
#include "send_events.h"

static void grid_main_specific_stop (void);

// send_events.c
extern gint n_events_per_round;
extern gint rounds;
extern gint increment;
extern enum event_type_e event_type;

static struct oio_directory_s *dir = NULL;
static struct oio_url_s *url = NULL;
static service_info_t *account_service_info = NULL;
GThread *fake_service_thread = NULL;

static gboolean
link_rawx_fake_service (void)
{
	dir = oio_directory__create_proxy(NAME_SPACE);
	if (!dir) {
		return FALSE;
	}
	g_assert_nonnull(dir);
	
	url = oio_url_init(NAME_SPACE "/" NAME_ACCOUNT_RDIR "/" RAWX_ADDRESS "/" NAME_SRVTYPE_RDIR "/toto");
	
	const char * const values[10] = {
		"host", FAKE_SERVICE_ADDRESS,
		"args", "",
		"type", NAME_SRVTYPE_RDIR,
		"id", NAME_SPACE "|" NAME_SRVTYPE_RDIR "|" FAKE_SERVICE_ADDRESS,
		NULL
	};
	
	GError *err = oio_directory__force(dir, url, NAME_SRVTYPE_RDIR, values);
	if (err) {
		GRID_ERROR("Failed to call 'reference/force': (%d) %s", err->code,
				err->message);
		g_clear_error(&err);
		
		return FALSE;
	}
	
	return TRUE;
}

static service_info_t *
get_account_service_info(void)
{
	GSList *services = NULL;
	
	GError *err = conscience_get_services(NAME_SPACE, NAME_SRVTYPE_ACCOUNT, FALSE, &services);
	if (err) {
		GRID_ERROR("Failed to load the list of [" NAME_SRVTYPE_ACCOUNT "] in NS=" NAME_SPACE);
		g_clear_error(&err);
		
		return NULL;
	}
	
	service_info_t * service_info = services->data;
	
	g_slist_free(services);
	
	return service_info;
}

static gpointer
_fake_service_run(gpointer p)
{
	(void) p;
	
	if (!fake_service_run()) {
		grid_main_set_status(EXIT_FAILURE);
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
	return "CHUNK_NEW/CHUNK_DELETED/CONTAINER_NEW/CONTAINER_STATE/CONTENT_DELETED";
}

static void
grid_main_set_defaults (void)
{
    send_events_defaults();
}

static gboolean
grid_main_configure (int argc, char **argv)
{
	if (argc < 1) {
		g_printerr("Invalid arguments number\n");
		return FALSE;
	}
	
	return fake_service_configure() && send_events_configure(argv[0]);
}

static void
grid_main_action (void)
{
	// Link the rawx address with the fake service address
	if (event_type == CHUNK_NEW || event_type == CHUNK_DELETED) {
		if (!link_rawx_fake_service()) {
			grid_main_set_status(EXIT_FAILURE);
			return;
		}
	}
	
	// Lock the account service
	if (event_type == CONTAINER_NEW || event_type == CONTAINER_STATE) {
		account_service_info = get_account_service_info();
		if (!account_service_info) {
			grid_main_set_status(EXIT_FAILURE);
			return;
		}
		account_service_info->score.value = SCORE_DOWN;
		conscience_push_service(NAME_SPACE, account_service_info);
	}
	
	// Launch the fake service
	GError *err;
	fake_service_thread = g_thread_try_new("fake_service", _fake_service_run, NULL, 
													&err);
	if (fake_service_thread == NULL) {
		GRID_ERROR("Failed to start the fake_service thread: (%d) %s", err->code,
		          err->message);
		grid_main_set_status(EXIT_FAILURE);
		return;
	}
	
	g_usleep(G_TIME_SPAN_SECOND);
	
	// Send the events
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
	
	if (url) {
		GError *err = oio_directory__unlink(dir, url, NAME_SRVTYPE_RDIR);
		if (err) {
			GRID_ERROR("Failed to call 'reference/unlink': (%d) %s", err->code,
					err->message);
			g_clear_error(&err);
		}
		oio_url_clean(url);
	}
	
	if (dir) {
		oio_directory__destroy(dir);
		dir = NULL;
	}
	
	if (account_service_info) {
		account_service_info->score.value = SCORE_UNLOCK;
		conscience_push_service(NAME_SPACE, account_service_info);
		service_info_clean(account_service_info);
	}
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
