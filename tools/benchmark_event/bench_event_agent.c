#include <glib.h>
#include <stdlib.h>

#include <metautils/lib/metautils.h>

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
static struct oio_cs_client_s *cs = NULL;
static struct oio_cs_registration_s *account_service = NULL;
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

static void
free_service(struct oio_cs_registration_s *service) {
	g_free((void *) service->id);
	g_free((void *) service->url);
	
	if (service->kv_tags) for (guint i=0; (service->kv_tags + i) && service->kv_tags[i]; i++) {
		g_free((void *) service->kv_tags[i]);
	}
	g_free((void *) service->kv_tags);
	
	g_free(service);
}

static struct oio_cs_registration_s *
get_account_service(void)
{
	GSList *services = NULL;
	void _on_reg (const struct oio_cs_registration_s *reg, int score) {
		(void) score;
		
		struct oio_cs_registration_s *reg_cpy = g_malloc0(sizeof(struct oio_cs_registration_s));
		
		reg_cpy->id = g_strdup(reg->id);
		reg_cpy->url = g_strdup(reg->url);
		
		GPtrArray *tmp = g_ptr_array_new ();
		if (reg->kv_tags) for (guint i=0; (reg->kv_tags + i) && reg->kv_tags[i]; i++) {
			g_ptr_array_add (tmp, g_strdup(reg->kv_tags[i]));
		}
		g_ptr_array_add (tmp, NULL);
		reg_cpy->kv_tags = (const char * const *) g_ptr_array_free (tmp, FALSE);
		
		services = g_slist_prepend (services, reg_cpy);
	}
	GError *err = oio_cs_client__list_services (cs, NAME_SRVTYPE_ACCOUNT, FALSE, _on_reg);
	if (err) {
		GRID_ERROR("Failed to load the account service: (%d) %s", err->code,
		          err->message);
		g_clear_error(&err);
		
		return NULL;
	}
	
	struct oio_cs_registration_s * account_reg = services->data;
	g_slist_free(services);
	
	return account_reg;
}

static gboolean
add_fake_account(void)
{
	const char * const kv[6] = {
		"tag.up", "True",
		"tag.slots", NAME_SRVTYPE_ACCOUNT
	};
	struct oio_cs_registration_s reg = {
		.id = FAKE_SERVICE_ADDRESS,
		.url = FAKE_SERVICE_ADDRESS,
		.kv_tags = kv
	};
	
	GError *err = oio_cs_client__lock_service(cs, NAME_SRVTYPE_ACCOUNT, &reg, SCORE_MAX);
	if (err) {
		GRID_ERROR("Failed to load the lock service: %d %s", err->code, err->message);
		g_clear_error(&err);
		
		return FALSE;
	}
	
	return TRUE;
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
	return "CHUNK_NEW/CHUNK_DELETED"
			"/CONTAINER_NEW/CONTAINER_STATE/CONTAINER_DELETED"
			"/CONTENT_DELETED";
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
	
	// Lock the account service and add fake account
	if (event_type == CONTAINER_NEW || event_type == CONTAINER_STATE 
			|| event_type == CONTAINER_DELETED) {
		cs = oio_cs_client__create_proxied(NAME_SPACE);
		
		account_service = get_account_service();
		if (!account_service) {
			grid_main_set_status(EXIT_FAILURE);
			return;
		}
		
		GError *err = oio_cs_client__lock_service(cs, NAME_SRVTYPE_ACCOUNT, account_service, SCORE_DOWN);
		if (err) {
			GRID_ERROR("Failed to lock service: %d %s", err->code, err->message);
			g_clear_error(&err);
			
			grid_main_set_status(EXIT_FAILURE);
			return;
		}
		
		if (!add_fake_account()) {
			grid_main_set_status(EXIT_FAILURE);
			return;
		}
		
		// Restart event-agent
		system("killall oio-event-agent");
		for (gint i = 0; i < 10; i++) {
			if (!grid_main_is_running()) {
				return;
			}
			
			g_usleep(G_TIME_SPAN_SECOND);
		}
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
	
	if (account_service) {
		GError *err = oio_cs_client__unlock_service(cs, NAME_SRVTYPE_ACCOUNT, account_service);
		if (err) {
			GRID_ERROR("Failed to unlock service: %d %s", err->code, err->message);
			g_clear_error(&err);
			
			grid_main_set_status(EXIT_FAILURE);
		}
		
		err = oio_cs_client__flush_services(cs, NAME_SRVTYPE_ACCOUNT);
		if (err) {
			GRID_ERROR("Failed to flush services: %d %s", err->code, err->message);
			g_clear_error(&err);
			
			grid_main_set_status(EXIT_FAILURE);
		}
		
		// Restart event-agent
		system("killall oio-event-agent");
		
		free_service(account_service);
	}
	
	if (cs) {
		oio_cs_client__destroy(cs);
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
