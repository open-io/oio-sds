/*
OpenIO SDS oio-event-benchmark
Copyright (C) 2017 OpenIO, as part of OpenIO Software Defined Storage

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
#include <stdlib.h>

#include <metautils/lib/metautils.h>

#include "conf_benchmark.h"
#include "fake_service.h"
#include "send_events.h"

static void grid_main_specific_stop(void);

// send_events.c
extern gint events_per_round;
extern gint rounds;
extern gint increment;
extern enum event_type_e event_type;

static struct oio_directory_s *dir = NULL;
static struct oio_url_s *rdir_rawx_url = NULL;
static struct oio_cs_client_s *cs = NULL;
static GSList *account_services = NULL;
GThread *fake_service_thread = NULL;
gchar namespace[LIMIT_LENGTH_NSNAME];

static gboolean
link_rawx_fake_service(void)
{
	dir = oio_directory__create_proxy(namespace);
	if (!dir) {
		return FALSE;
	}
	g_assert_nonnull(dir);

	rdir_rawx_url = oio_url_empty();
	oio_url_set(rdir_rawx_url, OIOURL_NS, namespace);
	oio_url_set(rdir_rawx_url, OIOURL_ACCOUNT, NAME_ACCOUNT_RDIR);
	oio_url_set(rdir_rawx_url, OIOURL_USER, RAWX_ADDRESS);
	oio_url_set(rdir_rawx_url, OIOURL_TYPE, NAME_SRVTYPE_RDIR);

	char *id = g_strdup_printf("%s|" NAME_SRVTYPE_RDIR "|" FAKE_SERVICE_ADDRESS,
			namespace);
	const char * const values[] = {
		"host", FAKE_SERVICE_ADDRESS,
		"args", "",
		"type", NAME_SRVTYPE_RDIR,
		"id", id,
		NULL
	};

	GError *err = oio_directory__force(dir, rdir_rawx_url, NAME_SRVTYPE_RDIR,
			values, 1);
	free(id);
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
	g_strfreev((char **) service->kv_tags);
	g_free(service);
}

static GSList *
get_account_services(void)
{
	GSList *services = NULL;
	void _on_reg(const struct oio_cs_registration_s *reg, int score) {
		(void) score;

		struct oio_cs_registration_s *reg_cpy =
				g_malloc0(sizeof(struct oio_cs_registration_s));

		reg_cpy->id = g_strdup(reg->id);
		reg_cpy->url = g_strdup(reg->url);

		if (reg->kv_tags) {
			reg_cpy->kv_tags = (const char * const *)
					g_strdupv((char **) reg->kv_tags);
		}

		services = g_slist_prepend(services, reg_cpy);
	}
	GError *err = oio_cs_client__list_services(cs, NAME_SRVTYPE_ACCOUNT, FALSE,
			_on_reg);
	if (err) {
		GRID_ERROR("Failed to list account services: (%d) %s", err->code,
				err->message);
		g_clear_error(&err);

		return NULL;
	}

	return services;
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

	GError *err = oio_cs_client__lock_service(cs, NAME_SRVTYPE_ACCOUNT, &reg,
			SCORE_MAX);
	if (err) {
		GRID_ERROR("Failed to lock service: %d %s", err->code,
				err->message);
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

static gboolean
kill_event_agent(void)
{
	GError *err = NULL;

	gboolean success = g_spawn_command_line_sync(
			"/usr/bin/killall oio-event-agent", NULL, NULL, NULL, &err);
	if (err) {
		GRID_ERROR("Command line failure': (%d) %s", err->code,
				err->message);
		g_clear_error(&err);
	}

	return success;
}

// Main callbacks

static struct grid_main_option_s *
grid_main_get_options(void)
{
	static struct grid_main_option_s cli_options[] = {
		{
			"Rounds", OT_UINT, {.i = &rounds},
			"Number of rounds for a test"
		},
		{
			"EventsPerRound", OT_UINT, {.i = &events_per_round},
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
grid_main_get_usage(void)
{
	return "NS CHUNK_NEW|CHUNK_DELETED"
			"|CONTAINER_NEW|CONTAINER_STATE|CONTAINER_DELETED"
			"|CONTENT_DELETED";
}

static void
grid_main_set_defaults(void)
{
	send_events_defaults();
}

static gboolean
grid_main_configure(int argc, char **argv)
{
	if (argc < 2) {
		g_printerr("Invalid arguments number\n");
		return FALSE;
	}

	gsize s = g_strlcpy(namespace, argv[0], LIMIT_LENGTH_NSNAME);
	if (s >= LIMIT_LENGTH_NSNAME) {
		GRID_ERROR("Namespace name too long (given=%"G_GSIZE_FORMAT" max=%u)",
				s, LIMIT_LENGTH_NSNAME);
		return FALSE;
	}
	GRID_DEBUG("NS configured to [%s]", namespace);

	return fake_service_configure() && send_events_configure(argv[1]);
}

static void
grid_main_action(void)
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
		cs = oio_cs_client__create_proxied(namespace);

		account_services = get_account_services();
		if (!account_services) {
			grid_main_set_status(EXIT_FAILURE);
			return;
		}
		GError *err;
		for (GSList *account = account_services; account && account->data;
					account = account->next) {
			err = oio_cs_client__lock_service(cs, NAME_SRVTYPE_ACCOUNT,
					account->data, SCORE_DOWN);
			if (err) {
				GRID_ERROR("Failed to lock account service: %d %s",
						err->code, err->message);
				g_clear_error(&err);

				grid_main_set_status(EXIT_FAILURE);
				return;
			}
		}

		if (!add_fake_account()) {
			grid_main_set_status(EXIT_FAILURE);
			return;
		}

		// Restart event-agent
		if (!kill_event_agent()) {
			grid_main_set_status(EXIT_FAILURE);
			return;
		}
		for (gint i = 0; i < 10; i++) {
			if (!grid_main_is_running()) {
				return;
			}

			g_usleep(G_TIME_SPAN_SECOND);
		}
	}

	// Launch the fake service
	GError *err;
	fake_service_thread = g_thread_try_new("fake_service", _fake_service_run,
			NULL, &err);
	if (fake_service_thread == NULL) {
		GRID_ERROR("Failed to start the fake_service thread: (%d) %s",
				err->code, err->message);
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
grid_main_specific_stop(void)
{
	fake_service_stop();
}

static void
grid_main_specific_fini(void)
{
	send_events_fini();
	fake_service_fini();

	if (rdir_rawx_url) {
		GError *err = oio_directory__unlink(dir, rdir_rawx_url, NAME_SRVTYPE_RDIR);
		if (err) {
			GRID_ERROR("Failed to call 'reference/unlink': (%d) %s", err->code,
					err->message);
			g_clear_error(&err);
		}
		oio_url_clean(rdir_rawx_url);
	}

	if (dir) {
		oio_directory__destroy(dir);
		dir = NULL;
	}

	if (account_services) {
		GError *err;

		// Unlock account services
		for (GSList *account = account_services; account && account->data;
					account = account->next) {
			err = oio_cs_client__unlock_service(cs,
					NAME_SRVTYPE_ACCOUNT, account->data);
			if (err) {
				GRID_ERROR("Failed to unlock account service: %d %s",
						err->code, err->message);
				g_clear_error(&err);

				grid_main_set_status(EXIT_FAILURE);
			}
		}

		err = oio_cs_client__flush_services(cs, NAME_SRVTYPE_ACCOUNT);
		if (err) {
			GRID_ERROR("Failed to flush services: %d %s", err->code,
					err->message);
			g_clear_error(&err);

			grid_main_set_status(EXIT_FAILURE);
		}

		// Restart event-agent
		kill_event_agent();

		g_slist_free_full(account_services, (GDestroyNotify) free_service);
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
main(int argc, char **argv)
{
	return grid_main(argc, argv, &main_callbacks);
}
