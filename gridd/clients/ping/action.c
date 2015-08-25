/*
OpenIO SDS gridd
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

static gboolean flag_reuse = FALSE;
static gboolean flag_flood = FALSE;
static gint64 max_packets = 0;
static gint nb_threads = 50;
static gchar ns_name[LIMIT_LENGTH_NSNAME];
static GPtrArray *addresses = NULL;

static const gchar*
main_get_usage(void)
{
	return "IP:PORT";
}

static void
main_set_defaults(void)
{
	addresses = g_ptr_array_new();
	memset(ns_name, 0, sizeof(ns_name));
	GRID_DEBUG("Defaults set!");
}

static struct grid_main_option_s*
main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{ "Flood",   OT_BOOL, {.b=&flag_flood},
			"Only one address is expected but several threads are started, sending requests without any pause."},
		{ "Threads", OT_INT,  {.i=&nb_threads},
			"Number of concurrent PING threads. Ignored when Flood disabled."},
		{ "MaxReq",  OT_INT64, {.i64=&max_packets},
			"How many requests attempts will be made in each thread"},
		{ "CnxReuse", OT_BOOL, {.b=&flag_reuse},
			"If enabled, each connection won't be closed after each request attempt."},
		{ NULL, 0, {.b=0}, NULL }
	};
	return options;
}

static void
main_specific_stop(void)
{
}

static void
main_specific_fini(void)
{
	if (addresses)
		g_ptr_array_free(addresses, TRUE);
	addresses = NULL;
	GRID_DEBUG("Finished!");
}

static gboolean
_config_single_address(const gchar *arg)
{
	if (!arg || !metautils_url_valid_for_connect(arg)) {
		GRID_ERROR("Invalid adress: %s", arg);
		return FALSE;
	}

	g_ptr_array_add(addresses, g_strdup(arg));
	GRID_DEBUG("Configured '%s'", arg);
	return TRUE;
}

static gboolean
_config_single_service(const gchar *arg)
{
	gchar **strv = g_strsplit(arg, "|", 4);

	if (g_strv_length(strv) < 3) {
		GRID_ERROR("Invalid service description [%s]", arg);
		g_strfreev(strv);
		return FALSE;
	}
	if (!_config_single_address(strv[2])) {
		g_strfreev(strv);
		return FALSE;
	}

	g_free(strv);
	return TRUE;
}

static gboolean
main_configure(int argc, char **args)
{
	int i;

	if (flag_flood) {
		if (nb_threads <= 0) {
			GRID_ERROR("Invalid number of threads [%d]", nb_threads);
			return FALSE;
		}
	}

	if (argc < 1) {
		GRID_ERROR("At least one argument expected");
		return FALSE;
	}
	
	if (flag_flood) {
		
		if (argc != 1) {
			GRID_ERROR("Flood option is not compatible with multiple addresses");
			return FALSE;
		}
		for (i=0; i < nb_threads ; i++) {
			gchar *arg = args[0];

			if (strchr(arg, '|')) {
				if (!_config_single_service(arg))
					return FALSE;
			}
			else {
				if (!_config_single_address(arg))
					return FALSE;
			}
		}
	}
	else {
		for (i=0; i<argc ;i++) {
			gchar *arg = args[i];

			if (strchr(arg, '|')) {
				if (!_config_single_service(arg))
					return FALSE;
			}
			else {
				if (!_config_single_address(arg))
					return FALSE;
			}
		}
	}

	GRID_INFO("Target address(es) configured!");
	return TRUE;
}

/* ------------------------------------------------------------------------- */

static gpointer
thread_worker(gpointer p)
{
	gint64 packets = 0;

	GRID_DEBUG("Connecting to [%s]", (gchar*)p);
	GByteArray *request = message_marshall_gba_and_clean(
			metautils_message_create_named("PING"));
	GTimer *timer = g_timer_new();
	do {
		g_timer_reset(timer);
		GError *err = gridd_client_exec((gchar*)p, 1.0, g_byte_array_ref(request));
		gdouble elapsed = g_timer_elapsed(timer, NULL);

		g_print("%s %s %f\n", (err?"ERROR":"PONG"), (gchar*)p, elapsed);

		if (err) g_clear_error(&err);
		if (max_packets > 0 && (++packets) >= max_packets)
			break;
		if (!flag_flood)
			usleep(1000000L);

	} while (grid_main_is_running());

	g_timer_destroy(timer);
	metautils_gba_unref(request);
	return p;
}

static GSList *
thread_start_N(void)
{
	GThread *th;
	GError *err = NULL;
	GSList *threads = NULL;

	for (guint i=0; i<addresses->len;i++) {
		gchar *url = g_strdup(addresses->pdata[i]);
		th = g_thread_try_new("worker", thread_worker, url, &err);
		if (th != NULL)
			threads = g_slist_prepend(threads, th);
		else {
			GRID_ERROR("GThread creation failure : %s", err->message);
			g_clear_error(&err);
		}
	}

	return threads;
}

static void
thread_join_all(GSList *threads)
{
	GThread *th;
	gpointer p;
	GSList *l;

	for (l=threads; l ;l=l->next) {
		if (!(th = l->data))
			continue;
		p = g_thread_join(th);
		g_free(p);
	}
}

static void
main_action(void)
{
	GSList *threads = NULL;

	/* Start several worker threads */
	threads = thread_start_N();
	GRID_INFO("Started %u worker threads", g_slist_length(threads));
	
	/* Join the threads started */
	thread_join_all(threads);
	g_slist_free(threads);
	GRID_INFO("Joined all the worker threads");
}

static struct grid_main_callbacks cb =
{
	.options = main_get_options,
	.action = main_action,
	.set_defaults = main_set_defaults,
	.specific_fini = main_specific_fini,
	.configure = main_configure,
	.usage = main_get_usage,
	.specific_stop = main_specific_stop
};

int
main(int argc, char **argv)
{
	return grid_main_cli(argc, argv, &cb);
}

