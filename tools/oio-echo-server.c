/*
OpenIO SDS oio-echo-server
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Affero General Public
License along with this program.
*/

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>

#include <metautils/lib/metautils.h>
#include <server/network_server.h>
#include <cluster/lib/gridcluster.h>

static struct network_server_s *server = NULL;
static GSList *urls = NULL;
static GString *announce = NULL;
static gchar *nsname = NULL;
static struct grid_task_queue_s *gtq_admin = NULL;
static GThread *th_admin = NULL;

static void
_task_register (gpointer p)
{
    (void) p;
    struct service_info_s *si = g_malloc0 (sizeof (*si));
    g_strlcpy (si->ns_name, nsname, sizeof (si->ns_name));
    g_strlcpy (si->type, "echo", sizeof (si->type));
    const char *id = announce ? announce->str : urls->data;
    grid_string_to_addrinfo (id, &si->addr);
    GError *err = register_namespace_service (si);

    service_info_clean (si);
    if (err) {
        GRID_WARN ("Failed to register [%s]: (%d) %s", id, err->code,
            err->message);
        g_clear_error (&err);
    }
}

static int
_notify_input (struct network_client_s *clt)
{
    struct data_slab_s *slab;
    while (data_slab_sequence_has_data (&(clt->input))) {
        if (!(slab = data_slab_sequence_shift (&(clt->input))))
            break;
        network_client_send_slab (clt, slab);
    }
    return clt->transport.waiting_for_close ? RC_NODATA : RC_PROCESSED;
}

static void
_factory (gpointer factory_udata, struct network_client_s *clt)
{
    (void) factory_udata;
    struct network_transport_s *transport = &(clt->transport);
    transport->client_context = NULL;
    transport->clean_context = NULL;
    transport->notify_input = _notify_input;
    transport->notify_error = NULL;
    network_client_allow_input (clt, TRUE);
}

static void
_echo_action (void)
{
    GError *err = NULL;

    if (NULL != (err = network_server_open_servers (server))) {
        GRID_ERROR ("Server opening error: %d %s", err->code, err->message);
		grid_main_set_status (1);
		return;
	}

    grid_task_queue_fire (gtq_admin);

    if (!(th_admin = grid_task_queue_run (gtq_admin, &err))) {
        GRID_ERROR ("Server opening error: %d %s", err->code, err->message);
		grid_main_set_status (1);
		return;
	}

    if (NULL != (err = network_server_run (server))) {
        GRID_ERROR ("Server opening error: %d %s", err->code, err->message);
		grid_main_set_status (1);
		return;
	}
}

static struct grid_main_option_s *
_echo_get_options (void)
{
    static struct grid_main_option_s options[] = {
        {"Endpoint", OT_LIST, {.lst = &urls}, "Bind to this IP:PORT"},
        {"Announce", OT_STRING, {.str = &announce},
            "Announce this to the conscience instead of the Endpoint"},
        {NULL, 0, {.i = 0}, NULL}
    };
    return options;
}

static void
_echo_set_defaults (void)
{
    urls = NULL;
    nsname = NULL;
    announce = NULL;
    gtq_admin = grid_task_queue_create ("admin");
    server = network_server_init ();
}

static void
_echo_specific_fini (void)
{
	// stop phase
	if (gtq_admin)
		grid_task_queue_stop (gtq_admin);
	if (server) {
		network_server_stop (server);
        network_server_close_servers (server);
	}
	// clean phase
    if (server)
        network_server_clean (server);
    g_slist_free_full (urls, g_free);
    g_free0 (nsname);
    grid_task_queue_destroy (gtq_admin);
}

static gboolean
_echo_configure (int argc, char **argv)
{
	if (!urls) {
        GRID_ERROR ("No URL configured");
        return FALSE;
	}
    if (argc != 1) {
        GRID_ERROR ("Missing mandatory parameter");
        return FALSE;
    }
    nsname = g_strdup (argv[0]);
    for (GSList * l = urls; l; l = l->next) {
        GRID_NOTICE ("Binding to [%s]", (gchar *) l->data);
        network_server_bind_host (server, l->data, NULL, _factory);
    }

    grid_task_queue_register (gtq_admin, 1, _task_register, NULL, NULL);
    return TRUE;
}

static const char *
_echo_get_usage (void)
{
    return "NS";
}

static void
_echo_specific_stop (void)
{
    if (server)
        network_server_stop (server);
    if (gtq_admin)
        grid_task_queue_stop (gtq_admin);
}

int
main (int argc, char **argv)
{
    struct grid_main_callbacks callbacks = {
        .options = _echo_get_options,
        .action = _echo_action,
        .set_defaults = _echo_set_defaults,
        .specific_fini = _echo_specific_fini,
        .configure = _echo_configure,
        .usage = _echo_get_usage,
        .specific_stop = _echo_specific_stop,
    };
    return grid_main (argc, argv, &callbacks);
}
