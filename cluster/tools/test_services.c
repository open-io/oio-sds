/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridcluster.tools"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <stdlib.h>
#include <glib.h>
#include <metatypes.h>
#include <metautils.h>
#include <metacomm.h>
#include "../remote/gridcluster_remote.h"

static gboolean is_running;
static addr_info_t addr;

static gint timeout;
static gint timeout_min;

static gsize nb_put;
static gsize nb_get;

static gchar ns_name[LIMIT_LENGTH_NSNAME];
static gchar type_name[LIMIT_LENGTH_SRVTYPE];

static struct service_info_s*
_build_random_srvinfo(void)
{
	int port;
	gchar str_addr[32];
	struct service_info_s *si;

	si = g_try_malloc0(sizeof(struct service_info_s));
	g_assert(si);

	g_snprintf(str_addr, sizeof(str_addr), "%ld.%ld.%ld.%ld", 1+(random()%225), 1+(random()%254), 1+(random()%254), 1+(random()%254));
	port = random()%65536;
	if (!service_info_set_address(si, str_addr, port, NULL)) {
		g_printerr("Failed to build address %s:%d\n", str_addr, port);
		abort();
	}
	g_strlcpy(si->type, type_name, sizeof(si->type));
	g_strlcpy(si->ns_name, ns_name, sizeof(si->ns_name));
	si->score.value = -2;
	si->score.timestamp = 0;

	si->tags = g_ptr_array_new();
	service_tag_set_value_i64(service_info_ensure_tag(si->tags, NAME_MACRO_CPU_NAME), 0LL);
	service_tag_set_value_i64(service_info_ensure_tag(si->tags, NAME_MACRO_SPACE_NAME), 0LL);

	return si;
}

static inline GSList*
_build_n_random_srvinfo(gsize n)
{
	GSList *list_srv;

	for (list_srv=NULL; n--!=0; )
		list_srv = g_slist_prepend(list_srv, _build_random_srvinfo());
	return list_srv;
}

static inline void
_randomize_srv_tags(GSList *list_srv)
{
	GSList *l;

	for (l=list_srv; l ;l=l->next) {
		struct service_info_s *si;

		si = l->data;
		service_tag_set_value_i64(service_info_ensure_tag(si->tags, NAME_MACRO_CPU_NAME), random()%100);
		service_tag_set_value_i64(service_info_ensure_tag(si->tags, NAME_MACRO_SPACE_NAME), random()%100);
	}
}

static gpointer
srv_getter(gpointer p)
{
	GTimer *timer;
	GSList *list_srv;

	timer = g_timer_new();
	while (is_running) {
		GError *error_local;

		g_timer_start(timer);
		error_local = NULL;
		list_srv = gcluster_get_services(&addr, timeout_min + (random()%timeout), "meta0,meta1,meta2,solr,rawx", &error_local);
		if (!list_srv)
			g_printerr("%p : Failed to get the services : %s\n", g_thread_self(), gerror_get_message(error_local));
		else {
			gdouble elapsed;
			gsize list_srv_length;
			
			elapsed = g_timer_elapsed(timer,NULL);
			list_srv_length = g_slist_length(list_srv);
			g_print("%p : [%d] services received in %.4f seconds\n", g_thread_self(), list_srv_length, elapsed);
		
			g_slist_foreach(list_srv, service_info_gclean, NULL);
			g_slist_free(list_srv);
		}

		if (error_local)
			g_error_free(error_local);
	}

	g_timer_destroy(timer);
	return p;
}

static gpointer
srv_pusher(gpointer p)
{
	gsize list_srv_length;
	GTimer *timer;
	GSList *list_srv;

	timer = g_timer_new();
	list_srv = _build_n_random_srvinfo(10);
	list_srv_length = g_slist_length(list_srv);
	
	while (is_running) {
		GError *error_local;

		_randomize_srv_tags(list_srv);

		g_timer_start(timer);
		error_local = NULL;
		if (!gcluster_push_services(&addr, timeout_min + (random()%timeout), list_srv, FALSE, &error_local))
			g_printerr("%p : Failed to push the services : %s\n", g_thread_self(), gerror_get_message(error_local));
		else
			g_print("%p : [%d] services sent in %.4f seconds\n", g_thread_self(), list_srv_length, g_timer_elapsed(timer,NULL));

		if (error_local)
			g_error_free(error_local);
	}

	g_timer_destroy(timer);
	return p;
}

static GSList*
_start_n_threads(gsize n, GThreadFunc func, gpointer p)
{
	GSList *list_threads;
	
	list_threads = NULL;
	while (n-- != 0) {
		GError *error_local;
		GThread *th;

		error_local = NULL;
		th = g_thread_create(func, p, TRUE, &error_local);
		g_assert(th);

		g_print("Thread started : %p\n", th);
		list_threads = g_slist_prepend(list_threads, th);
	}
	
	return list_threads;
}

static void
_join_n_threads(GSList *list_threads)
{
	GSList *l;

	for (l=list_threads; l ;l=l->next) {
		GThread *th;

		th = l->data;
		if (!th)
			continue;
		g_thread_join(th);
		g_print("Thread stopped : %p\n", th);
	}
}

#include <signal.h>

static void sighandler_stop(int s);

void
sighandler_stop(int s)
{
	switch (s) {
		case SIGTERM:
		case SIGHUP:
		case SIGINT:
		case SIGKILL:
			is_running = FALSE;
	}
	signal(s,sighandler_stop);
}

static void
init_defaults(void)
{
	is_running = TRUE;
	memset(&addr,0x00,sizeof(addr_info_t));
	timeout = 5000;
	timeout_min = 5;
	nb_get = 0;
	nb_put = 0;

	g_strlcpy(ns_name,"TEST",sizeof(ns_name));
	g_strlcpy(type_name,"solr",sizeof(type_name));
}

static void
parse_arguments(int argc, char ** args)
{
	g_assert(argc > 0);
	g_assert(l4_address_init_with_url(&addr,args[0],NULL));

	while (--argc > 0) {
		if (g_str_has_prefix(args[argc],"get:"))
			nb_get += atoi(args[argc]+sizeof("get:")-1);
		else if (g_str_has_prefix(args[argc],"put:"))
			nb_put += atoi(args[argc]+sizeof("put:")-1);
		else {
			g_printerr("Argument ignored : %s\n", args[argc]);
			abort();
		}
	}
	g_print("PUT:%d GET:%d\n", nb_put, nb_get);
}

int
main(int argc, char ** args)
{
	GSList *threads;

	if (!g_thread_supported())
		g_thread_init(NULL);

	srandom(time(0));
	signal(SIGTERM,sighandler_stop);
	signal(SIGHUP,sighandler_stop);
	signal(SIGINT,sighandler_stop);
	signal(SIGKILL,sighandler_stop);

	init_defaults();
	parse_arguments(argc-1,args+1);

	threads = NULL;
	threads = g_slist_concat(threads,_start_n_threads(nb_put,srv_pusher,NULL));
	threads = g_slist_concat(threads,_start_n_threads(nb_get,srv_getter,NULL));
	_join_n_threads(threads);

	return 0;
}

