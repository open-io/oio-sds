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
# define LOG_DOMAIN "gridcluster.tools.tools"
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

static gint timeout = 8000;
static gboolean is_running;

static void
cid_randomize(void *buf, gsize buf_size)
{
	gsize i, max;

	for (i=0, max=buf_size/sizeof(long); i<max ;i++)
		((long*)buf)[i] = random();
}

static gchar *
_get_random_element(void)
{
	gchar str_cid[STRLEN_CONTAINERID];
	container_id_t cid;
	
	if (random()%2) {
		switch (random()%4) {
			case 3:/*META1*/
				return g_strdup("META1:10.0.0.1:6001");
			case 2:/*CONTENT*/
				cid_randomize(cid,sizeof(container_id_t));
				container_id_to_string(cid,str_cid,sizeof(str_cid));
				return g_strdup_printf("10.0.0.2:6002:%s:content:GET", str_cid);
			case 1:/*CONTAINER*/
				cid_randomize(cid,sizeof(container_id_t));
				container_id_to_string(cid,str_cid,sizeof(str_cid));
				return g_strdup_printf("10.0.0.3:6003:%s::", str_cid);
			case 0:/*META2*/
				return g_strdup("10.0.0.4:6004:::");
		}
	}
	else {
		int port, r, ip1, ip2, ip3, ip4;

		ip1 = 1 + (random()%254);
		ip2 = 1 + (random()%254);
		ip3 = 1 + (random()%254);
		ip4 = 1 + (random()%254);
		port = random() % (65536-1024);
		switch (random()%4) {
			case 3:/*META1*/
				return g_strdup_printf("META1:%d.%d.%d.%d:%d", ip1, ip2, ip3, ip4, port);
			case 2:/*CONTENT*/
				cid_randomize(cid,sizeof(container_id_t));
				container_id_to_string(cid,str_cid,sizeof(str_cid));
				return g_strdup_printf("%d.%d.%d.%d:%d:%s:content:GET", ip1, ip2, ip3, ip4, port, str_cid);
			case 1:/*CONTAINER*/
				cid_randomize(cid,sizeof(container_id_t));
				container_id_to_string(cid,str_cid,sizeof(str_cid));
				return g_strdup_printf("%d.%d.%d.%d:%d:%s::", ip1, ip2, ip3, ip4, port, str_cid);
			case 0:/*META2*/
				return g_strdup_printf("%d.%d.%d.%d:%d:::", ip1, ip2, ip3, ip4, port);
		}
	}
}

static gpointer
brk_getter(gpointer p)
{
	GTimer *timer;
	addr_info_t *addr_conscience;

	addr_conscience = p;
	timer = g_timer_new();
	while (is_running) {
		GSList *list_brk;
		GError *error_local;

		g_timer_start(timer);
		error_local = NULL;
		list_brk = gcluster_get_broken_container(addr_conscience, timeout, &error_local);
		if (!list_brk && error_local)
			g_printerr("Failed to get broken elements : %s\n", gerror_get_message(error_local));
		else
			g_printerr("[%d] broken elements received in %.4f seconds\n", g_slist_length(list_brk), g_timer_elapsed(timer,NULL));

		g_slist_foreach(list_brk,g_free1,NULL);
		g_slist_free(list_brk);
		if (error_local)
			g_error_free(error_local);
	}

	g_timer_destroy(timer);
	return p;
}

static gpointer
brk_pusher(gpointer p)
{
	GTimer *timer;
	gsize i, max;
	addr_info_t *addr_conscience;

	addr_conscience = p;
	timer = g_timer_new();
	while (is_running) {
		GSList *list_brk;
		GError *error_local;

		list_brk = NULL;
		for (i=0, max=1+random()%10L; i<max ;i++)
			list_brk = g_slist_prepend(list_brk,_get_random_element());
		
		g_timer_start(timer);
		error_local = NULL;
		if (!gcluster_push_broken_container(addr_conscience, timeout, list_brk, &error_local))
			g_printerr("Failed to push broken elements : %s\n", gerror_get_message(error_local));
		else
			g_printerr("[%d] broken elements sent in %.4f seconds\n", g_slist_length(list_brk), g_timer_elapsed(timer,NULL));

		g_slist_foreach(list_brk,g_free1,NULL);
		g_slist_free(list_brk);
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

		g_printerr("Thread started : %p\n", th);
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
		g_printerr("Thread stopped : %p\n", th);
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

int
main(int argc, char ** args)
{
	GSList *threads;
	addr_info_t addr;

	if (!g_thread_supported())
		g_thread_init(NULL);

	signal(SIGTERM,sighandler_stop);
	signal(SIGHUP,sighandler_stop);
	signal(SIGINT,sighandler_stop);
	signal(SIGKILL,sighandler_stop);

	is_running = TRUE;
	g_assert(argc > 0);	
	g_assert(l4_address_init_with_url(&addr,args[1],NULL));
	srandom(time(0));

	threads = NULL;
	threads = g_slist_concat(threads,_start_n_threads(20,brk_pusher,&addr));
	threads = g_slist_concat(threads,_start_n_threads(7,brk_getter,&addr));
	_join_n_threads(threads);

	return 0;
}

