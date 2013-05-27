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
# define LOG_DOMAIN "metautils.test"
#endif

#include <stdlib.h>
#include <string.h>
#include "../lib/metautils.h"
#include "../lib/metacomm.h"

#define WORD32 "01234567012345670123456701234567"
#define WORD64 WORD32 WORD32 
#define WORD128 WORD64 WORD64
#define WORD256 WORD128 WORD128
#define WORD512 WORD256 WORD256
#define WORD1024 WORD512 WORD512
#define WORD2048 WORD1024 WORD1024

static gpointer
thread_action(gpointer p)
{
	gsize max, i;
	for (max=0; max<1048576; max++) {
		void *body;
		gsize body_size;
		GError *error, *real_error;
		MESSAGE m;
		
		error = NULL;
		GSETERROR(&error,"argl");
		for (i=0; i<max ;i++) {
			GSETCODE(&error,i,"%s", WORD2048);
		}
		g_printerr("size=%"G_GSIZE_FORMAT"\n", strlen(error->message));
		ERROR("Something very bad happened : %s", gerror_get_message(error));

		m = NULL;
		real_error = NULL;
		if (!message_create(&m, &real_error))
			abort();
		if (!message_set_NAME(m, "REPLY", sizeof("REPLY")-1, &real_error))
			abort();
		if (!message_add_field(m, NAME_MSGKEY_MESSAGE, sizeof(NAME_MSGKEY_MESSAGE) - 1,
			gerror_get_message(error), strlen(gerror_get_message(error)), &real_error))
			abort();
		do {                    /*ensures and formats the error code */
			gchar bufCode[4];
			gint code;
			code = gerror_get_code(error);
			if (code < 100)
				code = 598;
			if (code > 699)
				code = 699;
			g_snprintf(bufCode, 4, "%03i", gerror_get_code(error));
			if (!message_add_field(m, NAME_MSGKEY_STATUS, sizeof(NAME_MSGKEY_STATUS) - 1, bufCode, 3, &real_error))
				abort();
		} while (0);

		if (!message_marshall(m, &body, &body_size, &real_error))
			abort();
		if (!message_destroy(m,&real_error))
			abort();

		if (body)
			g_free(body);
		g_error_free(error);
	}
	return p;
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

int
main(int argc, char **args)
{
	GSList *threads;
	
	(void)argc;
	(void)args;

	if (!g_thread_supported ())
		g_thread_init (NULL);
	if (log4c_init())
		abort();
	threads = _start_n_threads(20,thread_action,NULL);
	_join_n_threads(threads);
	return 0;
}

