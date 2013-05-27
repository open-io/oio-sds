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
#define LOG_DOMAIN "metautils.test"
#endif

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "../lib/metatypes.h"
#include "../lib/metautils.h"
#include "../lib/metacomm.h"

#define TEST_ID "id"
#define TEST_VERSION "version"
#define TEST_NAME "name"


int main (int argc, char ** args)
{
	gsize i,max;

	if (argc>1) {
		char *e=NULL;
		max = strtoul(args[1],&e,10);
	}
	else
	{
		max = 32;
	}

	for (i=0; i<max ; i++)
	{
		GError *error=NULL;
		MESSAGE m1=NULL, m2=NULL;
		gsize size, size2;
		void *buf=NULL;

		g_assert (message_create (&m1, &error));
		g_assert (message_create (&m2, &error));
		g_assert (message_set_ID (m1, TEST_ID, sizeof(TEST_ID)-1, &error));
		g_assert (message_set_NAME (m1, TEST_NAME, sizeof(TEST_NAME)-1, &error));
		g_assert (message_set_VERSION (m1, TEST_VERSION, sizeof(TEST_VERSION)-1, &error));
		g_assert (message_add_field (m1, "plop", strlen("plop"), "plop_valeur", strlen("plop_valeur"), &error));
		g_assert (message_add_field (m1, "plip", strlen("plip"), "plip_valeur", strlen("plip_valeur"), &error));
		g_assert (message_add_field (m1, "plup", strlen("plup"), "plup_valeur", strlen("plup_valeur"), &error));
		g_assert (message_add_field (m1, "plep", strlen("plep"), "plep_valeur", strlen("plep_valeur"), &error));
		g_assert (message_add_field (m1, "plap", strlen("plap"), "plap_valeur", strlen("plap_valeur"), &error));

		message_print (m1, LOG_DOMAIN, "message: ", &error);


		g_assert (message_marshall (m1, &buf, &size, &error));
		g_assert (buf!=NULL);

		size2=size;
		INFO("size=%i size2=%i buf=%p", size, size2, buf);
		g_assert (l4v_get_size (buf, &size2, &error));

		size2=size;
		g_assert (message_unmarshall (m2, buf, &size2, &error));

		g_free (buf);
		g_assert (message_destroy (m1, &error));
		g_assert (message_destroy (m2, &error));
	}

	g_mem_profile();
	
	return 0;
}

