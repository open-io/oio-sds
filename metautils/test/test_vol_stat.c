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

#include <string.h>
#include <stdlib.h>

#include <glib.h>

#include "../lib/metatypes.h"
#include "../lib/metautils.h"
#include "../lib/metacomm.h"

addr_info_t *ai;

#define GETARG_INT(N,Default) (((N)<argc && (N)>0)?atoi(args[N]):Default)

int main (int argc, char ** args)
{
	int i, max_elements, nb_loops;
	GSList *list_api = NULL;

	max_elements = GETARG_INT(1,64);
	nb_loops = GETARG_INT(2,64);

	ai = build_addr_info( "10.232.192.193", 6002, NULL);
	log4c_init();

	for (i=max_elements; i>=0 ;i--) {
		volume_stat_t *vs;

		vs = g_try_malloc0(sizeof(volume_stat_t));
		vs->cpu_idle = i;
		vs->io_idle = i;
		vs->free_chunk = i;
		g_strlcpy( vs->info.name, "/DATA/BENCH_ORANGE/CORAID0101/vol01", sizeof(vs->info.name)-1);
		memcpy( &(vs->info.addr), ai, sizeof(addr_info_t));
		vs->info.score.value = i;
		vs->info.score.timestamp = time(0);

		list_api = g_slist_prepend( list_api, vs);
	}

	volume_stat_print_all( "root", "encoded:", list_api );


	for (i=nb_loops-1; i>=0 ;i--) {
		void *encoded=NULL;
		gsize encoded_size=0;
		GSList *decoded = NULL;

		if (0>=volume_stat_marshall( list_api, &encoded, &encoded_size, NULL)) {
			abort();
		}

		if (0>=volume_stat_unmarshall( &decoded, encoded, &encoded_size, NULL)) {
			abort();
		}

		g_free( encoded );

		if (!i) volume_stat_print_all( "root", "decoded:", decoded );
		
		g_slist_foreach( decoded, volume_stat_gclean, NULL );
		g_slist_free( decoded );
	}

	g_slist_foreach( list_api, volume_stat_gclean, NULL );
	g_slist_free( list_api );

	return 0;
}


