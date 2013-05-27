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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>

#include <glib.h>
#include <openssl/md5.h>

#include <metautils.h>
#include <../lib/grid_client.h>

int main (int argc, char ** args)
{
	int rc = -1;

	gs_error_t *err = NULL;
	gs_grid_storage_t *hc;
	gs_container_t *container;
	char *ns;
	char cname[60];

	srand(time(NULL));

	if (argc != 2) {
		g_error("Usage: %s NS\n", args[0]);
		return rc;
	}

	ns = args[1];

	bzero(cname, sizeof(cname));
	g_snprintf(cname, sizeof(cname), "SOLR%d", rand());

	printf("Working with container [%s]\n", cname);

	hc = gs_grid_storage_init( ns, &err );
	if(!hc) {
		printf("failed to init hc\n");
		return rc;
	}

	container = gs_get_container(hc, cname, 1, &err);
	if(!container) {
		printf("Failed to resolve container\n");
		goto end_label;
	}

	gs_service_t **srv_array = NULL;
	srv_array = gs_container_service_get_available(container, "meta0", &err);
	char url[256];
	bzero(url, sizeof(url));
	gs_service_get_url(srv_array[0], url, sizeof(url));
	printf("New service linked\n");
	printf("service url = [%s]\n", url);

	if(srv_array)
		gs_service_free_array(srv_array); 
	
	srv_array = gs_container_service_get_all(container, "meta0", &err);

	bzero(url, sizeof(url));
	gs_service_get_url(srv_array[0], url, sizeof(url));
	printf("Already linked service :\n");
	printf("service url = [%s]\n", url);

	if(srv_array)
		gs_service_free_array(srv_array); 

end_label:

	if(container) {
		gs_container_free(container);
		container = NULL;
	}

	if(hc) {
		gs_grid_storage_free(hc);
		hc = NULL;
	}

	if(err) {
		gs_error_free(err);
		err= NULL;
	}
}

